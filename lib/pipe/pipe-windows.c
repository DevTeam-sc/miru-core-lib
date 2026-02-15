#include "pipe-glue.h"

#include "pipe-sddl.h"

#include <sddl.h>
#include <windows.h>

#define PIPE_BUFSIZE (1024 * 1024)

#define CHECK_WINAPI_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto winapi_failed; \
  }

typedef struct _MiruPipeBackend MiruPipeBackend;
typedef guint MiruWindowsPipeRole;

struct _MiruPipeBackend
{
  MiruWindowsPipeRole role;
  HANDLE pipe;
  gboolean connected;
  HANDLE read_complete;
  HANDLE read_cancel;
  HANDLE write_complete;
  HANDLE write_cancel;
};

enum _MiruWindowsPipeRole
{
  MIRU_WINDOWS_PIPE_SERVER = 1,
  MIRU_WINDOWS_PIPE_CLIENT
};

struct _MiruWindowsPipeInputStream
{
  GInputStream parent;

  MiruPipeBackend * backend;
};

struct _MiruWindowsPipeOutputStream
{
  GOutputStream parent;

  MiruPipeBackend * backend;
};

static HANDLE miru_windows_pipe_open_named_pipe (const gchar * name, MiruWindowsPipeRole role, GError ** error);

static gssize miru_windows_pipe_input_stream_read (GInputStream * base, void * buffer, gsize count, GCancellable * cancellable, GError ** error);
static gboolean miru_windows_pipe_input_stream_close (GInputStream * base, GCancellable * cancellable, GError ** error);

static gssize miru_windows_pipe_output_stream_write (GOutputStream * base, const void * buffer, gsize count, GCancellable * cancellable, GError ** error);
static gboolean miru_windows_pipe_output_stream_close (GOutputStream * base, GCancellable * cancellable, GError ** error);

static gchar * miru_pipe_generate_name (void);
static WCHAR * miru_pipe_path_from_name (const gchar * name);

static gboolean miru_windows_pipe_backend_await (MiruPipeBackend * self, HANDLE complete, HANDLE cancel, GCancellable * cancellable, GError ** error);
static void miru_windows_pipe_backend_on_cancel (GCancellable * cancellable, gpointer user_data);

G_DEFINE_TYPE (MiruWindowsPipeInputStream, miru_windows_pipe_input_stream, G_TYPE_INPUT_STREAM)
G_DEFINE_TYPE (MiruWindowsPipeOutputStream, miru_windows_pipe_output_stream, G_TYPE_OUTPUT_STREAM)

void
miru_pipe_transport_set_temp_directory (const gchar * path)
{
}

void *
_miru_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error)
{
  gchar * name;

  name = miru_pipe_generate_name ();

  *local_address = g_strdup_printf ("pipe:role=server,name=%s", name);
  *remote_address = g_strdup_printf ("pipe:role=client,name=%s", name);

  g_free (name);

  return NULL;
}

void
_miru_pipe_transport_destroy_backend (void * backend)
{
}

void *
_miru_windows_pipe_create_backend (const gchar * address, GError ** error)
{
  MiruPipeBackend * backend;
  const gchar * role, * name;

  backend = g_slice_new0 (MiruPipeBackend);

  role = strstr (address, "role=") + 5;
  backend->role = role[0] == 's' ? MIRU_WINDOWS_PIPE_SERVER : MIRU_WINDOWS_PIPE_CLIENT;
  name = strstr (address, "name=") + 5;
  backend->pipe = miru_windows_pipe_open_named_pipe (name, backend->role, error);
  if (backend->pipe != INVALID_HANDLE_VALUE)
  {
    backend->read_complete = CreateEvent (NULL, TRUE, FALSE, NULL);
    backend->read_cancel = CreateEvent (NULL, TRUE, FALSE, NULL);
    backend->write_complete = CreateEvent (NULL, TRUE, FALSE, NULL);
    backend->write_cancel = CreateEvent (NULL, TRUE, FALSE, NULL);
  }
  else
  {
    _miru_windows_pipe_destroy_backend (backend);
    backend = NULL;
  }

  return backend;
}

void
_miru_windows_pipe_destroy_backend (void * opaque_backend)
{
  MiruPipeBackend * backend = opaque_backend;

  if (backend->read_complete != NULL)
    CloseHandle (backend->read_complete);
  if (backend->read_cancel != NULL)
    CloseHandle (backend->read_cancel);
  if (backend->write_complete != NULL)
    CloseHandle (backend->write_complete);
  if (backend->write_cancel != NULL)
    CloseHandle (backend->write_cancel);

  if (backend->pipe != INVALID_HANDLE_VALUE)
    CloseHandle (backend->pipe);

  g_slice_free (MiruPipeBackend, backend);
}

static HANDLE
miru_windows_pipe_open_named_pipe (const gchar * name, MiruWindowsPipeRole role, GError ** error)
{
  HANDLE result = INVALID_HANDLE_VALUE;
  BOOL success;
  const gchar * failed_operation;
  WCHAR * path;
  LPCWSTR sddl;
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;

  path = miru_pipe_path_from_name (name);
  sddl = miru_pipe_get_sddl_string_for_pipe ();
  success = ConvertStringSecurityDescriptorToSecurityDescriptorW (sddl, SDDL_REVISION_1, &sd, NULL);
  CHECK_WINAPI_RESULT (success, !=, FALSE, "ConvertStringSecurityDescriptorToSecurityDescriptor");

  sa.nLength = sizeof (sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;

  if (role == MIRU_WINDOWS_PIPE_SERVER)
  {
    result = CreateNamedPipeW (path,
        PIPE_ACCESS_DUPLEX |
        FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE |
        PIPE_READMODE_BYTE |
        PIPE_WAIT,
        1,
        PIPE_BUFSIZE,
        PIPE_BUFSIZE,
        0,
        &sa);
    CHECK_WINAPI_RESULT (result, !=, INVALID_HANDLE_VALUE, "CreateNamedPipe");
  }
  else
  {
    result = CreateFileW (path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        &sa,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);
    CHECK_WINAPI_RESULT (result, !=, INVALID_HANDLE_VALUE, "CreateFile");
  }

  goto beach;

winapi_failed:
  {
    DWORD last_error = GetLastError ();
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (last_error),
        "Error opening named pipe (%s returned 0x%08lx)",
        failed_operation, last_error);
    goto beach;
  }

beach:
  {
    if (sd != NULL)
      LocalFree (sd);

    g_free (path);

    return result;
  }
}

static gboolean
miru_windows_pipe_backend_connect (MiruPipeBackend * backend, GCancellable * cancellable, GError ** error)
{
  gboolean success = FALSE;
  HANDLE connect, cancel;
  OVERLAPPED overlapped = { 0, };
  BOOL ret, last_error;
  DWORD bytes_transferred;

  if (backend->connected)
  {
    return TRUE;
  }
  else if (backend->role == MIRU_WINDOWS_PIPE_CLIENT)
  {
    backend->connected = TRUE;
    return TRUE;
  }

  connect = CreateEvent (NULL, TRUE, FALSE, NULL);
  cancel = CreateEvent (NULL, TRUE, FALSE, NULL);
  overlapped.hEvent = connect;

  ret = ConnectNamedPipe (backend->pipe, &overlapped);
  last_error = GetLastError ();
  if (!ret && last_error != ERROR_IO_PENDING && last_error != ERROR_PIPE_CONNECTED)
    goto failure;

  if (last_error == ERROR_IO_PENDING)
  {
    if (!miru_windows_pipe_backend_await (backend, connect, cancel, cancellable, error))
      goto beach;

    if (!GetOverlappedResult (backend->pipe, &overlapped, &bytes_transferred, FALSE))
      goto failure;
  }

  backend->connected = TRUE;
  success = TRUE;
  goto beach;

failure:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (last_error),
        "Error opening named pipe");
    goto beach;
  }
beach:
  {
    CloseHandle (connect);
    CloseHandle (cancel);
    return success;
  }
}

static gboolean
miru_windows_pipe_backend_await (MiruPipeBackend * self, HANDLE complete, HANDLE cancel, GCancellable * cancellable, GError ** error)
{
  gulong handler_id = 0;
  HANDLE events[2];

  if (cancellable != NULL)
  {
    handler_id = g_cancellable_connect (cancellable, G_CALLBACK (miru_windows_pipe_backend_on_cancel), cancel, NULL);
  }

  events[0] = complete;
  events[1] = cancel;
  WaitForMultipleObjects (G_N_ELEMENTS (events), events, FALSE, INFINITE);

  if (cancellable != NULL)
  {
    g_cancellable_disconnect (cancellable, handler_id);
    if (g_cancellable_set_error_if_cancelled (cancellable, error))
    {
      CancelIo (self->pipe);
      return FALSE;
    }
  }

  return TRUE;
}

static void
miru_windows_pipe_backend_on_cancel (GCancellable * cancellable, gpointer user_data)
{
  HANDLE cancel = (HANDLE) user_data;

  SetEvent (cancel);
}

gboolean
_miru_windows_pipe_close_backend (void * opaque_backend, GError ** error)
{
  MiruPipeBackend * backend = opaque_backend;

  if (!CloseHandle (backend->pipe))
    goto failure;
  backend->pipe = INVALID_HANDLE_VALUE;
  return TRUE;

failure:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (GetLastError ()),
        "Error closing named pipe");
    return FALSE;
  }
}

GInputStream *
_miru_windows_pipe_make_input_stream (void * backend)
{
  MiruWindowsPipeInputStream * stream;

  stream = g_object_new (MIRU_TYPE_WINDOWS_PIPE_INPUT_STREAM, NULL);
  stream->backend = backend;

  return G_INPUT_STREAM (stream);
}

GOutputStream *
_miru_windows_pipe_make_output_stream (void * backend)
{
  MiruWindowsPipeOutputStream * stream;

  stream = g_object_new (MIRU_TYPE_WINDOWS_PIPE_OUTPUT_STREAM, NULL);
  stream->backend = backend;

  return G_OUTPUT_STREAM (stream);
}

static void
miru_windows_pipe_input_stream_class_init (MiruWindowsPipeInputStreamClass * klass)
{
  GInputStreamClass * stream_class = G_INPUT_STREAM_CLASS (klass);

  stream_class->read_fn = miru_windows_pipe_input_stream_read;
  stream_class->close_fn = miru_windows_pipe_input_stream_close;
}

static void
miru_windows_pipe_input_stream_init (MiruWindowsPipeInputStream * self)
{
}

static gssize
miru_windows_pipe_input_stream_read (GInputStream * base, void * buffer, gsize count, GCancellable * cancellable, GError ** error)
{
  MiruWindowsPipeInputStream * self = MIRU_WINDOWS_PIPE_INPUT_STREAM (base);
  MiruPipeBackend * backend = self->backend;
  gssize result = -1;
  OVERLAPPED overlapped = { 0, };
  BOOL ret;
  DWORD bytes_transferred;

  if (!miru_windows_pipe_backend_connect (backend, cancellable, error))
    goto beach;

  overlapped.hEvent = backend->read_complete;
  ret = ReadFile (backend->pipe, buffer, count, NULL, &overlapped);
  if (!ret && GetLastError () != ERROR_IO_PENDING)
    goto failure;

  if (!miru_windows_pipe_backend_await (backend, backend->read_complete, backend->read_cancel, cancellable, error))
    goto beach;

  if (!GetOverlappedResult (backend->pipe, &overlapped, &bytes_transferred, FALSE))
    goto failure;

  result = bytes_transferred;
  goto beach;

failure:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (GetLastError ()),
        "Error reading from named pipe");
    goto beach;
  }
beach:
  {
    return result;
  }
}

static gboolean
miru_windows_pipe_input_stream_close (GInputStream * base, GCancellable * cancellable, GError ** error)
{
  return TRUE;
}

static void
miru_windows_pipe_output_stream_class_init (MiruWindowsPipeOutputStreamClass * klass)
{
  GOutputStreamClass * stream_class = G_OUTPUT_STREAM_CLASS (klass);

  stream_class->write_fn = miru_windows_pipe_output_stream_write;
  stream_class->close_fn = miru_windows_pipe_output_stream_close;
}

static void
miru_windows_pipe_output_stream_init (MiruWindowsPipeOutputStream * self)
{
}

static gssize
miru_windows_pipe_output_stream_write (GOutputStream * base, const void * buffer, gsize count, GCancellable * cancellable, GError ** error)
{
  MiruWindowsPipeOutputStream * self = MIRU_WINDOWS_PIPE_OUTPUT_STREAM (base);
  MiruPipeBackend * backend = self->backend;
  gssize result = -1;
  OVERLAPPED overlapped = { 0, };
  BOOL ret;
  DWORD bytes_transferred;

  if (!miru_windows_pipe_backend_connect (backend, cancellable, error))
    goto beach;

  overlapped.hEvent = backend->write_complete;
  ret = WriteFile (backend->pipe, buffer, count, NULL, &overlapped);
  if (!ret && GetLastError () != ERROR_IO_PENDING)
    goto failure;

  if (!miru_windows_pipe_backend_await (backend, backend->write_complete, backend->write_cancel, cancellable, error))
    goto beach;

  if (!GetOverlappedResult (backend->pipe, &overlapped, &bytes_transferred, FALSE))
    goto failure;

  result = bytes_transferred;
  goto beach;

failure:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (GetLastError ()),
        "Error writing to named pipe");
    goto beach;
  }
beach:
  {
    return result;
  }
}

static gboolean
miru_windows_pipe_output_stream_close (GOutputStream * base, GCancellable * cancellable, GError ** error)
{
  return TRUE;
}

static gchar *
miru_pipe_generate_name (void)
{
  GString * s;
  guint i;

  s = g_string_new ("miru-");
  for (i = 0; i != 16; i++)
    g_string_append_printf (s, "%02x", g_random_int_range (0, 255));

  return g_string_free (s, FALSE);
}

static WCHAR *
miru_pipe_path_from_name (const gchar * name)
{
  gchar * path_utf8;
  WCHAR * path;

  path_utf8 = g_strconcat ("\\\\.\\pipe\\", name, NULL);
  path = (WCHAR *) g_utf8_to_utf16 (path_utf8, -1, NULL, NULL, NULL);
  g_free (path_utf8);

  return path;
}
