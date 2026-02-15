#include "miru-helper-service-glue.h"

#include <windows.h>

#if defined (HAVE_ARM64)
# define MIRU_HELPER_SERVICE_ARCH "arm64"
#elif GLIB_SIZEOF_VOID_P == 8
# define MIRU_HELPER_SERVICE_ARCH "x86_64"
#else
# define MIRU_HELPER_SERVICE_ARCH "x86"
#endif

#define STANDALONE_JOIN_TIMEOUT_MSEC (5 * 1000)

typedef struct _MiruServiceContext MiruServiceContext;

struct _MiruServiceContext
{
  gchar * service_basename;

  SC_HANDLE scm;

  GQueue system_services;
  GQueue standalone_services;
};

static void WINAPI miru_managed_helper_service_main (DWORD argc, WCHAR ** argv);
static DWORD WINAPI miru_managed_helper_service_handle_control_code (DWORD control, DWORD event_type, void * event_data, void * context);
static void miru_managed_helper_service_report_status (DWORD current_state, DWORD exit_code, DWORD wait_hint);

static gboolean miru_register_and_start_services (MiruServiceContext * self, gchar ** archs, gint archs_length);
static void miru_stop_and_unregister_services (MiruServiceContext * self);
static gboolean miru_spawn_standalone_services (MiruServiceContext * self, gchar ** archs, gint archs_length);
static gboolean miru_join_standalone_services (MiruServiceContext * self);
static void miru_kill_standalone_services (MiruServiceContext * self);
static void miru_release_standalone_services (MiruServiceContext * self);

static gboolean miru_register_services (MiruServiceContext * self, gchar ** archs, gint archs_length);
static gboolean miru_unregister_services (MiruServiceContext * self);
static gboolean miru_start_services (MiruServiceContext * self);
static gboolean miru_stop_services (MiruServiceContext * self);

static SC_HANDLE miru_register_service (MiruServiceContext * self, const gchar * suffix);
static gboolean miru_unregister_service (MiruServiceContext * self, SC_HANDLE handle);
static void miru_unregister_stale_services (MiruServiceContext * self);
static gboolean miru_start_service (MiruServiceContext * self, SC_HANDLE handle);
static gboolean miru_stop_service (MiruServiceContext * self, SC_HANDLE handle);

static HANDLE miru_spawn_standalone_service (MiruServiceContext * self, const gchar * suffix);
static gboolean miru_join_standalone_service (MiruServiceContext * self, HANDLE handle);
static void miru_kill_standalone_service (MiruServiceContext * self, HANDLE handle);

static MiruServiceContext * miru_service_context_new (const gchar * service_basename);
static void miru_service_context_free (MiruServiceContext * self);

static void miru_rmtree (GFile * file);

static WCHAR * miru_managed_helper_service_name = NULL;
static SERVICE_STATUS_HANDLE miru_managed_helper_service_status_handle = NULL;

void *
miru_helper_manager_start_services (const char * service_basename, gchar ** archs, gint archs_length, MiruPrivilegeLevel level)
{
  MiruServiceContext * self;

  self = miru_service_context_new (service_basename);

  self->scm = (level == MIRU_PRIVILEGE_LEVEL_ELEVATED)
      ? OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS)
      : NULL;
  if (self->scm != NULL)
  {
    miru_unregister_stale_services (self);

    if (!miru_register_and_start_services (self, archs, archs_length))
    {
      CloseServiceHandle (self->scm);
      self->scm = NULL;
    }
  }

  if (self->scm == NULL)
  {
    if (!miru_spawn_standalone_services (self, archs, archs_length))
    {
      miru_service_context_free (self);
      self = NULL;
    }
  }

  return self;
}

void
miru_helper_manager_stop_services (void * context)
{
  MiruServiceContext * self = context;

  if (self->scm != NULL)
  {
    miru_stop_and_unregister_services (self);
  }
  else
  {
    if (!miru_join_standalone_services (self))
      miru_kill_standalone_services (self);
  }

  miru_service_context_free (self);
}

char *
miru_helper_service_derive_basename (void)
{
  WCHAR filename_utf16[MAX_PATH + 1] = { 0, };
  gchar * name, * tmp;

  GetModuleFileNameW (NULL, filename_utf16, MAX_PATH);

  name = g_utf16_to_utf8 (filename_utf16, -1, NULL, NULL, NULL);

  tmp = g_path_get_dirname (name);
  g_free (name);
  name = tmp;

  tmp = g_path_get_basename (name);
  g_free (name);
  name = tmp;

  tmp = g_strconcat (name, "-", NULL);
  g_free (name);
  name = tmp;

  return name;
}

char *
miru_helper_service_derive_filename_for_suffix (const char * suffix)
{
  WCHAR filename_utf16[MAX_PATH + 1] = { 0, };
  gchar * name, * tail, * tmp;
  glong len;

  GetModuleFileNameW (NULL, filename_utf16, MAX_PATH);

  name = g_utf16_to_utf8 (filename_utf16, -1, NULL, &len, NULL);
  tail = strrchr (name, '-');
  if (tail != NULL)
  {
    tail[1] = '\0';
    tmp = g_strconcat (name, suffix, ".exe", NULL);
    g_free (name);
    name = tmp;
  }
  else
  {
    g_critical ("Unexpected filename: %s", name);
  }

  return name;
}

char *
miru_helper_service_derive_svcname_for_self (void)
{
  gchar * basename, * name;

  basename = miru_helper_service_derive_basename ();
  name = g_strconcat (basename, MIRU_HELPER_SERVICE_ARCH, NULL);
  g_free (basename);

  return name;
}

char *
miru_helper_service_derive_svcname_for_suffix (const char * suffix)
{
  gchar * basename, * name;

  basename = miru_helper_service_derive_basename ();
  name = g_strconcat (basename, suffix, NULL);
  g_free (basename);

  return name;
}

void
miru_managed_helper_service_enter_dispatcher_and_main_loop (void)
{
  SERVICE_TABLE_ENTRYW dispatch_table[2] = { 0, };
  gchar * name;

  name = miru_helper_service_derive_svcname_for_self ();
  miru_managed_helper_service_name = g_utf8_to_utf16 (name, -1, NULL, NULL, NULL);
  g_free (name);

  dispatch_table[0].lpServiceName = miru_managed_helper_service_name;
  dispatch_table[0].lpServiceProc = miru_managed_helper_service_main;

  StartServiceCtrlDispatcherW (dispatch_table);

  miru_managed_helper_service_status_handle = NULL;

  g_free (miru_managed_helper_service_name);
  miru_managed_helper_service_name = NULL;
}

static void WINAPI
miru_managed_helper_service_main (DWORD argc, WCHAR ** argv)
{
  GMainLoop * loop;

  (void) argc;
  (void) argv;

  loop = g_main_loop_new (NULL, FALSE);

  miru_managed_helper_service_status_handle = RegisterServiceCtrlHandlerExW (
      miru_managed_helper_service_name,
      miru_managed_helper_service_handle_control_code,
      loop);

  miru_managed_helper_service_report_status (SERVICE_START_PENDING, NO_ERROR, 0);

  miru_managed_helper_service_report_status (SERVICE_RUNNING, NO_ERROR, 0);
  g_main_loop_run (loop);
  miru_managed_helper_service_report_status (SERVICE_STOPPED, NO_ERROR, 0);

  g_main_loop_unref (loop);
}

static gboolean
miru_managed_helper_service_stop (gpointer data)
{
  GMainLoop * loop = data;

  g_main_loop_quit (loop);

  return FALSE;
}

static DWORD WINAPI
miru_managed_helper_service_handle_control_code (DWORD control, DWORD event_type, void * event_data, void * context)
{
  GMainLoop * loop = context;

  (void) event_type;
  (void) event_data;

  switch (control)
  {
    case SERVICE_CONTROL_STOP:
      miru_managed_helper_service_report_status (SERVICE_STOP_PENDING, NO_ERROR, 0);
      g_idle_add (miru_managed_helper_service_stop, loop);
      return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
      return NO_ERROR;

    default:
      return ERROR_CALL_NOT_IMPLEMENTED;
  }
}

static void
miru_managed_helper_service_report_status (DWORD current_state, DWORD exit_code, DWORD wait_hint)
{
  SERVICE_STATUS status;
  static DWORD checkpoint = 1;

  status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  status.dwCurrentState = current_state;

  if (current_state == SERVICE_START_PENDING)
    status.dwControlsAccepted = 0;
  else
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

  status.dwWin32ExitCode = exit_code;
  status.dwServiceSpecificExitCode = 0;

  if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED)
  {
    status.dwCheckPoint = 0;
  }
  else
  {
    status.dwCheckPoint = checkpoint++;
  }

  status.dwWaitHint = wait_hint;

  SetServiceStatus (miru_managed_helper_service_status_handle, &status);
}

static gboolean
miru_register_and_start_services (MiruServiceContext * self, gchar ** archs, gint archs_length)
{
  if (!miru_register_services (self, archs, archs_length))
    return FALSE;

  if (!miru_start_services (self))
  {
    miru_unregister_services (self);
    return FALSE;
  }

  return TRUE;
}

static void
miru_stop_and_unregister_services (MiruServiceContext * self)
{
  miru_stop_services (self);
  miru_unregister_services (self);
}

static gboolean
miru_spawn_standalone_services (MiruServiceContext * self, gchar ** archs, gint archs_length)
{
  gint i;

  for (i = 0; i != archs_length; i++)
  {
    HANDLE service = miru_spawn_standalone_service (self, archs[i]);
    if (service == NULL)
      goto unable_to_spawn;
    g_queue_push_tail (&self->standalone_services, service);
  }

  return TRUE;

unable_to_spawn:
  {
    miru_kill_standalone_services (self);
    return FALSE;
  }
}

static gboolean
miru_join_standalone_services (MiruServiceContext * self)
{
  gboolean success = TRUE;
  GList * cur;

  for (cur = self->standalone_services.head; cur != NULL; cur = cur->next)
    success &= miru_join_standalone_service (self, cur->data);

  if (success)
    miru_release_standalone_services (self);

  return success;
}

static void
miru_kill_standalone_services (MiruServiceContext * self)
{
  GList * cur;

  for (cur = self->standalone_services.head; cur != NULL; cur = cur->next)
    miru_kill_standalone_service (self, cur->data);

  miru_release_standalone_services (self);
}

static void
miru_release_standalone_services (MiruServiceContext * self)
{
  HANDLE service;

  while ((service = g_queue_pop_tail (&self->standalone_services)) != NULL)
    CloseHandle (service);
}

static gboolean
miru_register_services (MiruServiceContext * self, gchar ** archs, gint archs_length)
{
  gint i;

  for (i = 0; i != archs_length; i++)
  {
    SC_HANDLE service = miru_register_service (self, archs[i]);
    if (service == NULL)
      goto unable_to_register;
    g_queue_push_tail (&self->system_services, service);
  }

  return TRUE;

unable_to_register:
  {
    miru_unregister_services (self);
    return FALSE;
  }
}

static gboolean
miru_unregister_services (MiruServiceContext * self)
{
  gboolean success = TRUE;
  SC_HANDLE service;

  while ((service = g_queue_pop_tail (&self->system_services)) != NULL)
  {
    success &= miru_unregister_service (self, service);
    CloseServiceHandle (service);
  }

  return success;
}

static gboolean
miru_start_services (MiruServiceContext * self)
{
  GList * cur;

  for (cur = self->system_services.head; cur != NULL; cur = cur->next)
  {
    if (!miru_start_service (self, cur->data))
      goto unable_to_start;
  }

  return TRUE;

unable_to_start:
  {
    miru_stop_services (self);
    return FALSE;
  }
}

static gboolean
miru_stop_services (MiruServiceContext * self)
{
  gboolean success = TRUE;
  GList * cur;

  for (cur = self->system_services.head; cur != NULL; cur = cur->next)
    success &= miru_stop_service (self, cur->data);

  return success;
}

static SC_HANDLE
miru_register_service (MiruServiceContext * self, const gchar * suffix)
{
  SC_HANDLE handle;
  gchar * servicename_utf8;
  WCHAR * servicename;
  gchar * displayname_utf8;
  WCHAR * displayname;
  gchar * filename_utf8;
  WCHAR * filename;

  servicename_utf8 = g_strconcat (self->service_basename, suffix, NULL);
  servicename = g_utf8_to_utf16 (servicename_utf8, -1, NULL, NULL, NULL);

  displayname_utf8 = g_strdup_printf ("Miru %s helper (%s)", suffix, servicename_utf8);
  displayname = g_utf8_to_utf16 (displayname_utf8, -1, NULL, NULL, NULL);

  filename_utf8 = miru_helper_service_derive_filename_for_suffix (suffix);
  filename = g_utf8_to_utf16 (filename_utf8, -1, NULL, NULL, NULL);

  handle = CreateServiceW (self->scm,
      servicename,
      displayname,
      SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS,
      SERVICE_DEMAND_START,
      SERVICE_ERROR_NORMAL,
      filename,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL);

  g_free (filename);
  g_free (filename_utf8);

  g_free (displayname);
  g_free (displayname_utf8);

  g_free (servicename);
  g_free (servicename_utf8);

  return handle;
}

static gboolean
miru_unregister_service (MiruServiceContext * self, SC_HANDLE handle)
{
  (void) self;

  return DeleteService (handle);
}

static void
miru_unregister_stale_services (MiruServiceContext * self)
{
  BYTE * services_data;
  DWORD services_size, bytes_needed, num_services, resume_handle;
  GQueue stale_services = G_QUEUE_INIT;

  services_size = 16384;
  services_data = g_malloc (services_size);

  resume_handle = 0;

  do
  {
    ENUM_SERVICE_STATUS_PROCESSW * services;
    DWORD i;

    num_services = 0;
    if (!EnumServicesStatusExW (self->scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_INACTIVE,
        services_data,
        services_size,
        &bytes_needed,
        &num_services,
        &resume_handle,
        NULL))
    {
      if (GetLastError () == ERROR_MORE_DATA)
      {
        if (num_services == 0)
        {
          services_data = g_realloc (services_data, bytes_needed);
          services_size = bytes_needed;
          continue;
        }
      }
      else
      {
        break;
      }
    }

    services = (ENUM_SERVICE_STATUS_PROCESSW *) services_data;
    for (i = 0; i != num_services; i++)
    {
      ENUM_SERVICE_STATUS_PROCESSW * service = &services[i];

      if (wcsncmp (service->lpServiceName, L"miru-", 6) == 0 && wcslen (service->lpServiceName) == 41)
      {
        SC_HANDLE handle = OpenServiceW (self->scm, service->lpServiceName, SERVICE_QUERY_CONFIG | DELETE);
        if (handle != NULL)
          g_queue_push_tail (&stale_services, handle);
      }
    }
  }
  while (num_services == 0 || resume_handle != 0);

  g_free (services_data);

  if (!g_queue_is_empty (&stale_services))
  {
    GHashTable * stale_dirs;
    QUERY_SERVICE_CONFIGW * config_data;
    DWORD config_size;
    GList * cur;
    GHashTableIter iter;
    gchar * stale_dir;

    stale_dirs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    config_data = NULL;
    config_size = 0;

    for (cur = stale_services.head; cur != NULL; cur = cur->next)
    {
      SC_HANDLE handle = cur->data;

retry:
      if (QueryServiceConfigW (handle, config_data, config_size, &bytes_needed))
      {
        gchar * binary_path, * tempdir_path;

        binary_path = g_utf16_to_utf8 (config_data->lpBinaryPathName, -1, NULL, NULL, NULL);
        tempdir_path = g_path_get_dirname (binary_path);

        g_hash_table_add (stale_dirs, tempdir_path);

        g_free (binary_path);
      }
      else if (GetLastError () == ERROR_INSUFFICIENT_BUFFER)
      {
        config_data = g_realloc (config_data, bytes_needed);
        config_size = bytes_needed;
        goto retry;
      }

      DeleteService (handle);
      CloseServiceHandle (handle);
    }

    g_hash_table_iter_init (&iter, stale_dirs);
    while (g_hash_table_iter_next (&iter, (gpointer *) &stale_dir, NULL))
    {
      GFile * file = g_file_new_for_path (stale_dir);
      miru_rmtree (file);
      g_object_unref (file);
    }

    g_free (config_data);
    g_hash_table_unref (stale_dirs);
  }

  g_queue_clear (&stale_services);
}

static gboolean
miru_start_service (MiruServiceContext * self, SC_HANDLE handle)
{
  (void) self;

  return StartService (handle, 0, NULL);
}

static gboolean
miru_stop_service (MiruServiceContext * self, SC_HANDLE handle)
{
  SERVICE_STATUS status = { 0, };

  (void) self;

  return ControlService (handle, SERVICE_CONTROL_STOP, &status);
}

static HANDLE
miru_spawn_standalone_service (MiruServiceContext * self, const gchar * suffix)
{
  HANDLE handle = NULL;
  gchar * appname_utf8;
  WCHAR * appname;
  gchar * cmdline_utf8;
  WCHAR * cmdline;
  STARTUPINFOW si = { 0, };
  PROCESS_INFORMATION pi = { 0, };

  (void) self;

  appname_utf8 = miru_helper_service_derive_filename_for_suffix (suffix);
  appname = (WCHAR *) g_utf8_to_utf16 (appname_utf8, -1, NULL, NULL, NULL);

  cmdline_utf8 = g_strconcat ("\"", appname_utf8, "\" STANDALONE", NULL);
  cmdline = (WCHAR *) g_utf8_to_utf16 (cmdline_utf8, -1, NULL, NULL, NULL);

  si.cb = sizeof (si);

  if (CreateProcessW (appname, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
  {
    handle = pi.hProcess;
    CloseHandle (pi.hThread);
  }

  g_free (cmdline);
  g_free (cmdline_utf8);

  g_free (appname);
  g_free (appname_utf8);

  return handle;
}

static gboolean
miru_join_standalone_service (MiruServiceContext * self, HANDLE handle)
{
  (void) self;

  return WaitForSingleObject (handle,
      STANDALONE_JOIN_TIMEOUT_MSEC) == WAIT_OBJECT_0;
}

static void
miru_kill_standalone_service (MiruServiceContext * self, HANDLE handle)
{
  (void) self;

  TerminateProcess (handle, 1);
}

static MiruServiceContext *
miru_service_context_new (const gchar * service_basename)
{
  MiruServiceContext * self;

  self = g_slice_new0 (MiruServiceContext);
  self->service_basename = g_strdup (service_basename);
  g_queue_init (&self->standalone_services);

  return self;
}

static void
miru_service_context_free (MiruServiceContext * self)
{
  g_assert (g_queue_is_empty (&self->system_services));
  g_assert (g_queue_is_empty (&self->standalone_services));

  if (self->scm != NULL)
    CloseServiceHandle (self->scm);

  g_free (self->service_basename);

  g_slice_free (MiruServiceContext, self);
}

static void
miru_rmtree (GFile * file)
{
  GFileEnumerator * enumerator =
      g_file_enumerate_children (file, G_FILE_ATTRIBUTE_STANDARD_NAME, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, NULL);
  if (enumerator != NULL)
  {
    GFileInfo * info;
    GFile * child;

    while (g_file_enumerator_iterate (enumerator, &info, &child, NULL, NULL) && child != NULL)
    {
      if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
        miru_rmtree (child);
      else
        g_file_delete (child, NULL, NULL);
    }

    g_object_unref (enumerator);
  }

  g_file_delete (file, NULL, NULL);
}
