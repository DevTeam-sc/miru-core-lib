#include "miru-helper-backend.h"

#include <windows.h>

#define MIRU_WAIT_HANDLE_SOURCE(s) ((MiruWaitHandleSource *) (s))

typedef struct _MiruWaitHandleSource MiruWaitHandleSource;

struct _MiruWaitHandleSource
{
  GSource source;

  HANDLE handle;
  gboolean owns_handle;
  GPollFD handle_poll_fd;
};

static void miru_wait_handle_source_finalize (GSource * source);

static gboolean miru_wait_handle_source_prepare (GSource * source,
    gint * timeout);
static gboolean miru_wait_handle_source_check (GSource * source);
static gboolean miru_wait_handle_source_dispatch (GSource * source,
    GSourceFunc callback, gpointer user_data);

static GSourceFuncs miru_wait_handle_source_funcs = {
  miru_wait_handle_source_prepare,
  miru_wait_handle_source_check,
  miru_wait_handle_source_dispatch,
  miru_wait_handle_source_finalize
};

GSource *
miru_wait_handle_source_create (void * handle, gboolean owns_handle)
{
  GSource * source;
  GPollFD * pfd;
  MiruWaitHandleSource * whsrc;

  source = g_source_new (&miru_wait_handle_source_funcs,
      sizeof (MiruWaitHandleSource));
  whsrc = MIRU_WAIT_HANDLE_SOURCE (source);
  whsrc->handle = handle;
  whsrc->owns_handle = owns_handle;

  pfd = &MIRU_WAIT_HANDLE_SOURCE (source)->handle_poll_fd;
#if GLIB_SIZEOF_VOID_P == 8
  pfd->fd = (gint64) handle;
#else
  pfd->fd = (gint) handle;
#endif
  pfd->events = G_IO_IN | G_IO_OUT | G_IO_HUP | G_IO_ERR;
  pfd->revents = 0;
  g_source_add_poll (source, pfd);

  return source;
}

static void
miru_wait_handle_source_finalize (GSource * source)
{
  MiruWaitHandleSource * self = MIRU_WAIT_HANDLE_SOURCE (source);

  if (self->owns_handle)
    CloseHandle (self->handle);
}

static gboolean
miru_wait_handle_source_prepare (GSource * source, gint * timeout)
{
  MiruWaitHandleSource * self = MIRU_WAIT_HANDLE_SOURCE (source);

  *timeout = -1;

  return WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0;
}

static gboolean
miru_wait_handle_source_check (GSource * source)
{
  MiruWaitHandleSource * self = MIRU_WAIT_HANDLE_SOURCE (source);

  return WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0;
}

static gboolean
miru_wait_handle_source_dispatch (GSource * source, GSourceFunc callback,
    gpointer user_data)
{
  g_assert (WaitForSingleObject (MIRU_WAIT_HANDLE_SOURCE (source)->handle, 0) == WAIT_OBJECT_0);

  return callback (user_data);
}
