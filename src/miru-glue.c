#include "config.h"
#include "miru-core.h"

#include <mumu/mumu.h>
#ifdef HAVE_GIOOPENSSL
# include <gioopenssl.h>
#endif

static MiruRuntime runtime;
static GThread * main_thread;
static GMainLoop * main_loop;
static GMainContext * main_context;

static gpointer run_main_loop (gpointer data);
static gboolean dummy_callback (gpointer data);
static gboolean stop_main_loop (gpointer data);

void
miru_init (void)
{
  miru_init_with_runtime (MIRU_RUNTIME_OTHER);
}

void
miru_init_with_runtime (MiruRuntime rt)
{
  static gsize miru_initialized = FALSE;

  runtime = rt;

  g_thread_set_garbage_handler (miru_on_pending_garbage, NULL);
  glib_init ();

  if (g_once_init_enter (&miru_initialized))
  {
    gio_init ();
    mumu_init ();
    miru_error_quark (); /* Initialize early so GDBus will pick it up */

#ifdef HAVE_GIOOPENSSL
    g_io_module_openssl_register ();
#endif

    if (runtime == MIRU_RUNTIME_OTHER)
    {
      main_context = g_main_context_ref (g_main_context_default ());
      main_loop = g_main_loop_new (main_context, FALSE);
      main_thread = g_thread_new ("miru-main-loop", run_main_loop, NULL);
    }

    g_once_init_leave (&miru_initialized, TRUE);
  }
}

void
miru_unref (gpointer obj)
{
  if (runtime == MIRU_RUNTIME_GLIB)
  {
    g_object_unref (obj);
  }
  else if (runtime == MIRU_RUNTIME_OTHER)
  {
    GSource * source;

    source = g_idle_source_new ();
    g_source_set_priority (source, G_PRIORITY_HIGH);
    g_source_set_callback (source, dummy_callback, obj, g_object_unref);
    g_source_attach (source, main_context);
    g_source_unref (source);
  }
}

void
miru_shutdown (void)
{
  if (runtime == MIRU_RUNTIME_OTHER)
  {
    GSource * source;

    g_assert (main_loop != NULL);

    source = g_idle_source_new ();
    g_source_set_priority (source, G_PRIORITY_LOW);
    g_source_set_callback (source, stop_main_loop, NULL, NULL);
    g_source_attach (source, main_context);
    g_source_unref (source);

    g_thread_join (main_thread);
    main_thread = NULL;
  }
}

void
miru_deinit (void)
{
  if (runtime == MIRU_RUNTIME_OTHER)
  {
    g_assert (main_loop != NULL);

    if (main_thread != NULL)
      miru_shutdown ();

    g_main_loop_unref (main_loop);
    main_loop = NULL;
    g_main_context_unref (main_context);
    main_context = NULL;
  }

  miru_invalidate_dbus_context ();

  mumu_shutdown ();
  gio_shutdown ();
  glib_shutdown ();

  mumu_deinit ();
  gio_deinit ();
  glib_deinit ();
}

GMainContext *
miru_get_main_context (void)
{
  if (runtime == MIRU_RUNTIME_GLIB)
    return g_main_context_get_thread_default ();
  else if (runtime == MIRU_RUNTIME_OTHER)
    return main_context;
  else
    g_assert_not_reached ();
}

void
miru_version (guint * major, guint * minor, guint * micro, guint * nano)
{
  if (major != NULL)
    *major = MIRU_MAJOR_VERSION;

  if (minor != NULL)
    *minor = MIRU_MINOR_VERSION;

  if (micro != NULL)
    *micro = MIRU_MICRO_VERSION;

  if (nano != NULL)
    *nano = MIRU_NANO_VERSION;
}

const gchar *
miru_version_string (void)
{
  return MIRU_VERSION;
}

static gpointer
run_main_loop (gpointer data)
{
  (void) data;

  g_main_context_push_thread_default (main_context);
  g_main_loop_run (main_loop);
  g_main_context_pop_thread_default (main_context);

  return NULL;
}

static gboolean
dummy_callback (gpointer data)
{
  (void) data;

  return FALSE;
}

static gboolean
stop_main_loop (gpointer data)
{
  (void) data;

  g_main_loop_quit (main_loop);

  return FALSE;
}
