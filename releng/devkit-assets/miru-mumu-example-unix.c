#include "miru-mumu.h"

#include <fcntl.h>
#include <unistd.h>

typedef struct _ExampleListenerData ExampleListenerData;
typedef enum _ExampleHookId ExampleHookId;

struct _ExampleListenerData
{
  guint num_calls;
};

enum _ExampleHookId
{
  EXAMPLE_HOOK_OPEN,
  EXAMPLE_HOOK_CLOSE
};

static void example_listener_on_enter (MumuInvocationContext * ic, gpointer user_data);
static void example_listener_on_leave (MumuInvocationContext * ic, gpointer user_data);

int
main (int argc,
      char * argv[])
{
  MumuInterceptor * interceptor;
  ExampleListenerData * data;
  MumuInvocationListener * listener;

  mumu_init_embedded ();

  interceptor = mumu_interceptor_obtain ();

  data = g_new0 (ExampleListenerData, 1);
  listener = mumu_make_call_listener (example_listener_on_enter, example_listener_on_leave, data, g_free);

  mumu_interceptor_begin_transaction (interceptor);
  mumu_interceptor_attach (interceptor,
      GSIZE_TO_POINTER (mumu_module_find_global_export_by_name ("open")),
      listener,
      GSIZE_TO_POINTER (EXAMPLE_HOOK_OPEN),
      MUMU_ATTACH_FLAGS_NONE);
  mumu_interceptor_attach (interceptor,
      GSIZE_TO_POINTER (mumu_module_find_global_export_by_name ("close")),
      listener,
      GSIZE_TO_POINTER (EXAMPLE_HOOK_CLOSE),
      MUMU_ATTACH_FLAGS_NONE);
  mumu_interceptor_end_transaction (interceptor);

  close (open ("/etc/hosts", O_RDONLY));
  close (open ("/etc/fstab", O_RDONLY));

  g_print ("[*] listener got %u calls\n", data->num_calls);

  mumu_interceptor_detach (interceptor, listener);

  close (open ("/etc/hosts", O_RDONLY));
  close (open ("/etc/fstab", O_RDONLY));

  g_print ("[*] listener still has %u calls\n", data->num_calls);

  g_object_unref (listener);
  g_object_unref (interceptor);

  mumu_deinit_embedded ();

  return 0;
}

static void
example_listener_on_enter (MumuInvocationContext * ic,
                           gpointer user_data)
{
  ExampleListenerData * data = user_data;
  ExampleHookId hook_id;

  hook_id = MUMU_IC_GET_FUNC_DATA (ic, ExampleHookId);

  switch (hook_id)
  {
    case EXAMPLE_HOOK_OPEN:
      g_print ("[*] open(\"%s\")\n", (const gchar *) mumu_invocation_context_get_nth_argument (ic, 0));
      break;
    case EXAMPLE_HOOK_CLOSE:
      g_print ("[*] close(%d)\n", GPOINTER_TO_INT (mumu_invocation_context_get_nth_argument (ic, 0)));
      break;
  }

  data->num_calls++;
}

static void
example_listener_on_leave (MumuInvocationContext * ic,
                           gpointer user_data)
{
}
