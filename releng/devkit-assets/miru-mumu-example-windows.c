/*
 * To build, set up your Release configuration like this:
 *
 * [Runtime Library]
 * Multi-threaded (/MT)
 *
 * Visit the Miru documentation to learn more.
 */

#include "miru-mumu.h"

#include <windows.h>

typedef struct _ExampleListenerData ExampleListenerData;
typedef enum _ExampleHookId ExampleHookId;

struct _ExampleListenerData
{
  guint num_calls;
};

enum _ExampleHookId
{
  EXAMPLE_HOOK_MESSAGE_BEEP,
  EXAMPLE_HOOK_SLEEP
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
  MumuModule * user32, * kernel32;

  mumu_init_embedded ();

  interceptor = mumu_interceptor_obtain ();

  data = g_new0 (ExampleListenerData, 1);
  listener = mumu_make_call_listener (example_listener_on_enter, example_listener_on_leave, data, g_free);

  user32 = mumu_process_find_module_by_name ("user32.dll");
  kernel32 = mumu_process_find_module_by_name ("kernel32.dll");

  mumu_interceptor_begin_transaction (interceptor);
  mumu_interceptor_attach (interceptor,
      GSIZE_TO_POINTER (mumu_module_find_export_by_name (user32, "MessageBeep")),
      listener,
      GSIZE_TO_POINTER (EXAMPLE_HOOK_MESSAGE_BEEP),
      MUMU_ATTACH_FLAGS_NONE);
  mumu_interceptor_attach (interceptor,
      GSIZE_TO_POINTER (mumu_module_find_export_by_name (kernel32, "Sleep")),
      listener,
      GSIZE_TO_POINTER (EXAMPLE_HOOK_SLEEP),
      MUMU_ATTACH_FLAGS_NONE);
  mumu_interceptor_end_transaction (interceptor);

  MessageBeep (MB_ICONINFORMATION);
  Sleep (1);

  g_print ("[*] listener got %u calls\n", data->num_calls);

  mumu_interceptor_detach (interceptor, listener);

  MessageBeep (MB_ICONINFORMATION);
  Sleep (1);

  g_print ("[*] listener still has %u calls\n", data->num_calls);

  g_object_unref (kernel32);
  g_object_unref (user32);
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
    case EXAMPLE_HOOK_MESSAGE_BEEP:
      g_print ("[*] MessageBeep(%u)\n", GPOINTER_TO_UINT (mumu_invocation_context_get_nth_argument (ic, 0)));
      break;
    case EXAMPLE_HOOK_SLEEP:
      g_print ("[*] Sleep(%u)\n", GPOINTER_TO_UINT (mumu_invocation_context_get_nth_argument (ic, 0)));
      break;
  }

  data->num_calls++;
}

static void
example_listener_on_leave (MumuInvocationContext * ic,
                           gpointer user_data)
{
}
