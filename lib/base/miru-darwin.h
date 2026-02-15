#ifndef __MIRU_DARWIN_H__
#define __MIRU_DARWIN_H__

#ifdef HAVE_MACOS

#include <glib.h>
#include <xpc/xpc.h>

typedef void (* MiruXpcHandler) (xpc_object_t object, gpointer user_data);
typedef gboolean (* MiruXpcDictionaryApplier) (const gchar * key, xpc_object_t val, gpointer user_data);

gpointer _miru_dispatch_retain (gpointer object);

void _miru_xpc_connection_set_event_handler (xpc_connection_t connection, MiruXpcHandler handler, gpointer user_data);
void _miru_xpc_connection_send_message_with_reply (xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq,
    MiruXpcHandler handler, gpointer user_data, GDestroyNotify notify);
gchar * _miru_xpc_object_to_string (xpc_object_t object);
gboolean _miru_xpc_dictionary_apply (xpc_object_t dict, MiruXpcDictionaryApplier applier, gpointer user_data);

#endif

#endif
