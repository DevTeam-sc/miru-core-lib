#ifndef __MIRU_SERVER_GLUE_H__
#define __MIRU_SERVER_GLUE_H__

#include <gio/gio.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL void miru_server_environment_init (void);
G_GNUC_INTERNAL void miru_server_environment_set_verbose_logging_enabled (gboolean enabled);
G_GNUC_INTERNAL void miru_server_environment_configure (void);

G_END_DECLS

#endif
