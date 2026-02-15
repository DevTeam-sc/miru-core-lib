#ifndef __MIRU_HELPER_PROCESS_GLUE_H__
#define __MIRU_HELPER_PROCESS_GLUE_H__

#include "miru-helper-backend.h"

G_BEGIN_DECLS

G_GNUC_INTERNAL void * miru_helper_factory_spawn (const gchar * path, const gchar * parameters, MiruPrivilegeLevel level,
    GError ** error);

G_GNUC_INTERNAL gboolean miru_helper_instance_is_process_still_running (void * handle);
G_GNUC_INTERNAL void miru_helper_instance_close_process_handle (void * handle);

G_END_DECLS

#endif
