#ifndef __MIRU_HELPER_SERVICE_GLUE_H__
#define __MIRU_HELPER_SERVICE_GLUE_H__

#include "miru-helper-backend.h"

G_BEGIN_DECLS

G_GNUC_INTERNAL void * miru_helper_manager_start_services (const char * service_basename, gchar ** archs, gint archs_length,
    MiruPrivilegeLevel level);
G_GNUC_INTERNAL void miru_helper_manager_stop_services (void * context);

G_GNUC_INTERNAL char * miru_helper_service_derive_basename (void);
G_GNUC_INTERNAL char * miru_helper_service_derive_filename_for_suffix (const char * suffix);
G_GNUC_INTERNAL char * miru_helper_service_derive_svcname_for_self (void);
G_GNUC_INTERNAL char * miru_helper_service_derive_svcname_for_suffix (const char * suffix);

G_GNUC_INTERNAL void miru_managed_helper_service_enter_dispatcher_and_main_loop (void);

G_END_DECLS

#endif
