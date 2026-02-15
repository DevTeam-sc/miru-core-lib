#include "inject-glue.h"

#include "miru-core.h"
#ifdef HAVE_ANDROID
# include "miru-selinux.h"
#endif

void
miru_inject_environment_init (void)
{
  miru_init_with_runtime (MIRU_RUNTIME_GLIB);

#ifdef HAVE_ANDROID
  miru_selinux_patch_policy ();
#endif
}
