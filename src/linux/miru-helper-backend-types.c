#include "miru-helper-backend.h"
#include "helpers/inject-context.h"

G_STATIC_ASSERT (sizeof (MiruHelperBootstrapContext) == sizeof (MiruBootstrapContext));
G_STATIC_ASSERT (sizeof (MiruHelperLoaderContext) == sizeof (MiruLoaderContext));
G_STATIC_ASSERT (sizeof (MiruHelperLibcApi) == sizeof (MiruLibcApi));
G_STATIC_ASSERT (sizeof (MiruHelperByeMessage) == sizeof (MiruByeMessage));
