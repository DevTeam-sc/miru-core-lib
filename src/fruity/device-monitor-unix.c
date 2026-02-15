#include "miru-core.h"

#include "miru-base.h"

void
_miru_fruity_usbmux_backend_extract_details_for_device (gint product_id, const char * udid, char ** name, GVariant ** icon,
    GError ** error)
{
  *name = g_strdup ("iOS Device");
  *icon = NULL;
}
