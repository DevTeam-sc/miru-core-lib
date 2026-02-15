#ifndef __MIRU_DARWIN_ICON_HELPERS_H__
#define __MIRU_DARWIN_ICON_HELPERS_H__

#include "miru-core.h"

typedef gpointer MiruNativeImage;

GVariant * _miru_icon_from_file (const gchar * filename, guint target_width, guint target_height);
GVariant * _miru_icon_from_native_image_scaled_to (MiruNativeImage native_image, guint target_width, guint target_height);

#endif
