#ifndef __MIRU_WINDOWS_ICON_HELPERS_H__
#define __MIRU_WINDOWS_ICON_HELPERS_H__

#include "miru-core.h"

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

typedef enum _MiruIconSize MiruIconSize;

enum _MiruIconSize
{
  MIRU_ICON_SMALL,
  MIRU_ICON_LARGE
};

GVariant * _miru_icon_from_process_or_file (DWORD pid, WCHAR * filename, MiruIconSize size);

GVariant * _miru_icon_from_process (DWORD pid, MiruIconSize size);
GVariant * _miru_icon_from_file (WCHAR * filename, MiruIconSize size);
GVariant * _miru_icon_from_resource_url (WCHAR * resource_url, MiruIconSize size);

GVariant * _miru_icon_from_native_icon_handle (HICON icon, MiruIconSize size);

#endif
