#ifdef _MSC_VER

#include <glib.h>

#ifdef HAVE_ARM64
# define MIRU_CGO_INIT_FUNC _st0_arm64_windows_lib
#elif GLIB_SIZEOF_VOID_P == 8
# define MIRU_CGO_INIT_FUNC _st0_amd64_windows_lib
#else
# define MIRU_CGO_INIT_FUNC st0_386_windows_lib
#endif

extern void MIRU_CGO_INIT_FUNC ();

void
_miru_compiler_backend_init_go_runtime (void)
{
  MIRU_CGO_INIT_FUNC ();
}

#else

void
_miru_compiler_backend_init_go_runtime (void)
{
}

#endif
