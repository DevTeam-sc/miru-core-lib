[CCode (cheader_filename = "libc-shim.h", lower_case_cprefix = "", gir_namespace = "MiruLibcShim", gir_version = "1.0")]
namespace Miru.LibcShim {
#if LINUX
	public int dup3 (int oldfd, int newfd, int flags);
#endif
}
