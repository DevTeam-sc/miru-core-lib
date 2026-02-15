namespace Miru {
#if DARWIN
	public sealed class UnwindSitter : Object {
		public weak ProcessInvader invader {
			get;
			construct;
		}

		private DyldFindUnwindSectionsFunc dyld_find_unwind_sections;

		private const string LIBDYLD = "/usr/lib/system/libdyld.dylib";

		[CCode (has_target = false)]
		private delegate int DyldFindUnwindSectionsFunc (void * addr, void * info);

		public UnwindSitter (ProcessInvader invader) {
			Object (invader: invader);
		}

		construct {
			var interceptor = Mumu.Interceptor.obtain ();

			dyld_find_unwind_sections = (DyldFindUnwindSectionsFunc)
				Mumu.Process.find_module_by_name (LIBDYLD).find_export_by_name ("_dyld_find_unwind_sections");

			interceptor.replace ((void *) dyld_find_unwind_sections, (void *) replacement_dyld_find_unwind_sections, this);

			_hook_libunwind ();
		}

		public override void dispose () {
			var interceptor = Mumu.Interceptor.obtain ();

			_unhook_libunwind ();
			interceptor.revert ((void *) dyld_find_unwind_sections);

			base.dispose ();
		}

		private static int replacement_dyld_find_unwind_sections (void * addr, void * info) {
			unowned Mumu.InvocationContext context = Mumu.Interceptor.get_current_invocation ();
			unowned UnwindSitter sitter = (UnwindSitter) context.get_replacement_data ();

			Mumu.MemoryRange range = sitter.invader.get_memory_range ();
			var range_end = range.base_address + range.size;

			var address = Mumu.Address.from_pointer (addr);
#if ARM64
			address &= 0x7ffffffffULL;
#endif
			var is_ours = address >= range.base_address && address < range_end;
			if (!is_ours)
				return sitter.dyld_find_unwind_sections (addr, info);

			_fill_unwind_sections (range.base_address, range_end, info);

			return 1;
		}

		public extern static void _fill_unwind_sections (Mumu.Address invader_start, Mumu.Address invader_end, void * info);
		public extern static void _hook_libunwind ();
		public extern static void _unhook_libunwind ();
	}
#else
	public sealed class UnwindSitter : Object {
		public weak ProcessInvader invader {
			get;
			construct;
		}

		public UnwindSitter (ProcessInvader invader) {
			Object (invader: invader);
		}
	}
#endif
}
