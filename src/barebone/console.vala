[CCode (gir_namespace = "MiruBarebone", gir_version = "1.0")]
namespace Miru.Barebone {
	private class ConsoleLogHandler : Object, CallbackHandler {
		public signal void output (string message);

		public uint arity {
			get { return 2; }
		}

		private GDB.Client mdb;

		public ConsoleLogHandler (GDB.Client mdb) {
			this.mdb = mdb;
		}

		public async uint64 handle_invocation (uint64[] args, CallFrame frame, Cancellable? cancellable)
				throws Error, IOError {
			var message = args[0];
			var len = (long) args[1];

			Bytes str_bytes = yield mdb.read_byte_array (message, len, cancellable);
			unowned uint8[] str_data = str_bytes.get_data ();
			unowned string str_raw = (string) str_data;
			string str = str_raw.substring (0, len);

			output (str);

			return 0;
		}
	}
}
