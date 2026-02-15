#include "miru-helper-backend.h"

#include <gio/gio.h>
#include <mumu/mumu.h>
#include <mumu/arch-arm64/mumuarm64writer.h>
#include <mumu/arch-x86/mumux86writer.h>

#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!((n1) cmp (n2))) \
  { \
    failed_operation = op; \
    goto os_failure; \
  }

#define CHECK_NT_RESULT(n1, cmp, n2, op) \
  if (!((n1) cmp (n2))) \
  { \
    failed_operation = op; \
    goto nt_failure; \
  }

typedef struct _MiruInjectInstance MiruInjectInstance;
typedef struct _MiruInjectionDetails MiruInjectionDetails;
typedef struct _MiruRemoteWorkerContext MiruRemoteWorkerContext;

struct _MiruInjectInstance
{
  HANDLE process_handle;
  gpointer free_address;
  gpointer stay_resident_address;
};

struct _MiruInjectionDetails
{
  HANDLE process_handle;
  const WCHAR * dll_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;
};

struct _MiruRemoteWorkerContext
{
  gboolean stay_resident;

  gpointer load_library_impl;
  gpointer get_proc_address_impl;
  gpointer free_library_impl;
  gpointer virtual_free_impl;
  gpointer get_last_error_impl;

  WCHAR dll_path[MAX_PATH + 1];
  gchar entrypoint_name[256];
  gchar entrypoint_data[MAX_PATH + 1];

  gpointer entrypoint;
  gpointer argument;
};

typedef struct _RtlClientId RtlClientId;

struct _RtlClientId
{
  SIZE_T unique_process;
  SIZE_T unique_thread;
};

typedef NTSTATUS (WINAPI * RtlCreateUserThreadFunc) (HANDLE process, SECURITY_DESCRIPTOR * sec,
    BOOLEAN create_suspended, ULONG stack_zero_bits, SIZE_T * stack_reserved, SIZE_T * stack_commit,
    LPTHREAD_START_ROUTINE start_address, LPVOID parameter, HANDLE * thread_handle, RtlClientId * result);

static void miru_propagate_open_process_error (guint32 pid, DWORD os_error, GError ** error);
static gboolean miru_enable_debug_privilege (void);

static gboolean miru_remote_worker_context_init (MiruRemoteWorkerContext * rwc, MiruInjectionDetails * details, GError ** error);
static gsize miru_remote_worker_context_emit_payload (MiruRemoteWorkerContext * rwc, gpointer code);
static void miru_remote_worker_context_destroy (MiruRemoteWorkerContext * rwc, MiruInjectionDetails * details);

static gboolean miru_remote_worker_context_has_resolved_all_kernel32_functions (const MiruRemoteWorkerContext * rwc);
static gboolean miru_remote_worker_context_collect_kernel32_export (const MumuExportDetails * details, gpointer user_data);

static gboolean miru_file_exists_and_is_readable (const WCHAR * filename);

void
_miru_windows_helper_backend_inject_library_file (guint32 pid, const gchar * path, const gchar * entrypoint, const gchar * data,
    void ** inject_instance, void ** waitable_thread_handle, GError ** error)
{
  gboolean success = FALSE;
  const gchar * failed_operation;
  NTSTATUS nt_status;
  MiruInjectionDetails details;
  DWORD desired_access;
  HANDLE thread_handle = NULL;
  gboolean rwc_initialized = FALSE;
  MiruRemoteWorkerContext rwc;
  MiruInjectInstance * instance;

  details.dll_path = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  details.entrypoint_name = entrypoint;
  details.entrypoint_data = data;
  details.process_handle = NULL;

  if (!miru_file_exists_and_is_readable (details.dll_path))
    goto invalid_path;

  miru_enable_debug_privilege ();

  desired_access =
      PROCESS_DUP_HANDLE    | /* duplicatable handle                  */
      PROCESS_VM_OPERATION  | /* for VirtualProtectEx and mem access  */
      PROCESS_VM_READ       | /*   ReadProcessMemory                  */
      PROCESS_VM_WRITE      | /*   WriteProcessMemory                 */
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;

  details.process_handle = OpenProcess (desired_access, FALSE, pid);
  CHECK_OS_RESULT (details.process_handle, !=, NULL, "OpenProcess");

  if (!miru_remote_worker_context_init (&rwc, &details, error))
    goto beach;
  rwc_initialized = TRUE;

  thread_handle = CreateRemoteThread (details.process_handle, NULL, 0, MUMU_POINTER_TO_FUNCPTR (LPTHREAD_START_ROUTINE, rwc.entrypoint),
      rwc.argument, 0, NULL);
  if (thread_handle == NULL)
  {
    RtlCreateUserThreadFunc rtl_create_user_thread;
    RtlClientId client_id;

    rtl_create_user_thread = (RtlCreateUserThreadFunc) GetProcAddress (GetModuleHandleW (L"ntdll.dll"), "RtlCreateUserThread");
    nt_status = rtl_create_user_thread (details.process_handle, NULL, FALSE, 0, NULL, NULL,
        MUMU_POINTER_TO_FUNCPTR (LPTHREAD_START_ROUTINE, rwc.entrypoint), rwc.argument, &thread_handle, &client_id);
    CHECK_NT_RESULT (nt_status, == , 0, "RtlCreateUserThread");
  }

  instance = g_slice_new (MiruInjectInstance);
  instance->process_handle = details.process_handle;
  details.process_handle = NULL;
  instance->free_address = rwc.entrypoint;
  instance->stay_resident_address = (guint8 *) rwc.argument + G_STRUCT_OFFSET (MiruRemoteWorkerContext, stay_resident);
  *inject_instance = instance;

  *waitable_thread_handle = thread_handle;
  thread_handle = NULL;

  success = TRUE;

  goto beach;

  /* ERRORS */
invalid_path:
  {
    g_set_error (error,
        MIRU_ERROR,
        MIRU_ERROR_INVALID_ARGUMENT,
        "Unable to find DLL at '%s'",
        path);
    goto beach;
  }
os_failure:
  {
    DWORD os_error;

    os_error = GetLastError ();

    if (details.process_handle == NULL)
    {
      miru_propagate_open_process_error (pid, os_error, error);
    }
    else
    {
      g_set_error (error,
          MIRU_ERROR,
          (os_error == ERROR_ACCESS_DENIED) ? MIRU_ERROR_PERMISSION_DENIED : MIRU_ERROR_NOT_SUPPORTED,
          "Unexpected error while attaching to process with pid %u (%s returned 0x%08lx)",
          pid, failed_operation, os_error);
    }

    goto beach;
  }
nt_failure:
  {
    gint code;

    if (nt_status == 0xC0000022) /* STATUS_ACCESS_DENIED */
      code = MIRU_ERROR_PERMISSION_DENIED;
    else
      code = MIRU_ERROR_NOT_SUPPORTED;

    g_set_error (error,
        MIRU_ERROR,
        code,
        "Unexpected error while attaching to process with pid %u (%s returned 0x%08lx)",
        pid, failed_operation, nt_status);
    goto beach;
  }

beach:
  {
    if (!success && rwc_initialized)
      miru_remote_worker_context_destroy (&rwc, &details);

    if (thread_handle != NULL)
      CloseHandle (thread_handle);

    if (details.process_handle != NULL)
      CloseHandle (details.process_handle);

    g_free ((gpointer) details.dll_path);
  }
}

void
_miru_windows_helper_backend_free_inject_instance (void * inject_instance, gboolean * is_resident)
{
  MiruInjectInstance * instance = inject_instance;
  gboolean stay_resident;
  SIZE_T n_bytes_read;

  if (ReadProcessMemory (instance->process_handle, instance->stay_resident_address, &stay_resident, sizeof (stay_resident),
      &n_bytes_read) && n_bytes_read == sizeof (stay_resident))
  {
    *is_resident = stay_resident;
  }
  else
  {
    *is_resident = FALSE;
  }

  VirtualFreeEx (instance->process_handle, instance->free_address, 0, MEM_RELEASE);

  CloseHandle (instance->process_handle);

  g_slice_free (MiruInjectInstance, instance);
}

static void
miru_propagate_open_process_error (guint32 pid, DWORD os_error, GError ** error)
{
  if (os_error == ERROR_INVALID_PARAMETER)
  {
    g_set_error (error,
        MIRU_ERROR,
        MIRU_ERROR_PROCESS_NOT_FOUND,
        "Unable to find process with pid %u",
        pid);
  }
  else if (os_error == ERROR_ACCESS_DENIED)
  {
    g_set_error (error,
        MIRU_ERROR,
        MIRU_ERROR_PERMISSION_DENIED,
        "Unable to access process with pid %u from the current user account",
        pid);
  }
  else
  {
    g_set_error (error,
        MIRU_ERROR,
        MIRU_ERROR_NOT_SUPPORTED,
        "Unable to access process with pid %u due to an unexpected error (OpenProcess returned 0x%08lx)",
        pid, os_error);
  }
}

static gboolean
miru_enable_debug_privilege (void)
{
  static gboolean enabled = FALSE;
  gboolean success = FALSE;
  HANDLE token = NULL;
  TOKEN_PRIVILEGES privileges;
  LUID_AND_ATTRIBUTES * p = &privileges.Privileges[0];

  if (enabled)
    return TRUE;

  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))
    goto beach;

  privileges.PrivilegeCount = 1;
  if (!LookupPrivilegeValueW (NULL, L"SeDebugPrivilege", &p->Luid))
    goto beach;
  p->Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges (token, FALSE, &privileges, 0, NULL, NULL))
    goto beach;

  if (GetLastError () == ERROR_NOT_ALL_ASSIGNED)
    goto beach;

  enabled = TRUE;
  success = TRUE;

beach:
  if (token != NULL)
    CloseHandle (token);

  return success;
}

static gboolean
miru_remote_worker_context_init (MiruRemoteWorkerContext * rwc, MiruInjectionDetails * details, GError ** error)
{
  gpointer code;
  guint code_size;
  MumuModule * kernel32;
  SIZE_T page_size, alloc_size;
  DWORD old_protect;

  mumu_init ();

  code = mumu_alloc_n_pages (1, MUMU_PAGE_RWX); /* Executable so debugger can be used to inspect code */
  code_size = miru_remote_worker_context_emit_payload (rwc, code);

  memset (rwc, 0, sizeof (MiruRemoteWorkerContext));

  kernel32 = mumu_process_find_module_by_name ("kernel32.dll");
  mumu_module_enumerate_exports (kernel32, miru_remote_worker_context_collect_kernel32_export, rwc);
  g_object_unref (kernel32);
  if (!miru_remote_worker_context_has_resolved_all_kernel32_functions (rwc))
    goto failed_to_resolve_kernel32_functions;

  StringCbCopyW (rwc->dll_path, sizeof (rwc->dll_path), details->dll_path);
  StringCbCopyA (rwc->entrypoint_name, sizeof (rwc->entrypoint_name), details->entrypoint_name);
  StringCbCopyA (rwc->entrypoint_data, sizeof (rwc->entrypoint_data), details->entrypoint_data);

  page_size = mumu_query_page_size ();
  g_assert (code_size <= page_size);

  alloc_size = page_size + sizeof (MiruRemoteWorkerContext);
  rwc->entrypoint = VirtualAllocEx (details->process_handle, NULL, alloc_size, MEM_COMMIT, PAGE_READWRITE);
  if (rwc->entrypoint == NULL)
    goto virtual_alloc_ex_failed;

  if (!WriteProcessMemory (details->process_handle, rwc->entrypoint, code, code_size, NULL))
    goto write_process_memory_failed;

  rwc->argument = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (rwc->entrypoint) + page_size);
  if (!WriteProcessMemory (details->process_handle, rwc->argument, rwc, sizeof (MiruRemoteWorkerContext), NULL))
    goto write_process_memory_failed;

  if (!VirtualProtectEx (details->process_handle, rwc->entrypoint, page_size, PAGE_EXECUTE_READ, &old_protect))
    goto virtual_protect_ex_failed;

  mumu_free_pages (code);
  return TRUE;

  /* ERRORS */
failed_to_resolve_kernel32_functions:
  {
    g_set_error (error,
        MIRU_ERROR,
        MIRU_ERROR_NOT_SUPPORTED,
        "Unexpected error while resolving kernel32 functions");
    goto error_common;
  }
virtual_alloc_ex_failed:
  {
    g_set_error (error,
        MIRU_ERROR,
        MIRU_ERROR_NOT_SUPPORTED,
        "Unexpected error allocating memory in target process (VirtualAllocEx returned 0x%08lx)",
        GetLastError ());
    goto error_common;
  }
write_process_memory_failed:
  {
    g_set_error (error,
        MIRU_ERROR,
        MIRU_ERROR_NOT_SUPPORTED,
        "Unexpected error writing to memory in target process (WriteProcessMemory returned 0x%08lx)",
        GetLastError ());
    goto error_common;
  }
virtual_protect_ex_failed:
  {
    g_set_error (error,
        MIRU_ERROR,
        MIRU_ERROR_NOT_SUPPORTED,
        "Unexpected error changing memory permission in target process (VirtualProtectEx returned 0x%08lx)",
        GetLastError ());
    goto error_common;
  }
error_common:
  {
    miru_remote_worker_context_destroy (rwc, details);
    mumu_free_pages (code);
    return FALSE;
  }
}

#define EMIT_ARM64_LOAD(reg, field) \
    mumu_arm64_writer_put_ldr_reg_reg_offset (&cw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (MiruRemoteWorkerContext, field))
#define EMIT_ARM64_LOAD_ADDRESS_OF(reg, field) \
    mumu_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (MiruRemoteWorkerContext, field))
#define EMIT_ARM64_MOVE(dstreg, srcreg) \
    mumu_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_##dstreg, ARM64_REG_##srcreg)
#define EMIT_ARM64_CALL(reg) \
    mumu_arm64_writer_put_blr_reg_no_auth (&cw, ARM64_REG_##reg)

static gsize
miru_remote_worker_context_emit_payload (MiruRemoteWorkerContext * rwc, gpointer code)
{
  gsize code_size;
  const gchar * loadlibrary_failed = "loadlibrary_failed";
  const gchar * skip_unload = "skip_unload";
  const gchar * return_result = "return_result";
#ifdef HAVE_ARM64
  MumuArm64Writer cw;

  mumu_arm64_writer_init (&cw, code);

  mumu_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  mumu_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_SP);
  mumu_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_X20);

  /* x20 = (MiruRemoteWorkerContext *) lpParameter */
  EMIT_ARM64_MOVE (X20, X0);

  /* x19 = LoadLibrary (x20->dll_path) */
  EMIT_ARM64_LOAD_ADDRESS_OF (X0, dll_path);
  EMIT_ARM64_LOAD (X8, load_library_impl);
  EMIT_ARM64_CALL (X8);
  mumu_arm64_writer_put_cbz_reg_label (&cw, ARM64_REG_X0, loadlibrary_failed);
  EMIT_ARM64_MOVE (X19, X0);

  /* x8 = GetProcAddress (x19, x20->entrypoint_name) */
  EMIT_ARM64_MOVE (X0, X19);
  EMIT_ARM64_LOAD_ADDRESS_OF (X1, entrypoint_name);
  EMIT_ARM64_LOAD (X8, get_proc_address_impl);
  EMIT_ARM64_CALL (X8);
  EMIT_ARM64_MOVE (X8, X0);

  /* x8 (x20->entrypoint_data, &x20->stay_resident, NULL) */
  EMIT_ARM64_LOAD_ADDRESS_OF (X0, entrypoint_data);
  EMIT_ARM64_LOAD_ADDRESS_OF (X1, stay_resident);
  EMIT_ARM64_MOVE (X2, XZR);
  EMIT_ARM64_CALL (X8);

  /* if (!x20->stay_resident) { */
  EMIT_ARM64_LOAD (X0, stay_resident);
  mumu_arm64_writer_put_cbnz_reg_label (&cw, ARM64_REG_X0, skip_unload);

  /* FreeLibrary (xsi) */
  EMIT_ARM64_MOVE (X0, X19);
  EMIT_ARM64_LOAD (X8, free_library_impl);
  EMIT_ARM64_CALL (X8);

  /* } */
  mumu_arm64_writer_put_label (&cw, skip_unload);

  /* result = ERROR_SUCCESS */
  EMIT_ARM64_MOVE (X0, XZR);
  mumu_arm64_writer_put_b_label (&cw, return_result);

  mumu_arm64_writer_put_label (&cw, loadlibrary_failed);
  /* result = GetLastError() */
  EMIT_ARM64_LOAD (X8, get_last_error_impl);
  EMIT_ARM64_CALL (X8);

  mumu_arm64_writer_put_label (&cw, return_result);
  mumu_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_X20);
  mumu_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  mumu_arm64_writer_put_ret (&cw);

  mumu_arm64_writer_flush (&cw);
  code_size = mumu_arm64_writer_offset (&cw);
  mumu_arm64_writer_clear (&cw);
#else
  MumuX86Writer cw;

  mumu_x86_writer_init (&cw, code);

  /* Will clobber these */
  mumu_x86_writer_put_push_reg (&cw, MUMU_X86_XBX);
  mumu_x86_writer_put_push_reg (&cw, MUMU_X86_XSI);
  mumu_x86_writer_put_push_reg (&cw, MUMU_X86_XDI); /* Alignment padding */

  /* xbx = (MiruRemoteWorkerContext *) lpParameter */
#if GLIB_SIZEOF_VOID_P == 4
  mumu_x86_writer_put_mov_reg_reg_offset_ptr (&cw, MUMU_X86_EBX, MUMU_X86_ESP, (3 + 1) * sizeof (gpointer));
#else
  mumu_x86_writer_put_mov_reg_reg (&cw, MUMU_X86_RBX, MUMU_X86_RCX);
#endif

  /* xsi = LoadLibrary (xbx->dll_path) */
  mumu_x86_writer_put_lea_reg_reg_offset (&cw, MUMU_X86_XCX,
      MUMU_X86_XBX, G_STRUCT_OFFSET (MiruRemoteWorkerContext, dll_path));
  mumu_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, MUMU_CALL_SYSAPI,
      MUMU_X86_XBX, G_STRUCT_OFFSET (MiruRemoteWorkerContext, load_library_impl),
      1,
      MUMU_ARG_REGISTER, MUMU_X86_XCX);
  mumu_x86_writer_put_test_reg_reg (&cw, MUMU_X86_XAX, MUMU_X86_XAX);
  mumu_x86_writer_put_jcc_near_label (&cw, X86_INS_JE, loadlibrary_failed, MUMU_UNLIKELY);
  mumu_x86_writer_put_mov_reg_reg (&cw, MUMU_X86_XSI, MUMU_X86_XAX);

  /* xax = GetProcAddress (xsi, xbx->entrypoint_name) */
  mumu_x86_writer_put_lea_reg_reg_offset (&cw, MUMU_X86_XDX,
      MUMU_X86_XBX, G_STRUCT_OFFSET (MiruRemoteWorkerContext, entrypoint_name));
  mumu_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, MUMU_CALL_SYSAPI,
      MUMU_X86_XBX, G_STRUCT_OFFSET (MiruRemoteWorkerContext, get_proc_address_impl),
      2,
      MUMU_ARG_REGISTER, MUMU_X86_XSI,
      MUMU_ARG_REGISTER, MUMU_X86_XDX);

  /* xax (xbx->entrypoint_data, &xbx->stay_resident, NULL) */
  mumu_x86_writer_put_lea_reg_reg_offset (&cw, MUMU_X86_XCX,
      MUMU_X86_XBX, G_STRUCT_OFFSET (MiruRemoteWorkerContext, entrypoint_data));
  mumu_x86_writer_put_lea_reg_reg_offset (&cw, MUMU_X86_XDX,
      MUMU_X86_XBX, G_STRUCT_OFFSET (MiruRemoteWorkerContext, stay_resident));
  mumu_x86_writer_put_call_reg_with_arguments (&cw, MUMU_CALL_CAPI, MUMU_X86_XAX,
      3,
      MUMU_ARG_REGISTER, MUMU_X86_XCX,
      MUMU_ARG_REGISTER, MUMU_X86_XDX,
      MUMU_ARG_ADDRESS, MUMU_ADDRESS (0));

  /* if (!xbx->stay_resident) { */
  mumu_x86_writer_put_mov_reg_reg_offset_ptr (&cw, MUMU_X86_EAX,
      MUMU_X86_XBX, G_STRUCT_OFFSET (MiruRemoteWorkerContext, stay_resident));
  mumu_x86_writer_put_test_reg_reg (&cw, MUMU_X86_EAX, MUMU_X86_EAX);
  mumu_x86_writer_put_jcc_short_label (&cw, X86_INS_JNE, skip_unload, MUMU_NO_HINT);

  /* FreeLibrary (xsi) */
  mumu_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, MUMU_CALL_SYSAPI,
      MUMU_X86_XBX, G_STRUCT_OFFSET (MiruRemoteWorkerContext, free_library_impl),
      1,
      MUMU_ARG_REGISTER, MUMU_X86_XSI);

  /* } */
  mumu_x86_writer_put_label (&cw, skip_unload);

  /* result = ERROR_SUCCESS */
  mumu_x86_writer_put_xor_reg_reg (&cw, MUMU_X86_EAX, MUMU_X86_EAX);
  mumu_x86_writer_put_jmp_short_label (&cw, return_result);

  mumu_x86_writer_put_label (&cw, loadlibrary_failed);
  /* result = GetLastError() */
  mumu_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, MUMU_CALL_SYSAPI,
      MUMU_X86_XBX, G_STRUCT_OFFSET (MiruRemoteWorkerContext, get_last_error_impl),
      0);

  mumu_x86_writer_put_label (&cw, return_result);
  mumu_x86_writer_put_pop_reg (&cw, MUMU_X86_XDI);
  mumu_x86_writer_put_pop_reg (&cw, MUMU_X86_XSI);
  mumu_x86_writer_put_pop_reg (&cw, MUMU_X86_XBX);
  mumu_x86_writer_put_ret (&cw);

  mumu_x86_writer_flush (&cw);
  code_size = mumu_x86_writer_offset (&cw);
  mumu_x86_writer_clear (&cw);
#endif

  return code_size;
}

static void
miru_remote_worker_context_destroy (MiruRemoteWorkerContext * rwc, MiruInjectionDetails * details)
{
  if (rwc->entrypoint != NULL)
  {
    VirtualFreeEx (details->process_handle, rwc->entrypoint, 0, MEM_RELEASE);
    rwc->entrypoint = NULL;
  }
}

static gboolean
miru_remote_worker_context_has_resolved_all_kernel32_functions (const MiruRemoteWorkerContext * rwc)
{
  return (rwc->load_library_impl != NULL) && (rwc->get_proc_address_impl != NULL) &&
      (rwc->free_library_impl != NULL) && (rwc->virtual_free_impl != NULL);
}

static gboolean
miru_remote_worker_context_collect_kernel32_export (const MumuExportDetails * details, gpointer user_data)
{
  MiruRemoteWorkerContext * rwc = user_data;

  if (details->type != MUMU_EXPORT_FUNCTION)
    return TRUE;

  if (strcmp (details->name, "LoadLibraryW") == 0)
    rwc->load_library_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "GetProcAddress") == 0)
    rwc->get_proc_address_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "FreeLibrary") == 0)
    rwc->free_library_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "VirtualFree") == 0)
    rwc->virtual_free_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "GetLastError") == 0)
    rwc->get_last_error_impl = GSIZE_TO_POINTER (details->address);

  return TRUE;
}

static gboolean
miru_file_exists_and_is_readable (const WCHAR * filename)
{
  HANDLE file;

  file = CreateFileW (filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING, 0, NULL);
  if (file == INVALID_HANDLE_VALUE)
    return FALSE;
  CloseHandle (file);

  return TRUE;
}
