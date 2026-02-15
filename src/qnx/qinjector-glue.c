#include "miru-core.h"

#include <gio/gunixinputstream.h>
#include <mumu/arch-arm/mumuarmwriter.h>
#include <mumu/arch-arm/mumuthumbwriter.h>
#include <mumu/mumu.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/debug.h>
#include <sys/mman.h>
#include <sys/netmgr.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/states.h>
#include <sys/types.h>
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#include <sys/wait.h>

enum {
  MUMU_QNX_ARM_REG_PC = ARM_REG_PC,
  MUMU_QNX_ARM_REG_LR = ARM_REG_LR,
  MUMU_QNX_ARM_REG_SP = ARM_REG_SP,
  MUMU_QNX_ARM_REG_R0 = ARM_REG_R0
};
#undef ARM_REG_R0
#undef ARM_REG_R1
#undef ARM_REG_R2
#undef ARM_REG_R3
#undef ARM_REG_R4
#undef ARM_REG_R5
#undef ARM_REG_R6
#undef ARM_REG_R7
#undef ARM_REG_R8
#undef ARM_REG_R9
#undef ARM_REG_R10
#undef ARM_REG_R11
#undef ARM_REG_R12
#undef ARM_REG_R13
#undef ARM_REG_R14
#undef ARM_REG_R15
#undef ARM_REG_SPSR
#undef ARM_REG_FP
#undef ARM_REG_IP
#undef ARM_REG_SP
#undef ARM_REG_LR
#undef ARM_REG_PC

#define PSR_T_BIT (1 << 5)

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto os_failure; \
  }

#define MIRU_REMOTE_PAYLOAD_SIZE (8192)
#define MIRU_REMOTE_DATA_OFFSET (512)
#define MIRU_REMOTE_STACK_OFFSET (MIRU_REMOTE_PAYLOAD_SIZE - 512)
#define MIRU_REMOTE_DATA_FIELD(n) \
    remote_address + MIRU_REMOTE_DATA_OFFSET + G_STRUCT_OFFSET (MiruTrampolineData, n)

typedef struct _MiruInjectionInstance MiruInjectionInstance;
typedef struct _MiruInjectionParams MiruInjectionParams;
typedef struct _MiruCodeChunk MiruCodeChunk;
typedef struct _MiruTrampolineData MiruTrampolineData;
typedef struct _MiruFindLandingStripContext MiruFindLandingStripContext;

typedef void (* MiruEmitFunc) (const MiruInjectionParams * params, MumuAddress remote_address, MiruCodeChunk * code);

struct _MiruInjectionInstance
{
  MiruQinjector * qinjector;
  guint id;
  pid_t pid;
  gboolean already_attached;
  int channel_id;
  MumuAddress remote_payload;
};

struct _MiruInjectionParams
{
  pid_t pid;
  const gchar * so_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;

  int channel_id;
  MumuAddress remote_address;
};

struct _MiruCodeChunk
{
  guint8 * cur;
  gsize size;
  guint8 bytes[2048];
};

struct _MiruTrampolineData
{
  gchar so_path[256];
  gchar entrypoint_name[256];
  gchar entrypoint_data[256];

  pthread_t worker_thread;
  gpointer module_handle;
};

struct _MiruFindLandingStripContext
{
  pid_t pid;
  MumuAddress result;
};

static gboolean miru_emit_and_remote_execute (MiruEmitFunc func, const MiruInjectionParams * params, MumuAddress * result, GError ** error);

static void miru_emit_payload_code (const MiruInjectionParams * params, MumuAddress remote_address, MiruCodeChunk * code);

static MumuAddress miru_remote_alloc (pid_t pid, size_t size, int prot, GError ** error);
static int miru_remote_dealloc (pid_t pid, MumuAddress address, size_t size, GError ** error);
static int miru_remote_pthread_create (pid_t pid, MumuAddress address, GError ** error);
static int miru_remote_msync (pid_t pid, MumuAddress remote_address, gint size, gint flags, GError ** error);
static gboolean miru_remote_write (pid_t pid, MumuAddress remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean miru_remote_write_fd (gint fd, MumuAddress remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean miru_remote_call (pid_t pid, MumuAddress func, const MumuAddress * args, gint args_length, MumuAddress * retval, GError ** error);

static MumuAddress miru_resolve_remote_libc_function (int remote_pid, const gchar * function_name);

static MumuAddress miru_resolve_remote_library_function (int remote_pid, const gchar * library_name, const gchar * function_name);
static MumuAddress miru_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path);

static MiruInjectionInstance *
miru_injection_instance_new (MiruQinjector * qinjector, guint id, pid_t pid, const char * temp_path)
{
  MiruInjectionInstance * instance;

  instance = g_slice_new0 (MiruInjectionInstance);
  instance->qinjector = g_object_ref (qinjector);
  instance->id = id;
  instance->pid = pid;
  instance->already_attached = FALSE;

  instance->channel_id = ChannelCreate_r (_NTO_CHF_DISCONNECT);

  return instance;
}

static void
miru_injection_instance_free (MiruInjectionInstance * instance, MiruUnloadPolicy unload_policy)
{
  if (instance->remote_payload != 0 && unload_policy == MIRU_UNLOAD_POLICY_IMMEDIATE)
  {
    GError * error = NULL;

    miru_remote_dealloc (instance->pid, instance->remote_payload, MIRU_REMOTE_PAYLOAD_SIZE, &error);

    g_clear_error (&error);
  }

  ChannelDestroy_r (instance->channel_id);
  g_object_unref (instance->qinjector);
  g_slice_free (MiruInjectionInstance, instance);
}

void
_miru_remote_thread_session_receive_pulse (void * opaque_instance, MiruQnxPulseCode * code, gint * val, GError ** error)
{
  MiruInjectionInstance * instance = opaque_instance;
  int res;
  struct _pulse pulse;

  res = MsgReceivePulse_r (instance->channel_id, &pulse, sizeof (pulse), NULL);
  if (res != EOK)
    goto failure;

  *code = pulse.code;
  *val = pulse.value.sival_int;

  return;

failure:
  {
    g_set_error (error,
        MIRU_ERROR,
        MIRU_ERROR_INVALID_OPERATION,
        "Unable to receive pulse: %s",
        strerror (-res));
    return;
  }
}

gboolean
_miru_remote_thread_session_thread_is_alive (guint pid, guint tid)
{
  gboolean alive = FALSE;
  gchar * path;
  gint fd;
  procfs_status status;

  path = g_strdup_printf ("/proc/%u", pid);

  fd = open (path, O_RDONLY);
  if (fd == -1)
    goto beach;

  status.tid = tid;
  if (devctl (fd, DCMD_PROC_TIDSTATUS, &status, sizeof (status), NULL) != EOK)
    goto beach;

  alive = status.tid == tid;

beach:
  if (fd != -1)
    close (fd);

  g_free (path);

  return alive;
}

void
_miru_qinjector_free_instance (MiruQinjector * self, void * instance, MiruUnloadPolicy unload_policy)
{
  miru_injection_instance_free (instance, unload_policy);
}

guint
_miru_qinjector_do_inject (MiruQinjector * self, guint pid, const gchar * path, const gchar * entrypoint, const gchar * data,
    const gchar * temp_path, GError ** error)
{
  MiruInjectionInstance * instance;
  MiruInjectionParams params = { pid, path, entrypoint, data };

  instance = miru_injection_instance_new (self, self->next_instance_id++, pid, temp_path);

  params.channel_id = instance->channel_id;
  params.remote_address = miru_remote_alloc (pid, MIRU_REMOTE_PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, error);
  if (params.remote_address == 0)
    goto beach;
  instance->remote_payload = params.remote_address;

  if (!miru_emit_and_remote_execute (miru_emit_payload_code, &params, NULL, error))
    goto beach;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instances), GUINT_TO_POINTER (instance->id), instance);

  return instance->id;

beach:
  {
    miru_injection_instance_free (instance, MIRU_UNLOAD_POLICY_IMMEDIATE);
    return 0;
  }
}

static gboolean
miru_emit_and_remote_execute (MiruEmitFunc func, const MiruInjectionParams * params, MumuAddress * result,
    GError ** error)
{
  MiruCodeChunk code;
  MiruTrampolineData * data;

  code.cur = code.bytes;
  code.size = 0;

  func (params, MUMU_ADDRESS (params->remote_address), &code);

  data = (MiruTrampolineData *) (code.bytes + MIRU_REMOTE_DATA_OFFSET);
  strcpy (data->so_path, params->so_path);
  strcpy (data->entrypoint_name, params->entrypoint_name);
  strcpy (data->entrypoint_data, params->entrypoint_data);
  data->worker_thread = 0;
  data->module_handle = NULL;

  if (!miru_remote_write (params->pid, params->remote_address, code.bytes, MIRU_REMOTE_DATA_OFFSET + sizeof (MiruTrampolineData), error))
    return FALSE;

  /*
   * We need to flush the data cache and invalidate the instruction cache before
   * trying to run the generated code.
   */
  if (miru_remote_msync (params->pid, params->remote_address, MIRU_REMOTE_PAYLOAD_SIZE, MS_INVALIDATE_ICACHE, error) != 0)
    return FALSE;

  if (miru_remote_pthread_create (params->pid, params->remote_address, error) != 0)
    return FALSE;

  return TRUE;
}

#define EMIT_MOVE(dst, src) \
    mumu_arm_writer_put_mov_reg_reg (&cw, ARM_REG_##dst, ARM_REG_##src)
#define EMIT_ADD(dst, src, offset) \
    mumu_arm_writer_put_add_reg_reg_imm (&cw, ARM_REG_##dst, ARM_REG_##src, offset)
#define EMIT_LOAD_FIELD(reg, field) \
    mumu_arm_writer_put_ldr_reg_address (&cw, ARM_REG_##reg, MIRU_REMOTE_DATA_FIELD (field)); \
    EMIT_LDR (reg, reg)
#define EMIT_STORE_FIELD(field, reg) \
    mumu_arm_writer_put_ldr_reg_address (&cw, ARM_REG_R0, MIRU_REMOTE_DATA_FIELD (field)); \
    mumu_arm_writer_put_str_reg_reg_offset (&cw, ARM_REG_##reg, ARM_REG_R0, 0)
#define EMIT_LDR(dst, src) \
    mumu_arm_writer_put_ldr_reg_reg_offset (&cw, ARM_REG_##dst, ARM_REG_##src, 0)
#define EMIT_LDR_U32(reg, value) \
    mumu_arm_writer_put_ldr_reg_u32 (&cw, ARM_REG_##reg, value)
#define EMIT_CALL_IMM(func, n_args, ...) \
    mumu_arm_writer_put_call_address_with_arguments (&cw, func, n_args, __VA_ARGS__)
#define EMIT_CALL_REG(reg, n_args, ...) \
    mumu_arm_writer_put_call_reg_with_arguments (&cw, ARM_REG_##reg, n_args, __VA_ARGS__)
#define EMIT_LABEL(name) \
    mumu_arm_writer_put_label (&cw, name)
#define EMIT_CMP(reg, imm) \
    mumu_arm_writer_put_cmp_reg_imm (&cw, ARM_REG_##reg, imm)
#define EMIT_B_COND(cond, label) \
    mumu_arm_writer_put_b_cond_label (&cw, ARM_CC_##cond, label)

#define ARG_IMM(value) \
    MUMU_ARG_ADDRESS, MUMU_ADDRESS (value)
#define ARG_REG(reg) \
    MUMU_ARG_REGISTER, ARM_REG_##reg

static void
miru_emit_payload_code (const MiruInjectionParams * params, MumuAddress remote_address, MiruCodeChunk * code)
{
  MumuArmWriter cw;
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_dlclose = "skip_dlclose";
  const gchar * skip_detach = "skip_detach";

  mumu_arm_writer_init (&cw, code->cur);

  mumu_arm_writer_put_push_regs (&cw, 4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);

  EMIT_CALL_IMM (miru_resolve_remote_libc_function (params->pid, "ConnectAttach_r"),
      5,
      ARG_IMM (ND_LOCAL_NODE),
      ARG_IMM (getpid ()),
      ARG_IMM (params->channel_id),
      ARG_IMM (_NTO_SIDE_CHANNEL),
      ARG_IMM (_NTO_COF_CLOEXEC));
  EMIT_MOVE (R7, R0);

  mumu_arm_writer_put_call_address_with_arguments (&cw, miru_resolve_remote_libc_function (params->pid, "gettid"), 0);
  EMIT_MOVE (R3, R0);

  EMIT_CALL_IMM (miru_resolve_remote_libc_function (params->pid, "MsgSendPulse_r"),
      4,
      ARG_REG (R7),
      ARG_IMM (-1),
      ARG_IMM (MIRU_QNX_PULSE_CODE_HELLO),
      ARG_REG (R3));

  EMIT_LOAD_FIELD (R6, module_handle);
  EMIT_CMP (R6, 0);
  EMIT_B_COND (NE, skip_dlopen);
  {
    EMIT_CALL_IMM (miru_resolve_remote_libc_function (params->pid, "dlopen"),
        2,
        ARG_IMM (MIRU_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (RTLD_LAZY));
    EMIT_MOVE (R6, R0);
    EMIT_STORE_FIELD (module_handle, R6);
  }
  EMIT_LABEL (skip_dlopen);

  EMIT_CALL_IMM (miru_resolve_remote_libc_function (params->pid, "dlsym"),
      2,
      ARG_REG (R6),
      ARG_IMM (MIRU_REMOTE_DATA_FIELD (entrypoint_name)));
  mumu_arm_writer_put_mov_reg_reg (&cw, ARM_REG_R5, ARM_REG_R0);

  EMIT_LDR_U32 (R0, MIRU_UNLOAD_POLICY_IMMEDIATE);
  mumu_arm_writer_put_push_regs (&cw, 2, ARM_REG_R0, ARM_REG_R7);
  EMIT_MOVE (R1, SP);
  EMIT_ADD (R2, SP, 4);
  EMIT_CALL_REG (R5,
      3,
      ARG_IMM (MIRU_REMOTE_DATA_FIELD (entrypoint_data)),
      ARG_REG (R1),
      ARG_REG (R2));

  EMIT_LDR (R0, SP);
  EMIT_CMP (R0, MIRU_UNLOAD_POLICY_IMMEDIATE);
  EMIT_B_COND (NE, skip_dlclose);
  {
    EMIT_CALL_IMM (miru_resolve_remote_libc_function (params->pid, "dlclose"),
        1,
        ARG_REG (R6));
  }
  EMIT_LABEL (skip_dlclose);

  EMIT_LDR (R0, SP);
  EMIT_CMP (R0, MIRU_UNLOAD_POLICY_DEFERRED);
  EMIT_B_COND (EQ, skip_detach);
  {
    EMIT_LOAD_FIELD (R0, worker_thread);
    EMIT_CALL_IMM (miru_resolve_remote_libc_function (params->pid, "pthread_detach"),
        1,
        ARG_REG (R0));
  }
  EMIT_LABEL (skip_detach);

  EMIT_LDR (R3, SP);
  EMIT_CALL_IMM (miru_resolve_remote_libc_function (params->pid, "MsgSendPulse_r"),
      4,
      ARG_REG (R7),
      ARG_IMM (-1),
      ARG_IMM (MIRU_QNX_PULSE_CODE_BYE),
      ARG_REG (R3));

  EMIT_CALL_IMM (miru_resolve_remote_libc_function (params->pid, "ConnectDetach_r"),
      1,
      ARG_REG (R7));

  mumu_arm_writer_put_pop_regs (&cw, 2, ARM_REG_R0, ARM_REG_R7);

  mumu_arm_writer_put_pop_regs (&cw, 4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_PC);

  mumu_arm_writer_flush (&cw);
  code->cur = mumu_arm_writer_cur (&cw);
  code->size += mumu_arm_writer_offset (&cw);
  mumu_arm_writer_clear (&cw);
}

static MumuAddress
miru_remote_alloc (pid_t pid, size_t size, int prot, GError ** error)
{
  MumuAddress args[] = {
    0,
    size,
    prot,
    MAP_PRIVATE | MAP_ANONYMOUS,
    -1,
    0
  };
  MumuAddress retval = 0;
  MumuAddress function = miru_resolve_remote_libc_function (pid, "mmap");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_alloc failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!miru_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return 0;

  if (retval == G_GUINT64_CONSTANT (0xffffffffffffffff))
    return 0;

  return retval;
}

static int
miru_remote_dealloc (pid_t pid, MumuAddress address, size_t size, GError ** error)
{
  MumuAddress args[] = {
    address,
    size
  };
  MumuAddress retval;
  MumuAddress function = miru_resolve_remote_libc_function (pid, "munmap");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_dealloc failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!miru_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return -1;

  return retval;
}

static int
miru_remote_pthread_create (pid_t pid, MumuAddress remote_address, GError ** error)
{
  MumuAddress args[] = {
    MIRU_REMOTE_DATA_FIELD (worker_thread),
    0,
    remote_address,
    0
  };
  MumuAddress retval;
  MumuAddress function = miru_resolve_remote_libc_function (pid, "pthread_create");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_pthread_create failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!miru_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return -1;

  return retval;
}

static int
miru_remote_msync (pid_t pid, MumuAddress remote_address, gint size, gint flags, GError ** error)
{
  MumuAddress args[] = {
    remote_address,
    size,
    flags
  };
  MumuAddress retval;
  MumuAddress function = miru_resolve_remote_libc_function (pid, "msync");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_msync failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!miru_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return -1;

  return retval;
}

static gboolean
miru_remote_write (pid_t pid, MumuAddress remote_address, gconstpointer data, gsize size, GError ** error)
{
  gint fd;
  gchar as_path[PATH_MAX];
  gboolean result;

  sprintf (as_path, "/proc/%d/as", pid);
  fd = open (as_path, O_RDWR);
  if (fd == -1)
    return FALSE;

  result = miru_remote_write_fd (fd, remote_address, data, size, error);

  close (fd);

  return result;
}

static gboolean
miru_remote_write_fd (gint fd, MumuAddress remote_address, gconstpointer data, gsize size, GError ** error)
{
  long ret;
  const gchar * failed_operation;

  ret = lseek (fd, GPOINTER_TO_SIZE (remote_address), SEEK_SET);
  CHECK_OS_RESULT (ret, ==, remote_address, "seek to address");

  ret = write (fd, data, size);
  CHECK_OS_RESULT (ret, ==, size, "write data");

  return TRUE;

os_failure:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_write %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
miru_remote_call (pid_t pid, MumuAddress func, const MumuAddress * args, gint args_length, MumuAddress * retval, GError ** error)
{
  gboolean success = FALSE;
  gint ret;
  const gchar * failed_operation;
  gint fd;
  gint i;
  gchar as_path[PATH_MAX];
  pthread_t tid;
  debug_thread_t thread;
  procfs_greg saved_registers, modified_registers;
  procfs_status status;
  procfs_run run;
  sigset_t * run_fault = (sigset_t *) &run.fault;

  sprintf (as_path, "/proc/%d/as", pid);
  fd = open (as_path, O_RDWR);
  if (fd == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_call failed to open process %d, errno: %d", pid, errno);
    return FALSE;
  }

  /*
   * Find the first active thread:
   */
  for (tid = 1;; tid++)
  {
    thread.tid = tid;
    if (devctl (fd, DCMD_PROC_TIDSTATUS, &thread, sizeof (thread), 0) == EOK)
      break;
  }

  /*
   * Set current thread and freeze our target thread:
   */
  ret = devctl (fd, DCMD_PROC_CURTHREAD, &tid, sizeof (tid), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_CURTHREAD");

  ret = devctl (fd, DCMD_PROC_STOP, &status, sizeof (status), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_STOP");

  if (status.state == STATE_DEAD)
    goto beach;

  if (status.state != STATE_STOPPED)
  {
    /*
     * If the thread was not in the STOPPED state, it's probably
     * blocked in a NANOSLEEP or some syscall. We'll SIGHUP
     * it to kick it out of the blocker and WAITSTOP until the
     * signal is delivered.
     */
    memset (&run, 0, sizeof (run));
    run.flags |= _DEBUG_RUN_TRACE;
    sigemptyset (&run.trace);
    sigaddset (&run.trace, SIGHUP);
    ret = devctl (fd, DCMD_PROC_RUN, &run, sizeof (run), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_RUN");

    kill (pid, SIGHUP);

    ret = devctl (fd, DCMD_PROC_WAITSTOP, &status, sizeof (status), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_WAITSTOP");
    if (status.why == _DEBUG_WHY_TERMINATED)
      goto beach;

    /*
     * We need the extra PROC_STOP because status.state is not
     * properly reported by WAITSTOP.
     */
    ret = devctl (fd, DCMD_PROC_STOP, &status, sizeof (status), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_STOP");
  }

  /*
   * Get the thread's registers:
   */
  ret = devctl (fd, DCMD_PROC_GETGREG, &saved_registers, sizeof (saved_registers), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_GETGREG");

  memcpy (&modified_registers, &saved_registers, sizeof (saved_registers));

  /*
   * Set the PC to be the function address and SP to the stack address.
   */
  if ((func & 1) != 0)
  {
    modified_registers.arm.gpr[MUMU_QNX_ARM_REG_PC] = (func & ~1);
    modified_registers.arm.spsr |= PSR_T_BIT;
  }
  else
  {
    modified_registers.arm.gpr[MUMU_QNX_ARM_REG_PC] = func;
    modified_registers.arm.spsr &= ~PSR_T_BIT;
  }

  for (i = 0; i < args_length && i < 4; i++)
  {
    modified_registers.arm.gpr[i] = args[i];
  }

  for (i = args_length - 1; i >= 4; i--)
  {
    modified_registers.arm.gpr[MUMU_QNX_ARM_REG_SP] -= 4;

    if (!miru_remote_write_fd (fd, modified_registers.arm.gpr[MUMU_QNX_ARM_REG_SP], &args[i],
        4, error))
      goto beach;
  }

  /*
   * Set the LR to be a dummy address which will trigger a pagefault.
   */
  modified_registers.arm.gpr[MUMU_QNX_ARM_REG_LR] = 0xfffffff0;

  ret = devctl (fd, DCMD_PROC_SETGREG, &modified_registers, sizeof (modified_registers), 0);
  CHECK_OS_RESULT (ret, ==, 0, "DCMD_PROC_SETGREG");

  while (modified_registers.arm.gpr[MUMU_QNX_ARM_REG_PC] != 0xfffffff0)
  {
    /*
     * Continue the process, watching for FLTPAGE which should trigger when
     * the dummy LR value (0xfffffff0) is reached.
     */
    memset (&run, 0, sizeof (run));
    sigemptyset (run_fault);
    sigaddset (run_fault, FLTPAGE);
    run.flags |= _DEBUG_RUN_FAULT | _DEBUG_RUN_CLRFLT | _DEBUG_RUN_CLRSIG;
    ret = devctl (fd, DCMD_PROC_RUN, &run, sizeof (run), 0);
    CHECK_OS_RESULT (ret, ==, 0, "DCMD_PROC_RUN");

    /*
     * Wait for the process to stop at the fault.
     */
    ret = devctl (fd, DCMD_PROC_WAITSTOP, &status, sizeof (status), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_WAITSTOP");

    /*
     * Get the thread's registers:
     */
    ret = devctl (fd, DCMD_PROC_GETGREG, &modified_registers,
        sizeof (modified_registers), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_GETGREG");
  }

  if (retval != NULL)
    *retval = modified_registers.arm.gpr[MUMU_QNX_ARM_REG_R0];

  /*
   * Restore the registers and continue the process:
   */
  ret = devctl (fd, DCMD_PROC_SETGREG, &saved_registers, sizeof (saved_registers), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_SETGREG");

  memset (&run, 0, sizeof (run));
  run.flags |= _DEBUG_RUN_CLRFLT | _DEBUG_RUN_CLRSIG;
  ret = devctl (fd, DCMD_PROC_RUN, &run, sizeof (run), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_RUN");

  success = TRUE;

beach:
  close (fd);

  return success;

os_failure:
  {
    if (fd != -1)
      close (fd);
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_call %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static MumuAddress
miru_resolve_remote_libc_function (int remote_pid, const gchar * function_name)
{
  return miru_resolve_remote_library_function (remote_pid, "libc", function_name);
}

static MumuAddress
miru_resolve_remote_library_function (int remote_pid, const gchar * library_name, const gchar * function_name)
{
  gchar * local_library_path, * remote_library_path, * canonical_library_name;
  MumuAddress local_base, remote_base, remote_address;
  gpointer module, local_address;

  local_base = miru_find_library_base (getpid (), library_name, &local_library_path);
  g_assert (local_base != 0);

  remote_base = miru_find_library_base (remote_pid, library_name, &remote_library_path);
  if (remote_base == 0)
  {
    g_free (local_library_path);
    return 0;
  }

  g_assert (g_strcmp0 (local_library_path, remote_library_path) == 0);

  canonical_library_name = g_path_get_basename (local_library_path);

  module = dlopen (canonical_library_name, RTLD_GLOBAL | RTLD_LAZY);
  g_assert (module != NULL);

  local_address = dlsym (module, function_name);
  g_assert (local_address != NULL);

  remote_address = remote_base + (MUMU_ADDRESS (local_address) - local_base);

  dlclose (module);

  g_free (local_library_path);
  g_free (remote_library_path);
  g_free (canonical_library_name);

  return remote_address;
}

static MumuAddress
miru_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path)
{
  MumuAddress result = 0;
  gchar * as_path = NULL;
  int fd = -1;
  int res;
  procfs_mapinfo * mapinfos = NULL;
  gint num_mapinfos;
  procfs_debuginfo * debuginfo = NULL;
  gint i;
  gchar * path;

  if (library_path != NULL)
    *library_path = NULL;

  as_path = g_strdup_printf ("/proc/%d/as", pid);

  fd = open (as_path, O_RDONLY);
  if (fd == -1)
    goto beach;

  res = devctl (fd, DCMD_PROC_PAGEDATA, 0, 0, &num_mapinfos);
  if (res != 0)
    goto beach;

  mapinfos = g_malloc (num_mapinfos * sizeof (procfs_mapinfo));
  debuginfo = g_malloc (sizeof (procfs_debuginfo) + 0x100);

  res = devctl (fd, DCMD_PROC_PAGEDATA, mapinfos,
      num_mapinfos * sizeof (procfs_mapinfo), &num_mapinfos);
  if (res != 0)
    goto beach;

  for (i = 0; i != num_mapinfos; i++)
  {
    debuginfo->vaddr = mapinfos[i].vaddr;
    res = devctl (fd, DCMD_PROC_MAPDEBUG, debuginfo,
        sizeof (procfs_debuginfo) + 0x100, NULL);
    if (res != 0)
      goto beach;
    path = debuginfo->path;

    if (strcmp (path, library_name) == 0)
    {
      result = mapinfos[i].vaddr;
      if (library_path != NULL)
        *library_path = g_strdup (path);
    }
    else
    {
      gchar * p = strrchr (path, '/');
      if (p != NULL)
      {
        p++;

        gchar * s = strrchr (p, '.');
        gboolean has_numeric_suffix = FALSE;
        if (s != NULL && g_ascii_isdigit (*(s + 1)))
        {
          has_numeric_suffix = TRUE;
          *s = '\0';
        }
        if (g_str_has_prefix (p, library_name) && g_str_has_suffix (p, ".so"))
        {
          gchar next_char = p[strlen (library_name)];
          if (next_char == '-' || next_char == '.')
          {
            result = mapinfos[i].vaddr;
            if (library_path != NULL)
            {
              if (has_numeric_suffix)
                *s = '.';
              *library_path = g_strdup (path);
              break;
            }
          }
        }
      }
    }
  }

beach:
  g_free (debuginfo);
  g_free (mapinfos);

  if (fd != -1)
    close (fd);

  g_free (as_path);

  return result;
}
