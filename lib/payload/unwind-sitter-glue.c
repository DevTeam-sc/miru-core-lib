#include "miru-payload.h"

#ifdef HAVE_DARWIN

#include <capstone.h>
#include <mumu/mumudarwin.h>
#include <mumu/mumumemory.h>
#include <ptrauth.h>

#define MIRU_MH_MAGIC_64 0xfeedfacf
#define MIRU_LIBUNWIND_PATH "/usr/lib/system/libunwind.dylib"
#define MIRU_UNWIND_CURSOR_VTABLE_OFFSET_SET_INFO 0x68
#define MIRU_UNWIND_CURSOR_VTABLE_OFFSET_GET_REG 0x18
#define MIRU_FP_TO_SP(fp) (fp + 0x10)
#ifdef HAVE_ARM64
# define MIRU_UNWIND_CURSOR_unwindInfoMissing 0x268
# define MIRU_UNWAARCH64_X29 29
# define MIRU_STRIP_MASK 0x0000007fffffffffULL
#else
# define MIRU_UNWIND_CURSOR_unwindInfoMissing 0x100
# define MIRU_UNWX86_64_RBP 6
#endif

typedef struct _MiruFillInfoContext MiruFillInfoContext;
typedef struct _MiruDyldUnwindSections MiruDyldUnwindSections;
typedef struct _MiruCreateArgs MiruCreateArgs;
typedef struct _MiruUnwindHookState MiruUnwindHookState;

struct _MiruFillInfoContext
{
  MiruDyldUnwindSections * info;
  guint missing_info;
};

struct _MiruDyldUnwindSections
{
  const void * mh;
  const void * dwarf_section;
  uintptr_t dwarf_section_length;
  const void * compact_unwind_section;
  uintptr_t compact_unwind_section_length;
};

struct _MiruCreateArgs
{
  MumuAddress range_start;
  MumuAddress range_end;
};

struct _MiruUnwindHookState
{
  gpointer vtable;
  gssize shift;
  gpointer * set_info_slot;
  gpointer set_info_original;
  void (* set_info) (gpointer cursor, gint is_return_address);
  gpointer (* get_reg) (gpointer cursor, gint reg);
  MumuInterceptor * interceptor;
};

#if __has_feature (ptrauth_calls)
# define MIRU_RESIGN_PTR(x) GSIZE_TO_POINTER (mumu_sign_code_address (mumu_strip_code_address (MUMU_ADDRESS (x))))
#else
# define MIRU_RESIGN_PTR(x) (x)
#endif

static MiruDyldUnwindSections * miru_get_cached_sections (MumuAddress range_start, MumuAddress range_end);
static MiruDyldUnwindSections * miru_create_cached_sections (MiruCreateArgs * args);
static gboolean miru_fill_info (const MumuDarwinSectionDetails * details, MiruFillInfoContext * ctx);
static void miru_unwind_cursor_set_info_replacement (gpointer cursor, gint is_return_address);
static gpointer miru_find_vtable (void);
static gboolean miru_compute_vtable_shift (gpointer vtable, gssize * shift);
#ifdef HAVE_ARM64
static gboolean miru_find_bss_range (const MumuSectionDetails * details, MumuMemoryRange * range);
#else
static gboolean miru_is_empty_function (MumuAddress address);
static gboolean miru_has_first_match (MumuAddress address, gsize size, gboolean * matches);
#endif

static MiruUnwindHookState * state = NULL;

void
_miru_unwind_sitter_fill_unwind_sections (MumuAddress invader_start, MumuAddress invader_end, void * info)
{
  MiruDyldUnwindSections * unwind_sections = info;
  MiruDyldUnwindSections * cached;

  cached = miru_get_cached_sections (invader_start, invader_end);
  if (cached == NULL)
    return;

  memcpy (unwind_sections, cached, sizeof (MiruDyldUnwindSections));
}

void
_miru_unwind_sitter_hook_libunwind (void)
{
#if GLIB_SIZEOF_VOID_P == 8
  gpointer * set_info_slot;
  gpointer get_reg_impl;

  if (state != NULL)
    return;

  state = g_slice_new0 (MiruUnwindHookState);
  if (state == NULL)
    return;

  state->vtable = miru_find_vtable ();
  if (state->vtable == NULL)
    goto unsupported_version;

  if (!miru_compute_vtable_shift (state->vtable, &state->shift))
    goto unsupported_version;

  set_info_slot = (gpointer *) (MUMU_ADDRESS (state->vtable) + MIRU_UNWIND_CURSOR_VTABLE_OFFSET_SET_INFO + state->shift);
  get_reg_impl = *(gpointer *) (MUMU_ADDRESS (state->vtable) + MIRU_UNWIND_CURSOR_VTABLE_OFFSET_GET_REG + state->shift);

  state->set_info_slot = set_info_slot;
  state->set_info_original = *set_info_slot;
  state->set_info = MIRU_RESIGN_PTR (state->set_info_original);
  state->get_reg = MIRU_RESIGN_PTR (get_reg_impl);

  state->interceptor = mumu_interceptor_obtain ();

  if (mumu_interceptor_replace (state->interceptor, state->set_info_original, miru_unwind_cursor_set_info_replacement, NULL, NULL)
      != MUMU_REPLACE_OK)
    goto unsupported_version;

  return;

unsupported_version:
  g_slice_free (MiruUnwindHookState, state);
  state = NULL;
#endif
}

void
_miru_unwind_sitter_unhook_libunwind (void)
{
  if (state == NULL)
    return;

  mumu_interceptor_revert (state->interceptor, state->set_info_original);

  g_object_unref (state->interceptor);

  g_slice_free (MiruUnwindHookState, state);
  state = NULL;
}

static MiruDyldUnwindSections *
miru_get_cached_sections (MumuAddress range_start, MumuAddress range_end)
{
  static GOnce get_sections_once = G_ONCE_INIT;
  MiruCreateArgs args;

  args.range_start = range_start;
  args.range_end = range_end;

  g_once (&get_sections_once, (GThreadFunc) miru_create_cached_sections, &args);

  return (MiruDyldUnwindSections *) get_sections_once.retval;
}

static MiruDyldUnwindSections *
miru_create_cached_sections (MiruCreateArgs * args)
{
  MiruDyldUnwindSections * cached_sections;
  gsize page_size;
  gpointer header;
  MumuPageProtection prot;
  MumuDarwinModule * module;
  MiruFillInfoContext ctx;

  page_size = mumu_query_page_size ();
  header = GSIZE_TO_POINTER (args->range_start);

  while ((mumu_memory_query_protection (header, &prot) && (prot & MUMU_PAGE_READ) == 0) ||
      (*(guint32 *) header != MIRU_MH_MAGIC_64 && header + 4 <= GSIZE_TO_POINTER (args->range_end)))
  {
    header += page_size;
  }
  if (*(guint32 *) header != MIRU_MH_MAGIC_64)
    return NULL;

  cached_sections = g_slice_new0 (MiruDyldUnwindSections);
  cached_sections->mh = header;

  module = mumu_darwin_module_new_from_memory ("Miru", mach_task_self (), GPOINTER_TO_SIZE (header), MUMU_DARWIN_MODULE_FLAGS_NONE, NULL);
  if (module == NULL)
    return cached_sections;

  ctx.info = cached_sections;
  ctx.missing_info = 2;
  mumu_darwin_module_enumerate_sections (module, (MumuFoundDarwinSectionFunc) miru_fill_info, &ctx);

  g_object_unref (module);

  return cached_sections;
}

static gboolean
miru_fill_info (const MumuDarwinSectionDetails * details, MiruFillInfoContext * ctx)
{
  if (strcmp ("__TEXT", details->segment_name) != 0)
    return TRUE;

  if (strcmp ("__eh_frame", details->section_name) == 0)
  {
    ctx->missing_info--;
    ctx->info->dwarf_section = GSIZE_TO_POINTER (details->vm_address);
    ctx->info->dwarf_section_length = details->size;
  }
  else if (strcmp ("__unwind_info", details->section_name) == 0)
  {
    ctx->missing_info--;
    ctx->info->compact_unwind_section = GSIZE_TO_POINTER (details->vm_address);
    ctx->info->compact_unwind_section_length = details->size;
  }

  return ctx->missing_info > 0;
}

static void
miru_unwind_cursor_set_info_replacement (gpointer self, gint is_return_address)
{
  gboolean missing_info;
  MumuAddress fp, stored_pc;
  gpointer * stored_pc_slot;
#if defined (HAVE_ARM64) && !__has_feature (ptrauth_calls)
  gboolean was_signed = FALSE;
#endif

  if (state == NULL)
    return;

  state->set_info (self, is_return_address);

#ifdef HAVE_ARM64
  fp = MUMU_ADDRESS (state->get_reg (self, MIRU_UNWAARCH64_X29));
#else
  fp = MUMU_ADDRESS (state->get_reg (self, MIRU_UNWX86_64_RBP));
#endif
  if (fp == 0 || fp == -1)
    return;

  missing_info = *((guint8 *) self + MIRU_UNWIND_CURSOR_unwindInfoMissing);

  stored_pc_slot = GSIZE_TO_POINTER (fp + GLIB_SIZEOF_VOID_P);
  stored_pc = MUMU_ADDRESS (*stored_pc_slot);
#if __has_feature (ptrauth_calls)
  stored_pc = mumu_strip_code_address (stored_pc);
#elif defined (HAVE_ARM64)
  was_signed = (stored_pc & ~MIRU_STRIP_MASK) != 0ULL;
  if (was_signed)
    stored_pc &= MIRU_STRIP_MASK;
#endif

  if (!missing_info)
  {
    MumuAddress translated;

    translated = MUMU_ADDRESS (mumu_invocation_stack_translate (mumu_interceptor_get_current_stack (), GSIZE_TO_POINTER (stored_pc)));
    if (translated != stored_pc)
    {
#if __has_feature (ptrauth_calls)
      *stored_pc_slot = ptrauth_sign_unauthenticated (
          ptrauth_strip (GSIZE_TO_POINTER (translated), ptrauth_key_asia), ptrauth_key_asib, MIRU_FP_TO_SP (fp));
#elif defined (HAVE_ARM64)
      if (was_signed)
      {
        MumuAddress resigned;

        asm volatile (
            "mov x17, %1\n\t"
            "mov x16, %2\n\t"
            ".byte 0x5f, 0x21, 0x03, 0xd5\n\t" /* pacib1716 */
            "mov %0, x17\n\t"
            : "=r" (resigned)
            : "r" (translated & MIRU_STRIP_MASK),
              "r" (MIRU_FP_TO_SP (fp))
            : "x16", "x17"
        );

        *stored_pc_slot = GSIZE_TO_POINTER (resigned);
      }
      else
      {
        *stored_pc_slot = GSIZE_TO_POINTER (translated);
      }
#else
      *stored_pc_slot = GSIZE_TO_POINTER (translated);
#endif
    }
  }
}

static gpointer
miru_find_vtable (void)
{
  MumuAddress result = 0;
  MumuModule * libunwind;
  MumuAddress export;
  uint64_t address;
  G_GNUC_UNUSED cs_err err;
  csh capstone;
  cs_insn * insn = NULL;
  const uint8_t * code;
  size_t size;
  const size_t max_size = 2048;

  libunwind = mumu_process_find_module_by_name (MIRU_LIBUNWIND_PATH);
  if (libunwind == NULL)
    goto beach;

  export = mumu_module_find_export_by_name (libunwind, "unw_init_local");
  if (export == 0)
    export = mumu_module_find_export_by_name (libunwind, "_Unwind_RaiseException");
  if (export == 0)
    goto beach;
  export = mumu_strip_code_address (export);
  address = export;

#ifdef HAVE_ARM64
  cs_arch_register_arm64 ();
  err = cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &capstone);
#else
  cs_arch_register_x86 ();
  err = cs_open (CS_ARCH_X86, CS_MODE_64, &capstone);
#endif
  g_assert (err == CS_ERR_OK);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert (err == CS_ERR_OK);

  insn = cs_malloc (capstone);
  code = GSIZE_TO_POINTER (export);
  size = max_size;

#ifdef HAVE_ARM64
  {
    MumuAddress last_adrp;
    guint last_adrp_reg;
    MumuMemoryRange bss_range;

    bss_range.base_address = 0;
    mumu_module_enumerate_sections (libunwind, (MumuFoundSectionFunc) miru_find_bss_range, &bss_range);

    while (cs_disasm_iter (capstone, &code, &size, &address, insn))
    {
      if (insn->id == ARM64_INS_RET || insn->id == ARM64_INS_RETAA || insn->id == ARM64_INS_RETAB)
        break;
      if (insn->id == ARM64_INS_ADRP)
      {
        if (result != 0)
          break;
        last_adrp = (MumuAddress) insn->detail->arm64.operands[1].imm;
        last_adrp_reg = insn->detail->arm64.operands[0].reg;
      }
      else if (insn->id == ARM64_INS_ADD && insn->detail->arm64.operands[0].reg == last_adrp_reg)
      {
        MumuAddress candidate;
        gboolean is_bss;

        candidate = last_adrp + (MumuAddress) insn->detail->arm64.operands[2].imm;

        is_bss = bss_range.base_address != 0 &&
            bss_range.base_address <= candidate &&
            candidate < bss_range.base_address + bss_range.size;
        if (!is_bss)
        {
          if (result == 0)
          {
            result = candidate;
            last_adrp = candidate;
          }
          else
          {
            result = candidate;
            break;
          }
        }
      }
      else if (result != 0)
      {
        break;
      }
    }
  }
#else
  while (cs_disasm_iter (capstone, &code, &size, &address, insn))
  {
    if (insn->id == X86_INS_RET)
      break;
    if (insn->id == X86_INS_LEA)
    {
      const cs_x86_op * op = &insn->detail->x86.operands[1];
      if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP)
      {
        result = address + op->mem.disp * op->mem.scale;
        break;
      }
    }
  }
#endif

  if (insn != NULL)
    cs_free (insn, 1);
  cs_close (&capstone);

beach:
  g_clear_object (&libunwind);

  return GSIZE_TO_POINTER (result);
}

#ifdef HAVE_ARM64

static gboolean
miru_find_bss_range (const MumuSectionDetails * details, MumuMemoryRange * range)
{
  if (strcmp (details->name, "__bss") == 0)
  {
    range->base_address = details->address;
    range->size = details->size;
    return FALSE;
  }

  return TRUE;
}

static gboolean
miru_compute_vtable_shift (gpointer vtable, gssize * shift)
{
  gboolean result = FALSE;
  G_GNUC_UNUSED cs_err err;
  csh capstone;
  cs_insn * insn = NULL;
  const uint8_t * code;
  uint64_t address;
  size_t size = 4;

  cs_arch_register_arm64 ();
  err = cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &capstone);
  g_assert (err == CS_ERR_OK);

  insn = cs_malloc (capstone);
  code = mumu_strip_code_pointer (*(gpointer *) vtable);
  address = GPOINTER_TO_SIZE (code);

  if (cs_disasm_iter (capstone, &code, &size, &address, insn))
  {
    if (insn->id == ARM64_INS_RET || insn->id == ARM64_INS_RETAA || insn->id == ARM64_INS_RETAB)
      *shift = 0;
    else
      *shift = -2 * GLIB_SIZEOF_VOID_P;

    result = TRUE;
  }

  if (insn != NULL)
    cs_free (insn, 1);
  cs_close (&capstone);

  return result;
}

#else

static gboolean
miru_compute_vtable_shift (gpointer vtable, gssize * shift)
{
  MumuAddress cursor = GPOINTER_TO_SIZE (vtable);
  MumuAddress error = cursor + 16 * GLIB_SIZEOF_VOID_P;

  while (cursor < error && *(gpointer *) GSIZE_TO_POINTER (cursor) == NULL)
    cursor += GLIB_SIZEOF_VOID_P;
  if (cursor == error)
    return FALSE;

  if (miru_is_empty_function (MUMU_ADDRESS (*(gpointer *) GSIZE_TO_POINTER (cursor))) &&
      miru_is_empty_function (MUMU_ADDRESS (*(gpointer *) GSIZE_TO_POINTER (cursor + GLIB_SIZEOF_VOID_P))))
  {
    *shift = cursor - GPOINTER_TO_SIZE (vtable);
  }
  else
  {
    *shift = cursor - GPOINTER_TO_SIZE (vtable) - 2 * GLIB_SIZEOF_VOID_P;
  }

  return TRUE;
}

static gboolean
miru_is_empty_function (MumuAddress address)
{
  gboolean matches = FALSE;
  MumuMemoryRange range;
  MumuMatchPattern * pattern;

  range.base_address = address;
  range.size = 6;

  /*
   * 55      push rbp
   * 4889e5  mov rbp, rsp
   * 5d      pop rbp
   * c3      ret
   */
  pattern = mumu_match_pattern_new_from_string ("55 48 89 e5 5d c3");

  mumu_memory_scan (&range, pattern, (MumuMemoryScanMatchFunc) miru_has_first_match, &matches);

  mumu_match_pattern_unref (pattern);

  return matches;
}

static gboolean
miru_has_first_match (MumuAddress address, gsize size, gboolean * matches)
{
  *matches = TRUE;
  return FALSE;
}

#endif

#endif
