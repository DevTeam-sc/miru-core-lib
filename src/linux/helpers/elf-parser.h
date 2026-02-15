#ifndef __MIRU_ELF_PARSER_H__
#define __MIRU_ELF_PARSER_H__

#include <elf.h>
#include <stdbool.h>
#ifndef NOLIBC
# include <stddef.h>
# include <stdint.h>
#endif

#ifndef __ELF_NATIVE_CLASS
# if defined (__x86_64__) || (defined (__aarch64__) && !defined (__ILP32__)) || defined (__mips64) || (defined (__riscv) && __riscv_xlen == 64)
#  define __ELF_NATIVE_CLASS 64
# else
#  define __ELF_NATIVE_CLASS 32
# endif
#endif

#ifndef ElfW
# define ElfW(type) _ElfW1 (Elf, __ELF_NATIVE_CLASS, type)
# define _ElfW1(a, b, c) _ElfW2 (a, b, _##c)
# define _ElfW2(a, b, c) a##b##c
#endif

#if __ELF_NATIVE_CLASS == 64
# define MIRU_ELF_ST_TYPE ELF64_ST_TYPE
# define MIRU_ELF_ST_BIND ELF64_ST_BIND
#else
# define MIRU_ELF_ST_TYPE ELF32_ST_TYPE
# define MIRU_ELF_ST_BIND ELF32_ST_BIND
#endif

#define MIRU_ELF_PAGE_ALIGN(value, page_size) \
    ((((ElfW(Addr)) (value)) + ((ElfW(Addr)) ((page_size) - 1))) & ~((ElfW(Addr)) ((page_size) - 1)))
#define MIRU_ELF_PAGE_START(value, page_size) \
    ((ElfW(Addr)) (value) & ~((ElfW(Addr)) ((page_size) - 1)))
#define MIRU_ELF_PAGE_OFFSET(value, page_size) \
    ((ElfW(Addr)) (value) & (ElfW(Addr)) (page_size - 1))

typedef struct _MiruElfExportDetails MiruElfExportDetails;
typedef bool (* MiruFoundElfSymbolFunc) (const MiruElfExportDetails * details, void * user_data);

struct _MiruElfExportDetails
{
  const char * name;
  void * address;
  uint8_t type;
  uint8_t bind;
};

const ElfW(Dyn) * miru_elf_find_dynamic_section (const ElfW(Ehdr) * ehdr);
const char * miru_elf_query_soname (const ElfW(Ehdr) * ehdr);
void miru_elf_enumerate_exports (const ElfW(Ehdr) * ehdr, MiruFoundElfSymbolFunc func, void * user_data);
void miru_elf_enumerate_symbols (const ElfW(Ehdr) * ehdr, void * loaded_base, MiruFoundElfSymbolFunc func, void * user_data);
ElfW(Addr) miru_elf_compute_base_from_phdrs (const ElfW(Phdr) * phdrs, ElfW(Half) phdr_size, ElfW(Half) phdr_count, size_t page_size);

#endif
