#ifndef __MIRU_SYSCALL_H__
#define __MIRU_SYSCALL_H__

#ifndef NOLIBC
# include <unistd.h>
#endif
#include <sys/syscall.h>

#define miru_syscall_0(n)          miru_syscall_4 (n, 0, 0, 0, 0)
#define miru_syscall_1(n, a)       miru_syscall_4 (n, a, 0, 0, 0)
#define miru_syscall_2(n, a, b)    miru_syscall_4 (n, a, b, 0, 0)
#define miru_syscall_3(n, a, b, c) miru_syscall_4 (n, a, b, c, 0)

ssize_t miru_syscall_4 (size_t n, size_t a, size_t b, size_t c, size_t d);

#endif
