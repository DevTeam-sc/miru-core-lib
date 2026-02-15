#ifndef __MIRU_ATOMICS_H__
#define __MIRU_ATOMICS_H__

#include <glib.h>

static inline guint64
miru_atomics_load_u64_acquire (void * p)
{
  return __atomic_load_n ((guint64 *) p, __ATOMIC_ACQUIRE);
}

static inline void
miru_atomics_store_u64_release (void * p, guint64 v)
{
  __atomic_store_n ((guint64 *) p, v, __ATOMIC_RELEASE);
}

static inline guint32
miru_atomics_load_u32_acquire (void * p)
{
  return __atomic_load_n ((guint32 *) p, __ATOMIC_ACQUIRE);
}

#endif
