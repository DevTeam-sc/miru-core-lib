#ifndef __MIRU_LINUX_BPF_H__
#define __MIRU_LINUX_BPF_H__

#include <glib.h>

G_BEGIN_DECLS

#define MIRU_BPF_RINGBUF_HEADER_SIZE 8

typedef guint32 MiruBpfRingbufFlags;

enum _MiruBpfRingbufFlags
{
  MIRU_BPF_RINGBUF_BUSY    = (1U << 31),
  MIRU_BPF_RINGBUF_DISCARD = (1U << 30),
};

G_END_DECLS

#endif
