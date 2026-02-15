#ifndef __MIRU_LINUX_PERF_EVENT_H__
#define __MIRU_LINUX_PERF_EVENT_H__

#include <glib.h>

G_BEGIN_DECLS

#define MIRU_PERF_EVENT_COUNT_SW_CPU_CLOCK  0

typedef struct _MiruPerfEventAttr MiruPerfEventAttr;
typedef guint32 MiruPerfEventType;

struct _MiruPerfEventAttr
{
  MiruPerfEventType event_type;
  guint32 size;
  guint64 config;

  union
  {
    guint64 sample_period;
    guint64 sample_freq;
  };

  guint64 sample_type;
  guint64 read_format;

  guint64 flags;

  guint32 wakeup_events;
  guint32 bp_type;

  union
  {
    guint64 bp_addr;
    guint64 config1;
  };

  union
  {
    guint64 bp_len;
    guint64 config2;
  };
};

enum _MiruPerfEventType
{
  MIRU_PERF_EVENT_TYPE_HARDWARE,
  MIRU_PERF_EVENT_TYPE_SOFTWARE,
};

G_END_DECLS

#endif
