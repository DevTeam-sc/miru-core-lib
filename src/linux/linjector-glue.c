#include "miru-core.h"

GBytes *
_miru_agent_descriptor_clone_so (GBytes * so)
{
  /* TODO: update .so identity */
  return g_bytes_ref (so);
}
