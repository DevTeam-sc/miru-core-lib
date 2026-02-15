#include "miru-core.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/procfs.h>

typedef struct _MiruEnumerateProcessesOperation MiruEnumerateProcessesOperation;

struct _MiruEnumerateProcessesOperation
{
  MiruScope scope;
  GArray * result;
};

static void miru_collect_process_info (guint pid, MiruEnumerateProcessesOperation * op);

void
miru_system_get_frontmost_application (MiruFrontmostQueryOptions * options, MiruHostApplicationInfo * result, GError ** error)
{
  g_set_error (error,
      MIRU_ERROR,
      MIRU_ERROR_NOT_SUPPORTED,
      "Not implemented");
}

MiruHostApplicationInfo *
miru_system_enumerate_applications (MiruApplicationQueryOptions * options, int * result_length)
{
  *result_length = 0;

  return NULL;
}

MiruHostProcessInfo *
miru_system_enumerate_processes (MiruProcessQueryOptions * options, int * result_length)
{
  MiruEnumerateProcessesOperation op;

  op.scope = miru_process_query_options_get_scope (options);
  op.result = g_array_new (FALSE, FALSE, sizeof (MiruHostProcessInfo));

  if (miru_process_query_options_has_selected_pids (options))
  {
    miru_process_query_options_enumerate_selected_pids (options, (GFunc) miru_collect_process_info, &op);
  }
  else
  {
    GDir * proc_dir;
    const gchar * proc_name;

    proc_dir = g_dir_open ("/proc", 0, NULL);

    while ((proc_name = g_dir_read_name (proc_dir)) != NULL)
    {
      guint pid;
      gchar * end;

      pid = strtoul (proc_name, &end, 10);
      if (*end == '\0')
        miru_collect_process_info (pid, &op);
    }

    g_dir_close (proc_dir);
  }

  *result_length = op.result->len;

  return (MiruHostProcessInfo *) g_array_free (op.result, FALSE);
}

static void
miru_collect_process_info (guint pid, MiruEnumerateProcessesOperation * op)
{
  MiruHostProcessInfo info = { 0, };
  gchar * as_path;
  gint fd;
  static struct
  {
    procfs_debuginfo info;
    char buff[PATH_MAX];
  } procfs_name;

  as_path = g_strdup_printf ("/proc/%u/as", pid);

  fd = open (as_path, O_RDONLY);
  if (fd == -1)
    goto beach;

  if (devctl (fd, DCMD_PROC_MAPDEBUG_BASE, &procfs_name, sizeof (procfs_name), 0) != EOK)
    goto beach;

  info.pid = pid;
  info.name = g_path_get_basename (procfs_name.info.path);

  info.parameters = miru_make_parameters_dict ();

  if (op->scope != MIRU_SCOPE_MINIMAL)
  {
    g_hash_table_insert (info.parameters, g_strdup ("path"), g_variant_ref_sink (g_variant_new_string (procfs_name.info.path)));
  }

  g_array_append_val (op->result, info);

beach:
  if (fd != -1)
    close (fd);

  g_free (as_path);
}

void
miru_system_kill (guint pid)
{
  kill (pid, SIGKILL);
}

gchar *
miru_temporary_directory_get_system_tmp (void)
{
  return g_strdup (g_get_tmp_dir ());
}
