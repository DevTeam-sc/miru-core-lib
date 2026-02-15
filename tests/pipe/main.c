#include <miru-pipe.h>

int
main (int argc, char * argv[])
{
  MiruPipeTransport * transport = NULL;
  const gchar * address;
  MiruPipe * pipe;
  gchar c;
  GError * error = NULL;

  glib_init ();
  gio_init ();

  if (argc == 1)
  {
    transport = miru_pipe_transport_new (NULL);
    address = miru_pipe_transport_get_local_address (transport);
    g_print ("listening on '%s'\n", miru_pipe_transport_get_remote_address (transport));
  }
  else
  {
    address = argv[1];
  }

  pipe = miru_pipe_new (address, &error);
  if (error != NULL)
  {
    g_printerr ("miru_pipe_new failed: %s\n", error->message);
  }
  else
  {
    if (transport != NULL)
    {
      while (TRUE)
      {
        ssize_t ret = g_input_stream_read (g_io_stream_get_input_stream (G_IO_STREAM (pipe)), &c, sizeof (c), NULL, &error);
        if (ret == 0)
        {
          g_printerr ("g_input_stream_read: EOF\n");
          break;
        }
        else if (error != NULL)
        {
          g_printerr ("g_input_stream_read failed: %s\n", error->message);
          break;
        }
        g_print ("read: %c\n", c);
      }
    }
    else
    {
      while (TRUE)
      {
        c = 'A' + g_random_int_range (0, 26);
        g_output_stream_write (g_io_stream_get_output_stream (G_IO_STREAM (pipe)), &c, sizeof (c), NULL, &error);
        if (error != NULL)
        {
          g_printerr ("g_output_stream_write failed: %s\n", error->message);
          break;
        }
        g_print ("wrote: %c\n", c);
        g_usleep (G_USEC_PER_SEC);
      }
    }

    g_object_unref (pipe);
  }

  if (transport != NULL)
    g_object_unref (transport);

  return 0;
}
