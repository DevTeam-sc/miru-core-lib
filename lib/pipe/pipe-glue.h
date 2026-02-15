#ifndef __MIRU_PIPE_GLUE_H__
#define __MIRU_PIPE_GLUE_H__

#include "miru-pipe.h"

#define MIRU_TYPE_WINDOWS_PIPE_INPUT_STREAM (miru_windows_pipe_input_stream_get_type ())
#define MIRU_TYPE_WINDOWS_PIPE_OUTPUT_STREAM (miru_windows_pipe_output_stream_get_type ())

G_DECLARE_FINAL_TYPE (MiruWindowsPipeInputStream, miru_windows_pipe_input_stream, MIRU, WINDOWS_PIPE_INPUT_STREAM, GInputStream)
G_DECLARE_FINAL_TYPE (MiruWindowsPipeOutputStream, miru_windows_pipe_output_stream, MIRU, WINDOWS_PIPE_OUTPUT_STREAM, GOutputStream)

#endif
