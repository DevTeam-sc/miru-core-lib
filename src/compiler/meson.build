compiler_sources = files(
  'compiler.vala',
  'backend-glue.c',
)

if have_compiler_backend
  output_suffix = compiler_backend_static_compilation ? '' : '-raw'
  compiler_backend = custom_target('miru-compiler-backend',
    input: [
      'go.mod',
      'go.sum',
      'backend.go',
      'backend.version',
      'tscompiler.go',
      'tsconfig.go',
      'shims.go',
      'package.json',
      'package-lock.json',
    ],
    output: [
      'miru-compiler-backend' + output_suffix + (compiler_backend_static_compilation ? '.a' : shlib_suffix),
      'miru-compiler-backend' + output_suffix + '.h',
    ],
    command: [
      python,
      files('build-backend.py'),
      go_config,
      meson.current_build_dir(),
      '@PRIVATE_DIR@',
      go,
      npm,
      '@INPUT@',
    ],
  )
  if compiler_backend_static_compilation
    backend_libs += compiler_backend[0]
  else
    filename = 'miru-compiler-backend' + shlib_suffix
    identity = (host_os_family == 'darwin') ? 'MiruCompilerBackend' : filename
    compiler_backend_shlib = custom_target('miru-compiler-backend-shlib',
      input: compiler_backend[0],
      output: filename,
      command: post_process + ['shared-library', identity, 'elf-cleaner:off'],
    )

    compiler_data = custom_target('miru-data-compiler',
      input: [
        'compiler.resources',
        compiler_backend_shlib,
      ],
      output: [
        'miru-data-compiler.vapi',
        'miru-data-compiler.h',
        'miru-data-compiler.c',
        'miru-data-compiler-blob' + resource_blob_extension,
      ],
      command: [
        resource_compiler_cmd_array,
        '-c', '@INPUT0@',
        '-o', meson.current_build_dir() / 'miru-data-compiler',
        '@INPUT1@',
      ],
    )
    backend_sources += compiler_data
  endif
endif
