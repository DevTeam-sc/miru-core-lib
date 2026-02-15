devkit_outputs = [
  'miru-core.gir',
  'miru-core.h',
  static_lib_prefix + 'miru-core' + static_lib_suffix,
  'miru-core-example.c',
]

if host_toolchain == 'microsoft'
  devkit_outputs += [
    'miru-core-example.sln',
    'miru-core-example.vcxproj',
    'miru-core-example.vcxproj.filters',
  ]
endif

custom_target('core-devkit',
  input: [core_public_h, core_public_vapi, core_public_lib],
  output: devkit_outputs,
  command: [
    mkdevkit,
    'miru-core',
    f'@host_os@-@host_arch@',
    meson.current_build_dir(),
  ] + devkit_options,
  install: true,
  install_dir: get_option('libdir') / 'miru' / 'devkits' / 'core'
)
