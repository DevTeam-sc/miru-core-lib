base_sources = [
    'miru.vala',
    'miru-glue.c',
    'package-manager.vala',
  'control-service.vala',
  'portal-service.vala',
  'host-session-service.vala',
  'agent-container.vala',
  'mdb.vala',
  'system.vala',
  'file-monitor.vala',
  'async-task.vala',
]

if host_os_family == 'darwin'
  base_sources += 'darwin' / 'system-darwin.m'
else
  base_sources += host_os_family / f'system-@host_os_family@.c'
endif
if host_os_family == 'windows'
  base_sources += 'windows' / 'icon-helpers.c'
elif host_os_family == 'darwin'
  base_sources += 'darwin' / 'icon-helpers.m'
endif

backend_sources = []
backend_vala_args = []
backend_vala_args_private = []
backend_libs = []
backend_deps = []

if host_os == 'android' or have_droidy_backend
  subdir('android-helper')

  helpers_native_prefix = 'linux' / 'helpers' / 'artifacts' / 'native'
  fs = import('fs')
  android_data = custom_target('miru-data-android',
    input: [
      'android.resources',
      android_helper_dex,
      fs.copyfile(helpers_native_prefix / 'x86' / 'zymbiote.bin', 'zymbiote-x86.bin'),
      fs.copyfile(helpers_native_prefix / 'x86_64' / 'zymbiote.bin', 'zymbiote-x86_64.bin'),
      fs.copyfile(helpers_native_prefix / 'arm' / 'zymbiote.bin', 'zymbiote-arm.bin'),
      fs.copyfile(helpers_native_prefix / 'arm64' / 'zymbiote.bin', 'zymbiote-arm64.bin'),
    ],
    output: [
      'miru-data-android.vapi',
      'miru-data-android.h',
      'miru-data-android.c',
      'miru-data-android-blob' + resource_blob_extension,
    ],
    command: [
      resource_compiler_cmd_array,
      '-c', '@INPUT0@',
      '-o', meson.current_build_dir() / 'miru-data-android',
      '@INPUT1@',
      '@INPUT2@',
      '@INPUT3@',
      '@INPUT4@',
      '@INPUT5@',
    ],
  )
  backend_sources += [android_data]
endif

if have_local_backend
  post_process_helper = post_process + ['executable', 're.miru.Helper']

  embed_helper = [
    python,
    files('embed-helper.py'),
    host_os,
    host_arch,
    host_toolchain,
    resource_compiler,
    '>>>', lipo, '<<<',
    meson.current_build_dir(),
    '@PRIVATE_DIR@',
    '@INPUT0@',
  ]

  if helper_emulated_modern == 'auto'
    helper_emulated_modern = ''
  endif

  if helper_emulated_legacy == 'auto'
    helper_emulated_legacy = ''
  endif

  if host_os_family == 'windows'
    backend_sources += [
      'windows' / 'windows-host-session.vala',
      'windows' / 'windows-host-session-glue.c',
      'windows' / 'winjector.vala',
      'windows' / 'winjector-glue.c',
      'windows' / 'miru-helper-process.vala',
      'windows' / 'miru-helper-process-glue.c',
      'windows' / 'access-helpers.c',
    ]
    backend_vala_args += '--pkg=miru-mumu-windows-1.0'

    helper_backend_sources = [
      'windows' / 'miru-helper-backend.vala',
      'windows' / 'miru-helper-backend-glue.c',
      'windows' / 'miru-helper-types.vala',
      'windows' / 'wait-handle-source.c',
    ]
    helper_backend_vala_args = [
      base_vala_args,
      '--pkg=miru-mumu-windows-1.0',
    ]
    helper_backend = static_library('miru-helper-backend', helper_backend_sources,
      vala_args: helper_backend_vala_args,
      c_args: miru_component_cflags,
      dependencies: [gio_dep, gee_dep, mumu_dep, base_dep],
    )
    backend_libs += helper_backend

    helper_sources = [
      'windows' / 'miru-helper-service.vala',
      'windows' / 'miru-helper-service-glue.c',
    ]
    raw_helper = executable('miru-helper-raw', helper_sources,
      vala_args: helper_backend_vala_args,
      link_with: helper_backend,
      dependencies: [gio_dep, gee_dep, mumu_dep, base_dep, pipe_dep],
    )

    helper = custom_target('miru-helper',
      input: raw_helper,
      output: helper_name,
      command: post_process_helper,
      build_by_default: true,
      install: get_option('assets') == 'installed',
      install_dir: asset_dir,
    )

    if get_option('assets') == 'embedded'
      if helper_modern == 'auto'
        helper_modern = host_is_modern ? helper : ''
      endif

      if helper_legacy == 'auto'
        helper_legacy = host_is_modern ? '' : helper
      endif

      helper_process_data = custom_target('miru-data-helper-process',
        input: 'helper.resources',
        output: [
          'miru-data-helper-process.vapi',
          'miru-data-helper-process.h',
          'miru-data-helper-process.c',
          'miru-data-helper-process-blob' + resource_blob_extension,
        ],
        command: embed_helper + [helper_modern, helper_legacy, helper_emulated_modern, helper_emulated_legacy],
        depends: helper_depends,
      )
      backend_sources += [helper_process_data]
    endif
  endif

  if host_os_family == 'darwin'
    subdir('darwin' / 'agent' / 'reportcrash')
    subdir('darwin' / 'agent' / 'osanalytics')

    backend_sources += [
      'darwin' / 'darwin-host-session.vala',
      'darwin' / 'darwin-host-session-glue.m',
      'darwin' / 'fruitjector.vala',
      'darwin' / 'miru-helper-process.vala',
    ]

    darwin_data = custom_target('miru-data-darwin',
      input: [
        'darwin' / 'miru-darwin.resources',
        'darwin' / 'agent' / 'launchd.js',
        'darwin' / 'agent' / 'xpcproxy.js',
        reportcrash_js,
        osanalytics_js,
      ],
      output: [
        'miru-data-darwin.vapi',
        'miru-data-darwin.h',
        'miru-data-darwin.c',
        'miru-data-darwin-blob' + resource_blob_extension,
      ],
      command: [
        resource_compiler_cmd_array,
        '-c', '@INPUT0@',
        '-o', meson.current_build_dir() / 'miru-data-darwin',
        '@INPUT1@',
        '@INPUT2@',
        '@INPUT3@',
        '@INPUT4@',
      ],
    )
    backend_sources += [darwin_data]

    helper_backend_sources = [
      'darwin' / 'miru-helper-types.vala',
      'darwin' / 'policy-softener.vala',
      'darwin' / 'policy-softener-glue.c',
    ]
    if host_os in ['macos', 'ios', 'tvos', 'xros']
      helper_backend_sources += [
        'darwin' / 'miru-helper-backend.vala',
        'darwin' / 'miru-helper-backend-glue.m',
        'darwin' / 'policyd.c',
        'darwin' / 'policyd-client.c',
      ]
    else
      helper_backend_sources += [
        'darwin' / 'miru-helper-null-backend.vala',
      ]
    endif
    if host_os in ['ios', 'tvos', 'xros']
      helper_backend_sources += [
        'darwin' / 'springboard.m',
        'darwin' / 'substituted-client.c',
        'darwin' / 'substituted2-client.c',
      ]
    endif
    helper_backend_vala_args = base_vala_args
    helper_backend = static_library('miru-helper-backend', helper_backend_sources,
      c_args: miru_component_cflags,
      vala_args: [
        helper_backend_vala_args,
        mumu_vala_args,
        '--pkg=miru-mumu-darwin-1.0',
        '--pkg=gmodule-2.0',
        '--pkg=gio-unix-2.0',
        '--pkg=posix',
      ],
      dependencies: [gmodule_dep, gio_dep, gio_unix_dep, gee_dep, mumu_dep, base_dep, pipe_dep],
    )
    backend_libs += [helper_backend]

    helper_sources = [
      'darwin' / 'miru-helper-service.vala',
      'darwin' / 'miru-helper-service-glue.m',
    ]
    helper_symlist = 'darwin' / 'miru-helper.symbols'
    helper_link_args = ['-Wl,-exported_symbols_list,' + meson.current_source_dir() / helper_symlist]
    helper_link_depends = [helper_symlist]
    if host_os == 'macos'
      helper_plist = 'darwin' / 'miru-helper.plist'
      helper_link_args += ['-Wl,-sectcreate,__TEXT,__info_plist,' + meson.current_source_dir() / helper_plist]
      helper_link_depends += [helper_plist]
    endif
    raw_helper = executable('miru-helper-raw', helper_sources,
      vala_args: [helper_backend_vala_args, '--pkg=posix'],
      link_args: [helper_link_args, backend_libs_private],
      link_depends: helper_link_depends,
      link_with: helper_backend,
      dependencies: [gio_dep, gio_unix_dep, gee_dep, mumu_dep, base_dep, pipe_dep],
      override_options: ['b_asneeded=false'],
    )

    need_universal_helper = get_option('assets') == 'installed' and helper_compat != ''

    helper = custom_target('miru-helper',
      input: [
        raw_helper,
        'darwin' / 'miru-helper.xcent',
      ],
      output: need_universal_helper ? f'@helper_name@-@host_abi@' : helper_name,
      command: post_process_helper + '@INPUT1@',
      build_by_default: true,
      install: get_option('assets') == 'installed' and not need_universal_helper,
      install_dir: asset_dir,
    )

    if need_universal_helper
      custom_target('miru-helper-universal',
        input: helper,
        output: helper_name,
        command: [
          lipo,
          '@INPUT@',
          helper_compat,
          '-create',
          '-output', meson.current_build_dir() / helper_name
        ],
        depends: helper_depends,
        install: true,
        install_dir: asset_dir,
      )
    endif

    if get_option('assets') == 'embedded'
      if helper_modern == 'auto'
        helper_modern = host_is_modern ? helper : ''
      endif

      if helper_legacy == 'auto'
        helper_legacy = host_is_modern ? '' : helper
      endif

      helper_process_data = custom_target('miru-data-helper-process',
        input: 'helper.resources',
        output: [
          'miru-data-helper-process.vapi',
          'miru-data-helper-process.h',
          'miru-data-helper-process.c',
          'miru-data-helper-process-blob' + resource_blob_extension,
        ],
        command: embed_helper + [helper_modern, helper_legacy, helper_emulated_modern, helper_emulated_legacy],
        depends: helper_depends,
      )
      backend_sources += [helper_process_data]
    endif
  endif

  if host_os_family == 'linux'
    backend_sources += [
      'linux' / 'linux-host-session.vala',
      'linux' / 'linjector.vala',
      'linux' / 'linjector-glue.c',
      'linux' / 'miru-helper-process.vala',
      'linux' / 'supersu.vala',
    ]

    if host_os == 'android'
      backend_vala_args_private += miru_selinux_vala_args
      backend_libs += miru_selinux
      backend_deps += miru_selinux_dep
    endif

    helper_backend_sources = [
      'linux' / 'miru-helper-backend.vala',
      'linux' / 'miru-helper-backend-glue.c',
      'linux' / 'miru-helper-backend-types.c',
      'linux' / 'miru-helper-types.vala',
      'linux' / 'activity-sampler.vala',
      'linux' / 'syscall-tracer.vala',
      'linux' / 'symbol-resolver.vala',
      'linux' / 'proc-maps.vala',
    ]
    if host_abi == 'armhf'
      host_lowlevel_abi = 'arm'
    else
      host_lowlevel_abi = host_abi
    endif
    if host_lowlevel_abi == 'arm' and host_machine.endian() == 'big'
      host_lowlevel_abi = 'armbe8'
    elif host_lowlevel_abi == 'arm64' and host_machine.endian() == 'big'
      host_lowlevel_abi = 'arm64be'
    endif
    bpf_arch_map = {
      'armhf': 'arm',
      'armv6kz': 'arm',
      'armbe8': 'armbe',
      'arm64beilp32': 'arm64be',
    }
    bpf_arch = bpf_arch_map.get(host_abi, host_abi)
    helpers_artifacts_dir = 'linux' / 'helpers' / 'artifacts'
    helpers_native_dir = helpers_artifacts_dir / 'native' / host_lowlevel_abi
    helpers_bpf_noarch_dir = helpers_artifacts_dir / 'bpf' / ('noarch-' + host_machine.endian())
    helpers_bpf_arch_dir = helpers_artifacts_dir / 'bpf' / bpf_arch
    helper_backend_data = custom_target('miru-data-helper-backend',
      input: [
        'linux' / 'miru-helper-backend.resources',
        helpers_native_dir / 'bootstrapper.bin',
        helpers_native_dir / 'loader.bin',
        helpers_bpf_noarch_dir  / 'activity-sampler.elf',
        helpers_bpf_arch_dir  / 'syscall-tracer.elf',
      ],
      output: [
        'miru-data-helper-backend.vapi',
        'miru-data-helper-backend.h',
        'miru-data-helper-backend.c',
        'miru-data-helper-backend-blob' + resource_blob_extension,
      ],
      command: [
        resource_compiler_cmd_array,
        '-c', '@INPUT0@',
        '-o', meson.current_build_dir() / 'miru-data-helper-backend',
        '@INPUT1@',
        '@INPUT2@',
        '@INPUT3@',
        '@INPUT4@',
      ],
    )
    helper_backend_sources += [helper_backend_data]
    helper_backend_extra_deps = []
    if host_os == 'android'
      helper_backend_extra_deps += [miru_selinux_dep]
    endif
    helper_backend_vala_args = [
      base_vala_args,
      mumu_vala_args,
      '--pkg=posix',
    ]
    helper_backend = static_library('miru-helper-backend', helper_backend_sources,
      c_args: miru_component_cflags,
      vala_args: [
        helper_backend_vala_args,
        '--pkg=linux',
        '--pkg=miru-linux',
    '--pkg=miru-mumu-linux-1.0',
      ],
      dependencies: [gio_dep, gio_unix_dep, gee_dep, mumu_dep, base_dep] + helper_backend_extra_deps,
    )
    backend_vala_args += helper_backend_vala_args
    backend_libs += [helper_backend]

    helper_sources = [
      'linux' / 'miru-helper-service.vala',
    ]
    helper_symscript = 'linux' / 'miru-helper.version'
    helper_link_args = ['-Wl,--version-script,' + meson.current_source_dir() / helper_symscript]
    helper_link_depends = [helper_symscript]
    raw_helper = executable('miru-helper-raw', helper_sources,
      vala_args: helper_backend_vala_args,
      link_args: helper_link_args,
      link_depends: helper_link_depends,
      link_with: helper_backend,
      dependencies: [gio_dep, gio_unix_dep, gee_dep, mumu_dep, base_dep],
    )

    helper = custom_target('miru-helper',
      input: raw_helper,
      output: helper_name,
      command: post_process_helper,
      build_by_default: true,
      install: get_option('assets') == 'installed',
      install_dir: asset_dir,
    )

    if get_option('assets') == 'embedded'
      if helper_modern == 'auto'
        helper_modern = host_is_modern ? helper : ''
      endif

      if helper_legacy == 'auto'
        helper_legacy = host_is_modern ? '' : helper
      endif

      # For our Linux backend, in-process is as capable as out-of-process, so we
      # only embed a helper if it's for the other architecture.
      if host_is_modern
        helper_modern = ''
      else
        helper_legacy = ''
      endif

      helper_process_data = custom_target('miru-data-helper-process',
        input: 'helper.resources',
        output: [
          'miru-data-helper-process.vapi',
          'miru-data-helper-process.h',
          'miru-data-helper-process.c',
          'miru-data-helper-process-blob' + resource_blob_extension,
        ],
        command: embed_helper + [helper_modern, helper_legacy, helper_emulated_modern, helper_emulated_legacy],
        depends: helper_depends,
      )
      backend_sources += [helper_process_data]
    endif
  endif

  if host_os_family == 'freebsd'
    backend_sources += [
      'freebsd' / 'freebsd-host-session.vala',
      'freebsd' / 'binjector.vala',
      'freebsd' / 'binjector-glue.c',
    ]
    backend_vala_args_private += '--pkg=miru-mumu-freebsd-1.0'
  endif

  if host_os_family == 'qnx'
    backend_sources += [
      'qnx' / 'qnx-host-session.vala',
      'qnx' / 'qinjector.vala',
      'qnx' / 'qinjector-glue.c',
    ]
  endif

  if get_option('assets') == 'embedded'
    if agent_modern == 'auto'
      agent_modern = host_is_modern ? agent : ''
    endif

    if agent_legacy == 'auto'
      agent_legacy = host_is_modern ? '' : agent
    endif

    if agent_emulated_modern == 'auto'
      agent_emulated_modern = ''
    endif

    if agent_emulated_legacy == 'auto'
      agent_emulated_legacy = ''
    endif

    backend_sources += custom_target('miru-data-agent',
      input: 'agent.resources',
      output: [
        'miru-data-agent-blob' + resource_blob_extension,
        'miru-data-agent.vapi',
        'miru-data-agent.h',
        'miru-data-agent.c',
      ],
      command: [
        python,
        files('embed-agent.py'),
        host_os,
        host_arch,
        host_toolchain,
        resource_compiler,
        '>>>', lipo, '<<<',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        '@INPUT0@',
        agent_modern,
        agent_legacy,
        agent_emulated_modern,
        agent_emulated_legacy,
        mumu_dep.get_variable('miru_dbghelp_prefix'),
        mumu_dep.get_variable('miru_symsrv_prefix'),
      ],
      depends: agent_depends,
    )
  endif
endif

if have_simmy_backend
  backend_sources += [
    'simmy' / 'simmy-host-session.vala',
    'simmy' / 'simmy-host-session-glue.m',
    'simmy' / 'text-plist.vala',
  ]

  simmy_data = custom_target('miru-data-simmy',
    input: [
      'simmy' / 'miru-simmy.resources',
      'simmy' / 'agent' / 'springboard.js',
    ],
    output: [
      'miru-data-simmy.vapi',
      'miru-data-simmy.h',
      'miru-data-simmy.c',
      'miru-data-simmy-blob' + resource_blob_extension,
    ],
    command: [
      resource_compiler_cmd_array,
      '-c', '@INPUT0@',
      '-o', meson.current_build_dir() / 'miru-data-simmy',
      '@INPUT1@',
    ],
  )
  backend_sources += [simmy_data]
endif

if have_fruity_backend
  backend_sources += [
    'fruity' / 'fruity-host-session.vala',
    'fruity' / 'device-monitor.vala',
    'fruity' / 'xpc.vala',
    'fruity' / 'dtx.vala',
    'fruity' / 'lockdown.vala',
    'fruity' / 'installation-proxy.vala',
    'fruity' / 'springboard-services.vala',
    'fruity' / 'mldb.vala',
    'fruity' / 'injector.vala',
    'fruity' / 'debugger-mappings.vala',
    'fruity' / 'usbmux.vala',
    'fruity' / 'dns.vala',
    'fruity' / 'keyed-archive.vala',
    'fruity' / 'plist.vala',
    'fruity' / 'plist-service.vala',
    'fruity' / 'opack.vala',
    'fruity' / 'network-stack.vala',
    'fruity' / 'usb.vala',
    'fruity' / 'ncm.vala',
  ]

  if host_os_family == 'windows'
    backend_sources += 'fruity' / 'device-monitor-windows.vala'
  elif host_os == 'macos'
    backend_sources += 'fruity' / 'device-monitor-macos.vala'
  elif host_os == 'linux'
    backend_sources += 'fruity' / 'device-monitor-linux.vala'
  endif

  if host_os_family == 'windows'
    backend_sources += 'fruity' / 'device-monitor-windows.c'
  elif host_os_family == 'darwin'
    backend_sources += 'fruity' / 'device-monitor-darwin.m'
  else
    backend_sources += 'fruity' / 'device-monitor-unix.c'
  endif

  backend_deps += openssl_dep
  backend_vala_args += [
    '--pkg=libnghttp2',
    '--pkg=libngtcp2',
    '--pkg=libngtcp2_crypto_quictls',
    '--pkg=libusb-1.0',
    '--pkg=lwip',
    '--pkg=openssl',
  ]
  if host_os_family == 'windows'
    backend_vala_args += '--pkg=windows-windns'
  elif host_os_family == 'darwin'
    backend_vala_args += [
      '--pkg=darwin-xnu',
      '--pkg=darwin-xpc',
      '--pkg=darwin-gcd',
      '--pkg=corefoundation',
    ]
  endif
  if host_os_family == 'linux'
    backend_vala_args += '--pkg=linux'
  endif
endif

if have_droidy_backend
  backend_sources += [
    'droidy' / 'droidy-host-session.vala',
    'droidy' / 'droidy-client.vala',
    'droidy' / 'jdwp.vala',
    'droidy' / 'injector.vala',
    'droidy' / 'axml.vala',
  ]
endif

if have_socket_backend
  backend_sources += [
    'socket' / 'socket-host-session.vala',
  ]
endif

if have_barebone_backend
  subdir('barebone')
endif

if host_os_family != 'windows'
  backend_vala_args_private += '--pkg=posix'
endif

subdir('compiler')

core_sources = base_sources + backend_sources + compiler_sources

internal_libs = [base, netif, pipe] + backend_libs
internal_deps = [base_dep, netif_dep, pipe_dep]

if host_os_family == 'windows'
  gio_platform_vala_args = ['--pkg=gio-windows-2.0']
  backend_deps += gio_windows_dep
else
  gio_platform_vala_args = ['--pkg=gio-unix-2.0']
  backend_deps += gio_unix_dep
endif

core_deps = [
  glib_dep,
  gobject_dep,
  gmodule_dep,
  gio_dep,
  gee_dep,
  json_glib_dep,
  mumu_dep,
  mumujs_inspector_dep,
  tls_provider_dep,
]
core_deps += backend_deps
core_deps += backend_deps_private

core_vala_args = [
  backend_vala_args,
  base_vala_args,
  '--pkg=gio-2.0',
  gio_platform_vala_args,
  '--pkg=json-glib-1.0',
]

core_gir_name = f'Miru-@api_version@.gir'

core = library('miru-core', core_sources,
  c_args: miru_component_cflags,
  vala_args: [
    core_vala_args,
    backend_vala_args_private,
    base_vala_args,
    mumujs_inspector_vala_args,
    '--pkg=gmodule-2.0',
    '--pkg=libsoup-3.0',
  ],
  vala_gir: core_gir_name,
  link_args: backend_libs_private,
  link_with: backend_libs,
  dependencies: core_deps + internal_deps,
)

alias_target('miru-core', core)


core_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_args: backend_libs_private,
  link_with: [core] + backend_libs,
  dependencies: [gio_dep, gee_dep, json_glib_dep, mumu_dep] + backend_deps + internal_deps,
)

core_build_dir = meson.current_build_dir()
subdir('api')
if 'core' in get_option('devkits')
  subdir('devkit')
endif
