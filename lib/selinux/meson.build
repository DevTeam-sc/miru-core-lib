miru_selinux_incdir = include_directories('.')

miru_selinux_h = files('miru-selinux.h')
install_headers(miru_selinux_h, subdir: 'miru-' + api_version)

miru_selinux = static_library('miru-selinux', 'patch.c',
  c_args: miru_component_cflags,
  dependencies: [glib_dep, gio_dep, libselinux_dep, libsepol_dep],
)

miru_selinux_dep = declare_dependency(
  include_directories: miru_selinux_incdir,
  link_with: miru_selinux,
)

miru_selinux_vala_args = ['--pkg=libselinux']
