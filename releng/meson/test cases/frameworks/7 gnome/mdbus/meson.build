mdbus_src = gnome.mdbus_codegen('generated-mdbus-no-docbook',
  'data/com.example.Sample.xml',
  interface_prefix : 'com.example.',
  namespace : 'Sample',
  annotations : [
    ['com.example.Hello()', 'org.freedesktop.DBus.Deprecated', 'true']
  ],
)

# check that empty annotations work
mdbus_src2 = gnome.mdbus_codegen(
  'generated-mdbus-no-docbook2',
  'data/com.example.Sample.xml',
  interface_prefix : 'com.example.',
  namespace : 'Sample',
  annotations : [],
)

assert(mdbus_src.length() == 2, 'expected 2 targets')
assert(mdbus_src[0].full_path().endswith('.c'), 'expected 1 c source file')
assert(mdbus_src[1].full_path().endswith('.h'), 'expected 1 c header file')

sample_xml = configure_file(input: 'data/com.example.Sample.xml',
  output: 'com.example.Sample.xml',
  copy: true)

mdbus_src = gnome.mdbus_codegen('generated-mdbus-no-docbook-files-posarg',
  sample_xml,
  interface_prefix : 'com.example.',
  namespace : 'Sample',
  annotations : [
    ['com.example.Hello()', 'org.freedesktop.DBus.Deprecated', 'true']
  ],
)
assert(mdbus_src.length() == 2, 'expected 2 targets')
assert(mdbus_src[0].full_path().endswith('.c'), 'expected 1 c source file')
assert(mdbus_src[1].full_path().endswith('.h'), 'expected 1 c header file')

mdbus_src = gnome.mdbus_codegen('generated-mdbus',
  sources : files('data/com.example.Sample.xml'),
  interface_prefix : 'com.example.',
  namespace : 'Sample',
  annotations : [
    ['com.example.Hello()', 'org.freedesktop.DBus.Deprecated', 'true'],
    ['com.example.Bye()', 'org.freedesktop.DBus.Deprecated', 'true'],
  ],
  docbook : 'generated-mdbus-doc',
  install_header : true,
  install_dir : get_option('includedir')
)
assert(mdbus_src.length() == 3, 'expected 3 targets')
assert(mdbus_src[0].full_path().endswith('.c'), 'expected 1 c source file')
assert(mdbus_src[1].full_path().endswith('.h'), 'expected 1 c header file')

if not pretend_glib_old and glib.version().version_compare('>=2.51.3')
  includes = []
else
  includes = include_directories('..')
endif

# check that custom targets work
mdbus_xml_ct = custom_target('built xml sources for mdbus',
  output: 'com.example.SampleCustomTarget.xml',
  input: 'data/com.example.Sample.xml',
  command : [copyfile, '@INPUT@', '@OUTPUT@'])

mdbus_src_ct = gnome.mdbus_codegen(
  'generated-mdbus-customtarget-src',
  mdbus_xml_ct,
  interface_prefix : 'com.example.',
  namespace : 'Sample',
  annotations : [],
)
mdbus_src_cti = gnome.mdbus_codegen(
  'generated-mdbus-customtargetindex-src',
  mdbus_xml_ct[0],
  interface_prefix : 'com.example.',
  namespace : 'Sample',
  annotations : [],
)

mdbus_src_gen = gnome.mdbus_codegen(
  'generated-mdbus-generator-src',
  copyfile_gen.process('data/com.example.Sample.xml'),
  interface_prefix : 'com.example.',
  namespace : 'Sample',
  annotations : [],
)

mdbus_exe = executable('mdbus-test', 'mdbusprog.c',
  mdbus_src,
  include_directories : includes,
  dependencies : giounix)

test('mdbus', mdbus_exe)
