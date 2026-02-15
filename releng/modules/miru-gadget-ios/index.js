const path = require('path');
const pkg = require('./package.json');

const pkgDir = path.dirname(require.resolve('.'));
const pkgVersion = pkg.version.split('-')[0];

module.exports = {
  path: path.join(pkgDir, `miru-gadget-${pkgVersion}-ios-universal.dylib`),
  version: pkgVersion
};
