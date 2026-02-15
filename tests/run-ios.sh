#!/bin/sh

arch=arm64e

remote_host=iphone
remote_prefix=/usr/local/opt/miru-tests-$arch

core_tests=$(cd $(dirname "$0") && pwd)

make -C .. build/.core-ios-stamp-miru-ios-$arch

cd "$core_tests/../../build/tmp-ios-$arch/miru-core" || exit 1

. ../../miru-env-macos-x86_64.rc
ninja || exit 1

cd tests

ssh "$remote_host" "mkdir -p '$remote_prefix'"
rsync -rLz \
  miru-tests \
  labrats \
  ../lib/agent/miru-agent.dylib \
  ../../../miru-ios-arm64e/lib/miru-gadget.dylib \
  "$core_tests/test-gadget-standalone.js" \
  "$remote_host:$remote_prefix/" || exit 1

ssh "$remote_host" "$remote_prefix/miru-tests" "$@"
