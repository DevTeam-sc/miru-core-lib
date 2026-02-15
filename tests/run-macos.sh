#!/bin/sh

arch=x86_64

miru_tests=$(dirname "$0")
cd "$miru_tests/../../build/tmp-macos-$arch/miru-core" || exit 1
. ../../miru-env-macos-x86_64.rc
ninja || exit 1
tests/miru-tests "$@"
