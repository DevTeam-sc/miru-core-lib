#!/bin/sh

arch=x86_64

miru_tests=$(dirname "$0")
cd "$miru_tests/../../build/tmp_thin-linux-$arch/miru-core" || exit 1
. ../../miru_thin-env-linux-x86_64.rc
ninja || exit 1
tests/miru-tests "$@"
