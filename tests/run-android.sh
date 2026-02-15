#!/bin/sh

remote_prefix=/data/local/tmp/miru-core-tests

set -e

core_tests=$(dirname "$0")
cd "$core_tests/../"
make
cd build/tests
adb shell "mkdir -p $remote_prefix"
adb push miru-tests labrats ../lib/agent/miru-agent.so $remote_prefix
adb shell "su -c '$remote_prefix/miru-tests $@'"
