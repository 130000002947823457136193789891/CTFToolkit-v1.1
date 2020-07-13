#!/bin/sh
(set -o igncr) 2>/dev/null && set -o igncr; # comment is needed
# Exec wrapper for /cygdrive/c/buildbot/wireshark/wireshark-2.0-32/windows-8.1-x86/build/test/test.sh
WS_BIN_PATH=/cygdrive/c/buildbot/wireshark/wireshark-2.0-32/windows-8.1-x86/build/cmbuild/run/RelWithDebInfo
export WS_BIN_PATH
WS_QT_BIN_PATH=/cygdrive/c/buildbot/wireshark/wireshark-2.0-32/windows-8.1-x86/build/cmbuild/run/RelWithDebInfo
export WS_QT_BIN_PATH
cd /cygdrive/c/buildbot/wireshark/wireshark-2.0-32/windows-8.1-x86/build/test
exec /cygdrive/c/buildbot/wireshark/wireshark-2.0-32/windows-8.1-x86/build/test/test.sh "$@"
