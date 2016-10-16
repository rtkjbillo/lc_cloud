#! /bin/sh
CURRENT_LC_RELEASE="https://github.com/refractionPOINT/limacharlie/releases/download/0.10-rc2/LC_0.10_RC2.zip"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
curl -L $CURRENT_LC_RELEASE > $DIR/release.zip
unzip $DIR/release.zip
rm $DIR/release.zip