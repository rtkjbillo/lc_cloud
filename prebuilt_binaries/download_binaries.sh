#! /bin/sh
CURRENT_LC_RELEASE="https://github.com/refractionPOINT/limacharlie/releases/download/1.0/lc_sensor_1.0.zip"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
curl -L $CURRENT_LC_RELEASE > $DIR/release.zip
unzip $DIR/release.zip
rm $DIR/release.zip