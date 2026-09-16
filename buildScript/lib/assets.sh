#!/bin/bash

set -e

DIR=app/src/main/assets/sing-box
rm -rf $DIR
mkdir -p $DIR
cd $DIR

get_latest_release() {
  curl --silent "https://api.github.com/repos/$1/releases/latest" | # Get latest release from GitHub api
    grep '"tag_name":' |                                            # Get tag line
    sed -E 's/.*"([^"]+)".*/\1/'                                    # Pluck JSON value
}

####
VERSION_GEOIP=`get_latest_release "SagerNet/sing-geoip"`
echo VERSION_GEOIP=$VERSION_GEOIP
echo -n $VERSION_GEOIP > geoip.version.txt
curl -fLSsO https://github.com/SagerNet/sing-geoip/releases/download/$VERSION_GEOIP/geoip.db
xz -9 geoip.db

####
VERSION_GEOSITE=`get_latest_release "SagerNet/sing-geosite"`
echo VERSION_GEOSITE=$VERSION_GEOSITE
echo -n $VERSION_GEOSITE > geosite.version.txt
curl -fLSsO https://github.com/SagerNet/sing-geosite/releases/download/$VERSION_GEOSITE/geosite.db
xz -9 geosite.db

# A fresh database is not enough: verify the categories referenced by presets.
python3 - <<'PY'
import lzma
with lzma.open('geosite.db.xz', 'rb') as source:
    def uvarint():
        value = 0
        for shift in range(0, 70, 7):
            byte = source.read(1)
            if not byte:
                raise ValueError('Truncated geosite metadata')
            value |= (byte[0] & 127) << shift
            if byte[0] < 128:
                return value
        raise ValueError('Invalid geosite metadata')
    assert source.read(1) == b'\0', 'Unsupported geosite format'
    codes = {}
    for _ in range(uvarint()):
        code = source.read(uvarint()).decode('utf-8')
        uvarint()  # data offset
        codes[code] = uvarint()
    for required in ('category-ru', 'category-ads-all'):
        assert codes.get(required, 0) > 0, 'Missing geosite preset category: ' + required
    print('Verified nonempty RU and ads geosite categories')
PY
