#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
VENVPATH=$PROJECT_ROOT/jmvenv
JM_ROOT=$PROJECT_ROOT

sudo apt-get install -y python3-dev python3-pip python3-venv git \
    build-essential automake pkg-config libtool libffi-dev libssl-dev


python3.12 -m venv $VENVPATH


. $VENVPATH/bin/activate


pip install .[gui]
pip install pyinstaller==6.14.2

# need to regenerate twisted/plugins/dropin.cache
python -c \
    'from twisted.plugin import IPlugin, getPlugins; list(getPlugins(IPlugin))'

rm -rf deps
mkdir -p deps
cd deps
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
git checkout v0.6.0
./autogen.sh
./configure --prefix $VENVPATH --enable-module-recovery \
    --enable-experimental --enable-module-ecdh --enable-benchmark=no
make
make check
make install
cd ../..


rm -rf libsodium
git clone https://github.com/jedisct1/libsodium.git
cd libsodium
git checkout 1.0.20-RELEASE
./autogen.sh
./configure --prefix $VENVPATH
make check
sudo make install
cd ..

cp contrib/build-linux/pyinstaller-build/joinmarket-clientserver.spec .

pyinstaller -y joinmarket-clientserver.spec

ls -l dist/joinmarket-clientserver/

cd dist

export JM_VERSION="${JM_VERSION}"

mv joinmarket-clientserver joinmarket-clientserver-${JM_VERSION}

tar -czvf joinmarket-clientserver-${JM_VERSION}.tgz \
          joinmarket-clientserver-${JM_VERSION}

ls -l
