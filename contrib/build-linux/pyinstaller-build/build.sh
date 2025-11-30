#!/bin/bash

set -e

export JM_VERSION="${JM_VERSION:-0.1-testbuild}"

PROJECT_ROOT=$(realpath "$(dirname "$(readlink -e "$0")")/../../..")
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

mv joinmarket-clientserver joinmarket-clientserver-${JM_VERSION}

tar -czvf joinmarket-clientserver-${JM_VERSION}.tgz \
          joinmarket-clientserver-${JM_VERSION}

ls -l

cd ..

rm joinmarket-clientserver.spec

rm -rf build

cp contrib/build-linux/pyinstaller-build/joinmarket-clientserver-qt.spec .

pyinstaller -y joinmarket-clientserver-qt.spec

ls -l dist/joinmarket-clientserver/

cd dist

mv joinmarket-clientserver joinmarket-clientserver-qt-${JM_VERSION}

tar -czvf joinmarket-clientserver-qt-${JM_VERSION}.tgz \
          joinmarket-clientserver-qt-${JM_VERSION}

ls -l

cd ..

rm joinmarket-clientserver-qt.spec

rm -rf build

cp contrib/build-linux/pyinstaller-build/joinmarket-clientserver-snicker.spec .

pyinstaller -y joinmarket-clientserver-snicker.spec

ls -l dist/joinmarket-clientserver/

cd dist

mv joinmarket-clientserver joinmarket-clientserver-snicker-${JM_VERSION}

tar -czvf joinmarket-clientserver-snicker-${JM_VERSION}.tgz \
          joinmarket-clientserver-snicker-${JM_VERSION}

ls -l

cd ..

rm joinmarket-clientserver-snicker.spec

rm -rf build

cp contrib/build-linux/pyinstaller-build/joinmarket-clientserver-obwatch.spec .

pyinstaller -y joinmarket-clientserver-obwatch.spec

ls -l dist/joinmarket-clientserver/

cd dist

mv joinmarket-clientserver joinmarket-clientserver-obwatch-${JM_VERSION}

tar -czvf joinmarket-clientserver-obwatch-${JM_VERSION}.tgz \
          joinmarket-clientserver-obwatch-${JM_VERSION}

ls -l

cd ..

rm joinmarket-clientserver-obwatch.spec

rm -rf build
