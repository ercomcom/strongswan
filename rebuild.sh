#! /bin/bash

# For now, disable --enable-kernel-pfroute (required by libipsec) : it exploits the sysctl header which is not available anymore !
PLUGINS="--enable-openssl --enable-kernel-libipsec --enable-kernel-netlink --enable-socket-default --enable-nonce --enable-charon --enable-ikev2 --enable-pkcs1 --enable-pubkey --enable-pem --enable-x509"

if [ "$1" == "--full" ]; then
	./autogen.sh || exit 1
	#./configure --disable-kernel-netlink --enable-kernel-libipsec #--enable-debug CFLAGS="-O0 -g" 
	CFLAGS="-g -O0" ./configure --disable-defaults $PLUGINS || exit 1
fi

make -j12 || exit 1

pushd src/frontends/ercom/
if [ "$1" == "--full" ]; then
	cmake -DCMAKE_BUILD_TYPE=Debug . || exit 1
fi
cmake --build . || exit 1
