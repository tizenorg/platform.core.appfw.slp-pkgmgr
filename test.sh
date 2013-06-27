
#export CFLAGS=""
#export LDFLAGS=""

cd `dirname $0`

PREFIX=/usr

rm -rf cmake_tmp
mkdir -p cmake_tmp
cd cmake_tmp

CFLAGS="${CFLAGS} -g" LDFLAGS="${LDFLAGS}" cmake .. -DCMAKE_INSTALL_PREFIX=${PREFIX} -DCMAKE_BUILD_TYPE=Debug &&
make &&
mkdir -p destdir &&
make install DESTDIR=destdir

