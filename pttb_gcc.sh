#!bin/sh
clear
gcc -o pttb pttb.c -Lmingw64/x86_64-w64-mingw32/lib -lole32 -loleaut32 -luuid -s -O3 -Wl,--gc-sections -nostartfiles --entry=pttb
test -f pttb.exe || exit
wc -c pttb.exe
strip --strip-all pttb.exe
wc -c pttb.exe
