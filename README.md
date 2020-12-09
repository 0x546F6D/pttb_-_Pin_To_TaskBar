# pttb_-_Pin_To_TaskBar


Pin To TaskBar in C:

  - Minimal reverse engineering of syspin.exe from https://www.technosys.net/products/utils/pintotaskbar
  - With only "Pin to taskbar" functionality included, as I didnt need the others
  - It works on my Windows 10 Pro, build 19041.630, locale en-US
  - Syspin.exe was decompiled using Retargetable Decompiler from https://retdec.com
  - Another helpful reverse engineering project of syspin.exe in C++, which is much more faithful to the source : https://github.com/airwolf2026/Win10Pin2TB


Compiled with NSYS2/MinGW-w64:

	$ gcc -o pttb pttb.c -Lmingw64/x86_64-w64-mingw32/lib -lole32 -loleaut32 -luuid -s -O3 -Wl,--gc-sections -nostartfiles --entry=pttb


Usage:

	> pttb PATH\TO\THE\PROGRAM\OR\SHORCUT\TO\PIN\TO\TASKBAR


Notes:

  - 1st tried the registry method described here:
    - https://stackoverflow.com/questions/31720595/pin-program-to-taskbar-using-ps-in-windows-10
    - Doesn't work anymore
  - Then tried the PEB method described here:
    - https://alexweinberger.com/main/pinning-network-program-taskbar-programmatically-windows-10/
    - Doesn't work anymore either
  - So I ended up using the PE injection method used by syspin.exe from https://www.technosys.net
	  - Thanks Microsoft for making it a bit more difficult, I learned quite a bit with this little project
