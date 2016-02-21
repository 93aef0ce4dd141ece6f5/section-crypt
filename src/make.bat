@echo off
echo [*] Building crypter...
gcc -Wall -Werror -s -o crypt main.c crypt.c
echo [*] Crypting %1.exe -> %2.exe
crypt %1.exe %2.exe
echo [*] Finished crypting
pause >NUL