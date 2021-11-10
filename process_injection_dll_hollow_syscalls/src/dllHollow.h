#pragma once
#include "windows.h"




EXTERN_C PVOID inject(unsigned char *shellcode, SIZE_T len, DWORD pid);