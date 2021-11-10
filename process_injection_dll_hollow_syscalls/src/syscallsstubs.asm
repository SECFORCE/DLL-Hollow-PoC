
.code

EXTERN SW2_GetSyscallNumber: PROC

NtProtectVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0415033ABh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtProtectVirtualMemory ENDP

NtAllocateVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03595233Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00B97293Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0003952E3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateThreadEx ENDP

NtWaitForSingleObject PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 03EA04C4Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForSingleObject ENDP

NtCreateThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0142C8815h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateThread ENDP

NtMapViewOfSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 01F071C6Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMapViewOfSection ENDP

NtCreateSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 034A314EDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateSection ENDP

end