[bits 16]
[section .text]

global _start

; Real Mode
_start:
	; cli
	mov eax, gdtr32
	lgdt [eax]		; loading the new GDT

	mov eax, cr0
	or al, 1
	mov cr0, eax	; enabling protected mode
	jmp 0x8:main32	; far jump to update the CS register

; 32bits Protected Mode
[bits 32]
[section .text]
main32:

	; Enabling Physical Address Extension
	mov eax, cr4
  	or eax, 0x20
  	mov cr4, eax

	; Enabling long mode and the NX bit
  	mov ecx, 0xC0000080
  	rdmsr
  	or eax, (0x100 | 0x800)
  	wrmsr

  	; Set cr3 to a pointer to Page Table Root
  	mov eax, 0x1000
  	mov cr3, eax

  	; Enabling Paging Mode
  	mov eax, cr0
  	or eax, 0x80000000
  	mov cr0, eax

	lgdt [gdtr64]
	jmp 0x8:main64


; Long Mode
[bits 64]
[section .text]
main64:

	; Set the Stack Pointer
	mov rsp, r14
	mov ebp, esp

	; Enabling SSE
	mov rax, cr4
	or ax, 3 << 9		;set CR4.OSFXSR and CR4.OSXMMEXCPT at the same time
	mov cr4, rax

	; Enable "syscall" instruction EFER
	mov rcx, 0xc0000080
	rdmsr
	xor edx, edx
	or eax, 0x001
	wrmsr

	; Set the syscall handler LSTAR
	mov rcx, 0xc0000082
	rdmsr
	mov eax, syscall_handler
	wrmsr
	
	; Set the user and kernel code segments STAR
	mov rcx, 0xc0000081
	rdmsr
	xor eax, eax
	mov edx, 0x00180008
	wrmsr
	mov rcx, r15 		; to be loaded into RIP
	mov r11, 0x202 		; to be loaded into EFLAGS
	vmcall
	o64 sysret 			; Use "o64 sysret" if you assemble with NASM to keep Long Mode

align 8
syscall_handler:		; Syscall handler
	hlt					; Triggers a VMexit in Virtualized Mode
	o64 sysret			; Return To Initial Flow


[section .data]
align 16
gdt32:
  	dq 0x0000000000000000	; NULL entry
  	dq 0x00cf9a000000ffff	; Kernel Code segment entry
  	dq 0x00cf92000000ffff	; Kernel Data segment entry
align 8
gdtr32:
	dw 23		; size of the GDT
	dd gdt32	; @ of the GDT


align 16
gdt64:
  	dq 0x0000000000000000	; NULL entry
  	dq 0x00af9a000000ffff	; Kernel Code segment entry
	dq 0x00af92000000ffff	; Kernel Data segment entry
	dq 0x00affa000000ffff	; User Code segment entry
	dq 0x00aff2000000ffff	; User Data segment entry

align 8
gdtr64:
	dw 0xff		; size of the GDT
	dd gdt64	; @ of the GDT
