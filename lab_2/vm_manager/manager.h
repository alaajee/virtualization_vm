#ifndef __MANAGER__
#define __MANAGER__
#pragma once
#include "../load_manager/loader.h"
#include "../syscall_manager/syscall_handler.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>

#include <sys/mman.h>
#include <sys/ioctl.h>
#define DEV_KVM "/dev/kvm"

#define TSS_OFSETT 0x5000

struct InterruptDescriptor64
{
	uint16_t offset_1;		 // offset bits 0..15
	uint16_t selector;		 // a code segment selector in GDT or LDT
	uint8_t ist;			 // bits 0..2 holds Interrupt Stack Table offset, rest of bits zero.
	uint8_t type_attributes; // gate type, dpl, and p fields
	uint16_t offset_2;		 // offset bits 16..31
	uint32_t offset_3;		 // offset bits 32..63
	uint32_t zero;			 // reserved
};

struct idt_ptr
{
	unsigned short limit;
	unsigned long long base;
} __attribute__((packed));

struct tss_entry_struct
{
	uint32_t prev_tss; // The previous TSS - with hardware task switching these form a kind of backward linked list.
	uint32_t esp0;	   // The stack pointer to load when changing to kernel mode.
	uint32_t ss0;	   // The stack segment to load when changing to kernel mode.
	// Everything below here is unused.
	uint32_t esp1; // esp and ss 1 and 2 would be used when switching to rings 1 or 2.
	uint32_t ss1;
	uint32_t esp2;
	uint32_t ss2;
	uint32_t cr3;
	uint32_t eip;
	uint32_t eflags;
	uint32_t eax;
	uint32_t ecx;
	uint32_t edx;
	uint32_t ebx;
	uint32_t esp;
	uint32_t ebp;
	uint32_t esi;
	uint32_t edi;
	uint32_t es;
	uint32_t cs;
	uint32_t ss;
	uint32_t ds;
	uint32_t fs;
	uint32_t gs;
	uint32_t ldt;
	uint16_t trap;
	uint16_t iomap_base;
} __attribute__((packed));
typedef struct tss_entry_struct tss_entry_t;

int create_vm(void);
int add_memory(size_t, uint64_t);
int create_bootstrap();
int launch_vm(uint64_t, uint64_t, uint64_t);
int vmexit_handler(int);
uint8_t *get_memory(void);
int setup_tss(uint32_t);
int ident_paging(uint8_t *);
void setup_idt();
#endif
