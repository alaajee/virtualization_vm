#ifndef __SYSCALL__
#define __SYSCALL__
#pragma once
#include "../memory_manager/memory.h"
#include "../vm_manager/manager.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include <time.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>
#include <sys/sendfile.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#include <stdint.h>
#include <linux/kvm.h>
       #include <asm/prctl.h>        /* Definition of ARCH_* constants */
       #include <sys/syscall.h>      /* Definition of SYS_* constants */
       #include <unistd.h>
#define SYS_RET	regs->rax
#define SYS_NUM	regs->rax
#define ARG1	regs->rdi
#define	ARG2 	regs->rsi
#define ARG3	regs->rdx
#define ARG4	regs->r10
#define ARG5	regs->r8 //changed 
#define ARG6  regs->r9

int syscall_handler(uint8_t *memory,int vcpufd);
#endif