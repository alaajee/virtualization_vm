#ifndef __LOADER__
#define __LOADER__

#include <stdio.h>
#include <stdint.h>
#include <linux/kvm.h>
#include "../vm_manager/manager.h"
int load_vm_code(const uint8_t *code);
#endif
