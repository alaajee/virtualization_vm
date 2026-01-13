#include "../../vm_manager/manager.h"
#include "../../load_manager/loader.h"
#include "../../utils/util.h"
#include "../../memory_manager/memory.h"

#include <stdio.h>
#include <string.h>

#define VM_MEMORY_SIZE  0xF000

int main(int argc, char *argv[])
{
    
    create_vm();
    add_memory(VM_MEMORY_SIZE, 0);
    create_bootstrap();
    restore();
    return 0;
}