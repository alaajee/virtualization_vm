#include "../../vm_manager/manager.h"
#include "../../load_manager/loader.h"
#include "../../utils/util.h"

#define VM_MEMORY_SIZE  0xF000
#define STACK_ADDRESS   0xE000
#define STACK_SIZE      0x3000


int main(int argc, char *argv)
{
    /* Creates Of The Virtual Machine: RAM and vCPU */
    create_vm();
    create_bootstrap();
    create_guest_physical_memory(VM_MEMORY_SIZE);

    /***
     * Binary Code of the Virtual Machine
     *  Display Of The Sum Of Registers RAX And RBX 
     * */
    const uint8_t code[] = {
        0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
        0x00, 0xd8,       /* add %bl, %al */
        0x04, '0',        /* add $'0', %al */
        0xee,             /* out %al, (%dx) */
        0xb0, '\n',       /* mov $'\n', %al */
        0xee,             /* out %al, (%dx) */
        0xf4,             /* hlt */
    };

    /* Loads The Binary Code In The Guest Physical Memory */
    load_vm_code(code);

    /* Runs The VM */
    launch_vm();
    
    return 0;
}
