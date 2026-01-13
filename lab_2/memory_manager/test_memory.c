#include "memory.h"

int main(void)
{
    uint8_t *memory = (uint8_t *)mmap(NULL, 0x10000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!memory)
        err(1, "allocating guest memory code\n");
    memory_map(memory, 0xFEE00000);
    return 0;
}