#ifndef __MEMORY__
#define __MEMORY__
#include "../vm_manager/manager.h"
#include "../utils/util.h"
#define pgd_index(addr) addr >> (12 + 3*9) & 0x1FF
#define pud_index(addr) addr >> (12 + 2*9) & 0x1FF
#define pmd_index(addr) addr >> (12 + 1*9) & 0x1FF
#define pte_index(addr) addr >> (12 + 0*9) & 0x1FF

#define CR3 0x1000

#define PRESENT 0x1
#define RW 0x2
#define USER 0x4

#define MAX_PAGE 0xF000000
void show_page_allocator(int);
void memory_map(uint8_t *, uint64_t, uint64_t);
uint64_t allocate_page(void);
void create_stack(uint64_t, size_t);
void set_page(uint64_t);
void invalidate_page(int);
uint64_t gva_to_gpa(uint8_t *,uint64_t);
uint8_t *gva_to_hva(uint8_t *, uint64_t);
#endif