#include "memory.h"
#define NB_PAGE 0x10000
int page_allocator_dico[NB_PAGE] = {0};

void show_page_allocator(int n)
{
    for(int i = 0; i < n; i++)
        printf("page %x - %d\n", i << 12, page_allocator_dico[i]);
}
void init_page_table()
{
    uint64_t *cr3;
}

uint64_t pointer_to_page(uint64_t *pointer)
{
    return *pointer & ~(0xFFF);
}

uint64_t new_page = 0x2000;

void set_page(uint64_t addr)
{
    new_page = addr;
}

void invalidate_page(int page)
{
    page_allocator_dico[page] = 1;
}

uint64_t allocate_page()
{
    uint64_t ret = 0;
    for (int i = 2; i < NB_PAGE; i++)
    {
        if (page_allocator_dico[i] == 0)
        {
            ret = i * 0x1000;
            page_allocator_dico[i] = 1;
            break;
        }
    }
    return ret;
}

bool not_present(uint64_t entry)
{
    return !(entry & PRESENT);
}

void memory_map(uint8_t *mem, uint64_t virt_addr, uint64_t phys_addr)
{
    uint64_t *cr3, *pgd, *pud, *pmd, *pte, page;
    uint64_t *pgd_p, *pud_p, *pmd_p, *pte_p;

    cr3 = (uint64_t *)&mem[CR3];
    pgd = &cr3[pgd_index(virt_addr)];
    if (not_present(*pgd))
    {
        page = allocate_page();
        *pgd = page | PRESENT | USER | RW;
        // printf("PGD[%x] = %lx\n",pgd_index(virt_addr), *pgd);
    }
    pud = (uint64_t *)&mem[pointer_to_page(pgd)];
    pud_p = &pud[pud_index(virt_addr)];
    if (not_present(*pud_p))
    {
        page = allocate_page();
        *pud_p = page | PRESENT | USER | RW;
        // printf("PUD[%x] = %lx\n",pud_index(virt_addr), *pud_p);
    }
    pmd = (uint64_t *)&mem[pointer_to_page(pud_p)];
    pmd_p = &pmd[pmd_index(virt_addr)];

    if (not_present(*pmd_p))
    {
        page = allocate_page();
        *pmd_p = page | PRESENT | USER | RW;
        // printf("PMD[%x] = %lx\n",pmd_index(virt_addr), *pmd_p);
    }
    pte = (uint64_t *)&mem[pointer_to_page(pmd_p)];
    pte_p = &pte[pte_index(virt_addr)];
    if (not_present(*pte_p))
    {
        if (virt_addr == 0)
            phys_addr = 0;
        else if (phys_addr == 0)
            phys_addr = allocate_page();
        else
            invalidate_page(phys_addr >> 12);

        page = phys_addr;
        *pte_p = page | PRESENT | USER | RW;
    }
}

uint8_t *gva_to_hva(uint8_t *mem, uint64_t gva)
{
    uint8_t *hva = 0;
    uint64_t gpa = gva_to_gpa(mem, gva);

    if (!gpa)
        goto out;
    hva = &mem[gpa];
out:
    return hva;
}

uint64_t gva_to_gpa(uint8_t *mem, uint64_t virt_addr)
{
    uint64_t *cr3, *pgd, *pud, *pmd, *pte, page;
    uint64_t *pgd_p, *pud_p, *pmd_p, *pte_p;
    cr3 = (uint64_t *)&mem[CR3];
    pgd = &cr3[pgd_index(virt_addr)];
    if (not_present(*pgd))
    {
        printf("pgd_p not present\n");
        return 0;
    }

    pud = (uint64_t *)&mem[pointer_to_page(pgd)];
    pud_p = &pud[pud_index(virt_addr)];
    if (not_present(*pud_p))
    {
        printf("pud_p not present\n");
        return 0;
    }

    pmd = (uint64_t *)&mem[pointer_to_page(pud_p)];
    pmd_p = &pmd[pmd_index(virt_addr)];
    if (not_present(*pmd_p))
    {
        printf("pmd_p not present\n");
        return 0;
    }

    pte = (uint64_t *)&mem[pointer_to_page(pmd_p)];
    pte_p = &pte[pte_index(virt_addr)];
    if (not_present(*pte_p))
    {
        printf("pte_p not present\n");
        return 0;
    }
    // printf("GVA %lx PTE %lx\n",virt_addr, *pte_p & ~0xFFF);
    return (*pte_p & ~0xFFF) | (virt_addr & 0xFFF);
}

void create_stack(uint64_t addr, size_t size)
{
    uint8_t *guest_memory = get_memory();

    memory_map(guest_memory, addr, addr);
    for (uint64_t i = addr - 0x1000; size; i -= 0x1000)
    {
        memory_map(guest_memory, i, i); /* Mapping The User Data */
        size -= 0x1000;
    }
}