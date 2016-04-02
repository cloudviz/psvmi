#include "psvmi_ctx.h"


int read_elem(struct psvmi_context *ctx, void *buf, ul_t offset,
	      ul_t buf_size);



ul_t phy_mem_offset(ul_t base)
{
	ul_t offset;

#ifdef X86_64
	if (base >= KERN1) {
		offset = base - KERN1;
	} else
#endif
	{
		offset = base - KERN;
	}

	return offset;
}


pud_t pgd_offset(struct psvmi_context * ctx, pgd_t pgd, addr_t va)
{
	pgd_t _pgd_offset;
	pud_t pud;

	_pgd_offset =
	    pgd + ((va >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1)) * PTR_SIZE;

	READ_ELEM(ctx, &pud, (_pgd_offset));

	return pud;
}


pmd_t pud_offset(struct psvmi_context * ctx, pud_t pud, addr_t va)
{
	pmd_t pmd;
	pud_t _pud_offset, pud_va;

#ifdef X86_64
	pud_va = (pud & PTE_PFN_MASK) + KERN;
	_pud_offset =
	    pud_va + ((va >> PUD_SHIFT) & (PTRS_PER_PUD - 1)) * PTR_SIZE;

	READ_ELEM(ctx, &pmd, (_pud_offset));
#else
	pmd = pud;
#endif

	return pmd;
}


pt_t pmd_offset(struct psvmi_context * ctx, pmd_t pmd, addr_t va)
{
	pt_t pt;
	pmd_t pmd_va, _pmd_offset;

#ifdef X86
	pt = pmd;
#else
	pmd_va = (pmd & PTE_PFN_MASK) + KERN;
	_pmd_offset =
	    pmd_va + ((va >> PMD_SHIFT) & (PTRS_PER_PMD - 1)) * PTR_SIZE;

	READ_ELEM(ctx, &pt, (_pmd_offset));
#endif

	return pt;
}


addr_t pt_offset(struct psvmi_context * ctx, pt_t pt, addr_t va)
{
	// Physical frame address, requested physical address
	addr_t pf, pa;
	pt_t _pt_offset, pt_va;

	/*
	 * Check if you got a page table or a 4MB/@MB page ... PSE bit 7,
	 * PRESENT bit 0 arch/x86/include/asm/pgtable_types.h
	 */
	if (((pt & 0x1) == 0x1) && ((pt & (1U << 7)) == (1U << 7))) {
		pf = pt;
		pa = (pf & HPAGE_MASK) | (va & (HPAGE_SIZE - 1));
	} else {
		pt_va = (pt & PTE_PFN_MASK) + KERN;
		//pgt_offset == pte  
		_pt_offset =
		    pt_va +
		    ((va >> PAGE_SHIFT) & (PTRS_PER_PTE - 1)) * PTR_SIZE;


		READ_ELEM(ctx, &pf, (_pt_offset));

		// Page alignment followed by offset into page
		//pa = (pf & PAGE_MASK) | (va & (PAGE_SIZE - 1));
		pa = (pf & PTE_PFN_MASK) | (va & (PAGE_SIZE - 1));
	}

	return pa;
}


addr_t get_physical_addr(struct psvmi_context * ctx, addr_t virtualAddress,
			 pgd_t pgd)
{
	addr_t va = virtualAddress;
	pud_t pud;
	pmd_t pmd;
	pt_t pt;
	addr_t pa;

	pud = pgd_offset(ctx, pgd, va);
	pmd = pud_offset(ctx, pud, va);
	pt = pmd_offset(ctx, pmd, va);
	pa = pt_offset(ctx, pt, va);

	return pa;
}
