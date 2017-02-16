/* radare - LGPL - 2017 - wolfvan */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>



static RBinInfo* info(RBinFile *arch) {
	ut8 rom_header[76];
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret || !arch || !arch->buf) {
		free (ret);
		return NULL;
	}
	
	ret->file = strdup("Infineon binary")
	ret->machine = strdup ("Infineon xc800");
	ret->os = strdup ("any");
	ret->arch = strdup ("xc800");
	ret->has_va = true;
	ret->bits = 8;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static RList* sections(RBinFile *arch){
        ut8 bank;
        int i;
        RList *ret;

        if (!arch)
                return NULL;

        ret = r_list_new();
        if (!ret )
                return NULL;

        RBinSection *bbank[bank];

        if (!arch->buf) {
                free (ret);
                return NULL;
        }

        ret->free = free;

        bbank[0] = R_NEW0 (RBinSection);
        strncpy (bbank[0]->name, "bank0", R_BIN_SIZEOF_STRINGS);
        bbank[0]->paddr = 0;
        bbank[0]->size = 0xFFFF;
        bbank[0]->vsize = 0xFFFF;
        bbank[0]->vaddr = 0;
        bbank[0]->srwx = r_str_rwx ("mrx");
        bbank[0]->add = true;

        r_list_append (ret, bbank[0]);

        for (i = 1; i < 16; i++) {
                bbank[i] = R_NEW0 (RBinSection);
                sprintf (bbank[i]->name,"bank%01x",i);
                bbank[i]->paddr = i*0x10000;
                bbank[i]->vaddr = i*0x10000;                    
                bbank[i]->size = bbank[i]->vsize = 0xFFFF;
                bbank[i]->srwx = r_str_rwx ("mrx");
                bbank[i]->add = true;
                r_list_append (ret,bbank[i]);
        }
        return ret;
}

static int destroy(RBinFile *arch) {
	r_buf_free (arch->buf);
	arch->buf = NULL;
	return true;
}


static RList* symbols(RBinFile *arch) {
	RList *ret = NULL;
	RBinSymbol *ptr[13];
	int i;
	if (!(ret = r_list_new()))
		return NULL;
	ret->free = free;

	for (i = 0; i < 8; i++) {
		if (!(ptr[i] = R_NEW0 (RBinSymbol))) {
			ret->free (ret);
			return NULL;
		}
		ptr[i]->name = r_str_newf ("rst_%i", i*8);
		ptr[i]->paddr = ptr[i]->vaddr = i*8;
		ptr[i]->size = 1;
		ptr[i]->ordinal = i;
		r_list_append (ret, ptr[i]);
	}

	if (!(ptr[8] = R_NEW0 (RBinSymbol)))
		return ret;
/*Falta poner la dirección concreta de todas las interrupciones*/
	
	ptr[8]->name = strdup ("External Interrupt 0");
	ptr[8]->paddr = ptr[8]->vaddr = 3;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;
	
	ptr[8]->name = strdup ("External Interrupt 1");
	ptr[8]->paddr = ptr[8]->vaddr = 11;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;
	
	ptr[8]->name = strdup ("External Interrupt 5 (Timer 2)");
	ptr[8]->paddr = ptr[8]->vaddr = 19;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;
	
	ptr[8]->name = strdup ("External Interrupt 6");
	ptr[8]->paddr = ptr[8]->vaddr = 27;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;
	
	ptr[8]->name = strdup ("External Interrupt 7");
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;
	
	ptr[8]->name = strdup ("External Interrupt 8");
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;
	
	ptr[8]->name = strdup ("External Interrupt 9");
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;
	
	ptr[8]->name = strdup ("External Interrupt 10");
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;
	
	ptr[8]->name = strdup ("External Interrupt 11");
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;
	
		
	ptr[8]->name = strdup ("External Interrupt 12");
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;
		
	ptr[8]->name = strdup ("External Interrupt 13");
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	r_list_append (ret, ptr[8]);

	if (!(ptr[9] = R_NEW0 (RBinSymbol)))
		return ret;

	ptr[9]->name = strdup ("Timer 0");
	ptr[9]->paddr = ptr[9]->vaddr = 72;
	ptr[9]->size = 1;
	ptr[9]->ordinal = 9;
	r_list_append (ret, ptr[9]);

	if (!(ptr[10] = R_NEW0 (RBinSymbol)))
		return ret;

	ptr[10]->name = strdup ("Timer 1");
	ptr[10]->paddr = ptr[10]->vaddr = 80;
	ptr[10]->size = 1;
	ptr[10]->ordinal = 10;
	r_list_append (ret, ptr[10]);

	if (!(ptr[11] = R_NEW0 (RBinSymbol)))
		return ret;

	ptr[11]->name = strdup ("UART");
	ptr[11]->paddr = ptr[11]->vaddr = 88;
	ptr[11]->size = 1;
	ptr[11]->ordinal = 11;
	r_list_append (ret, ptr[11]);

	if (!(ptr[12] = R_NEW0 (RBinSymbol)))
		return ret;

	ptr[12]->name = strdup ("Non-maskable Interrupt");
	ptr[12]->paddr = ptr[12]->vaddr = 96;
	ptr[12]->size = 1;
	ptr[12]->ordinal = 12;
	r_list_append (ret, ptr[12]);

	return ret;
}


RList *mem (RBinFile *arch) {
	RList *ret;
	RBinMem *m, *n;
	if (!(ret = r_list_new()))
		return NULL;
	ret->free = free;
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
	m->name = strdup ("iram");
	m->addr = 0x00;
	m->size = 0x7F;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	if (!(m = R_NEW0 (RBinMem)))
		return ret;
	m->name = strdup ("xram");
	m->addr = 0x80;
	m->size = 0x7F;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);

	return ret;
}


struct r_bin_plugin_t r_bin_plugin_ningb = {
	.name = "xc800",
	.desc = "Infineon xc800 r_bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	//.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.mem = &mem,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_xc800,
	.version = R2_VERSION
};
#endif
