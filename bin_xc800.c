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
	r_buf_read_at (arch->buf, 0x104, rom_header, 76);
	ret->file = calloc (1, 17);
	strncpy (ret->file, (const char*)&rom_header[48], 16);
	ret->type = malloc (128);
	ret->type[0] = 0;
	//gb_get_gbtype (ret->type, rom_header[66], rom_header[63]);
	//gb_add_cardtype (ret->type, rom_header[67]); // XXX
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
	m->size = 0x6F;
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
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.mem = &mem,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ningb,
	.version = R2_VERSION
};
#endif
