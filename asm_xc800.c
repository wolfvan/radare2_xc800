/* radare2 - LGPL - Copyright 2017 - wolfvan */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include <8051_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char *tmp = NULL;

	xc800_op o = xc800_decode (buf, len);
	memset(op->buf_asm, 0, sizeof (op->buf_asm));
	if (!o.name) return 0; // invalid instruction
	tmp = xc800_disasm (o, a->pc, op->buf_asm, sizeof (op->buf_asm));
	if (tmp) {
		if (strlen(tmp) < sizeof (op->buf_asm)) {
			strncpy (op->buf_asm, tmp, strlen (tmp));
		} else {
			eprintf ("Too big opcode!\n");
			free (tmp);
			op->size = -1;
			return -1;
		}
		free (tmp);
	}
	if (!*op->buf_asm) {
		op->size = 1;
		return -1;
	}
	return (op->size = o.length);
}

RAsmPlugin r_asm_plugin_xc800 = {
	.name = "xc800",
	.arch = "xc800",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "Infineon xc800",
	.disassemble = &disassemble,
	.assemble = NULL,
	.license = "PD"
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_xc800,
	.version = R2_VERSION
};
#endif

#include <r_types.h>


#undef _
#define _ (xc800_op)
#define _ARG(x) ARG, 0, x, buf
#define _ADDR11(x) ADDR11, ((x[1])+((x[0]>>5)<<8)), NULL, buf
#define _ADDR16(x) ADDR16, ((x[1])<<8)+((x[2])), NULL, buf
#define _OFFSET(x) OFFSET, ((x[1])), NULL, buf
#define _DIRECT(x) DIRECT, (x[1]), NULL, x

static const char *arg[] = {
	"#immed", "#imm", "@r0", "@r1",
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"
};

static const char *ops[] = {
	"inc",         
	"dec",         
	"add a,",      
	"addc a,",     
	"orl a,",      
	"anl a,",      
	"xrl a,",      
	"+, $1;mov",   
	"mov direct,", 
	"subb a,",     
	"+, $1;mov",
	"+, $1, $2;cjne",
	"xch a,",       
	"+, $1;djnz", 
	"mov a,",       
	"+, a;mov"      
};

xc800_op xc800_decode(const ut8 *buf, int len) {
	ut8 op = buf[0];
	if (!op) {
		return _{ "nop", 1, NONE, 0 };
	}
	if ((op & 0xf) == 1) {
		return _{((op>>4)%2)? "acall": "ajmp", 2, _ADDR11(buf)};
	}
	switch (op) {
	case 0x10: return _{ "jbc bit,", 3, _ADDR16(buf) };
	case 0x20: return _{ "jb bit,", 3, _ADDR16(buf) };
	case 0x30: return _{ "jnb bit,", 3, _ADDR16(buf) };
	case 0x40: return _{ "jc", 2, _OFFSET(buf) };
	case 0x50: return _{ "jnc", 2, _OFFSET(buf) };
	case 0x60: return _{ "jz", 2, _OFFSET(buf) };
	case 0x70: return _{ "jnz", 2, _OFFSET(buf) };
	case 0x80: return _{ "sjmp", 2, _OFFSET (buf) };

	case 0x90: return _{ "mov dptr,", 3, _ADDR16(buf) }; // XXX
	case 0xa0: return _{ "orl c, /bin", 2, NONE };
	case 0xb0: return _{ "anl c, /bin", 2, NONE };

	case 0xc0: return _{ "push", 2, _DIRECT (buf)};
	case 0xd0: return _{ "pop", 2, _DIRECT (buf)};

	case 0x02: return _{ "ljmp", 3, _ADDR16(buf) };
	case 0x12: return _{ "lcall", 3, _ADDR16(buf) };
	case 0x22: return _{ "ret", 1, NONE };
	case 0x32: return _{ "reti", 1, NONE };
	case 0x42: return _{ "orl direct, a", 2, _DIRECT (buf)};
	case 0x92: return _{ "+, c;mov", 2, _DIRECT (buf) };
	case 0xc2: return _{ "clr bit", 2, _DIRECT (buf) };
	case 0xd2: return _{ "setb", 2, _DIRECT (buf) };
	case 0xa2: return _{ "mov c,", 2, _DIRECT (buf) };

	case 0x03: return _{ "rr a", 1, NONE };
	case 0x13: return _{ "rrc a", 1, NONE };
	case 0x23: return _{ "rl a", 1, NONE };
	case 0x33: return _{ "rlc a", 1, NONE };
	case 0x43: return _{ "orl direct, #imm", 3, NONE };
	case 0x73: return _{ "jmp @a+dptr", 1, NONE };
	case 0x83: return _{ "movc a, @a+pc", 1, NONE };
	case 0x93: return _{ "movc a, @a+dptr", 1, NONE };
	case 0xa3: return _{ "inc dptr", 1, NONE };
	case 0xb3: return _{ "cpl c", 1, NONE };
	case 0xc3: return _{ "clr c", 1, NONE };
	case 0xd3: return _{ "setb c", 1, NONE };

	case 0xe0: return _{ "movx a, @dptr", 1, NONE };
	case 0xe2: return _{ "movx a, @r0", 1, NONE };
	case 0xe3: return _{ "movx a, @r1", 1, NONE };
	case 0xf0: return _{ "movx @dptr, a", 1, NONE };
	case 0xf2: return _{ "movx @r0, a", 1, NONE };
	case 0xf3: return _{ "movx @r1, a", 1, NONE };
	case 0x74: return _{ "mov a,", 2, _DIRECT(buf) };
	}

	if ((op&0xf)>=4) {
		int opidx = (op>>4);
		int argidx = (op&0xf)-4;
		const char *opstr = ops[opidx];
		const char *argstr = arg[argidx];
		int length = ((op&0xf)<6)? 2: 1;
		switch (op) {
		case 0x04: length = 1; opstr = "inc a"; argstr=""; break;
		case 0x14: length = 1; opstr = "dec a"; break;
		case 0x75: opstr = "mov $1, #RAM_D0"; argstr=""; length = 3; break;
		case 0xa4: opstr = "mul ab"; break;
		case 0xa5: opstr = "reserved"; break;
		case 0xc4: opstr = "swap a"; break;
		case 0xd4: opstr = "da a"; break;
		case 0xd5: opstr = "djnz d, "; break;
		case 0xd6: opstr = "xchd a, r0"; break;
		case 0xd7: opstr = "xchd a, r1"; break;
		case 0xd8: length = 2; break;
		case 0xe4: opstr = "clr a"; argstr=""; length = 1; break;
		case 0xf4: opstr = "cpl a"; break;
		}

		if (op==0x06) length = 2;
		else if (op==0x84) length = 1;
		else if (op==0x85) length = 3;
		else if (op >= 0x86 && op <= 0x8f) length = 2;
		else if (op >= 0xa6 && op <= 0xaf) length = 2;
		else if (op >= 0x76 && op <= 0x7f) length = 2;
		else if (op >= 0xb4 && op <= 0xbf) length = 3;
		return _{ opstr, length, _ARG (argstr) };
	}
	return _{ "xxx", 0, 0 };
}

static char *strdup_filter(const char *str, const ut8 *buf) {
	char *o;
	int i, j, len;
	if (!str) {
		return NULL;
	}
	len = strlen (str);
	if ((len * 4) + 1 < len) {
		return NULL;
	}
	o = malloc (1 + (len * 4));
	if (!o) {
		return NULL;
	}
	for (i = j = 0; i < len; i++) {
		if (str[i] == '$' && buf) {
			int n = str[i+1];
			if (n >= '0' && n <= '9') {
				n -= '0';
				i++;
				j += sprintf (o + j, "0x%02x", buf[n]);
			} else {
				eprintf ("strdup_filter: Internal bug\n");
			}
		} else {
			o[j++] = str[i];
		}
	}
	o[j] = 0;
	return o;
}

char xc00_disasm(r_8051_op op, ut32 addr, char *str, int len) {
	char *tmp, *tmp2, *eof, *out = NULL;
	if (str && *str && len > 10) {
		out = strdup (str);
	} else {
		len = 64;
		out = malloc (len);
		*out = 0;
	}
	switch (op.operand) {
	case NONE: 
		strncpy (out, op.name, len-1); 
		break;
	case ARG:
		if (!strncmp (op.arg, "#imm", 4)) {
			snprintf (out, len, "%s 0x%x", op.name, op.buf[1]);
		} else {
			snprintf (out, len, "%s %s", op.name, op.arg);
		}
		break;
	case ADDR11:
	case ADDR16:
	case DIRECT:
		snprintf (out, len, "%s 0x%02x", op.name, op.addr);
		break;
	case OFFSET:
		snprintf (out, len, "%s 0x%02x", op.name, op.addr + addr + 2);
		break;
	}
	if (*out == '+') {
		eof = strchr (out + 1, ';');
		if (eof) {
			*eof = 0;
			tmp = strdup_filter (out+1, (const ut8*)op.buf);
			tmp2 = strdup (eof+1);
			strcpy (out, tmp2);
			strcat (out, tmp);
			free (tmp);
			free (tmp2);
		} else {
			eprintf ("do8051disasm: Internal bug\n");
		}
	} else {
		tmp = out;
		out = strdup_filter (out, (const ut8*)op.buf);
		free (tmp);
	}
	return out;
}

#if MAIN

int main() {
	char *str;
	ut8 buf[3] = { 0xb3, 0x11, 0x22 };
	r_8051_ op = r_8051_decode (buf, sizeof (buf));
	str = r_8051_disasm (op, 0, NULL, 0);
	eprintf ("%s\n", str);
	free (str);
	return 0;
}

#endif
