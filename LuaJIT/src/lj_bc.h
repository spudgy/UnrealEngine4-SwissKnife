/*
** Bytecode instruction format.
** Copyright (C) 2005-2017 Mike Pall. See Copyright Notice in luajit.h
*/

#ifndef _LJ_BC_H
#define _LJ_BC_H

#include "lj_def.h"
#include "lj_arch.h"

/* Bytecode instruction format, 32 bit wide, fields of 8 or 16 bit:
**
** +----+----+----+----+
** | B  | C  | A  | OP | Format ABC
** +----+----+----+----+
** |    D    | A  | OP | Format AD
** +--------------------
** MSB               LSB
**
** In-memory instructions are always stored in host byte order.
*/

/* Operand ranges and related constants. */
#define BCMAX_A		0xff
#define BCMAX_B		0xff
#define BCMAX_C		0xff
#define BCMAX_D		0xffff
#define BCBIAS_J	0x8000
#define NO_REG		BCMAX_A
#define NO_JMP		(~(BCPos)0)

/* Macros to get instruction fields. */
#define bc_op(i)	((BCOp)((i)&0xff))
#define bc_a(i)		((BCReg)(((i)>>8)&0xff))
#define bc_b(i)		((BCReg)((i)>>24))
#define bc_c(i)		((BCReg)(((i)>>16)&0xff))
#define bc_d(i)		((BCReg)((i)>>16))
#define bc_j(i)		((ptrdiff_t)bc_d(i)-BCBIAS_J)

/* Macros to set instruction fields. */
#define setbc_byte(p, x, ofs) \
  ((uint8_t *)(p))[LJ_ENDIAN_SELECT(ofs, 3-ofs)] = (uint8_t)(x)
#define setbc_op(p, x)	setbc_byte(p, (x), 0)
#define setbc_a(p, x)	setbc_byte(p, (x), 1)
#define setbc_b(p, x)	setbc_byte(p, (x), 3)
#define setbc_c(p, x)	setbc_byte(p, (x), 2)
#define setbc_d(p, x) \
  ((uint16_t *)(p))[LJ_ENDIAN_SELECT(1, 0)] = (uint16_t)(x)
#define setbc_j(p, x)	setbc_d(p, (BCPos)((int32_t)(x)+BCBIAS_J))

/* Macros to compose instructions. */
#define BCINS_ABC(o, a, b, c) \
  (((BCIns)(o))|((BCIns)(a)<<8)|((BCIns)(b)<<24)|((BCIns)(c)<<16))
#define BCINS_AD(o, a, d) \
  (((BCIns)(o))|((BCIns)(a)<<8)|((BCIns)(d)<<16))
#define BCINS_AJ(o, a, j)	BCINS_AD(o, a, (BCPos)((int32_t)(j)+BCBIAS_J))

/* Bytecode instruction definition. Order matters, see below.
**
** (name, filler, Amode, Bmode, Cmode or Dmode, metamethod)
**
** The opcode name suffixes specify the type for RB/RC or RD:
** V = variable slot
** S = string const
** N = number const
** P = primitive type (~itype)
** B = unsigned byte literal
** M = multiple args/results
*/
#define BCDEF(_) \
  /* Comparison ops. ORDER OPR. */ \
  _(ISLT,	var,	___,	var,	lt,	61) \
  _(ISGE,	var,	___,	var,	lt,	92) \
  _(ISLE,	var,	___,	var,	le,	27) \
  _(ISGT,	var,	___,	var,	le,	51) \
  \
  _(ISEQV,	var,	___,	var,	eq,	87) \
  _(ISNEV,	var,	___,	var,	eq,	12) \
  _(ISEQS,	var,	___,	str,	eq,	85) \
  _(ISNES,	var,	___,	str,	eq,	5) \
  _(ISEQN,	var,	___,	num,	eq,	53) \
  _(ISNEN,	var,	___,	num,	eq,	24) \
  _(ISEQP,	var,	___,	pri,	eq,	93) \
  _(ISNEP,	var,	___,	pri,	eq,	38) \
  \
  /* Unary test and copy ops. */ \
  _(ISTC,	dst,	___,	var,	___,	41) \
  _(ISFC,	dst,	___,	var,	___,	52) \
  _(IST,	___,	___,	var,	___,	46) \
  _(ISF,	___,	___,	var,	___,	96) \
  _(ISTYPE,	var,	___,	lit,	___,	63) \
  _(ISNUM,	var,	___,	lit,	___,	2) \
  \
  /* Unary ops. */ \
  _(MOV,	dst,	___,	var,	___,	81) \
  _(NOT,	dst,	___,	var,	___,	75) \
  _(UNM,	dst,	___,	var,	unm,	66) \
  _(LEN,	dst,	___,	var,	len,	49) \
  \
  /* Binary ops. ORDER OPR. VV last, POW must be next. */ \
  _(ADDVN,	dst,	var,	num,	add,	8) \
  _(SUBVN,	dst,	var,	num,	sub,	29) \
  _(MULVN,	dst,	var,	num,	mul,	59) \
  _(DIVVN,	dst,	var,	num,	div,	1) \
  _(MODVN,	dst,	var,	num,	mod,	30) \
  \
  _(ADDNV,	dst,	var,	num,	add,	77) \
  _(SUBNV,	dst,	var,	num,	sub,	83) \
  _(MULNV,	dst,	var,	num,	mul,	15) \
  _(DIVNV,	dst,	var,	num,	div,	89) \
  _(MODNV,	dst,	var,	num,	mod,	21) \
  \
  _(ADDVV,	dst,	var,	var,	add,	0) \
  _(SUBVV,	dst,	var,	var,	sub,	45) \
  _(MULVV,	dst,	var,	var,	mul,	11) \
  _(DIVVV,	dst,	var,	var,	div,	22) \
  _(MODVV,	dst,	var,	var,	mod,	62) \
  \
  _(POW,	dst,	var,	var,	pow,	18) \
  _(CAT,	dst,	rbase,	rbase,	concat,	37) \
  \
  /* Constant ops. */ \
  _(KSTR,	dst,	___,	str,	___,	64) \
  _(KCDATA,	dst,	___,	cdata,	___,	44) \
  _(KSHORT,	dst,	___,	lits,	___,	56) \
  _(KNUM,	dst,	___,	num,	___,	84) \
  _(KPRI,	dst,	___,	pri,	___,	60) \
  _(KNIL,	base,	___,	base,	___,	36) \
  \
  /* Upvalue and function ops. */ \
  _(UGET,	dst,	___,	uv,	___,	82) \
  _(USETV,	uv,	___,	var,	___,	42) \
  _(USETS,	uv,	___,	str,	___,	68) \
  _(USETN,	uv,	___,	num,	___,	39) \
  _(USETP,	uv,	___,	pri,	___,	31) \
  _(UCLO,	rbase,	___,	jump,	___,	79) \
  _(FNEW,	dst,	___,	func,	gc,	95) \
  \
  /* Table ops. */ \
  _(TNEW,	dst,	___,	lit,	gc,	23) \
  _(TDUP,	dst,	___,	tab,	gc,	35) \
  _(GGET,	dst,	___,	str,	index,	17) \
  _(GSET,	var,	___,	str,	newindex,	47) \
  _(TGETV,	dst,	var,	var,	index,	9) \
  _(TGETS,	dst,	var,	str,	index,	48) \
  _(TGETB,	dst,	var,	lit,	index,	50) \
  _(TGETR,	dst,	var,	var,	index,	91) \
  _(TSETV,	var,	var,	var,	newindex,	43) \
  _(TSETS,	var,	var,	str,	newindex,	70) \
  _(TSETB,	var,	var,	lit,	newindex,	40) \
  _(TSETM,	base,	___,	num,	newindex,	88) \
  _(TSETR,	var,	var,	var,	newindex,	32) \
  \
  /* Calls and vararg handling. T = tail call. */ \
  _(CALLM,	base,	lit,	lit,	call,	76) \
  _(CALL,	base,	lit,	lit,	call,	33) \
  _(CALLMT,	base,	___,	lit,	call,	67) \
  _(CALLT,	base,	___,	lit,	call,	54) \
  _(ITERC,	base,	lit,	lit,	call,	58) \
  _(ITERN,	base,	lit,	lit,	call,	7) \
  _(VARG,	base,	lit,	lit,	___,	19) \
  _(ISNEXT,	base,	___,	jump,	___,	16) \
  \
  /* Returns. */ \
  _(RETM,	base,	___,	lit,	___,	65) \
  _(RET,	rbase,	___,	lit,	___,	71) \
  _(RET0,	rbase,	___,	lit,	___,	57) \
  _(RET1,	rbase,	___,	lit,	___,	10) \
  \
  /* Loops and branches. I/J = interp/JIT, I/C/L = init/call/loop. */ \
  _(FORI,	base,	___,	jump,	___,	80) \
  _(JFORI,	base,	___,	jump,	___,	94) \
  \
  _(FORL,	base,	___,	jump,	___,	20) \
  _(IFORL,	base,	___,	jump,	___,	72) \
  _(JFORL,	base,	___,	lit,	___,	6) \
  \
  _(ITERL,	base,	___,	jump,	___,	34) \
  _(IITERL,	base,	___,	jump,	___,	4) \
  _(JITERL,	base,	___,	lit,	___,	86) \
  \
  _(LOOP,	rbase,	___,	jump,	___,	13) \
  _(ILOOP,	rbase,	___,	jump,	___,	74) \
  _(JLOOP,	rbase,	___,	lit,	___,	28) \
  \
  _(JMP,	rbase,	___,	jump,	___,	69) \
  \
  /* Function headers. I/J = interp/JIT, F/V/C = fixarg/vararg/C func. */ \
  _(FUNCF,	rbase,	___,	___,	___,	78) \
  _(IFUNCF,	rbase,	___,	___,	___,	25) \
  _(JFUNCF,	rbase,	___,	lit,	___,	55) \
  _(FUNCV,	rbase,	___,	___,	___,	73) \
  _(IFUNCV,	rbase,	___,	___,	___,	14) \
  _(JFUNCV,	rbase,	___,	lit,	___,	90) \
  _(FUNCC,	rbase,	___,	___,	___,	26) \
  _(FUNCCW,	rbase,	___,	___,	___,	3)

/* Bytecode opcode numbers. */
typedef enum {
#define BCENUM(name, ma, mb, mc, mt, opcode)	BC_##name,
BCDEF(BCENUM)
#undef BCENUM
  BC__MAX
} BCOp;

LJ_STATIC_ASSERT((int)BC_ISEQV+1 == (int)BC_ISNEV);
LJ_STATIC_ASSERT(((int)BC_ISEQV^1) == (int)BC_ISNEV);
LJ_STATIC_ASSERT(((int)BC_ISEQS^1) == (int)BC_ISNES);
LJ_STATIC_ASSERT(((int)BC_ISEQN^1) == (int)BC_ISNEN);
LJ_STATIC_ASSERT(((int)BC_ISEQP^1) == (int)BC_ISNEP);
LJ_STATIC_ASSERT(((int)BC_ISLT^1) == (int)BC_ISGE);
LJ_STATIC_ASSERT(((int)BC_ISLE^1) == (int)BC_ISGT);
LJ_STATIC_ASSERT(((int)BC_ISLT^3) == (int)BC_ISGT);
LJ_STATIC_ASSERT((int)BC_IST-(int)BC_ISTC == (int)BC_ISF-(int)BC_ISFC);
LJ_STATIC_ASSERT((int)BC_CALLT-(int)BC_CALL == (int)BC_CALLMT-(int)BC_CALLM);
LJ_STATIC_ASSERT((int)BC_CALLMT + 1 == (int)BC_CALLT);
LJ_STATIC_ASSERT((int)BC_RETM + 1 == (int)BC_RET);
LJ_STATIC_ASSERT((int)BC_FORL + 1 == (int)BC_IFORL);
LJ_STATIC_ASSERT((int)BC_FORL + 2 == (int)BC_JFORL);
LJ_STATIC_ASSERT((int)BC_ITERL + 1 == (int)BC_IITERL);
LJ_STATIC_ASSERT((int)BC_ITERL + 2 == (int)BC_JITERL);
LJ_STATIC_ASSERT((int)BC_LOOP + 1 == (int)BC_ILOOP);
LJ_STATIC_ASSERT((int)BC_LOOP + 2 == (int)BC_JLOOP);
LJ_STATIC_ASSERT((int)BC_FUNCF + 1 == (int)BC_IFUNCF);
LJ_STATIC_ASSERT((int)BC_FUNCF + 2 == (int)BC_JFUNCF);
LJ_STATIC_ASSERT((int)BC_FUNCV + 1 == (int)BC_IFUNCV);
LJ_STATIC_ASSERT((int)BC_FUNCV + 2 == (int)BC_JFUNCV);

/* This solves a circular dependency problem, change as needed. */
#define FF_next_N	4

/* Stack slots used by FORI/FORL, relative to operand A. */
enum {
  FORL_IDX, FORL_STOP, FORL_STEP, FORL_EXT
};

/* Bytecode operand modes. ORDER BCMode */
typedef enum {
  BCMnone, BCMdst, BCMbase, BCMvar, BCMrbase, BCMuv,  /* Mode A must be <= 7 */
  BCMlit, BCMlits, BCMpri, BCMnum, BCMstr, BCMtab, BCMfunc, BCMjump, BCMcdata,
  BCM_max
} BCMode;
#define BCM___		BCMnone

#define bcmode_a(op)	((BCMode)(lj_bc_mode[op] & 7))
#define bcmode_b(op)	((BCMode)((lj_bc_mode[op]>>3) & 15))
#define bcmode_c(op)	((BCMode)((lj_bc_mode[op]>>7) & 15))
#define bcmode_d(op)	bcmode_c(op)
#define bcmode_hasd(op)	((lj_bc_mode[op] & (15<<3)) == (BCMnone<<3))
#define bcmode_mm(op)	((MMS)(lj_bc_mode[op]>>11))

#define BCMODE(name, ma, mb, mc, mm, opcode) \
  (BCM##ma|(BCM##mb<<3)|(BCM##mc<<7)|(MM_##mm<<11)),
#define BCMODE_FF	0

static LJ_AINLINE int bc_isret(BCOp op)
{
  return (op == BC_RETM || op == BC_RET || op == BC_RET0 || op == BC_RET1);
}

LJ_DATA const uint16_t lj_bc_mode[];
LJ_DATA const uint16_t lj_bc_ofs[];

#endif
