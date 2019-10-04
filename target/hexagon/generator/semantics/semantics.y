%{
/*
 * Hexagon emulation for qemu: semantics parser.
 *
 * Copyright (c) 2017-2019 Comsecuris UG (haftungsbeschraenkt)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "semantics_struct.h"

#if __STDC_VERSION__ >= 201112L
#define C11
#endif

#define TCGV_NAME_SIZE 7
#define MAX_WRITTEN_REGS 32
#define OFFSET_STR_LEN 32

enum op_type {ADD, SUBTRACT, ADDSUB, MULTIPLY, DIVIDE,
              ASHIFTL, ASHIFTR, LSHIFTR, ROTATE, ANDB, ORB, ANDORB, XORB,
              MINI, MAXI, MODULO};
enum cmp_type {EQ_OP, NEQ_OP, OPTEQ_OP, LT_OP, LTU_OP, GT_OP, GTU_OP,
               LTE_OP, LEU_OP, GTE_OP, GEU_OP};
enum mem_type {MEM_BYTE, MEM_HALF, MEM_WORD, MEM_DOUBLE};

/* Global Variables */
int tmp_count = 0;
int qemu_tmp_count = 0;
int not_count = 0;
int zeroone_count = 0;
int predicate_count = 0;
int highlow_count = 0;
int p_reg_count = 0;
int if_count = 0;
bool no_track_regs = false;
bool is_extra_created[TMP_T - EA_T + 1] = { 0 };
bool ea_declared = false;
bool is_jump = false;
bool is_stop = false;
bool mem_unsigned = false;
enum mem_type mem_size = MEM_DOUBLE; 
char written_regs[MAX_WRITTEN_REGS] = { 0 };
int written_index = 0;

extern void yyerror(const char *s);
extern int error_count;

/* Print functions */
void str_print(const char *string) {
    printf("%s", string);
}

void uint64_print(uint64_t *num) {
    printf("%" PRIu64, *num);
}

void int_print(int *num) {
    printf("%d", *num);
}

void tmp_print(t_hex_tmp *tmp) {
    printf("tmp_");
    printf("%d", tmp->index);
}

void reg_print(t_hex_reg *reg, bool is_dotnew, bool is_optnew) {
  /* TODO: Handle optnew */
  char * reg_prefix;
  switch (reg->type) {
    case GENERAL_PURPOSE:
        reg_prefix = "GPR";
        for(int i = 0; i < written_index; i++) {
          if (reg->id == written_regs[i]) {
              is_dotnew = true;
              is_optnew = false;
          }
        }
        break;
    case CONTROL: reg_prefix = "CR"; break;
    case SYSTEM: reg_prefix = "SR"; break;
  }
  assert(reg->type != SYSTEM || !is_dotnew &&
         "System registers can't be .new!");
  char * reg_suffix = (is_dotnew) ? "_new[" : "[";
  if (reg->offset != 0)
    printf("%s%s%d +", reg_prefix, reg_suffix, reg->offset);
  else
    printf("%s%s", reg_prefix, reg_suffix);
  if (reg->is_const)
    printf("%d", reg->id);
  else
    printf("%c", reg->id);
  printf("]");
}

void imm_print(t_hex_imm *imm) {
    switch(imm->type) {
        case VARIABLE:
            printf("%c", imm->id);
            break;
        case VALUE:
            printf("%" PRIu64, imm->value);
            break;
        case QEMU_TMP:
            printf("qemu_tmp_%" PRIu64, imm->index);
            break;
        case IMM_PC:
            printf("dc->pc");
            break;
        case IMM_CONSTEXT:
            printf("dc->extender_present");
            break;
        default:
            assert(false && "Cannot print this!");
            yyerror("Cannot print this expression");
    }
}

void extra_print(t_hex_extra *extra) {
    switch (extra->type) {
        case EA_T:
            printf("EA");
            break;
        case LPCFG_T:
            printf("LPCFG");
            break;
        case LC_T:
            printf("LC[%d]", extra->index); 
            break;
        case SA_T:
            printf("SA[%d]", extra->index); 
            break;
        case WIDTH_T:
            printf("width");
            break;
        case OFFSET_T:
            printf("offset");
            break;
        case SHAMT_T:
            printf("shamt");
            break;
        case ADDR_T:
            printf("addr");
            break;
        case SUMR_T:
            printf("sumr");
            break;
        case SUMI_T:
            printf("sumi");
            break;
        case CTRL_T:
            printf("control");
            break;
        case TMPR_T:
            printf("tmpr");
            break;
        case TMPI_T:
            printf("tmpi");
            break;
        case X0_T:
            printf("x0");
            break;
        case X1_T:
            printf("x1");
            break;
        case Y0_T:
            printf("y0");
            break;
        case Y1_T:
            printf("y1");
            break;
        case PROD0_T:
            printf("prod0");
            break;
        case PROD1_T:
            printf("prod1");
            break;
        case MAX_T:
            printf("max");
            break;
        case MIN_T:
            printf("min");
            break;
        case TMP_T:
            printf("tmp");
            break;
        default:
            assert(false && "Error: malformed extra type!");
    }
}

void rvalue_out(void *pointer) {
  t_hex_value *rvalue = (t_hex_value *) pointer;
  switch (rvalue->type) {
      case REGISTER:
          reg_print(&rvalue->reg, rvalue->is_dotnew, rvalue->is_optnew);
          break;
      case TEMP:
          tmp_print(&rvalue->tmp);
          break;
      case IMMEDIATE:
          imm_print(&rvalue->imm);
          break;
      case EXTRA:
          extra_print(&rvalue->extra);
          break;
      default:
          assert(false && "Cannot print this!");
          yyerror("Cannot print this expression");
  }
}

void cmp_out(void *pointer) {
    enum cmp_type *type = (enum cmp_type *) pointer;
    switch(*type) {
        case EQ_OP:
            puts("TCG_COND_EQ");
            break;
        case NEQ_OP:
            puts("TCG_COND_NE");
            break;
        case OPTEQ_OP:
            printf("not");
            printf("%d", not_count);
            printf(" ? TCG_COND_NE : TCG_COND_EQ");
            not_count++;
            break;
        case LT_OP:
            puts("TCG_COND_LT");
            break;
        case LTU_OP:
            puts("TCG_COND_LTU");
            break;
        case GT_OP:
            puts("TCG_COND_GT");
            break;
        case GTU_OP:
            puts("TCG_COND_GTU");
            break;
        case LTE_OP:
            puts("TCG_COND_LE");
            break;
        case LEU_OP:
            puts("TCG_COND_LEU");
            break;
        case GTE_OP:
            puts("TCG_COND_GE");
            break;
        case GEU_OP:
            puts("TCG_COND_GEU");
            break;
        default:
            assert(false && "Unhandled comparison operator!");
    }
}

#ifdef C11

#define OUT_IMPL(x)                                             \
  do {                                                          \
    _Generic((x),                                               \
             char *: str_print,                                 \
             const char *: str_print,                           \
             int *: int_print,                                  \
             uint64_t *: uint64_print,                          \
             t_hex_value *: rvalue_out,                         \
             enum cmp_type *: cmp_out)((x));                    \
  } while(0);

#else

#define OUT_IMPL(x)                                                     \
  do {                                                                  \
    if (__builtin_types_compatible_p (typeof (*x), char))               \
      str_print((char *) x);                                            \
    else if (__builtin_types_compatible_p (typeof (*x), uint64_t))      \
      uint64_print((uint64_t *) x);                                     \
    else if (__builtin_types_compatible_p (typeof (*x), int))           \
      int_print((int *) x);                                             \
    else if (__builtin_types_compatible_p (typeof (*x), t_hex_value))     \
      rvalue_out((t_hex_value *) x);                                         \
    else if (__builtin_types_compatible_p (typeof (*x), enum cmp_type)) \
      cmp_out((enum cmp_type *) x);                                     \
    else                                                                \
      assert(false && "Unhandled print type!");                         \
  } while(0);

#endif

// Make a FOREACH macro
#define FE_1(WHAT, X) WHAT(X)
#define FE_2(WHAT, X, ...) WHAT(X)FE_1(WHAT, __VA_ARGS__)
#define FE_3(WHAT, X, ...) WHAT(X)FE_2(WHAT, __VA_ARGS__)
#define FE_4(WHAT, X, ...) WHAT(X)FE_3(WHAT, __VA_ARGS__)
#define FE_5(WHAT, X, ...) WHAT(X)FE_4(WHAT, __VA_ARGS__)
#define FE_6(WHAT, X, ...) WHAT(X)FE_5(WHAT, __VA_ARGS__)
#define FE_7(WHAT, X, ...) WHAT(X)FE_6(WHAT, __VA_ARGS__)
#define FE_8(WHAT, X, ...) WHAT(X)FE_7(WHAT, __VA_ARGS__)
#define FE_9(WHAT, X, ...) WHAT(X)FE_8(WHAT, __VA_ARGS__)
//... repeat as needed

#define GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, NAME, ...) NAME

#define FOR_EACH(action, ...)                   \
  do {                                          \
    GET_MACRO(__VA_ARGS__,                      \
              FE_9,                             \
              FE_8,                             \
              FE_7,                             \
              FE_6,                             \
              FE_5,                             \
              FE_4,                             \
              FE_3,                             \
              FE_2,                             \
              FE_1)(action,                     \
                    __VA_ARGS__)                \
  } while (0)

#define OUT(...) FOR_EACH(OUT_IMPL, __VA_ARGS__)

enum cmp_type cmp_swap(enum cmp_type type) {
    switch(type) {
        case EQ_OP:
            return EQ_OP;
            break;
        case NEQ_OP:
            return NEQ_OP;
            break;
        case LT_OP:
            return GT_OP;
            break;
        case LTU_OP:
            return GTU_OP;
            break;
        case GT_OP:
            return LT_OP;
            break;
        case GTU_OP:
            return LTU_OP;
            break;
        case LTE_OP:
            return GTE_OP;
            break;
        case LEU_OP:
            return GEU_OP;
            break;
        case GTE_OP:
            return LTE_OP;
            break;
        case GEU_OP:
            return LEU_OP;
            break;
        default:
            assert(false && "Unhandled comparison swap!");
    }
}

t_hex_value gen_extra(enum rvalue_extra_type type, int index, bool temp) {
    t_hex_value rvalue;
    rvalue.type = EXTRA;
    rvalue.is_unsigned = false;
    rvalue.is_dotnew = false;
    rvalue.is_optnew = false;
    rvalue.is_vectorial = false;
    rvalue.is_range = false;
    rvalue.is_symbol = false;
    rvalue.extra.type = type;
    rvalue.extra.index = index;
    rvalue.extra.temp = temp;
    rvalue.bit_width = (type == TMP_T) ? 64 : 32;
    return rvalue;
}

/* Temporary values creation */
t_hex_value gen_tmp(int bit_width) {
    t_hex_value rvalue;
    rvalue.type = TEMP;
    bit_width = (bit_width == 64) ? 64 : 32;
    rvalue.bit_width = bit_width;
    rvalue.is_unsigned = false;
    rvalue.is_dotnew = false;
    rvalue.is_optnew = false;
    rvalue.is_vectorial = false;
    rvalue.is_range = false;
    rvalue.is_symbol = false;
    rvalue.tmp.index = tmp_count;
    OUT("TCGv_i", &bit_width, " tmp_", &tmp_count, " = tcg_temp_new_i",
        &bit_width, "();\n");
    tmp_count++;
    return rvalue;
}

t_hex_value gen_local_tmp(int bit_width) {
    t_hex_value rvalue;
    rvalue.type = TEMP;
    bit_width = (bit_width == 64) ? 64 : 32;
    rvalue.bit_width = bit_width;
    rvalue.is_unsigned = false;
    rvalue.is_dotnew = false;
    rvalue.is_optnew = false;
    rvalue.is_vectorial = false;
    rvalue.is_range = false;
    rvalue.is_symbol = false;
    rvalue.tmp.index = tmp_count;
    OUT("TCGv_i", &bit_width, " tmp_", &tmp_count, " = tcg_temp_local_new_i",
        &bit_width, "();\n");
    tmp_count++;
    return rvalue;
}

t_hex_value gen_tmp_value(char * value, int bit_width) {
    t_hex_value rvalue;
    rvalue.type = TEMP;
    rvalue.bit_width = bit_width;
    rvalue.is_unsigned = false;
    rvalue.is_dotnew = false;
    rvalue.is_optnew = false;
    rvalue.is_vectorial = false;
    rvalue.is_range = false;
    rvalue.is_symbol = false;
    rvalue.tmp.index = tmp_count;
    OUT("TCGv_i", &bit_width, " tmp_", &tmp_count, " = tcg_const_i", &bit_width, "(",
        value, ");\n");
    tmp_count++;
    return rvalue;
}

t_hex_value gen_imm_value(int value, int bit_width) {
    t_hex_value rvalue;
    rvalue.type = IMMEDIATE;
    rvalue.bit_width = bit_width;
    rvalue.is_unsigned = false;
    rvalue.is_dotnew = false;
    rvalue.is_optnew = false;
    rvalue.is_vectorial = false;
    rvalue.is_range = false;
    rvalue.is_symbol = false;
    rvalue.imm.type = VALUE;
    rvalue.imm.value = value;
    return rvalue;
}

void rvalue_free(t_hex_value *rvalue) {
    if (rvalue->type == TEMP) {
        char * bit_suffix = (rvalue->bit_width == 64) ? "i64" : "i32";
        OUT("tcg_temp_free_", bit_suffix, "(", rvalue, ");\n");
    }
}

void rvalue_materialize(t_hex_value *rvalue) {
    if (rvalue->type == IMMEDIATE) {
        t_hex_value tmp = gen_tmp(rvalue->bit_width);
        char * bit_suffix = (rvalue->bit_width == 64) ? "i64" : "i32";
        OUT("tcg_gen_movi_", bit_suffix, "(", &tmp, ", ", rvalue, ");\n");
        tmp.is_symbol = rvalue->is_symbol;
        rvalue_free(rvalue);
        *rvalue = tmp;
    }
}

void rvalue_extend(t_hex_value *rvalue) {
    if (rvalue->type == IMMEDIATE)
        rvalue->bit_width = 64;
    else {
        if (rvalue->bit_width == 32) {
            t_hex_value tmp = gen_tmp(64);
            char * sign_suffix = (rvalue->is_unsigned) ? "u" : "";
            OUT("tcg_gen_ext", sign_suffix, "_i32_i64(", &tmp, ", ", rvalue, ");\n");
            rvalue_free(rvalue);
            *rvalue = tmp;
        }
    }
}

void rvalue_truncate(t_hex_value *rvalue) {
    if (rvalue->type == IMMEDIATE)
        rvalue->bit_width = 32;
    else {
        if (rvalue->bit_width == 64) {
            t_hex_value tmp = gen_tmp(32);
            OUT("tcg_gen_trunc_i64_tl(", &tmp, ", ", rvalue, ");\n");
            rvalue_free(rvalue);
            *rvalue = tmp;
        }
    }
}

t_hex_value reg_concat(t_hex_value *rvalue) {
    if (rvalue->type == REGISTER) {
        if (rvalue->bit_width == 64) {
            /* In a register pair the first register holds
               the lower 32 bits, the next one holds the upper
               32 bits */
            const char * reg_prefix;
            switch (rvalue->reg.type) {
              case GENERAL_PURPOSE: reg_prefix = "GPR["; break;
              case CONTROL: reg_prefix = "CR["; break;
              case SYSTEM: reg_prefix = "SR["; break;
            }
            t_hex_value res = gen_tmp(64);
            if (rvalue->reg.offset != 0) {
                OUT("tcg_gen_concat_i32_i64(", &res, ", ");
                OUT(reg_prefix, &(rvalue->reg.offset), " + ");
                OUT(&(rvalue->reg.id), "], ");
                OUT(reg_prefix, &(rvalue->reg.offset), " + ");
                OUT(&(rvalue->reg.id), " + 1]);\n");
            } else {
                OUT("tcg_gen_concat_i32_i64(", &res, ", ", rvalue, ", ");
                OUT(reg_prefix, &(rvalue->reg.id), " + 1]);\n");
            }
            res.vec = rvalue->vec;
            res.is_unsigned = rvalue->is_unsigned;
            res.is_dotnew = rvalue->is_dotnew;
            res.is_optnew = rvalue->is_optnew;
            res.is_vectorial = rvalue->is_vectorial;
            return res;
        }
    }
    return *rvalue;
}

void ea_free() {
    OUT("tcg_temp_free(EA);\n");
}

void reg_set_written(t_hex_value *reg, int offset) {
    written_regs[written_index] = reg->reg.id;
    written_index++;
    if (!no_track_regs)
        OUT("SET_USED_REG(regs, ");
    if (offset != 0) {
        char *sign = (offset > 0) ? " + " : " - ";
        int abs_offset = abs(offset);
        if (reg->reg.is_const)
          printf("(%d", reg->reg.id);
        else
          printf("(%c", reg->reg.id);
        OUT(sign, &abs_offset, ")");
    }
    else {
        if (reg->reg.is_const)
          printf("%d", reg->reg.id);
        else
          printf("%c", reg->reg.id);
    }
    OUT(");\n");
}

/* Code generation functions */
t_hex_value gen_bin_op(enum op_type type,
                     t_hex_value *op1,
                     t_hex_value *op2)
{
#define IMM_IMM 0
#define IMM_REG 1
#define REG_IMM 2
#define REG_REG 3

    int op_types = (op1->type != IMMEDIATE) << 1 | (op2->type != IMMEDIATE);

    /* Find bit width of the two operands,
       if at least one is 64 bit use a 64bit operation,
       eventually extend 32bit operands. */
    bool op_is64bit = op1->bit_width == 64 || op2->bit_width == 64;
    /* Multiplication is always 64 bits wide */
    if (type == MULTIPLY)
        op_is64bit = true;
    /* Shift greater than 32 are 64 bits wide */
    if (type == ASHIFTL && op2->type == IMMEDIATE &&
        op2->imm.type == VALUE && op2->imm.value >= 32)
        op_is64bit = true;
    char * bit_suffix = op_is64bit ? "i64" : "i32";
    int bit_width = (op_is64bit) ? 64 : 32;
    /* TODO: Handle signedness */
    if (op_is64bit) {
        switch(op_types) {
            case IMM_REG:
                rvalue_extend(op2);
                break;
            case REG_IMM:
                rvalue_extend(op1);
                break;
            case REG_REG:
                rvalue_extend(op1);
                rvalue_extend(op2);
                break;
        }
    }
    t_hex_value res;
    if (op_types != IMM_IMM) {
        /* TODO: If one of the operands is a temp reuse it and don't free it */
        res = gen_tmp(bit_width);
        res.type = TEMP;
    } else {
        res.type = IMMEDIATE;
        res.is_unsigned = false;
        res.is_dotnew = false;
        res.is_optnew = false;
        res.is_vectorial = false;
        res.is_range = false;
        res.is_symbol = false;
        res.imm.type = QEMU_TMP;
        res.imm.index = qemu_tmp_count;
    }

    switch(type) {
        case ADD:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = ", op1, " + ", op2, ";\n");
                    break;
                case IMM_REG:
                    OUT("tcg_gen_addi_", bit_suffix, "(", &res, ", ", op2, ", ", op1, ");\n");
                    break;
                case REG_IMM:
                    OUT("tcg_gen_addi_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case REG_REG:
                    OUT("tcg_gen_add_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case SUBTRACT:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = ", op1, " - ", op2, ";\n");
                    break;
                case IMM_REG:
                    OUT("tcg_gen_subfi_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case REG_IMM:
                    OUT("tcg_gen_subi_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case REG_REG:
                    OUT("tcg_gen_sub_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case ADDSUB:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = plus_minus ? (");
                    OUT(op1, " + ", op2, ") : (", op1, " - ", op2, ");\n");
                    break;
                case IMM_REG:
                    OUT("if (plus_minus)\n");
                    OUT("tcg_gen_addi_", bit_suffix, "(", &res, ", ", op2, ", ", op1, ");\n");
                    OUT("else\n");
                    OUT("tcg_gen_subi_", bit_suffix, "(", &res, ", ", op2, ", ", op1, ");\n");
                    break;
                case REG_IMM:
                    OUT("if (plus_minus)\n");
                    OUT("tcg_gen_addi_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    OUT("else\n");
                    OUT("tcg_gen_subi_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case REG_REG:
                    OUT("if (plus_minus)\n");
                    OUT("tcg_gen_add_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    OUT("else\n");
                    OUT("tcg_gen_sub_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case MULTIPLY:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int64_t ", &res, " = ", op1, " * ", op2, ";\n");
                    break;
                case IMM_REG:
                    rvalue_extend(op2);
                    OUT("tcg_gen_muli_i64(", &res, ", ", op2, ", (int64_t)", op1, ");\n");
                    break;
                case REG_IMM:
                    rvalue_extend(op1);
                    OUT("tcg_gen_muli_i64(", &res, ", ", op1, ", (int64_t)", op2, ");\n");
                    break;
                case REG_REG:
                    rvalue_extend(op1);
                    rvalue_extend(op2);
                    OUT("tcg_gen_mul_i64(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case DIVIDE:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int64_t ", &res, " = ", op1, " / ", op2, ";\n");
                    break;
                case IMM_REG:
                case REG_IMM:
                case REG_REG:
                    OUT(&res, " = gen_helper_divu(cpu_env, ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case ASHIFTL:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = ", op1, " << ", op2, ";\n");
                    break;
                case REG_IMM:
                    OUT("tcg_gen_shli_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case IMM_REG:
                    rvalue_materialize(op1);
                    /* fallthrough */
                case REG_REG:
                    OUT("tcg_gen_shl_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            if (op_types != IMM_IMM) {
                /* Handle left shift by 64 which hexagon-sim expects to clear out register */
                t_hex_value edge = gen_tmp_value("64", bit_width);
                t_hex_value zero = gen_tmp_value("0", bit_width);
                if (op_is64bit)
                    rvalue_extend(op2);
                rvalue_materialize(op1);
                rvalue_materialize(op2);
                op2->is_symbol = true;
                rvalue_materialize(&edge);
                OUT("tcg_gen_movcond_i", &bit_width);
                if (op_types == REG_REG || op_types == IMM_REG)
                    OUT("(TCG_COND_EQ, ", &res, ", ", op2, ", ", &edge);
                else
                    OUT("(TCG_COND_EQ, ", &res, ", ", op2, ", ", &edge);
                OUT(", ", &zero, ", ", &res, ");\n");
                rvalue_free(&edge);
                rvalue_free(&zero);
            }
            break;
        }
        case ASHIFTR:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = ", op1, " >> ", op2, ";\n");
                    break;
                case REG_IMM:
                    OUT("tcg_gen_sari_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case IMM_REG:
                    rvalue_materialize(op1);
                    /* fallthrough */
                case REG_REG:
                    OUT("tcg_gen_sar_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case LSHIFTR:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = ", op1, " >> ", op2, ";\n");
                    break;
                case REG_IMM:
                    OUT("tcg_gen_shri_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case IMM_REG:
                    rvalue_materialize(op1);
                    /* fallthrough */
                case REG_REG:
                    OUT("tcg_gen_shr_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case ROTATE:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = ", op1, " >> ", op2, ";\n");
                    break;
                case REG_IMM:
                    OUT("tcg_gen_rotli_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case IMM_REG:
                    rvalue_materialize(op1);
                    /* fallthrough */
                case REG_REG:
                    OUT("tcg_gen_rotl_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case ANDB:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = ", op1, " & ", op2, ";\n");
                    break;
                case IMM_REG:
                    OUT("tcg_gen_andi_", bit_suffix, "(", &res, ", ", op2, ", ", op1, ");\n");
                    break;
                case REG_IMM:
                    OUT("tcg_gen_andi_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case REG_REG:
                    OUT("tcg_gen_and_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case ORB:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = ", op1, " & ", op2, ";\n");
                    break;
                case IMM_REG:
                    OUT("tcg_gen_ori_", bit_suffix, "(", &res, ", ", op2, ", ", op1, ");\n");
                    break;
                case REG_IMM:
                    OUT("tcg_gen_ori_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case REG_REG:
                    OUT("tcg_gen_or_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case ANDORB:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = and_or ? (");
                    OUT(op1, " & ", op2, ") : (", op1, " | ", op2, ");\n");
                    break;
                case IMM_REG:
                    OUT("if (and_or)\n");
                    OUT("tcg_gen_andi_", bit_suffix, "(", &res, ", ", op2, ", ", op1, ");\n");
                    OUT("else\n");
                    OUT("tcg_gen_ori_", bit_suffix, "(", &res, ", ", op2, ", ", op1, ");\n");
                    break;
                case REG_IMM:
                    OUT("if (and_or)\n");
                    OUT("tcg_gen_andi_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    OUT("else\n");
                    OUT("tcg_gen_ori_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case REG_REG:
                    OUT("if (and_or)\n");
                    OUT("tcg_gen_and_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    OUT("else\n");
                    OUT("tcg_gen_or_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case XORB:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = ", op1, " & ", op2, ";\n");
                    break;
                case IMM_REG:
                    OUT("tcg_gen_xori_", bit_suffix, "(", &res, ", ", op2, ", ", op1, ");\n");
                    break;
                case REG_IMM:
                    OUT("tcg_gen_xori_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                case REG_REG:
                    OUT("tcg_gen_xor_", bit_suffix, "(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case MINI:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = (", op1, " <= ");
                    OUT(op2, ") ? ", op1, " : ", op2, ";\n");
                    break;
                case IMM_REG:
                    rvalue_materialize(op1);
                    OUT("tcg_gen_movcond_i", &bit_width);
                    OUT("(TCG_COND_LE, ", &res, ", ", op1, ", ", op2);
                    OUT(", ", op1, ", ", op2, ");\n");
                    break;
                case REG_IMM:
                    rvalue_materialize(op2);
                    /* Fallthrough */
                case REG_REG:
                    OUT("tcg_gen_movcond_i", &bit_width);
                    OUT("(TCG_COND_LE, ", &res, ", ", op1, ", ", op2);
                    OUT(", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case MAXI:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int", &bit_width, "_t ", &res, " = (", op1, " <= ");
                    OUT(op2, ") ? ", op2, " : ", op1, ";\n");
                    break;
                case IMM_REG:
                    rvalue_materialize(op1);
                    OUT("tcg_gen_movcond_i", &bit_width);
                    OUT("(TCG_COND_LE, ", &res, ", ", op1, ", ", op2);
                    OUT(", ", op2, ", ", op1, ");\n");
                    break;
                case REG_IMM:
                    rvalue_materialize(op2);
                    /* Fallthrough */
                case REG_REG:
                    OUT("tcg_gen_movcond_i", &bit_width);
                    OUT("(TCG_COND_LE, ", &res, ", ", op1, ", ", op2);
                    OUT(", ", op2, ", ", op1, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
        case MODULO:
        {
            switch(op_types) {
                case IMM_IMM:
                    OUT("int64_t ", &res, " = ", op1, " % ", op2, ";\n");
                    break;
                case IMM_REG:
                case REG_IMM:
                case REG_REG:
                    OUT("gen_helper_mod(", &res, ", ", op1, ", ", op2, ");\n");
                    break;
                default:
                    fprintf(stderr, "Error in evalutating immediateness!");
                    abort();
            }
            break;
        }
    }
    /* Free operands only if they are unnamed */
    if (!op1->is_symbol)
        rvalue_free(op1);
    if (!op2->is_symbol)
        rvalue_free(op2);
    if (op_types == IMM_IMM)
        qemu_tmp_count++;
    return res;

#undef IMM_IMM
#undef IMM_REG
#undef REG_IMM
#undef REG_REG
}

t_hex_value gen_bin_cmp(enum cmp_type type,
                      t_hex_value *op1,
                      t_hex_value *op2)
{
#define IMM_IMM 0
#define IMM_REG 1
#define REG_IMM 2
#define REG_REG 3

    int op_types = (op1->type != IMMEDIATE) << 1 | (op2->type != IMMEDIATE);

    /* Find bit width of the two operands,
       if at least one is 64 bit use a 64bit operation,
       eventually extend 32bit operands. */
    bool op_is64bit = op1->bit_width == 64 || op2->bit_width == 64;
    char * bit_suffix = op_is64bit ? "i64" : "i32";
    int bit_width = (op_is64bit) ? 64 : 32;
    /* TODO: Handle signedness */
    if (op_is64bit) {
        switch(op_types) {
            case IMM_REG:
                rvalue_extend(op2);
                break;
            case REG_IMM:
                rvalue_extend(op1);
                break;
            case REG_REG:
                rvalue_extend(op1);
                rvalue_extend(op2);
                break;
        }
    }

    t_hex_value res = gen_tmp(bit_width);

    switch(op_types) {
        case IMM_IMM:
        {
            OUT("tcg_gen_movi_", bit_suffix, "(", &res, ", ", op1, " == ", op2, ");\n");
            break;
        }
        case IMM_REG:
        {
            t_hex_value swp = *op2;
            *op2 = *op1;
            *op1 = swp;
            /* Swap comparison direction */
            type = cmp_swap(type);
            /* fallthrough */
        }
        case REG_IMM:
        {
            OUT("tcg_gen_setcondi_", bit_suffix, "(");
            OUT(&type, ", ", &res, ", ", op1, ", ", op2, ");\n");
            break;
        }
        case REG_REG:
        {
            OUT("tcg_gen_setcond_", bit_suffix, "(");
            OUT(&type, ", ", &res, ", ", op1, ", ", op2, ");\n");
            break;
        }
        default:
        {
            fprintf(stderr, "Error in evalutating immediateness!");
            abort();
        }
    }
    /* Free operands */
    /* TODO: Try to eliminate double free */
    rvalue_free(op1);
    rvalue_free(op2);

    return res;

#undef IMM_IMM
#undef IMM_REG
#undef REG_IMM
#undef REG_REG
}

t_hex_value gen_extract(t_hex_value *source) {
    if (!source->is_vectorial) {
        /* Handle range extraction */
        if (source->is_range) {
            int bit_width = (source->bit_width == 64) ? 64 : 32;
            int begin = source->range.begin;
            int end = source->range.end;
            int width = end - begin + 1;
            t_hex_value res = gen_tmp(bit_width);
            OUT("tcg_gen_extract_i", &bit_width, "(", &res, ", ", source);
            OUT(", ", &begin, ", ", &width, ");\n");
            *source = res;
            return res;
        } else {
            return *source;
        }
    }
    t_hex_vec access = source->vec;
    int width = access.width;
    t_hex_value res = gen_tmp(source->bit_width);
    /* Generating string containing access offset */
    char offset_string[OFFSET_STR_LEN];
    int offset_value = access.index * width;
    snprintf(offset_string, OFFSET_STR_LEN, "%d", offset_value);
    char * offset = offset_string;
    /* Parametric half-word access index */
    if (access.is_zeroone) {
        if (highlow_count == 0)
            OUT("int ");
        OUT("offset = (high_low", &highlow_count);
        OUT(") ? ", &width, " : 0;\n");
        offset = "offset";
        highlow_count++;
    } else if (access.iter_type != NO_ITER) {
        /* All iteration types */
        switch(access.iter_type) {
            case I_ITER:
                snprintf(offset, OFFSET_STR_LEN, "i * %d", width);
                break;
            case I2_ITER:
                snprintf(offset, OFFSET_STR_LEN, "i*2 * %d", width);
                break;
            case I2PLUS1_ITER:
                snprintf(offset, OFFSET_STR_LEN, "(i*2+1) * %d", width);
                break;
            case IPLUS1_ITER:
                snprintf(offset, OFFSET_STR_LEN, "(i+1) * %d", width);
                break;
            case IPLUS4_ITER:
                snprintf(offset, OFFSET_STR_LEN, "(i+4) * %d", width);
                break;
            default:
                assert(false && "Unhandled iterator enum type!\n");
        }
    }
    /* Sanity check that offset is positive */
    assert(offset[0] != '-' && "Offset is negative, fix lexer!\n");
    if (source->type == REGISTER) {
        char * increment = "";
        /* Handle write to 64 bit registers */
        if (offset_value >= 32) {
            offset_value -= 32;
            snprintf(offset_string, OFFSET_STR_LEN, "%d", offset_value);
            increment = " + 1";
        }
        if (source->is_optnew) {
            OUT("TCGv *reg = (new) ? GPR_new : GPR;\n");
            OUT("tcg_gen_extract_i32(", &res, ", reg[");
            OUT(&(source->reg.id), increment);
            OUT("], ", offset, ", ", &width, ");\n");
        } else {
            char * dotnew = (source->is_dotnew) ? "_new" : "";
            OUT("tcg_gen_extract_i32(", &res, ", GPR", dotnew);
            OUT("[", &(source->reg.id), increment);
            OUT("], ", offset, ", ", &width, ");\n");
        }
    } else {
        if (source->bit_width == 64)
            rvalue_extend(source);
        rvalue_materialize(source);
        int bit_width = (source->bit_width == 64) ? 64 : 32;
        OUT("tcg_gen_extract_i", &bit_width, "(", &res, ", ", source);
        OUT(", ", offset, ", ", &width, ");\n");
        rvalue_truncate(&res);
    }
    /* Handle vectorial+range extraction */
    if (source->is_range) {
        int bit_width = (source->bit_width == 64) ? 64 : 32;
        int begin = source->range.begin;
        int end = source->range.end;
        int width = end - begin + 1;
        OUT("tcg_gen_extract_i", &bit_width, "(", &res, ", ", &res);
        OUT(", ", &begin, ", ", &width, ");\n");
    }
    rvalue_free(source);
    /* Apply source properties */
    res.is_unsigned = source->is_unsigned;
    return res;
}

void gen_deposit(t_hex_value *dest,
                 t_hex_value *value) {
    t_hex_vec access = dest->vec;
    int width = access.width;
    /* Generating string containing access offset */
    char offset_string[OFFSET_STR_LEN] = { 0 };
    char increment_string[OFFSET_STR_LEN] = { 0 };
    char * offset = offset_string;
    char * increment = increment_string;
    int offset_value = access.index * width;
    snprintf(offset_string, OFFSET_STR_LEN, "%d", offset_value);
    /* Parametric half-word access index */
    if (access.is_zeroone) {
        if (highlow_count == 0)
            OUT("int ");
        OUT("offset = (high_low", &highlow_count);
        OUT(") ? ", &width, " : 0;\n");
        offset = "offset";
        highlow_count++;
    } else if (access.iter_type != NO_ITER) {
        /* All iteration types */
        switch(access.iter_type) {
            case I_ITER:
                offset = "i";
                break;
            case I2_ITER:
                offset = "i*2";
                break;
            case I2PLUS1_ITER:
                offset = "i*2+1";
                break;
            case IPLUS1_ITER:
                offset = "i+1";
                break;
            case IPLUS4_ITER:
                offset = "i+4";
                break;
            default:
                assert(false && "Unhandled iterator enum type!\n");
        }
    }
    if (dest->type == REGISTER) {
        /* Handle write to 64 bit registers */
        if (!access.is_zeroone && access.iter_type == NO_ITER && offset_value >= 32) {
            offset_value -= 32;
            snprintf(offset_string, OFFSET_STR_LEN, "%d", offset_value);
            increment = " + 1";
            reg_set_written(dest, 1);
        }
        /* Handle runtime 64bit register selection by i iterator */
        if (access.iter_type != NO_ITER) {
            // deposit is broken when saving to 64bit registers
            // Algorithm is: offset = <iterator> % (32 / width)
            //            increment = <iterator> / (32 / width)
            // If width is 32 it is fine, if width is 16 we have to store
            // split up the deposit
            snprintf(increment_string, OFFSET_STR_LEN, "+ %s / (32 / %d)", offset, width);
            snprintf(offset_string, OFFSET_STR_LEN, "(%s %% (32 / %d)) * %d", offset, width, width);
            offset = offset_string;
            // Emit conditional regs written
            OUT("SET_USED_REG(regs, ", &(dest->reg.id), increment, ");\n");
            rvalue_truncate(value);
            rvalue_materialize(value);
            OUT("tcg_gen_deposit_i32(GPR_new[", &(dest->reg.id), increment);
            OUT("], GPR_new[", &(dest->reg.id), increment, "], ", value);
            OUT(", ", offset, ", ", &width, ");\n");
        } else {
            rvalue_truncate(value);
            rvalue_materialize(value);
            OUT("if (GET_USED_REG(regs, ", &(dest->reg.id), increment, "))\n");
            OUT("tcg_gen_deposit_i32(GPR_new[", &(dest->reg.id), increment);
            OUT("], GPR_new[", &(dest->reg.id), increment, "], ", value);
            OUT(", ", offset, ", ", &width, ");\n");
            OUT("else\n");
            OUT("tcg_gen_deposit_i32(GPR_new[", &(dest->reg.id), increment);
            OUT("], GPR[", &(dest->reg.id), increment, "], ", value);
            OUT(", ", offset, ", ", &width, ");\n");
        }
        reg_set_written(dest, 0);
    } else {
        if (dest->extra.temp) {
            if (!is_extra_created[dest->extra.type]) {
                OUT("TCGv_i", &dest->bit_width, " ", dest,
                    " = tcg_temp_new_i", &dest->bit_width, "();\n");
            }
        }
        OUT("tcg_gen_deposit_i32(", dest, ", ", dest, ", ");
        OUT(value, ", ", offset, ", ", &width, ");\n");
    }
    rvalue_free(value);
}

void gen_assign(t_hex_value *dest, t_hex_value *value) {
    dest->is_symbol = true;
    value->is_symbol = true;

    int bit_width = dest->bit_width;
    if (dest->is_vectorial) {
        gen_deposit(dest, value);
        return;
    }
    if (dest->type == EXTRA) {
        if (dest->bit_width == 64)
            rvalue_extend(value);
        if (dest->extra.temp) {
            assert(!(dest->extra.type == EA_T && is_extra_created[EA_T]) &&
                   "EA assigned multiple times!");
            if (!is_extra_created[dest->extra.type]) {
                /* EA must be a tmp_local because it might cross a branch */
                OUT("TCGv_i", &bit_width, " ", dest,
                    " = tcg_temp_local_new_i", &bit_width, "();\n");
                is_extra_created[dest->extra.type] = true;
            }
        }
        if (value->type == IMMEDIATE)
            OUT("tcg_gen_movi_i", &bit_width, "(", dest, ", ", value, ");\n");
        else
            OUT("tcg_gen_mov_i", &bit_width, "(", dest, ", ", value, ");\n");
        rvalue_free(value); /* Free temporary value */
        return;
    }
    if (dest->bit_width == 64) {
        rvalue_extend(value);
        rvalue_materialize(value);
        assert(value->bit_width == 64 &&
               "Bit width mismatch in assignment!");
        OUT("tcg_gen_extrl_i64_i32(");
        t_hex_value reg_new = *dest;
        if (dest->reg.type != SYSTEM)
            reg_new.is_dotnew = true;
        OUT(&reg_new, ", ", value, ");\n", "tcg_gen_extrh_i64_i32(GPR_new[");
        OUT(&(dest->reg.id), " + 1], ", value, ");\n");
        reg_set_written(dest, 0);
        reg_set_written(dest, 1);
        /* TODO assert that no one is using this value as Nt */
    } else if (dest->bit_width == 32){
        if (value->type == IMMEDIATE)
            OUT("tcg_gen_movi_tl(");
        else {
            if (value->bit_width == 64)
                OUT("tcg_gen_trunc_i64_tl(");
            else
                OUT("tcg_gen_mov_tl(");
        }
        t_hex_value reg_new = *dest;
        if (dest->reg.type != SYSTEM)
            reg_new.is_dotnew = true;
        OUT(&reg_new, ", ", value, ");\n");
        if (dest->reg.type == CONTROL)
            reg_set_written(dest, 32);
        else if (dest->reg.type == GENERAL_PURPOSE)
            reg_set_written(dest, 0);
    } else
        assert(false && "Unhandled bit width!");
    rvalue_free(value);
}

t_hex_value gen_cast_op(t_hex_value *source, unsigned target_width) {
    // Bit width sanity check
    //assert((source->bit_width == 32 || source->bit_width == 64) &&
    //       (target_width == 32 || target_width == 64) &&
    //       "Unhandled cast operation!");
    if (source->bit_width == target_width)
        return *source;
    else if (source->type == IMMEDIATE) {
        source->bit_width = target_width;
        return *source;
    } else {
        t_hex_value res = gen_tmp(target_width);
        // Truncate
        if (source->bit_width > target_width)
            OUT("tcg_gen_trunc_i64_tl(", &res, ", ", source, ");\n");
        // Extend unsigned
        else if (source->is_unsigned)
            OUT("tcg_gen_extu_i32_i64(", &res, ", ", source, ");\n");
        // Extend signed
        else
            OUT("tcg_gen_ext_i32_i64(", &res, ", ", source, ");\n");
        rvalue_free(source);
        return res;
    }
}

t_hex_value gen_convround(t_hex_value *source, t_hex_value *round_bit) {
    round_bit->is_symbol = true;
    /* Round bit is given in one hot encoding */
    /* If input is 64 bit cast it to 32 (used for vavgw) */
    *source = gen_cast_op(source, 32);
    source->is_symbol = true;
    /* Add .5 if > .5 but not if is == .5 and value is even */
    assert(source->bit_width <= 32 &&
           "Convround not implemented for bit widths > 32!");
    t_hex_value zero = gen_tmp_value("0", 32);
    t_hex_value one = gen_imm_value(1, 32);
    t_hex_value two = gen_imm_value(2, 32);
    t_hex_value remainder = gen_bin_op(ANDB, source, round_bit);
    t_hex_value tmp_mask = gen_bin_op(ASHIFTL, round_bit, &two);
    t_hex_value mask = gen_bin_op(SUBTRACT, &tmp_mask, &one);
    t_hex_value masked_value = gen_bin_op(ANDB, source, &mask);
    rvalue_materialize(&masked_value);
    rvalue_materialize(round_bit);
    /* If value is even and == .5 do not round */
    t_hex_value new_remainder = gen_tmp(32);
    OUT("tcg_gen_movcond_i32(TCG_COND_EQ, ", &new_remainder);
    OUT(", ", &masked_value, ", ", round_bit, ", ");
    OUT(&zero, ", ", &remainder, ");\n");
    t_hex_value res = gen_bin_op(ADD, source, &new_remainder);
    /* Zero out trailing bits */
    mask = gen_bin_op(ASHIFTL, round_bit, &one);
    mask = gen_bin_op(SUBTRACT, &mask, &one);
    t_hex_value new_mask = gen_tmp(32);
    OUT("tcg_gen_not_i32(", &new_mask, ", ", &mask, ");\n");
    res = gen_bin_op(ANDB, &res, &new_mask);
    rvalue_free(&remainder);
    rvalue_free(&masked_value);
    rvalue_free(&mask);
    rvalue_free(&zero);
    rvalue_free(source);
    rvalue_free(round_bit);
    return res;
}

/* Circular buffer operation */
t_hex_value gen_circ_op(t_hex_value *addr,
                        t_hex_value *increment,
                        t_hex_value *slot) {
    /* Circular addressing mode with auto-increment */
    /* Extract iteration variables */
    t_hex_value I = gen_tmp(32);
    t_hex_value K = gen_tmp(32);
    t_hex_value Length = gen_tmp(32);
    t_hex_value tmp = gen_tmp(32);
    t_hex_value delta = gen_tmp(32);
    /* Assume that CS0 is populated, since it's required by the ISA reference manual */
    OUT("tcg_gen_extract_i32(", &I, ", ", slot, ", 17, 7);\n");
    OUT("tcg_gen_extract_i32(", &K, ", ", slot, ", 24, 3);\n");
    OUT("tcg_gen_extract_i32(", &Length, ", ", slot, ", 0, 16);\n");
    OUT("tcg_gen_extract_i32(", &tmp, ", ", slot, ", 28, 4);\n");
    OUT("tcg_gen_deposit_i32(", &I, ", ", &I, ", ", &tmp);
    OUT(", 7, 4);\n");
    /* The increment must become modulo Length */
    t_hex_value res = gen_bin_op(ADD, addr, increment);
    OUT("tcg_gen_sub_i32(", &delta, ", ", &res);
    OUT(", CR[12 + ", &(slot->reg.id), "]);");
    res = gen_bin_op(MODULO, &delta, &Length);
    OUT("tcg_gen_add_i32(", &res, ", CR[12 + ", &(slot->reg.id));
    OUT("], ", &res, ");");
    return res;
}

t_hex_value gen_bitcnt_op(t_hex_value *source,
                          bool negate,
                          bool reverse)
{
    char * bit_suffix = source->bit_width == 64 ? "64" : "32";
    t_hex_value res = gen_tmp(source->bit_width == 64 ? 64 : 32);
    res.type = TEMP;
    /* TODO: use native c primitive if we deal with immediates */
    rvalue_materialize(source);
    switch(negate << 1 | reverse) {
        case 0b00:
            OUT("tcg_gen_clzi_i", bit_suffix, "(", &res, ", ", source, ", ");
            OUT(bit_suffix, ");");
            break;
        case 0b01:
            OUT("tcg_gen_ctzi_i", bit_suffix, "(", &res, ", ", source, ", ");
            OUT(bit_suffix, ");");
            break;
        case 0b10:
            OUT("tcg_gen_not_i", bit_suffix, "(", &res, ", ", source, ");\n");
            OUT("tcg_gen_clzi_i", bit_suffix, "(", &res, ", ", &res, ", ");
            OUT(bit_suffix, ");");
            break;
        case 0b11:
            OUT("tcg_gen_not_i", bit_suffix, "(", &res, ", ", source, ");\n");
            OUT("tcg_gen_clzi_i", bit_suffix, "(", &res, ", ", &res, ", ");
            OUT(bit_suffix, ");");
            break;
    }
    rvalue_free(source);
    return res;
}

/* Keep compiler happy */
int yylex();

%}

%define parse.error verbose
%define parse.lac full

%union {
    t_hex_value rvalue;
    t_hex_vec vec;
    t_hex_range range;
    int index;
}


/* Tokens */
%start code

%expect 1

%token LBR RBR LPAR RPAR LSQ RSQ LARR
%token SEMI COLON PLUS MINUS PMINUS MUL POW DIV MOD ABS CROUND ROUND CIRCADD
%token AND OR ANDOR XOR NOT OPTSHIFT NSHIFT
%token ASSIGN INC DEC INCDECA ANDA ORA XORA ANDORA PLUSPLUS
%token LT GT ASL ASR LSR ROL EQ NEQ OPTEQ LTE GTE MIN MAX
%token ANDL ORL NOTL OPTNOTL
%token COMMA FOR I ICIRC IF
%token MAPPED EXT FSCR FCHK TLB IPEND DEBUG MODECTL
%token SXT ZXT NEW OPTNEW ZEROONE CONSTEXT LOCNT BREV U64
%token HASH EA PC FP GP NPC LPCFG STAREA WIDTH OFFSET SHAMT ADDR SUMR SUMI CTRL
%token TMPR TMPI X0 X1 Y0 Y1 PROD0 PROD1 TMP QMARK TRAP0 TRAP1 CAUSE EX INT NOP
%token DCKILL DCLEAN DCINVA DZEROA DFETCH ICKILL L2KILL ISYNC BRKPT SYNCHT LOCK

%token <index> SA
%token <index> LC
%token <rvalue> REG
%token <rvalue> IMM
%token <rvalue> PRE
%token <index> ELSE
%token <vec> VEC
%token <range> RANGE
%type <rvalue> rvalue
%type <rvalue> lvalue
%type <rvalue> assign_statement
%type <rvalue> pre
%type <rvalue> reg
%type <rvalue> extra
%type <index> if_stmt
%type <index> IF

/* Operator Precedences */
%right INT
%left COMMA
%left ASSIGN
%right CIRCADD
%right INC DEC INCDECA ANDA ORA XORA ANDORA
%left QMARK COLON
%left ORL
%left ANDL
%left OR
%left XOR ANDOR
%left AND
%left EQ NEQ OPTEQ
%left LT GT LTE GTE
%left ASL ASR LSR ROL
%right ABS CROUND
%left MINUS PLUS PMINUS
%left POW
%left MUL DIV MOD
%right NOT NOTL OPTNOTL
%left LSQ
%left NEW OPTNEW ZEROONE
%left VEC OPTSHIFT NSHIFT
%right EXT LOCNT BREV

/* Bison Grammar */
%%

/* Return the modified registers list */
code  : statements
      {
         YYACCEPT;
      }
;

/* A list of one or more statements */
statements  : statements statement       { /* does nothing */ }
            | statement                  { /* does nothing */ }
;

code_block : LBR statements RBR          { /* does nothing */ }
           | statement                   { /* does nothing */ }
;

/* Statements can be assignment, control or memory statements */
statement   : control_statement          { /* does nothing */ }
            | rvalue SEMI                { /* does nothing */ }
;

/* Add this to the modified registers list */
assign_statement  : lvalue ASSIGN rvalue
                  {
                    gen_assign(&$1, &$3);
                    $$ = $1;
                  }
                  | lvalue INC rvalue
                  {
                    t_hex_value reg = reg_concat(&$1);
                    t_hex_value tmp = gen_bin_op(ADD, &reg, &$3);
                    gen_assign(&$1, &tmp);
                    $$ = $1;
                  }
                  | lvalue DEC rvalue
                  {
                    t_hex_value reg = reg_concat(&$1);
                    t_hex_value tmp = gen_bin_op(SUBTRACT, &reg, &$3);
                    gen_assign(&$1, &tmp);
                    $$ = $1;
                  }
                  | lvalue INCDECA rvalue
                  {
                    t_hex_value reg = reg_concat(&$1);
                    t_hex_value tmp = gen_bin_op(ADDSUB, &reg, &$3);
                    gen_assign(&$1, &tmp);
                    $$ = $1;
                  }
                  | lvalue ANDA rvalue
                  {
                    t_hex_value reg = reg_concat(&$1);
                    t_hex_value tmp = gen_bin_op(ANDB, &reg, &$3);
                    gen_assign(&$1, &tmp);
                    $$ = $1;
                  }
                  | lvalue ORA rvalue
                  {
                    t_hex_value reg = reg_concat(&$1);
                    t_hex_value tmp = gen_bin_op(ORB, &reg, &$3);
                    gen_assign(&$1, &tmp);
                    $$ = $1;
                  }
                  | lvalue XORA rvalue
                  {
                    t_hex_value reg = reg_concat(&$1);
                    t_hex_value tmp = gen_bin_op(XORB, &reg, &$3);
                    gen_assign(&$1, &tmp);
                    $$ = $1;
                  }
                  | lvalue ANDORA rvalue
                  {
                    t_hex_value reg = reg_concat(&$1);
                    t_hex_value tmp = gen_bin_op(ANDORB, &reg, &$3);
                    gen_assign(&$1, &tmp);
                    $$ = $1;
                  }
                  | pre ASSIGN rvalue
                  {
                    assert(!$1.is_optnew && "Cannot assign to .new predicate!");
                    /* Write to predicate register */
                    OUT("int pre_index", &predicate_count, " = "); /* Get predicate index */
                    if ($1.pre.is_zeroone)
                        OUT("zero_one", &zeroone_count, ";\n");
                    else
                        OUT(&($1.pre.id), ";\n");
                    rvalue_truncate(&$3);
                    rvalue_materialize(&$3);
                    if (!no_track_regs) {
                        OUT("TCGv p_reg", &p_reg_count);
                        OUT(" = (GET_WRITTEN_ANY_PRE(dc)) ? ");
                        OUT("CR_new[CR_P] : CR[CR_P];\n");
                    }
                    /* Bitwise predicate assignment */
                    if ($1.pre.is_bit_iter) {
                         /* Extract lsb */
                         OUT("tcg_gen_andi_i32(", &$3, ", ", &$3, ", 1);\n");
                         /* Shift to reach predicate and bit offset */
                         OUT("tcg_gen_shli_i32(", &$3, ", ", &$3, ", 8 * pre_index",
                             &predicate_count, " + i);\n");
                         /* Clear previous predicate value */
                         t_hex_value mask = gen_tmp(32);
                         t_hex_value one = gen_tmp_value("1", 32);
                         OUT("tcg_gen_shli_i32(", &mask);
                         OUT(", ", &one, ", 8 * pre_index", &predicate_count, " + i);\n");
                         OUT("tcg_gen_not_i32(", &mask, ", ", &mask, ");\n");
                         OUT("tcg_gen_and_i32(CR_new[CR_P], p_reg", &p_reg_count, ", ",
                              &mask, ");\n");
                         p_reg_count++;
                         /* Store new predicate value */
                         if (no_track_regs) {
                            if ($3.type == IMMEDIATE)
                                OUT("tcg_gen_ori_i32(CR[CR_P], CR[CR_P], ", &$3, ");\n");
                            else
                                OUT("tcg_gen_or_i32(CR[CR_P], CR[CR_P], ", &$3, ");\n");
                         } else {
                            if ($3.type == IMMEDIATE)
                                OUT("tcg_gen_ori_i32(CR_new[CR_P], CR_new[CR_P], ", &$3, ");\n");
                            else
                                OUT("tcg_gen_or_i32(CR_new[CR_P], CR_new[CR_P], ", &$3, ");\n");
                         }
                    /* Range-based predicate assignment */
                    } else if ($1.is_range) {
                        /* (bool) ? 0xff : 0x00 */
                        t_hex_value tmp = gen_tmp(32);
                        t_hex_value zero = gen_tmp_value("0x0", 32);
                        t_hex_value ff = gen_tmp_value("0xff", 32);
                        OUT("tcg_gen_movcond_i32");
                        OUT("(TCG_COND_EQ, ", &tmp, ", ", &$3, ", ", &zero);
                        OUT(", ", &zero, ", ", &ff, ");\n");
                        /* Deposit into range */
                        int begin = $1.range.begin;
                        int end = $1.range.end;
                        int width = end - begin + 1;
                        OUT("tcg_gen_deposit_i32(CR_new[CR_P], p_reg");
                        OUT(&p_reg_count, ", ");
                        p_reg_count++;
                        OUT(&tmp, ", 8 * pre_index", &predicate_count, " + ");
                        OUT(&begin, ", ", &width, ");\n");
                        rvalue_free(&zero);
                        rvalue_free(&ff);
                        rvalue_free(&tmp);
                    /* Standard bytewise predicate assignment */
                    } else {
                         
                         /* Extract first 8 bits */
                         OUT("tcg_gen_andi_i32(", &$3, ", ", &$3, ", 0xff);\n");
                         /* Shift to reach predicate */
                         OUT("tcg_gen_shli_i32(", &$3, ", ", &$3, ", 8 * pre_index",
                             &predicate_count, ");\n");
                        if (!no_track_regs) {
                            /* If predicate was already assigned just perform
                               the logical AND between the two assignments */
                            OUT("if (GET_WRITTEN_PREV_PRE(dc, pre_index0)) {");
                            /* Filter out other predicate bytes */
                            OUT("tcg_gen_ori_i32(", &$3, ", ", &$3, ", ");
                            OUT("pred_whitening[pre_index", &predicate_count, "]);\n");
                            if ($3.type == IMMEDIATE)
                                OUT("tcg_gen_andi_i32(CR_new[CR_P], p_reg", &p_reg_count, ", ", &$3, ");\n");
                            else
                                OUT("tcg_gen_and_i32(CR_new[CR_P], p_reg", &p_reg_count, ", ", &$3, ");\n");
                            /* Otherwise replace the old value completely */
                            OUT("} else {\n");
                            /* Clear previous predicate value */
                            OUT("tcg_gen_andi_i32(CR_new[CR_P], p_reg", &p_reg_count, ", "
                                    "pred_whitening[pre_index", &predicate_count, "]);\n");
                            p_reg_count++;
                            /* Store new predicate value */
                            if ($3.type == IMMEDIATE)
                                OUT("tcg_gen_ori_i32(CR_new[CR_P], CR_new[CR_P], ", &$3, ");\n");
                            else
                                OUT("tcg_gen_or_i32(CR_new[CR_P], CR_new[CR_P], ", &$3, ");\n");
                                OUT("}\n");
                        /* endloop0 special handling */
                        } else {
                            /* Clear previous predicate value */
                            OUT("tcg_gen_andi_i32(CR[CR_P], CR[CR_P], "
                                "pred_whitening[pre_index", &predicate_count, "]);\n");
                            /* Store new predicate value */
                            if ($3.type == IMMEDIATE)
                                OUT("tcg_gen_ori_i32(CR[CR_P], CR[CR_P], ", &$3, ");\n");
                            else
                                OUT("tcg_gen_or_i32(CR[CR_P], CR[CR_P], ", &$3, ");\n");
                        }
                    }
                    if (!no_track_regs) {
                        OUT("SET_USED_REG(regs, CR_P + 32);\n");
                        OUT("SET_WRITTEN_PRE(dc, pre_index", &predicate_count, ");\n");
                    }
                    rvalue_free(&$3);  /* Free temporary value */
                    predicate_count++;
                    $$ = $1;
                  }
                  | IMM ASSIGN rvalue
                  {
                    assert($3.type == IMMEDIATE &&
                           "Cannot assign non-immediate to immediate!");
                    assert($1.imm.type == VARIABLE &&
                           "Cannot assign to non-variable!");
                    /* Assign to the function argument */
                    OUT(&$1, " = ", &$3, ";\n");
                    $$ = $1;
                  }
                  | PC ASSIGN rvalue
                  {
                    /* Do not assign PC if pc_written is 1 */
                    t_hex_value one = gen_tmp_value("1", 32);
                    rvalue_materialize(&$3);
                    OUT("tcg_gen_movcond_i32(");
                    OUT("TCG_COND_EQ, CR[CR_PC], PC_written, ", &one, ", CR[CR_PC]");
                    OUT(", ", &$3, ");\n");
                    /* Update PC_written */
                    if (!no_track_regs) {
                        OUT("SET_USED_REG(regs, CR_PC + 32);\n");
                    }
                    OUT("tcg_gen_addi_i32(PC_written, PC_written, 1);\n");
                    rvalue_free(&$3); /* Free temporary value */
                  }
                  | STAREA ASSIGN rvalue /* Store primitive */
                  {
                    rvalue_materialize(&$3);
                    char *size_suffix;
                    /* Select memop width according to rvalue bit width */
                    switch(mem_size) {
                        case MEM_BYTE: size_suffix = "8"; break;
                        case MEM_HALF: size_suffix = "16"; break;
                        case MEM_WORD: size_suffix = "32"; break;
                        case MEM_DOUBLE: size_suffix = "64"; break;
                        default: assert(false && "Wrong load size!");
                    }
                    if (mem_size != MEM_DOUBLE)
                        rvalue_truncate(&$3);
                    OUT("tcg_gen_qemu_st", size_suffix);
                    OUT("(", &$3, ", EA, 0);\n");
                    rvalue_free(&$3); /* Free temporary value */
                  }
                  | CAUSE ASSIGN IMM
                  {
                    /* TODO: Sync PC and flags between translator and runtime */
                  }
                  | EX ASSIGN IMM
                  {
                    /* TODO: Implement exception register */
                  }
                  | LOCK ASSIGN IMM
                  {
                    /* Do nothing since multithread lock is not implemented */
                  }
;

control_statement : frame_check          { /* does nothing */ }
                  | ckill_statement      { /* does nothing */ }
                  | tlb_write            { /* does nothing */ }
                  | clear_interrupts     { /* does nothing */ }
                  | stop_statement       { /* does nothing */ }
                  | trap_statement       { /* does nothing */ }
                  | if_statement         { /* does nothing */ }
                  | for_statement        { /* does nothing */ }
                  | ISYNC SEMI           { /* does nothing */ }
                  | BRKPT SEMI           { /* does nothing */ }
                  | SYNCHT SEMI          { /* does nothing */ }
                  | NOP SEMI             { /* does nothing */ }
                  | SEMI                 { /* does nothing */ }
;

frame_check       : FCHK LPAR rvalue RPAR SEMI  { /* does nothing */ }
;

ckill_statement  : DCKILL LPAR RPAR SEMI        { /* does nothing */ }
                 | ICKILL LPAR RPAR SEMI        { /* does nothing */ }
                 | L2KILL LPAR RPAR SEMI        { /* does nothing */ }
                 | DCLEAN LPAR rvalue RPAR SEMI { /* does nothing */ }
                 | DCINVA LPAR rvalue RPAR SEMI { /* does nothing */ }
                 | DZEROA LPAR rvalue RPAR SEMI { /* does nothing */ }
                 | DFETCH LPAR rvalue RPAR SEMI { /* does nothing */ }
;

tlb_write        : TLB LSQ rvalue RSQ ASSIGN rvalue SEMI
                 {
                    /* We are not emulating the TLB, since we are
                       only performing userspace emulation */
                 }
;

clear_interrupts : IPEND ANDA rvalue SEMI { /* does nothing */ }
;

stop_statement : IF DEBUG MODECTL ASSIGN IMM SEMI { /* does nothing */ }
;

trap_statement    : TRAP0 SEMI
                  {
                    t_hex_value tmp = gen_tmp_value("j", 32);
                    /* Put next program counter in ELR register */
                    OUT("tcg_gen_movi_i32(SR[3], dc->pc + 4);\n");
                    /* Jump to interrupt handler */
                    t_hex_value handler_pc = gen_tmp(32);
                    OUT("tcg_gen_addi_i32(", &handler_pc, ", SR[16], 0x1c);\n");
                    OUT("tcg_gen_mov_i32(CR[CR_PC], ", &handler_pc, ");\n");
                    OUT("gen_helper_handle_trap(cpu_env, ", &tmp, ");\n");
                    rvalue_free(&tmp);
                  }
                  | TRAP1 SEMI
                  {
                    t_hex_value tmp = gen_tmp_value("j", 32);
                    /* Put next program counter in ELR register */
                    OUT("tcg_gen_movi_i32(SR[3], dc->pc + 4);\n");
                    /* Jump to interrupt handler */
                    t_hex_value handler_pc = gen_tmp(32);
                    OUT("tcg_gen_addi_i32(", &handler_pc, ", SR[16], 0x20);\n");
                    OUT("tcg_gen_mov_i32(CR[CR_PC], ", &handler_pc, ");\n");
                    OUT("gen_helper_handle_trap(cpu_env, ", &tmp, ");\n");
                    rvalue_free(&tmp);
                  }
;

if_statement : if_stmt
             {
                /* Fix else label */
               OUT("gen_set_label(if_label_", &$1, ");\n");
             }
             | if_stmt ELSE
             {
               /* Generate label to jump if else is not verified */
               OUT("TCGLabel *if_label_", &if_count, " = gen_new_label();\n");
               $2 = if_count;
               if_count++;
               /* Jump out of the else statement */
               OUT("tcg_gen_br(if_label_", &$2, ");\n");
               /* Fix the else label */
               OUT("gen_set_label(if_label_", &$1, ");\n");
             }
             code_block
             {
               OUT("gen_set_label(if_label_", &$2, ");\n");
             }
;

for_statement : FOR LPAR I ASSIGN IMM SEMI I LT IMM SEMI I PLUSPLUS RPAR
              {
                OUT("for(int i = ", &$5, "; i < ", &$9, "; i++) {\n");
              }
              code_block
              {
                OUT("}\n");
              }
;

for_statement : FOR LPAR I ASSIGN IMM SEMI I LT IMM SEMI I INC IMM RPAR
              {
                OUT("for(int i = ", &$5, "; i < ", &$9, "; i += ", &$13, ") {\n");
              }
              code_block
              {
                OUT("}\n");
              }
;

if_stmt      : IF
             {
               if (!no_track_regs)
                 OUT("SET_BEGIN_COND();\n");
               /* Generate an end label, if false branch to that label */
               OUT("TCGLabel *if_label_", &if_count, " = gen_new_label();\n");
             }
             LPAR rvalue RPAR
             {
               rvalue_materialize(&$4);
               char * bit_suffix = ($4.bit_width == 64) ? "i64" : "i32";
               OUT("tcg_gen_brcondi_", bit_suffix, "(TCG_COND_EQ, ", &$4,
                   ", 0, if_label_", &if_count, ");\n");
               rvalue_free(&$4);
               $1 = if_count;
               if_count++;
             }
             code_block
             {
               if (!no_track_regs)
                 OUT("SET_END_COND();\n");
               $$ = $1;
             }
;

rvalue            : assign_statement            { /* does nothing */ }
                  | reg
                  {
                    $1 = reg_concat(&$1);
                    $$ = gen_extract(&$1);
                  }
                  | IMM
                  {
                    $$ = $1;
                  }
                  | extra
                  {
                    $$ = gen_extract(&$1);
                  }
                  | pre
                  {
                    assert(!($1.is_dotnew && $1.is_optnew) && ".new cannot be"
                           "optional and not optional at the same time!");
                    /* Extract predicate value into a temporary */
                    OUT("int pre_index", &predicate_count, " = "); /* Get predicate index */
                    if ($1.pre.is_zeroone) {
                        OUT("zero_one", &zeroone_count, ";\n");
                        zeroone_count++;
                    }
                    else
                        OUT(&($1.pre.id), ";\n");
                    $$ = gen_tmp(32);
                    if ($1.is_optnew) {
                        OUT("TCGv p_reg", &p_reg_count);
                        OUT(" = (new || GET_WRITTEN_PRE(dc, pre_index");
                        OUT(&predicate_count, ")) ? CR_new[CR_P] : CR[CR_P];\n");
                        OUT("tcg_gen_mov_i32(", &$$, ", ", "p_reg", &p_reg_count, ");\n");
                        OUT("if (new)");
                        OUT("SET_READ_PRE(dc, pre_index", &predicate_count, ");\n");
                        p_reg_count++;
                    } else {
                        char * dotnew = ($1.is_dotnew) ? "_new" : "";
                        OUT("TCGv p_reg", &p_reg_count);
                        OUT(" = (GET_WRITTEN_PRE(dc, pre_index");
                        OUT(&predicate_count, ")) ? ");
                        OUT("CR_new[CR_P] : CR", dotnew, "[CR_P];\n");
                        OUT("tcg_gen_mov_i32(", &$$, ", ", "p_reg", &p_reg_count, ");\n");
                        p_reg_count++;
                        if ($1.is_dotnew) 
                            OUT("SET_READ_PRE(dc, pre_index", &predicate_count, ");\n");
                        
                    }
                    /* Shift to select predicate */
                    OUT("tcg_gen_shri_i32(", &$$, ", ", &$$, ", 8 * pre_index",
                        &predicate_count, ");\n");
                    /* Extract first 8 bits */
                    OUT("tcg_gen_andi_i32(", &$$, ", ", &$$, ", 0xff);\n");
                    predicate_count++;
                  }
                  | PC
                  {
                    t_hex_value rvalue;
                    rvalue.type = IMMEDIATE;
                    rvalue.imm.type = IMM_PC;
                    rvalue.is_unsigned = true;
                    rvalue.is_dotnew = false;
                    rvalue.is_optnew = false;
                    rvalue.is_vectorial = false;
                    rvalue.is_range = false;
                    rvalue.is_symbol = false;
                    $$ = rvalue;
                  }
                  | NPC
                  {
                    /* Extract program counter into a temporary */
                    $$ = gen_tmp(32);
                    t_hex_value pc = gen_tmp_value("dc->npc", 32);
                    OUT("tcg_gen_mov_i32(", &$$, ", ", &pc, ");\n");
                  }
                  | CONSTEXT
                  {
                    t_hex_value rvalue;
                    rvalue.type = IMMEDIATE;
                    rvalue.imm.type = IMM_CONSTEXT;
                    rvalue.is_unsigned = true;
                    rvalue.is_dotnew = false;
                    rvalue.is_optnew = false;
                    rvalue.is_vectorial = false;
                    rvalue.is_range = false;
                    rvalue.is_symbol = false;
                    $$ = rvalue;
                  }
                  | rvalue PLUS rvalue
                  {
                    $$ = gen_bin_op(ADD, &$1, &$3);
                  }
                  | rvalue MINUS rvalue
                  {
                    $$ = gen_bin_op(SUBTRACT, &$1, &$3);
                  }
                  | rvalue PMINUS rvalue
                  {
                    $$ = gen_bin_op(ADDSUB, &$1, &$3);
                  }
                  | rvalue MUL rvalue
                  {
                    $$ = gen_bin_op(MULTIPLY, &$1, &$3);
                  }
                  | rvalue POW rvalue
                  {
                    /* We assume that this is a shorthand for a shift */
                    assert($1.type == IMMEDIATE && $1.imm.value == 2 &&
                           "Exponentiation is not a left shift!\n");
                    t_hex_value one = gen_imm_value(1, 32);
                    t_hex_value shift = gen_bin_op(SUBTRACT, &$3, &one);
                    $$ = gen_bin_op(ASHIFTL, &$1, &shift);
                    rvalue_free(&one);
                    rvalue_free(&shift);
                  }
                  | rvalue DIV rvalue
                  {
                    $$ = gen_bin_op(DIVIDE, &$1, &$3);
                  }
                  | rvalue MOD rvalue
                  {
                    $$ = gen_bin_op(MODULO, &$1, &$3);
                  }
                  | rvalue ASL rvalue
                  {
                    $$ = gen_bin_op(ASHIFTL, &$1, &$3);
                  }
                  | rvalue ASR rvalue
                  {
                    $$ = gen_bin_op(ASHIFTR, &$1, &$3);
                  }
                  | rvalue LSR rvalue
                  {
                    $$ = gen_bin_op(LSHIFTR, &$1, &$3);
                  }
                  | rvalue ROL rvalue
                  {
                    $$ = gen_bin_op(ROTATE, &$1, &$3);
                  }
                  | rvalue AND rvalue
                  {
                    $$ = gen_bin_op(ANDB, &$1, &$3);
                  }
                  | rvalue OR rvalue
                  {
                    $$ = gen_bin_op(ORB, &$1, &$3);
                  }
                  | rvalue ANDOR rvalue
                  {
                    $$ = gen_bin_op(ANDORB, &$1, &$3);
                  }
                  | rvalue XOR rvalue
                  {
                    $$ = gen_bin_op(XORB, &$1, &$3);
                  }
                  | MIN LPAR rvalue COMMA rvalue RPAR
                  {
                    $$ = gen_bin_op(MINI, &$3, &$5);
                  }
                  | MAX LPAR rvalue COMMA rvalue RPAR
                  {
                    $$ = gen_bin_op(MAXI, &$3, &$5);
                  }
                  | NOT rvalue
                  {
                    char * bit_suffix = ($2.bit_width == 64) ? "i64" : "i32";
                    int bit_width = ($2.bit_width == 64) ? 64 : 32;
                    t_hex_value res;
                    res.is_unsigned = $2.is_unsigned;
                    res.is_dotnew = false;
                    res.is_optnew = false;
                    res.is_vectorial = false;
                    res.is_range = false;
                    res.is_symbol = false;
                    if ($2.type == IMMEDIATE) {
                        res.type = IMMEDIATE;
                        res.imm.type = QEMU_TMP;
                        res.imm.index = qemu_tmp_count;
                        OUT("int", &bit_width, "_t ", &res, " = ~", &$2, ";\n");
                        qemu_tmp_count++;
                    } else {
                        res = gen_tmp(bit_width);
                        OUT("tcg_gen_not_", bit_suffix, "(", &res,
                            ", ", &$2, ");\n");
                        rvalue_free(&$2);
                    }
                    $$ = res;
                  }
                  | NOTL rvalue
                  {
                    char * bit_suffix = ($2.bit_width == 64) ? "i64" : "i32";
                    int bit_width = ($2.bit_width == 64) ? 64 : 32;
                    t_hex_value res;
                    res.is_unsigned = $2.is_unsigned;
                    res.is_dotnew = false;
                    res.is_optnew = false;
                    res.is_vectorial = false;
                    res.is_range = false;
                    res.is_symbol = false;
                    if ($2.type == IMMEDIATE) {
                        res.type = IMMEDIATE;
                        res.imm.type = QEMU_TMP;
                        res.imm.index = qemu_tmp_count;
                        OUT("int", &bit_width, "_t ", &res, " = !", &$2, ";\n");
                        qemu_tmp_count++;
                        $$ = res;
                    } else {
                        res = gen_tmp(bit_width);
                        t_hex_value zero = gen_tmp_value("0", bit_width);
                        t_hex_value one = gen_tmp_value("0xff", bit_width);
                        OUT("tcg_gen_movcond_", bit_suffix);
                        OUT("(TCG_COND_EQ, ", &$$, ", ", &$2, ", ", &zero);
                        OUT(", ", &one, ", ", &zero, ");\n");
                        rvalue_free(&$2);
                        rvalue_free(&zero);
                        rvalue_free(&one);
                        $$ = res;
                    }
                  }
                  | OPTNOTL rvalue
                  {
                    char * bit_suffix = ($2.bit_width == 64) ? "i64" : "i32";
                    OUT("if (not", &not_count, ") {\n");
                    t_hex_value zero = gen_tmp_value("0", 32);
                    t_hex_value one = gen_tmp_value("0xff", 32);
                    OUT("tcg_gen_movcond_", bit_suffix);
                    OUT("(TCG_COND_EQ, ", &$2, ", ", &$2, ", ", &zero);
                    OUT(", ", &one, ", ", &zero, ");\n");
                    rvalue_free(&zero);
                    rvalue_free(&one);
                    OUT("}\n");
                    not_count++;
                    $$ = $2;
                  }
                  | VEC rvalue
                  {
                    $2.vec = $1;
                    $$ = $2;
                  }
                  | LPAR rvalue RPAR VEC
                  {
                    $2.vec = $4;
                    $$ = $2;
                  }
                  | rvalue LSQ rvalue RSQ
                  {
                    t_hex_value one = gen_imm_value(1, $3.bit_width);
                    t_hex_value tmp = gen_bin_op(ASHIFTR, &$1, &$3);
                    $$ = gen_bin_op(ANDB, &tmp, &one);
                  }
                  | rvalue EQ rvalue
                  {
                    $$ = gen_bin_cmp(EQ_OP, &$1, &$3);
                  }
                  | rvalue NEQ rvalue
                  {
                    $$ = gen_bin_cmp(NEQ_OP, &$1, &$3);
                  }
                  | rvalue OPTEQ rvalue
                  {
                    $$ = gen_bin_cmp(OPTEQ_OP, &$1, &$3);
                  }
                  | rvalue LT rvalue
                  {
                    if ($1.is_unsigned && $3.is_unsigned)
                        $$ = gen_bin_cmp(LTU_OP, &$1, &$3);
                    else if (!$1.is_unsigned && !$3.is_unsigned)
                        $$ = gen_bin_cmp(LT_OP, &$1, &$3);
                    else {
                        if (mem_unsigned)
                            $$ = gen_bin_cmp(LTU_OP, &$1, &$3);
                        else
                            $$ = gen_bin_cmp(LT_OP, &$1, &$3);
                    }
                  }
                  | rvalue GT rvalue
                  {
                    if ($1.is_unsigned && $3.is_unsigned)
                        $$ = gen_bin_cmp(GTU_OP, &$1, &$3);
                    else if (!$1.is_unsigned && !$3.is_unsigned)
                        $$ = gen_bin_cmp(GT_OP, &$1, &$3);
                    else {
                        if (mem_unsigned)
                            $$ = gen_bin_cmp(GTU_OP, &$1, &$3);
                        else
                            $$ = gen_bin_cmp(GT_OP, &$1, &$3);
                    }
                  }
                  | rvalue LTE rvalue
                  {
                    if ($1.is_unsigned && $3.is_unsigned)
                        $$ = gen_bin_cmp(LEU_OP, &$1, &$3);
                    else if (!$1.is_unsigned && !$3.is_unsigned)
                        $$ = gen_bin_cmp(LTE_OP, &$1, &$3);
                    else {
                        if (mem_unsigned)
                            $$ = gen_bin_cmp(LEU_OP, &$1, &$3);
                        else
                            $$ = gen_bin_cmp(LTE_OP, &$1, &$3);
                    }
                  }
                  | rvalue GTE rvalue
                  {
                    if ($1.is_unsigned && $3.is_unsigned)
                        $$ = gen_bin_cmp(GEU_OP, &$1, &$3);
                    else if (!$1.is_unsigned && !$3.is_unsigned)
                        $$ = gen_bin_cmp(GTE_OP, &$1, &$3);
                    else {
                        if (mem_unsigned)
                            $$ = gen_bin_cmp(GEU_OP, &$1, &$3);
                        else
                            $$ = gen_bin_cmp(GTE_OP, &$1, &$3);
                    }
                  }
                  | rvalue QMARK rvalue COLON rvalue
                  {
                    bool is_64bit = ($3.bit_width == 64) || ($5.bit_width == 64);
                    int bit_width = (is_64bit) ? 64 : 32;
                    if (is_64bit) {
                        rvalue_extend(&$1);
                        rvalue_extend(&$3);
                        rvalue_extend(&$5);
                    } else {
                        rvalue_truncate(&$1);
                    }
                    rvalue_materialize(&$1);
                    rvalue_materialize(&$3);
                    rvalue_materialize(&$5);
                    t_hex_value res = gen_local_tmp(bit_width);
                    t_hex_value zero = gen_tmp_value("0", bit_width);
                    OUT("tcg_gen_movcond_i", &bit_width);
                    OUT("(TCG_COND_NE, ", &res, ", ", &$1, ", ", &zero);
                    OUT(", ", &$3, ", ", &$5, ");\n");
                    rvalue_free(&zero);
                    rvalue_free(&$1);
                    rvalue_free(&$3);
                    rvalue_free(&$5);
                    $$ = res;
                  }
                  | FSCR LPAR rvalue RPAR
                  {
                    t_hex_value key = gen_tmp(64);
                    t_hex_value res = gen_tmp(64);
                    rvalue_extend(&$3);
                    OUT("tcg_gen_concat_i32_i64(", &key,", CR[17], CR[17]);\n");
                    OUT("tcg_gen_xor_i64(", &res, ", ", &$3,", ", &key, ");\n");
                    $$ = res;
                  }
                  | SXT IMM LARR IMM LPAR rvalue RPAR
                  {
                    /* Handle weird destination widths */
                    if ($4.imm.value > 32)
                        $4.imm.value = 64;
                    /* 32 bit constants are already sign extended */
                    if ($4.imm.value == 32)
                        $$ = $6;
                    else if ($4.imm.value == 64) {
                        $6.is_unsigned = false;
                        rvalue_extend(&$6);
                    } else
                        assert(false && "Unhandled destination bit width!");
                    $$ = $6;
                  }
                  | ZXT rvalue LARR IMM LPAR rvalue RPAR
                  {
                    /* Handle weird destination widths */
                    if ($4.imm.value > 32)
                        $4.imm.value = 64;
                    t_hex_value tmp = $6;
                    if ($2.type != IMMEDIATE || $2.imm.value != $6.bit_width) {
                        // Cast $2 bit width to $6 bit width
                        $2 = gen_cast_op(&$2, $6.bit_width);
                        rvalue_materialize(&$2);
                        /* First zero-out unwanted bits */
                        t_hex_value reg = reg_concat(&$6);
                        t_hex_value one = gen_imm_value(1, $6.bit_width);
                        t_hex_value tmp_mask = gen_bin_op(ASHIFTL, &one, &$2);
                        one = gen_imm_value(1, $6.bit_width);
                        t_hex_value mask = gen_bin_op(SUBTRACT, &tmp_mask, &one);
                        tmp = gen_bin_op(ANDB, &reg, &mask);
                    }
                    /* 32 bit constants are already zero extended */
                    if ($4.imm.value == 32)
                        $$ = tmp;
                    else if ($4.imm.value == 64) {
                        tmp.is_unsigned = true;
                        rvalue_extend(&tmp);
                    } else
                        assert(false && "Unhandled destination bit width!");
                    $$ = tmp;
                  }
                  | EXT LPAR IMM RPAR
                  {
                    $$ = $3;
                  }
                  | INT rvalue
                  {
                    $$ = $2;
                  }
                  | STAREA /* Load primitive */
                  {
                    int bit_width = (mem_size == MEM_DOUBLE) ? 64 : 32;
                    char *sign_suffix = "", *size_suffix;
                    if (mem_size != MEM_DOUBLE)
                        sign_suffix = mem_unsigned ? "u" : "s";
                    t_hex_value tmp = gen_tmp(bit_width);
                    /* Select memop width according to rvalue bit width */
                    switch(mem_size) {
                        case MEM_BYTE: size_suffix = "8"; break;
                        case MEM_HALF: size_suffix = "16"; break;
                        case MEM_WORD: size_suffix = "32"; break;
                        case MEM_DOUBLE: size_suffix = "64"; break;
                        default: assert(false && "Wrong load size!");
                    }
                    OUT("tcg_gen_qemu_ld", size_suffix, sign_suffix);
                    /* If signed perform 32 or 64 bit sign extension */
                    OUT("(", &tmp, ", EA, 0);\n");
                    $$ = tmp;
                  }
                  | LPAR rvalue RPAR
                  {
                    $$ = $2;
                  }
                  | ABS rvalue
                  {
                    char * bit_suffix = ($2.bit_width == 64) ? "i64" : "i32";
                    int bit_width = ($2.bit_width == 64) ? 64 : 32;
                    t_hex_value res;
                    res.is_unsigned = $2.is_unsigned;
                    res.is_dotnew = false;
                    res.is_optnew = false;
                    res.is_vectorial = false;
                    res.is_range = false;
                    res.is_symbol = false;
                    if ($2.type == IMMEDIATE) {
                        res.type = IMMEDIATE;
                        res.imm.type = QEMU_TMP;
                        res.imm.index = qemu_tmp_count;
                        OUT("int", &bit_width, "_t ", &res, " = abs(", &$2, ");\n");
                        qemu_tmp_count++;
                        $$ = res;
                    } else {
                        res = gen_tmp(bit_width);
                        t_hex_value zero = gen_tmp_value("0", bit_width);
                        OUT("tcg_gen_neg_", bit_suffix, "(", &res, ", ",
                            &$2, ");\n");
                        OUT("tcg_gen_movcond_i", &bit_width);
                        OUT("(TCG_COND_GT, ", &res, ", ", &$2, ", ", &zero);
                        OUT(", ", &$2, ", ", &res, ");\n");
                        rvalue_free(&$2);
                        $$ = res;
                    }
                  }
                  | CROUND LPAR rvalue COMMA rvalue RPAR
                  {
                    $$ = gen_convround(&$3, &$5);
                  }
                  | CROUND LPAR rvalue RPAR
                  {
                    /* When is not specified assume mask = 1 */
                    t_hex_value one = gen_imm_value(1, 32);
                    $$ = gen_convround(&$3, &one);
                  }
                  | ROUND LPAR rvalue COMMA rvalue RPAR
                  {
                    /* Add .5 only if .5 bit is set */
                    assert($3.bit_width <= 32 &&
                           "Convround not implemented for bit widths > 32!");
                    t_hex_value one = gen_imm_value(1, 32);
                    t_hex_value remainder = gen_bin_op(ANDB, &$3, &$5);
                    t_hex_value res = gen_bin_op(ADD, &$3, &remainder);
                    /* Zero out trailing bits */
                    t_hex_value mask = gen_bin_op(ASHIFTL, &$5, &one);
                    mask = gen_bin_op(SUBTRACT, &mask, &one);
                    rvalue_materialize(&mask);
                    OUT("tcg_gen_not_i32(", &mask, ", ", &mask, ");\n");
                    res = gen_bin_op(ANDB, &res, &mask);
                    rvalue_free(&$3);
                    rvalue_free(&$5);
                    $$ = res;
                  }
                  | MINUS rvalue
                  {
                    char * bit_suffix = ($2.bit_width == 64) ? "i64" : "i32";
                    int bit_width = ($2.bit_width == 64) ? 64 : 32;
                    t_hex_value res;
                    res.is_unsigned = $2.is_unsigned;
                    res.is_dotnew = false;
                    res.is_optnew = false;
                    res.is_vectorial = false;
                    res.is_range = false;
                    res.is_symbol = false;
                    if ($2.type == IMMEDIATE) {
                        res.type = IMMEDIATE;
                        res.imm.type = QEMU_TMP;
                        res.imm.index = qemu_tmp_count;
                        OUT("int", &bit_width, "_t ", &res, " = -", &$2, ";\n");
                        qemu_tmp_count++;
                        $$ = res;
                    } else {
                        res = gen_tmp(bit_width);
                        OUT("tcg_gen_neg_", bit_suffix, "(", &res, ", ",
                            &$2, ");\n");
                        rvalue_free(&$2);
                        $$ = res;
                    }
                  }
                  | rvalue OPTSHIFT
                  {
                    char * bit_suffix = ($1.bit_width == 64) ? "i64" : "i32";
                    OUT("if (opt_shift) {\n");
                    OUT("tcg_gen_shli_", bit_suffix, "(", &$1, ", ", &$1, ", 1);\n");
                    OUT("}\n");
                  }
                  | rvalue NSHIFT
                  {
                    t_hex_value N = gen_tmp_value("N", 32);
                    $$ = gen_bin_op(ASHIFTL, &$1, &N);
                  }
                  | CIRCADD LPAR rvalue COMMA rvalue COMMA rvalue RPAR
                  {
                    $$ = gen_circ_op(&$3, &$5, &$7);
                  }
                  | CIRCADD LPAR rvalue COMMA ICIRC ASL IMM COMMA rvalue RPAR
                  {
                    t_hex_value I = gen_tmp(32);
                    OUT("tcg_gen_extract_i32(", &I, ", ", &$9, ", 17, 7);\n");
                    I = gen_bin_op(ASHIFTL, &I, &$7);
                    $$ = gen_circ_op(&$3, &I, &$9);
                  }
                  | LOCNT LPAR rvalue RPAR
                  {
                    /* Leading ones count */
                    $$ = gen_bitcnt_op(&$3, true, false);
                  }
                  | LOCNT LPAR BREV LPAR rvalue RPAR RPAR
                  {
                    /* Trailing ones count */
                    $$ = gen_bitcnt_op(&$5, true, true);
                  }
                  | LOCNT LPAR NOT BREV LPAR rvalue RPAR RPAR
                  {
                    /* Trailing zeroes count */
                    $$ = gen_bitcnt_op(&$6, false, true);
                  }
                  | LOCK
                  {
                    $$ = gen_tmp_value("true", 32);
                  }
;

pre               : PRE
                  {
                    $$ = $1;
                  }
                  | pre ZEROONE
                  {
                    $$ = $1;
                    $$.pre.is_zeroone = true;
                  }
                  | pre NEW
                  {
                    $$ = $1;
                    $$.is_dotnew = true;
                  }
                  | pre OPTNEW
                  {
                    $$ = $1;
                    $$.is_optnew = true;
                  }
                  | pre VEC
                  {
                    assert($2.width == 1 && "Not-bitwise access to predicate!");
                    $$ = $1;
                    $$.pre.is_bit_iter = true;
                  }
                  | pre RANGE
                  {
                    $$ = $1;
                    $$.range = $2;
                    $$.is_range = true;
                  }
;

lvalue            : reg       { /* does nothing */ }
                  | extra     { /* does nothing */ }
;

reg               : REG
                  {
                    $$ = $1;
                  }
                  | reg NEW
                  {
                    $$ = $1;
                    $$.is_dotnew = true;
                  }
                  | reg OPTNEW
                  {
                    $$ = $1;
                    $$.is_optnew = true;
                  }
                  | reg VEC
                  {
                    $$ = $1;
                    $$.vec = $2;
                    $$.is_vectorial = true;
                    $$.is_unsigned = $2.is_unsigned;
                  }
                  | reg RANGE
                  {
                    $$ = $1;
                    $$.range = $2;
                    $$.is_range = true;
                  }
                  | reg U64
                  {
                    $$ = $1;
                    $$.is_unsigned = true;
                  }
;

extra             : LPCFG
                  {
                    $$ = gen_extra(LPCFG_T, 0, false);
                  }
                  | LC
                  {
                    $$ = gen_extra(LC_T, $1, false);
                  }
                  | SA
                  {
                    $$ = gen_extra(SA_T, $1, false);
                  }
                  | EA
                  {
                    $$ = gen_extra(EA_T, 0, true);
                  }
                  | WIDTH
                  {
                    $$ = gen_extra(WIDTH_T, 0, true);
                  }
                  | OFFSET
                  {
                    $$ = gen_extra(OFFSET_T, 0, true);
                  }
                  | SHAMT
                  {
                    $$ = gen_extra(SHAMT_T, 0, true);
                  }
                  | ADDR
                  {
                    $$ = gen_extra(ADDR_T, 0, true);
                  }
                  | SUMR
                  {
                    $$ = gen_extra(SUMR_T, 0, true);
                  }
                  | SUMI
                  {
                    $$ = gen_extra(SUMI_T, 0, true);
                  }
                  | CTRL
                  {
                    $$ = gen_extra(CTRL_T, 0, true);
                  }
                  | TMPR
                  {
                    $$ = gen_extra(TMPR_T, 0, true);
                  }
                  | TMPI
                  {
                    $$ = gen_extra(TMPI_T, 0, true);
                  }
                  | X0
                  {
                    $$ = gen_extra(X0_T, 0, true);
                  }
                  | X1
                  {
                    $$ = gen_extra(X1_T, 0, true);
                  }
                  | Y0
                  {
                    $$ = gen_extra(Y0_T, 0, true);
                  }
                  | Y1
                  {
                    $$ = gen_extra(Y1_T, 0, true);
                  }
                  | PROD0
                  {
                    $$ = gen_extra(PROD0_T, 0, true);
                  }
                  | PROD1
                  {
                    $$ = gen_extra(PROD1_T, 0, true);
                  }
                  | MAX
                  {
                    $$ = gen_extra(MAX_T, 0, true);
                  }
                  | MIN
                  {
                    $$ = gen_extra(MIN_T, 0, true);
                  }
                  | TMP
                  {
                    $$ = gen_extra(TMP_T, 0, true);
                  }
                  | extra VEC
                  {
                    $$ = $1;
                    $$.vec = $2;
                    $$.is_vectorial = true;
                    $$.is_unsigned = $2.is_unsigned;
                  }
                  | I
                  {
                    $$ = gen_tmp_value("i", 32);
                  }
;

%%

int main(int argc, char **argv)
{
    
    /* Argument parsing */
    int opt;
    while ((opt = getopt(argc, argv, "jstulbhwd")) != -1) {
        switch (opt) {
        case 'j': is_jump = true; break;
        case 's': is_stop = true; break;
        case 't': no_track_regs = true; break;
        case 'u': mem_unsigned = true; break;
        case 'b': mem_size = MEM_BYTE; break;
        case 'h': mem_size = MEM_HALF; break;
        case 'w': mem_size = MEM_WORD; break;
        case 'd': mem_size = MEM_DOUBLE; break;
        default:
            fprintf(stderr, "Usage: %s [-nbhwd]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    /* Emit fake jump dependency */
    if (is_jump)
        OUT("SET_JUMP_FLAG(dc);\n");

    /* Emit stop instruction */
    if (is_stop) {
        OUT("tcg_gen_movi_i32(GPR[0], 24);\n");
        t_hex_value tmp = gen_tmp_value("0", 32);
        OUT("gen_helper_handle_trap(cpu_env, ", &tmp, ");\n");
    }

    /* Start the parsing procedure */
    yyparse();

    if (error_count != 0) {
        printf("Parsing generated %d errors!\n", error_count);
        return 1;
    }
    return 0;
}
