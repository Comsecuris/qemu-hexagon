/*
 * Semantics struct header
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

#ifndef SEMANTICS_STRUCT_H
#define SEMANTICS_STRUCT_H

enum reg_type {GENERAL_PURPOSE, CONTROL, SYSTEM};

/* Semantic Records */
typedef struct t_hex_reg
{
    char id;
    bool is_const;
    enum reg_type type;
    int offset;
} t_hex_reg;

typedef struct t_hex_tmp
{
    int index;
} t_hex_tmp;

enum imm_union_tag {VARIABLE, VALUE, QEMU_TMP, IMM_PC, IMM_CONSTEXT};

typedef struct t_hex_imm
{
    union {
        char id;
        uint64_t value;
        uint64_t index;
    };
    enum imm_union_tag type;
} t_hex_imm;

typedef struct t_hex_pre
{
    char id;
    bool is_zeroone;
    bool is_bit_iter;
} t_hex_pre;

enum rvalue_extra_type {EA_T, LPCFG_T, LC_T, SA_T, WIDTH_T, OFFSET_T,
                        SHAMT_T, ADDR_T, SUMR_T, SUMI_T, CTRL_T, TMPR_T,
                        TMPI_T, X0_T, X1_T, Y0_T, Y1_T, PROD0_T, PROD1_T,
                        MAX_T, MIN_T, TMP_T};

typedef struct t_hex_extra
{
    int index;
    enum rvalue_extra_type type;
    bool temp;
} t_hex_extra;

enum iterable_type {NO_ITER, I_ITER, I2_ITER, IPLUS1_ITER, IPLUS4_ITER,
                    I2PLUS1_ITER};

typedef struct t_hex_vec
{
    int index;
    int width;
    bool is_unsigned;
    bool is_zeroone;
    enum iterable_type iter_type;
} t_hex_vec;

typedef struct t_hex_range
{
    int begin;
    int end;
} t_hex_range;

enum rvalue_union_tag {REGISTER, TEMP, IMMEDIATE, PREDICATE, EXTRA};

typedef struct t_hex_value
{
    union {
        t_hex_reg reg;
        t_hex_tmp tmp;
        t_hex_imm imm;
        t_hex_pre pre;
        t_hex_extra extra;
    };
    enum rvalue_union_tag type;
    unsigned bit_width;
    bool is_unsigned;
    bool is_dotnew;
    bool is_optnew;
    bool is_vectorial;
    bool is_range;
    bool is_symbol;
    t_hex_vec vec;
    t_hex_range range;
} t_hex_value;

#endif /* SEMANTICS_STRUCT_H */
