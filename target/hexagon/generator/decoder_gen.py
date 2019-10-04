#!/usr/bin/env python3
#
# Code generator for the header file required by the Hexagon decoder
#
# Copyright (c) 2017-2019 Comsecuris UG (haftungsbeschraenkt)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

from collections import namedtuple
from collections import defaultdict
from pprint import pprint

import argparse
import csv
import json
import re
import subprocess

instruction_strings = []
sub_instruction_strings = []
meta_instructions = []
instructions_masks = []
specialization_params = {}
endloops = {}
patterns = []
meta_mapping = defaultdict(list)
implemented_meta = 0
implemented_insn = 0
system_insn = 0
float_insn = 0
implemented_vect = 0
vectorial_meta = 0
Constant = namedtuple('Constant', ['identifier', 'bits', 'signed',
                                   'multiple', 'pc_offset', 'ranges'])
Register = namedtuple('Register', ['identifier', 'bits', 'ranges',
                                   'dot_new', 'predicate'])
Range = namedtuple('Range', ['start', 'end'])

DECODER_HEADER = """#ifndef HEXAGON_DECODER_H
#define HEXAGON_DECODER_H

#include "exec/log.h"
#include "qemu-common.h"
#include "tcg.h"

#define LOG_DIS(...) qemu_log_mask(CPU_LOG_TB_IN_ASM, ## __VA_ARGS__)
#define SET_USED_REG(reg_struct, reg) {\\
        if (is_conditional) \\
            reg_struct.conditional |= (uint64_t)1 << (reg); \\
        else \\
            reg_struct.written |= (uint64_t)1 << (reg); \\
        if (reg < 32) \\
            push_destination_reg(&(reg_struct.destination), reg); \\
}
#define SET_WRITTEN_PRE(dc, pre_index) dc->deps[dc->i].written |= (uint8_t)1 << (pre_index)
#define GET_WRITTEN_PRE(dc, pre_index) dc->deps[dc->i].written & (uint64_t)1 << (pre_index)
#define GET_WRITTEN_PREV_PRE(dc, pre_index)                      \\
        (dc->i == 0 ?                                            \\
        (dc->deps[1].written & (uint64_t)1 << (pre_index)) |     \\
        (dc->deps[2].written & (uint64_t)1 << (pre_index)) |     \\
        (dc->deps[3].written & (uint64_t)1 << (pre_index))       \\
        : dc->i == 1 ?                                           \\
        (dc->deps[0].written & (uint64_t)1 << (pre_index)) |     \\
        (dc->deps[2].written & (uint64_t)1 << (pre_index)) |     \\
        (dc->deps[3].written & (uint64_t)1 << (pre_index))       \\
        : dc->i == 2 ?                                           \\
        (dc->deps[0].written & (uint64_t)1 << (pre_index)) |     \\
        (dc->deps[1].written & (uint64_t)1 << (pre_index)) |     \\
        (dc->deps[3].written & (uint64_t)1 << (pre_index))       \\
        : dc->i == 3 ?                                           \\
        (dc->deps[0].written & (uint64_t)1 << (pre_index)) |     \\
        (dc->deps[1].written & (uint64_t)1 << (pre_index)) |     \\
        (dc->deps[2].written & (uint64_t)1 << (pre_index)) : -1 )
#define GET_WRITTEN_ANY_PRE(dc) \\
        (dc->deps[0].written & 0b1111) | \\
        (dc->deps[1].written & 0b1111) | \\
        (dc->deps[2].written & 0b1111) | \\
        (dc->deps[3].written & 0b1111)
#define SET_READ_PRE(dc, pre_index) dc->deps[dc->i].read |= (uint8_t)1 << (pre_index)
#define GET_USED_REG(reg_struct, reg) (reg_struct).written & (uint64_t)1 << (reg)
#define GET_COND_REG(reg_struct, reg) (reg_struct).conditional & (uint64_t)1 << (reg)
#define SET_BEGIN_COND() is_conditional = true;
#define SET_END_COND() is_conditional = false;
#define SET_JUMP_FLAG(dc) { \\
    switch (dc->jump_count) { \\
        case 0: SET_WRITTEN_PRE(dc, 4); break; \\
        case 1: SET_READ_PRE(dc, 4); break; \\
        default: assert(false && "More than two jumps in a packet!"); \\
    } \\
    dc->jump_count++; \\
}
#define ADD_IF_ZERO(x, y) {\\
        assert((x == 0 || y == 0) && "Overlapping instruction encodings!");\\
        x += y;\\
}
#define EXTRACT_P(index, dotnew) (dotnew) ? \\
        ((CR[P] & (0xff << 8 * index)) >> 8 * index) : \\
        ((CR_new[P] & (0xff << 8 * index)) >> 8 * index) : \\

#define EXTR(src, start, end) \\
(((src) >> (31 - end)) & ((1 << (end - start + 1)) - 1))
#define EXTR_2(src, start, end, start2, end2) \\
(EXTR(src, start, end) << (end2 - start2 + 1)) | EXTR(src, start2, end2)
#define EXTR_3(src, start, end, start2, end2, start3, end3) \\
(EXTR(src, start, end) << (end2 - start2 + end3 - start3 + 2)) |\\
(EXTR(src, start2, end2) << (end3 - start3 + 1)) | (EXTR(src, start3, end3));
#define EXTR_4(src, start, end, start2, end2, start3, end3, start4, end4) \\
EXTR(src, start, end) << (end2 - start2 + end3 - start3 + end4 - start4 + 3)\\
| (EXTR(src, start2, end2) << (end3 - start3 + end4 - start4 + 2))\\
| (EXTR(src, start3, end3) << (end4 - start4 + 1))\\
| EXTR(src, start4, end4)
#define EXTR_BITS(src, x) \\
((src >> x) & 1)
#define EXTR_BITS_2(src, x, y) \\
(EXTR_BITS(src, x) | (EXTR_BITS(src, y) << 1))
#define EXTR_BITS_3(src, x, y, z) \\
(EXTR_BITS_2(src, x, y) | (EXTR_BITS(src, z) << 2))
#define EXTR_BITS_4(src, x, y, z, a) \\
(EXTR_BITS_2(src, x, y) | (EXTR_BITS_2(src, z, a) << 2))
#define EXTR_BITS_5(src, x, y, z, a, b) \\
(EXTR_BITS_4(src, x, y, z, a) | (EXTR_BITS(src, b) << 4))
#define EXTR_BITS_6(src, x, y, z, a, b, c) \\
(EXTR_BITS_3(src, x, y, z) | (EXTR_BITS_3(src, a, b, c) << 3))\n

typedef struct destination_reg_node {
    int index;
    struct destination_reg_node *next;
} d_reg_node;
typedef d_reg_node * d_reg_list;

typedef struct regs {
    uint64_t written;
    uint64_t conditional;
    d_reg_list destination;
} regs_t;

typedef struct dep {
    TCGOp *begin;
    TCGOp *end;
    uint8_t written;
    uint8_t read;
} deps_t;

/* This is the state at translation time.  */
typedef struct DisasContext {
    HexagonCPU *cpu;
    target_ulong pc;
    target_ulong old_pc;
    target_ulong instruction_pc;
    target_ulong npc;

    int i;
    uint32_t ir;
    uint32_t const_ext;
    bool block_end;
    bool new_packet;
    bool extender_present;
    bool pc_written;
    bool duplex;
    bool endloop[2];
    bool is_pre_written;
    TCGOp *packet_first_op;
    int jump_count;
    regs_t regs;
    deps_t deps[4];
    deps_t * original[4];
    deps_t * ordered[4];

    struct TranslationBlock *tb;
} DisasContext;

extern TCGv GPR[32];
extern TCGv CR[32];
extern TCGv SR[64];
extern TCGv GPR_new[32];
extern TCGv CR_new[32];
extern TCGv PC_written;
extern TCGv SA[2];
extern TCGv LC[2];
extern TCGv LPCFG;

int get_destination_reg(regs_t regs, int t);
void push_destination_reg(d_reg_list* list, int index);
void register_dependency(int index, DisasContext *dc);
uint32_t decode(uint32_t ir);
uint32_t sub_decode(uint32_t ir);
regs_t execute(unsigned inst_id, DisasContext *dc);
regs_t sub_execute(unsigned inst_id, DisasContext *dc);
void endloop0(void);
void endloop01(void);
void endloop1(void);

"""
DECODER_INCLUDES = """#include "qemu/osdep.h"
#include "cpu.h"
#include "decoder.h"
#include "tcg-op.h"

static const int pred_whitening[4] = { 0xffffff00,
                                       0xffff00ff,
                                       0xff00ffff,
                                       0x00ffffff };

bool is_conditional = false;

int get_destination_reg(regs_t regs, int t) {
    d_reg_list reg_list = regs.destination;
    if (reg_list == NULL)
        assert(false && "Invalid .new instruction reference!");
    for(int i = 1; i < t; i++) {
        assert(reg_list != NULL && "Invalid .new instruction reference!");
        reg_list = reg_list->next;
    }
    return reg_list->index;
}

void push_destination_reg(d_reg_list* list, int index) {
    if (index == 29 || index == 30 || index == 31 ||
        (list != NULL && *list != NULL && (*list)->index == index)) {
        return;
    }
    d_reg_node *new_reg = (d_reg_node *)malloc(sizeof(d_reg_node));
    new_reg->next = *list;
    new_reg->index = index;
    *list = new_reg;
}

"""

def gen_macros():
    code = ""
    code += DECODER_INCLUDES
    with open(decoder_c, "w") as d:
        d.write(code)


def find_integer(string):
    for i, letter in enumerate(string):
        if not letter.isdigit():
            return i
    return len(string)


def extract_shift(string):
    if string[1:5] == ":<<N":
        return Constant(identifier="N", bits=32, signed=False,
                        multiple=1, pc_offset=False, ranges=[])
    else:
        return None


# Parse a constant from a tokenized string
def extract_const(string):
    # Extract features from constant placeholders
    identifier = "j" if string[1].islower() else "I"
    if string[1] in {"u", "U"}:
        # Unsigned N-bit immediate value
        signed = False
        pc_offset = False
    elif string[1] in {"s", "S"}:
        # Signed N-bit immediate value
        signed = True
        pc_offset = False
    elif string[1] in {"m", "M"}:
        # Signed N-bit immediate value
        signed = True
        pc_offset = False
    elif string[1] in {"r", "R"}:
        # Signed N-bit immediate value
        signed = True
        pc_offset = True
    elif string[1] == "#":
        # 32 bit value
        return Constant(bits=32)
    elif string[1] == "-" or string[1].isdigit():
        return None
    else:
        assert(False and "Constant placeholder parsing error!")

    bits_delimiter = find_integer(string[2:]) + 2
    bits = int(string[2:bits_delimiter])
    if len(string) > bits_delimiter and string[bits_delimiter] == ":":
        multiple_delimiter = find_integer(
                string[bits_delimiter + 1:]) + bits_delimiter + 1
        multiple = 2 ** int(string[bits_delimiter + 1:multiple_delimiter])
    else:
        multiple = 1
    return Constant(identifier=identifier, bits=bits, signed=signed,
                    multiple=multiple, pc_offset=pc_offset, ranges=[])


# Parse a register from a tokenized string
def extract_reg(string):
    # TODO: Handle 64bit composite registers
    if string[0] in {"R", "C", "P",
                     "M", "G", "S"}:
        if string[1] in {"e", "s", "d", "t", "u", "v", "x", "y"}:
            if len(string) >= 3 and string[2] == string[1]:
                return Register(identifier=string[1],
                                bits=64,
                                ranges=[],
                                dot_new=False,
                                predicate=string[0] == "P")
            return Register(identifier=string[1],
                            bits=32,
                            ranges=[],
                            dot_new=False,
                            predicate=string[0] == "P")
    elif string[0] in {"N"}:
        if string[1] in {"t"}:
            return Register(identifier=string[1],
                            bits=32,
                            ranges=[],
                            dot_new=True,
                            predicate=False)
        elif string[1] in {"s"}:
            return Register(identifier=string[1],
                            bits=32,
                            ranges=[],
                            dot_new=True,
                            predicate=False)


# Search operand from identifier
def find_op(identifier, operands):
    return [op for op in operands if op.identifier == identifier][0]


# Parse operands and compute format strings
def parse_op(inst_str):
    # Find operands order
    operands = []
    format_identifiers = []
    for i, letter in enumerate(inst_str):
        op = None
        # Signed and unsigned constants
        if letter == "#":
            op = extract_const(inst_str[i:])
        elif letter == "[":
            op = extract_shift(inst_str[i:])
        # Registers and predicates
        else:
            op = extract_reg(inst_str[i:])
        format_identifiers.append(op)
        if op not in operands:
            operands.append(op)
    identifiers = []
    for op in format_identifiers:
        if op is not None:
            if op.bits == 64:
                identifiers.append("(" + op.identifier + " + 1)")
                identifiers.append(op.identifier)
            else:
                identifiers.append(op.identifier)
    return ([op for op in operands if op is not None],
            identifiers)


# Operands extraction code generation
def gen_extract_op(inst_str, encoding, operands):
    code = ""
    identifiers = set([c.identifier
                       if type(c) in {Constant, Register}
                       else c
                       for c in operands])
    # Extract bit ranges from encoding scheme
    char, start = '', 0
    for i, letter in enumerate(encoding):
        if letter != char:
            if char in identifiers:
                find_op(char, operands).ranges.append(
                        Range(start=start, end=(i - 1)))
            start = i
            char = letter
        # Verify that no meaningful bits are left behind
        if letter not in {'0', '1', '-', 'P'}.union(set(identifiers)):
            print("Bit " + letter +
                  " was not parsed in instruction " + inst_str)

    if char in identifiers:
        find_op(char, operands).ranges.append(
                Range(start=start, end=(len(encoding) - 1)))

    # Verify encoding scheme coherence
    for op in operands:
        if type(op) == Constant and op.identifier != "N":
            sum = 0
            for r in op.ranges:
                sum += r.end - r.start + 1
            assert(sum == op.bits and "Non-coherent encoding scheme!")

    # Patch Nt encoding ranges
    for op in operands:
        if type(op) == Register and op.dot_new:
            old_range = op.ranges[-1]
            op.ranges[-1] = Range(start=old_range.start, end=old_range.end - 1)

    # Constand extender is not present, apply multiplier
    ext_imm = extendable_index(inst_str)
    constant_index = 0
    # Emit code for each operand
    for i, op in enumerate(operands):
        multiple = ""
        if len(op.ranges) == 1:
            code += "raw_value = EXTR(dc->ir, {}, {});\n".format(
                    op.ranges[0].start,
                    op.ranges[0].end)
        elif len(op.ranges) == 2:
            code += "raw_value = EXTR_2(dc->ir, {}, {}, {}, {});\n".format(
                            op.ranges[0].start,
                            op.ranges[0].end,
                            op.ranges[1].start,
                            op.ranges[1].end)
        elif len(op.ranges) == 3:
            code += "raw_value = EXTR_3(dc->ir, {}, {}, {}, {}, {}, {});"\
                    "\n".format(
                            op.ranges[0].start,
                            op.ranges[0].end,
                            op.ranges[1].start,
                            op.ranges[1].end,
                            op.ranges[2].start,
                            op.ranges[2].end)
        elif len(op.ranges) == 4:
            code += "raw_value = EXTR_4(dc->ir, {}, {}, {}, {}, {}, {}, {},"\
                    " {});\n".format(
                            op.ranges[0].start,
                            op.ranges[0].end,
                            op.ranges[1].start,
                            op.ranges[1].end,
                            op.ranges[2].start,
                            op.ranges[2].end,
                            op.ranges[3].start,
                            op.ranges[3].end)
        if type(op) == Constant:
            if op.multiple != 0:
                multiple = " * "+str(op.multiple)
            if op.signed:
                extended = "((0xffffffff >> {bits}) << {bits}) | "\
                        "raw_value".format(bits=op.bits)
                code += "uint32_t {op_name} = ((raw_value >> ({bits} - 1))"\
                        " ? ({extended}) : raw_value);".format(
                                op_name=op.identifier,
                                bits=op.bits,
                                extended=extended)
                # If is extendable emit conditional multiplier
                if constant_index == ext_imm:
                    code += "{op_name} = (dc->extender_present ? "\
                            "{op_name} : ({op_name}{multiple}));\n".format(
                                    op_name=op.identifier,
                                    multiple=multiple)
                # Otherwise just multiply
                else:
                    code += "{op_name} = {op_name}{multiple};\n".format(
                                    op_name=op.identifier,
                                    multiple=multiple)

            else:
                code += "uint32_t {op_name} = "\
                        "raw_value;".format(
                                op_name=op.identifier,
                                index=i,
                                bits=op.bits)
                # If is extendable emit conditional multiplier
                if constant_index == ext_imm:
                    code += "{op_name} = (dc->extender_present ? "\
                            "{op_name} : ({op_name}{multiple}));\n".format(
                                    op_name=op.identifier,
                                    multiple=multiple)
                # Otherwise just multiply
                else:
                    code += "{op_name} = {op_name}{multiple};\n".format(
                                    op_name=op.identifier,
                                    multiple=multiple)
            constant_index += 1
        else:
            code += "uint32_t "+op.identifier+" = raw_value;"
    return code


def extendable_index(inst_str):
    inst_str = inst_str.replace(" ", "")
    extendables = []
    with open(const_ext_csv) as f:
        lines = csv.reader(f)
        for line in lines:
            extendables.append(line)
    indexes, expressions = zip(*extendables)
    regexes = map(to_extender_regex, expressions)
    patterns = map(re.compile, regexes)
    for i, pattern in enumerate(patterns):
        match = pattern.match(inst_str)
        if match is not None:
            return int(indexes[i])
    return None


# Function execution code generation
def gen_execute():
    global system_insn
    code = "regs_t execute(unsigned inst_id, DisasContext *dc) {"\
           "uint32_t raw_value = 0;"\
           "regs_t regs = { 0 };"\
           "switch (inst_id) {"
    encodings = parse_encodings(instructions_csv)
    # Count SYSTEM instructions
    for e in encodings:
        if e[0:4] == ['0', '1', '1', '0']:
            system_insn += 1
    for inst_id, inst_str in enumerate(instruction_strings):
        operands, format_identifiers = parse_op(inst_str)
        identifiers = [op.identifier for op in operands]
        code += "case {}:\n{{".format(inst_id)
        code += gen_extract_op(inst_str, encodings[inst_id], operands)
        for op in operands:
            if type(op) == Register and op.dot_new:
                code += "{id} = get_destination_reg(dc->regs, {id});\n".format(
                        id=op.identifier)
            if type(op) == Register and not op.dot_new and not op.predicate:
                sum = 0
                for r in op.ranges:
                    sum += r.end - r.start + 1
                    if sum < 5:
                        code += "if (" + op.identifier + " >= 8)\n"
                        code += op.identifier + " += 8;\n"
        # If present, apply constant extender value
        ext_imm = extendable_index(inst_str)
        if ext_imm is not None:
            constants = [op for op in operands if type(op) == Constant]
            identifier = constants[ext_imm].identifier
            code += "if (dc->extender_present) {\n"
            code += identifier + " &= 0x3f;\n"
            code += identifier + " |= dc->const_ext;\n"
            code += "}\n"
        # if inst_id == 233:
        #    pprint(inst_str)
        #    pprint(ext_imm)
        # Print LOG_DIS disassembly using format.h
        code += ("LOG_DIS({}" +
                 ", {}" * len(format_identifiers) +
                 ");\n").format(to_format_string(inst_str), *format_identifiers)
        # Call the correct semantics function
        code += gen_function_call(inst_str, identifiers)
        code += "break;\n}\n"

    code += 'default: assert(false && '\
            '"Decoding not implemented for this instruction");'

    code += "}\nreturn regs;\n}\n\n"

    with open(decoder_c, "a") as d:
        d.write(code)


# Translate regex groups to function parameters
def get_params(pattern):
    flags = {}
    params = []
    # Each group becomes a parameter
    for k, v in pattern.groupindex.items():
        flags[v - 1] = k
    for i in range(len(flags)):
        params.append(flags[i])
    return params


# Invoke semantics compiler to fill function body
def gen_function_body(pattern_index):
    global implemented_meta
    global implemented_insn
    global implemented_vect
    qemu_code = ""
    qemu_code += "regs_t regs = { 0 };\n"
    instruction_code = meta_instructions[pattern_index]["code"]
    # Patch missing semicolons
    instruction_code = instruction_code.replace(" if", "; if")
    # Parse memory operation size
    mem_args = []
    mem_size = re.findall(r'mem(.*)\(', meta_instructions[pattern_index]["str"])
    assert(len(mem_size) < 2 and "More than one memory operation!")
    if len(mem_size) == 1:
        mem_size = mem_size[0]
        if "u" in mem_size:
            mem_args.append("-u")
        if "b" in mem_size:
            mem_args.append("-b")
        elif "h" in mem_size:
            mem_args.append("-h")
        elif "w" in mem_size:
            mem_args.append("-w")
        elif "d" in mem_size:
            mem_args.append("-d")
    # Parse comparison signedness
    cmp_sign = re.findall(r'cmp.(?:gt|ge|lt|le)(.)\(',
                          meta_instructions[pattern_index]["str"])
    if len(cmp_sign) == 1 and "u" in cmp_sign:
        mem_args.append("-u")
    # Parse jump flag
    jumps = re.findall(r'jump', meta_instructions[pattern_index]["str"])
    if len(jumps) > 0:
        mem_args.append("-j")
    # Parse stop instruction
    if meta_instructions[pattern_index]["str"] == "stop(Rs)":
        mem_args.append("-s")
    args = [semantics_path] + mem_args
    proc = subprocess.Popen(" ".join(args),
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)
    proc.stdin.write(instruction_code.encode("utf-8"))
    proc.stdin.close()
    proc.wait()
    # Check bison exit code
    if proc.returncode == 0:
        qemu_code += proc.stdout.read().decode("utf-8")
        implemented_meta += 1
        implemented_insn += len(meta_mapping[pattern_index])
        if "=v" in meta_instructions[pattern_index]["str"]:
            implemented_vect += 1
    else:
        qemu_code += 'assert(false && "Instruction not implemented!");\n'
        # pprint(meta_instructions[pattern_index]["code"])
    qemu_code += "return regs;"
    return qemu_code


# Generate functions signatures
def gen_functions():
    code = ""
    regexes = map(to_regex, meta_instructions)
    patterns = map(re.compile, regexes)
    # Map meta-instructions into effective instructions
    for pattern_index, pattern in enumerate(patterns):
        meta_instruction = meta_instructions[pattern_index]["str"]
        meta_instruction = re.sub(r"\[(:<<N)\]", r"\[:<<N\]", meta_instruction)
        meta_instruction = re.sub(r"\[(:<<1)\]", r"\[:<<N\]", meta_instruction)
        operands, _ = parse_op(meta_instruction)
        identifiers = [op.identifier for op in operands]
        params = get_params(pattern)
        # Add function string comment
        code += "/* " + meta_instructions[pattern_index]["str"] + " */\n"
        code += "/* " + meta_instructions[pattern_index]["code"] + " */\n"
        # Generate function signature
        if len(identifiers) + len(params) == 0:
            code += "regs_t function_{}(DisasContext *dc) {{".format(pattern_index)
        else:
            function_str = ("regs_t function_{}(DisasContext *dc, " +
                            ", ".join(["uint32_t {}"] * len(identifiers) +
                                      ["bool {}"] * len(params)) + "){{\n")
            code += function_str.format(pattern_index,
                                        *identifiers,
                                        *params)
        code += gen_function_body(pattern_index)
        code += "}\n"
    with open(decoder_c, "a") as d:
        d.write(code)
    print("{}/{} meta instructions are vectorial!".format(vectorial_meta, len(meta_instructions)))
    print("{}/{} meta instructions have been implemented!".format(implemented_meta, len(meta_instructions)))
    print("{}/{} vectorial meta instructions have been implemented!".format(implemented_vect, vectorial_meta))
    print("{}/{} instructions have been implemented!".format(implemented_insn, len(instruction_strings) - system_insn - float_insn))

# Match instructions corresponding to a meta-instruction
def gen_pattern_matching(candidates, instruction_masks):
    if len(candidates) == 0:
        code = 'assert(false && '\
                '"Invalid instruction encoding!");'
        return code
    elif len(candidates) == 1:
        return "return {};".format(candidates[0])
    else:
        code = ""
        for candidate in candidates:
            code += "ADD_IF_ZERO(inst_index, "\
                    "(((ir & {}) ^ {}) == 0) * {});\n".format(
                        hex(int(instruction_masks[candidate][1], 2)),
                        hex(int(instruction_masks[candidate][0], 2)),
                        candidate)
        code += "return inst_index;\n"
        return code


# Generate switch case for decoding
def explore_switch(decode, instruction_masks):
    # Recursively generate switch cases
    n_bits = len(decode["bits"])
    code = ("switch (" +
            "EXTR_BITS_{}(".format(n_bits) +
            ("ir"+", {}"*n_bits+")) {{").format(*decode["bits"]))
    if "options" in decode.keys():
        for option in decode["options"]:
            code += "case {}: ".format(hex(int(option, 2)))
            code += explore_switch(decode["options"][option],
                                   instruction_masks)
            code += "break;"
        code += 'default: assert(false && '\
                '"Invalid instruction encoding!");'
    elif "instructions" in decode.keys():
        for instruction in decode["instructions"]:
            code += "case {}:".format(hex(int(instruction, 2)))
            code += gen_pattern_matching(decode["instructions"][instruction],
                                         instruction_masks)
            code += "break;"
        code += 'default: assert(false && '\
                '"Invalid instruction encoding!");'
    else:
        assert(False and "Unable to generate parsing code for:")
        pprint(decode)
    code += "}"
    return code


def gen_decoder_switch():
    with open(instruction_decoding_json) as f:
        decoding_json = json.loads(f.read())
    decode = decoding_json["decode"]
    instruction_masks = decoding_json["instructions"]

    code = "uint32_t decode(uint32_t ir) {\n"
    code += "uint64_t inst_index = 0;"
    code += explore_switch(decode, instruction_masks)
    code += "}"
    with open(decoder_c, "a") as d:
        d.write(code)


# Translate instruction string into a format string
def to_format_string(inst_str):
    code = ""
    code += "    "
    code += '"'
    format_string = re.sub("Nt", "Rt", inst_str)
    format_string = re.sub("([RCPMGNS])[esdtuvxy]{2}",
                           '\g<1>%" PRIu32 ":%" PRIu32 "', format_string)
    format_string = re.sub("([RCPMGNS])[esdtuvxy]",
                           '\g<1>%" PRIu32 "', format_string)
    format_string = re.sub("\[:<<N\]", '[:<<%" PRIi32 "]', format_string)
    format_string = re.sub("#[uU][0-9]+:[0-9]+", '#%" PRIu32 "', format_string)
    format_string = re.sub("#[uU][0-9]+", '#%" PRIu32 "', format_string)
    format_string = re.sub("#[sS][0-9]+:[0-9]+", '#%" PRIi32 "', format_string)
    format_string = re.sub("#[sS][0-9]+", '#%" PRIi32 "', format_string)
    format_string = re.sub("#m[0-9]+", '#%" PRIi32 "', format_string)
    format_string = re.sub("#r[0-9]+", '#%" PRIi32 "', format_string)
    format_string = re.sub("##", '#%" PRIi32 "', format_string)
    code += format_string
    code += '"\n'
    return code


# Translate a meta-instruction string into a regex
def to_regex(meta_instruction):
    regex = meta_instruction["str"]
    regex = regex.replace("(", "\(")
    regex = regex.replace(")", "\)")
    regex = regex.replace("*", "\*")
    regex = regex.replace("?", "\?")
    regex = regex.replace("^", "\^")
    regex = regex.replace("\n", "")
    regex = regex.replace(" ", "")
    regex = re.sub(r"\[(:<<1)\]", r"(?P<opt_shift>\1)?", regex)
    regex = re.sub(r"\[(:<<N)\]", r"\[:<<N\]", regex)
    regex = re.sub(r"\[(:<<1)\]", r"\[:<<N\]", regex)
    regex = re.sub(r"\[([&|]+)\]", r"(?P<and_or>[\1])", regex)
    regex = re.sub(r"\[([+-]+)\]", r"(?P<plus_minus>[\1])", regex)
    regex = re.sub(r"\[([HL]+)\]", r"(?P<high_low0>[\1])", regex, count=1)
    regex = re.sub(r"(?<!>)\[([HL]+)\]", r"(?P<high_low1>[\1])", regex, count=1)
    regex = re.sub(r"\[([01]+)\]", r"(?P<zero_one0>[01])", regex, count=1)
    regex = re.sub(r"(?<!>)\[([01]+)\]", r"(?P<zero_one1>[01])", regex, count=1)
    regex = re.sub(r"\[!\]", r"(?P<not0>[!]*)?", regex, count=1)
    regex = re.sub(r"(?<!>)\[!\]", r"(?P<not1>[!]*)", regex, count=1)
    regex = re.sub(r"\[(:sat)\]", r"(?P<sat>\1)?", regex)
    regex = re.sub(r"\[(:rnd)\]", r"(?P<rnd>\1)?", regex)
    regex = re.sub(r"\[(.new)\]", r"(?P<new>\1)?", regex)
    regex = re.sub(r":<hint>", r"(?P<hint>\:n?t)?", regex)
    regex = regex.replace("+", "\+")
    regex = regex.replace("|", "\|")
    regex = regex.replace(".", "\.")
    regex = "^" + regex + "$"
    return regex


# Translate a constant extender string into a regex
def to_extender_regex(meta_instruction):
    regex = meta_instruction
    regex = regex.replace("(", "\(")
    regex = regex.replace(")", "\)")
    regex = regex.replace("?", "\?")
    regex = regex.replace("Rd[d]", "Rdd?")
    regex = regex.replace("[.new]", r"(.new)?")
    regex = regex.replace("{", "(?:")
    regex = regex.replace("}", ")")
    regex = regex.replace("*", "\*")
    regex = regex.replace("^", "\^")
    regex = regex.replace("\n", "")
    regex = regex.replace(" ", "")
    regex = regex.replace("+", "\+")
    regex = regex.replace(".", "\.")
    regex = re.sub(r"\[!\]", r"!?", regex, count=1)
    regex = regex.replace(",", "\,")
    regex = regex.replace("hint", "n?t")
    regex = regex.replace("xx", "(?:gt|ge|lt|le|eq)u?")
    regex = regex.replace("target", "#[rRuUsS][0-9]+(?:\:?[0-9]+)?")
    regex = regex.replace("#u6", "#[uUsS][0-9]+(?:\:?[0-9]+)?")
    regex = regex.replace("##u32", "#[uUsS][0-9]+(?:\:?[0-9]+)?")
    regex = regex.replace("##U32", "#[uUsS][0-9]+(?:\:?[0-9]+)?")
    regex = regex.replace("##s32", "#[rRsS][0-9]+(?:\:?[0-9]+)?")
    regex = regex.replace("##S32", "#[rRsS][0-9]+(?:\:?[0-9]+)?")
    regex = regex.replace("Pt", "P[a-z]")
    regex = regex.replace("add/sub/and/or", "(?:add|sub|and|or)")
    regex = regex.replace("asl/asr/lsr", "(?:asl|asr|lsr)")
    # pprint(regex)
    return regex


def parse_instructions(filename):
    global float_insn
    instruction_strings = []
    # Extract effective instructions from instructions.csv
    with open(filename) as f:
        inst_reader = csv.reader(f, delimiter=",", quotechar='"')
        for inst_id, inst_str in enumerate(inst_reader):
            instruction_strings.append(inst_str[-1])
            # Count floating point instructions
            if "=sf" in inst_str[-1]:
                float_insn += 1
    return instruction_strings


def parse_encodings(filename):
    instruction_strings = []
    # Extract effective instructions from instructions.csv
    with open(filename) as f:
        inst_reader = csv.reader(f, delimiter=",", quotechar='"')
        for inst_id, inst_str in enumerate(inst_reader):
            instruction_strings.append(inst_str[:32])
    return instruction_strings


def parse_meta_instructions():
    global endloops
    global vectorial_meta
    meta_instructions = []
    with open(meta_instructions_csv) as inst:
        insts = csv.reader(inst)
        instruction = {}
        for inst in insts:
            if inst[0] in {"endloop0", "endloop1", "endloop01"}:
                endloops[inst[0]] = inst[1]
                continue
            # Exclude syntactic sugar
            if "Assembler" in inst[1]:
                continue
            if len(inst[0]) != 0:
                meta_instructions.append(instruction)
                instruction = {}
                instruction["str"] = inst[0]
                if "=v" in instruction["str"]:
                    vectorial_meta += 1
                if len(inst[1]) == 0:
                    instruction["code"] = "NOP;"
                else:
                    instruction["code"] = inst[1]
            else:
                instruction["code"] += "\n"+inst[1]
        meta_instructions.append(instruction)
        del meta_instructions[0]
    return meta_instructions


def gen_function_call(inst_str, identifiers):
    inst_str = inst_str.replace(" ", "")
    arguments = identifiers
    pattern_id = None
    matched = False
    for i, pattern in enumerate(patterns):
        match = pattern.match(inst_str)
        if match is not None:
            matched = True
            for group in match.groups():
                arguments.append("true" if group in {"&", "+", "1", "!", "H",
                                                     ":sat", ":rnd", ".new",
                                                     "t"} else "false")
            pattern_id = i
            break
    if matched:
        meta_mapping[pattern_id].append(inst_str)
        return ("regs = function_{}(dc" +
                ", {}" * len(identifiers) +
                ");\n").format(pattern_id, *arguments)
    else:
        return ('assert(false && "This instruction is not implemented!");')


def gen_sub_decoder():
    global duplex_masks
    with open(sub_instruction_decoding_json) as f:
        decoding_json = json.loads(f.read())
    decode = decoding_json["decode"]
    duplex_masks = decoding_json["instructions"]

    code = "uint32_t sub_decode(uint32_t ir) {\n"
    code += "uint64_t inst_index = 0;"
    code += explore_switch(decode, duplex_masks)
    code += "}"
    with open(decoder_c, "a") as d:
        d.write(code)


# Function execution code generation
def gen_sub_execute():
    code = "regs_t sub_execute(unsigned inst_id, DisasContext *dc) {"\
           "uint32_t raw_value = 0;"\
           "regs_t regs = { 0 };"\
           "switch (inst_id) {"
    encodings = parse_encodings(sub_instructions_csv)
    for inst_id, inst_str in enumerate(sub_instruction_strings):
        operands, format_identifiers = parse_op(inst_str)
        identifiers = [op.identifier for op in operands]
        code += "case {}:\n{{".format(inst_id)
        # Implement weird operator encoding
        code += gen_extract_op(inst_str, encodings[inst_id], operands)
        for op in operands:
            if type(op) == Register:
                if op.bits == 64:
                    code += op.identifier + " *= 2;\n"
                code += "if (" + op.identifier + " >= 8)\n"
                code += op.identifier + " += 8;\n"
        # If present, apply constant extender value
        ext_imm = extendable_index(inst_str)
        if ext_imm is not None:
            constants = [op for op in operands if type(op) == Constant]
            identifier = constants[ext_imm].identifier
            code += "if (dc->extender_present) {\n"
            code += identifier + " &= 0x3f;\n"
            code += identifier + " |= dc->const_ext;\n"
            code += "dc->extender_present = false;\n"
            code += "dc->const_ext = 0;\n"
            code += "}\n"
        # Print LOG_DIS disassembly using format.h
        code += ("LOG_DIS({}" +
                 ", {}" * len(format_identifiers) +
                 ");\n").format(to_format_string(inst_str), *format_identifiers)
        # Call the correct semantics function
        code += gen_function_call(inst_str, identifiers)
        code += "break;\n}\n"

    code += 'default: assert(false && '\
            '"Decoding not implemented for this instruction");'

    code += "}\nreturn regs;\n}\n\n"

    with open(decoder_c, "a") as d:
        d.write(code)


def gen_endloop():
    code = ""
    for name, pseudocode in endloops.items():
        code += "void "+name+"(void)\n"
        code += "{\n"
        proc = subprocess.Popen([semantics_path,
                                 '-t'],
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE)
        proc.stdin.write(pseudocode.encode("utf-8"))
        proc.stdin.close()
        proc.wait()
        assert(proc.returncode == 0 and "Unhandled endloop instruction!")
        code += proc.stdout.read().decode("utf-8")
        code += "}\n"
    with open(decoder_c, "a") as d:
        d.write(code)


def analyse_inst_mapping():
    no_match_count = 0
    regexes = map(to_regex, meta_instructions)
    patterns = list(map(re.compile, regexes))
    for i, inst_str in enumerate(instruction_strings):
        # Patch instruction strings to make them more easily parsable
        inst_str = inst_str.replace(" ", "")
        no_match = True
        for pattern in patterns:
            match = pattern.match(inst_str)
            if match is not None:
                no_match = False
        if no_match:
            no_match_count += 1
            assert(inst_str.split("=")[1][0] == "v" and "Non-vectorial "
                   "instruction has no corresponding meta-instruction!")
    print("{}/{} instructions did not match any meta "
          "instruction!".format(no_match_count, len(instruction_strings)))


def gen_decoder_header():
    multi_reference_count = 0
    decoder_header = DECODER_HEADER
    regexes = map(to_regex, meta_instructions)
    patterns = map(re.compile, regexes)
    # Map meta-instructions into effective instructions
    for pattern_index, pattern in enumerate(patterns):
        meta_instruction = meta_instructions[pattern_index]["str"]
        meta_instruction = re.sub(r"\[(:<<N)\]", r"\[:<<N\]", meta_instruction)
        meta_instruction = re.sub(r"\[(:<<1)\]", r"\[:<<N\]", meta_instruction)
        operands, _ = parse_op(meta_instruction)
        identifiers = [op.identifier for op in operands]
        flags = {}
        params = []
        # Each group becomes a parameter
        for k, v in pattern.groupindex.items():
            flags[v - 1] = k
        for i in range(len(flags)):
            params.append(flags[i])
        # Generate function signature
        if len(identifiers) + len(params) == 0:
            decoder_header += "regs_t function_{}(DisasContext *dc);\n".format(pattern_index)
        else:
            function_str = ("regs_t function_{}(DisasContext *dc, " +
                            ", ".join(["uint32_t {}"] * len(identifiers) +
                                      ["bool {}"] * len(params)) + ");\n")
            decoder_header += function_str.format(pattern_index,
                                                  *identifiers,
                                                  *params)
    print("{}/{} instructions were referenced multiple "
          "times!".format(multi_reference_count, len(instruction_strings)))
    decoder_header += "\n#endif"
    with open(decoder_h, "w") as f:
        f.write(decoder_header)


def indent():
    # Optionally, indent
    try:
        subprocess.run("indent -linux " + decoder_c, shell=True, check=True)
    except:
        pass

def main():
    parser = argparse.ArgumentParser()
    # Support programs
    parser.add_argument("semantics", metavar="SEMANTICS")

    # Data extracted from ISA reference manual
    parser.add_argument("meta_instructions_csv", metavar="META_INSTRUCTION_CSV")
    parser.add_argument("instructions_csv", metavar="INSTRUCTION_CSV")
    parser.add_argument("sub_instructions_csv", metavar="SUB_INSTRUCTION_CSV")
    parser.add_argument("const_ext_csv", metavar="CONST_EXT_CSV")

    # Generated by best-decoding
    parser.add_argument("instruction_decoding_json", metavar="INSTRUCTION_DECODING_JSON")
    parser.add_argument("sub_instruction_decoding_json", metavar="SUB_INSTRUCTION_DECODING_JSON")

    # Output files
    parser.add_argument("decoder_c", metavar="DECODER_C")
    parser.add_argument("decoder_h", metavar="DECODER_H")

    args = parser.parse_args()

    global semantics_path
    global meta_instructions_csv
    global instructions_csv
    global sub_instructions_csv
    global const_ext_csv
    global instruction_decoding_json
    global sub_instruction_decoding_json
    global decoder_c
    global decoder_h
    semantics_path = args.semantics
    meta_instructions_csv = args.meta_instructions_csv
    instructions_csv = args.instructions_csv
    sub_instructions_csv = args.sub_instructions_csv
    const_ext_csv = args.const_ext_csv
    instruction_decoding_json = args.instruction_decoding_json
    sub_instruction_decoding_json = args.sub_instruction_decoding_json
    decoder_c = args.decoder_c
    decoder_h = args.decoder_h

    global meta_instructions
    global instruction_strings
    global sub_instruction_strings
    global patterns
    # Parse instructions and meta-instructions
    meta_instructions = parse_meta_instructions()
    instruction_strings = parse_instructions(instructions_csv)
    sub_instruction_strings = parse_instructions(sub_instructions_csv)
    regexes = map(to_regex, meta_instructions)
    patterns = list(map(re.compile, regexes))
    analyse_inst_mapping()
    # decoder.h
    gen_decoder_header()
    # decoder.c
    gen_macros()
    gen_decoder_switch()
    gen_execute()
    gen_functions()
    # Duplex instructions
    gen_sub_decoder()
    gen_sub_execute()
    gen_endloop()
    # auto-indent
    indent()

if __name__ == "__main__":
    main()
