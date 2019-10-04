/*
 * Hexagon emulation for qemu: main translation routines.
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

#include "qemu/osdep.h"
#include "cpu.h"
#include "decoder.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg-op.h"
#include "tcg.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "exec/helper-gen.h"
#include "exec/translator.h"

#include "trace-tcg.h"
#include "exec/log.h"

#define LOG_DIS(...) qemu_log_mask(CPU_LOG_TB_IN_ASM, ## __VA_ARGS__)
#define EXTRACT_FIELD(src, start, end) \
    (((src) >> start) & ((1 << (end - start + 1)) - 1))
#define EXTRACT_FIELD_2(src, start, end, start2, end2) \
    (EXTRACT_FIELD(src, start2, end2) << (end - start + 1)) | \
    (EXTRACT_FIELD(src, start, end))

//#define DUMP_EVERY_INST

TCGv GPR[32];
TCGv CR[32];
TCGv SR[64];
TCGv GPR_new[32];
TCGv CR_new[32];
TCGv PC_written;
TCGv PC_trace;
TCGv SA[2];
TCGv LC[2];
TCGv LPCFG;

#include "exec/gen-icount.h"

static const char *general_regnames[] =
{
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
    "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
};

static const char *general_regnames_new[] =
{
    "r0.new", "r1.new", "r2.new", "r3.new", "r4.new", "r5.new", "r6.new",
    "r7.new", "r8.new", "r9.new", "r10.new", "r11.new", "r12.new", "r13.new",
    "r14.new", "r15.new", "r16.new", "r17.new", "r18.new", "r19.new",
    "r20.new", "r21.new", "r22.new", "r23.new", "r24.new", "r25.new",
    "r26.new", "r27.new", "r28.new", "r29.new", "r30.new", "r31.new",
};

static const char *control_regnames[] =
{
    "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7",
    "c8", "c9", "c10", "c11", "c12", "c13", "c14", "c15",
    "c16", "c17", "c18", "c19", "c20", "c21", "c22", "c23",
    "c24", "c25", "c26", "c27", "c28", "c29", "c30", "c31",
};

static const char *control_regnames_new[] =
{
    "c0.new", "c1.new", "c2.new", "c3.new", "c4.new", "c5.new", "c6.new",
    "c7.new", "c8.new", "c9.new", "c10.new", "c11.new", "c12.new", "c13.new",
    "c14.new", "c15.new", "c16.new", "c17.new", "c18.new", "c19.new",
    "c20.new", "c21.new", "c22.new", "c23.new", "c24.new", "c25.new",
    "c26.new", "c27.new", "c28.new", "c29.new", "c30.new", "c31.new",
};

static const char *system_regnames[] =
{
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
    "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
    "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",
    "s32", "s33", "s34", "s35", "s36", "s37", "s38", "s39",
    "s40", "s41", "s42", "s43", "s44", "s45", "s46", "s47",
    "s48", "s49", "s50", "s51", "s52", "s53", "s54", "s55",
    "s56", "s57", "s58", "s59", "s60", "s61", "s62", "s63",
};

static const char *hwloop_regnames[] =
{
    "sa0", "sa1", "lc0", "lc1", "lpcfg",
};

static int first_sub_type[] =  {0, 0, 1, 4, 4, 4, 4, 4, 0, 1, 2, 2, 0, 1, 3};
static int last_sub_type[] = {0, 1, 1, 4, 0, 1, 2, 3, 2, 2, 2, 3, 3, 3, 3};

static void clear_d_reg_helper(d_reg_list list)
{
    if (list == NULL)
        return;
    if (list->next == NULL)
        free(list);
    else
        clear_d_reg_helper(list->next);
}

static inline void clear_destination_reg(DisasContext *dc)
{
    regs_t *regs = &(dc->regs);
    d_reg_list *list = &regs->destination;
    clear_d_reg_helper(*list);
    *list = NULL;
}

static inline void extend_destination_reg(d_reg_list* list, d_reg_list ext)
{
    if (ext != 0) {
        /* Copy only the first destination register,
           if there are two it means that the destination is a 64bit register */
        //assert(ext->next == NULL && "Destination list contains more than 1 node!");
        clear_d_reg_helper(ext->next);
        ext->next = *list;
        *list = ext;
    }
}

static inline void regs_append(DisasContext *dc, regs_t regs) {
    // If no output reg has been written add -1 to the list
    if (regs.destination == NULL)
        push_destination_reg(&regs.destination, -1);
    (dc->regs).written |= regs.written;
    (dc->regs).written |= regs.conditional;
    (dc->regs).conditional |= regs.conditional;
    extend_destination_reg(&(dc->regs.destination), regs.destination);
    // If the predicate has been written note it in the dc
    if ((dc->regs).written & (uint64_t)1 << (CR_P + 32))
        dc->is_pre_written = true;
}

static inline uint8_t compute_collapse(DisasContext *dc, int placed) {
    uint8_t written_regs = 0;
    for (int i = 0; i < placed; i++)
        written_regs |= (dc->ordered[i])->written;
    return written_regs;
}

static inline int add_solved_deps(DisasContext *dc,
                                  int *placed,
                                  uint8_t written_regs) {
    int i = 0;
    for (i = 0; i <= dc->i; i++) {
        // Check if all the read registers have been written //
        if (dc->original[i] != NULL) {
            uint8_t needed_regs = (dc->original[i])->read &
                                  ~(dc->original[i])->written;
            if ((needed_regs & written_regs) == needed_regs) {
                dc->ordered[*placed] = dc->original[i];
                (*placed)++;
                dc->original[i] = NULL;
            }
        }
    }
    return i - 1;
}

static inline void print_op(TCGOp *op) {
    if (op == 0) {
        LOG_DIS("NULL");
        return;
    }
    TCGOpcode c = op->opc;
    TCGOpDef *def = &tcg_op_defs[c];
    LOG_DIS("%s\n", def->name);
}

static inline void reorder_ops(DisasContext *dc) {
    //for (int i = dc->i; i >= 0; i--) {
    //    deps_t *to_move = dc->ordered[i];
    //    tcg_op_move_range_after(to_move->begin, to_move->end, dc->packet_first_op);
    //}
    for (int i = 0; i <= dc->i; i++) {
        deps_t *to_move = dc->ordered[i];
        qemu_log("from: %p ", to_move->begin);
        qemu_log("to: %p\n", to_move->end);
    }
    TCGOp *pos = dc->packet_first_op;
    for (int i = 0; i <= dc->i; i++) {
        deps_t *to_move = dc->ordered[i];
        tcg_op_move_range_after(to_move->begin, to_move->end, pos);
        pos = to_move->end;
    }
}

static inline void solve_dependencies(DisasContext *dc) {
    bool ordering_needed = false;
    int placed = 0, order = 0;
    uint8_t written_regs = 0;

    for(int i = 0; i <= dc->i; i++)
        dc->original[i] = &(dc->deps[i]);

    while (placed <= dc->i) {
        // Update collapse of written regs 
        written_regs = compute_collapse(dc, placed);
        // Add instructions whose deps are already solved 
        order = add_solved_deps(dc, &placed, written_regs);
        if (order != placed - 1) {
            ordering_needed = true;
        }
    }

    // Reorder only if needed
    if (ordering_needed) {
        reorder_ops(dc);
    }
}

static inline void handle_packet_begin(DisasContext *dc)
{
   LOG_DIS("{ ");
   dc->new_packet = false;
}

static inline void handle_packet_end(DisasContext *dc)
{
    LOG_DIS(" }");

    solve_dependencies(dc);

    /* Commit temporary registers to CPU registers */
    for (int i = 0; i < 32; i++) {
        if (GET_USED_REG(dc->regs, i))
            tcg_gen_mov_tl(GPR[i], GPR_new[i]);
    }
    for (int i = 0; i < 32; i++) {
        if (i != CR_PC && GET_USED_REG(dc->regs, (i + 32)))
            tcg_gen_mov_tl(CR[i], CR_new[i]);
    }

    // Clear temp registers
    for (int i = 0; i < 32; i++) {
        if (GET_USED_REG(dc->regs, i))
            tcg_gen_movi_tl(GPR_new[i], 0);
    }
    for (int i = 0; i < 32; i++) {
        if (i != CR_PC && GET_USED_REG(dc->regs, (i + 32)))
            tcg_gen_movi_tl(CR_new[i], 0);
    }

    /* Detect if CR_PC has been written */
    if (GET_USED_REG(dc->regs, (CR_PC + 32))) {
        dc->pc_written = true;
        // Emit control flow runtime handler
        // If pc has not been written increment PC
        TCGv tmp = tcg_temp_new_i32();
        TCGv zero = tcg_const_i32(0);
        TCGv pc = tcg_const_i32(dc->instruction_pc);
        tcg_gen_addi_i32(tmp, pc, 4);
        tcg_gen_movcond_i32(TCG_COND_GT, CR[CR_PC], PC_written, zero, CR[CR_PC], tmp);
        tcg_gen_movi_i32(PC_written, 0);
    }

    /* Inject initialization for conditional registers */
    bool first_move = true;
    TCGOp *begin_op = NULL;
    for (int i = 0; i < 32; i++) {
        if (GET_COND_REG(dc->regs, i)) {
            tcg_gen_mov_tl(GPR_new[i], GPR[i]);
            if (first_move) {
                begin_op = tcg_last_op();
                first_move = false;
            }
        }
    }
    for (int i = 0; i < 32; i++) {
        if (i != CR_PC && GET_COND_REG(dc->regs, (i + 32))) {
            tcg_gen_mov_tl(CR_new[i], CR[i]);
            if (first_move) {
                begin_op = tcg_last_op();
                first_move = false;
            }
        }
    }

    /* Mark the end of the register initialization sequence */
    TCGOp *end_op = tcg_last_op();

    if (begin_op != NULL)
        tcg_op_move_range_after(begin_op, end_op, dc->packet_first_op);

    clear_destination_reg(dc);
    memset(&dc->regs, 0, sizeof(regs_t));
    memset(&dc->deps, 0, 4 * sizeof(deps_t));
    memset(&dc->original, 0, 4 * sizeof(deps_t *));
    memset(&dc->ordered, 0, 4 * sizeof(deps_t *));
    dc->is_pre_written = false;
    dc->i = -1;

    /* Handle hardware loops */
    if (dc->endloop[0] || dc->endloop[1]) {
        if (dc->endloop[0] && dc->endloop[1])
            endloop01();
        else if (dc->endloop[0]) {
            LOG_DIS(" :endloop0");
            endloop0();
        }
        else if (dc->endloop[1]) {
            LOG_DIS(" :endloop1");
            endloop1();
        }
        dc->pc_written = true;
        // Emit control flow runtime handler
        // If pc has not been written increment PC
        TCGv tmp = tcg_temp_new_i32();
        TCGv zero = tcg_const_i32(0);
        TCGv pc = tcg_const_i32(dc->instruction_pc);
        tcg_gen_addi_i32(tmp, pc, 4);
        tcg_gen_movcond_i32(TCG_COND_GT, CR[CR_PC], PC_written, zero, CR[CR_PC], tmp);
        tcg_gen_movi_tl(PC_written, 0);
    }
    dc->endloop[0] = false;
    dc->endloop[1] = false;
};

static inline void decode_packet(DisasContext *dc, CPUState *cs, uint32_t ir)
{
    if (dc->new_packet) {
        /* Set the beginning of the packet list */
        dc->packet_first_op = tcg_last_op();
    }

    /* Update the PC at each instruction */
    tcg_gen_movi_tl(PC_trace, dc->instruction_pc);

    dc->i++;
    /* Instruction begin */
    dc->deps[dc->i].begin = tcg_last_op();

    dc->ir = ir;
    LOG_DIS("%8.8x\t", dc->ir);
    bool packet_end = false;
    /* TODO: Assert that we have at most 4 instructions in a packet */
    uint8_t parse_bits = EXTRACT_FIELD(ir, 14, 15);
    uint8_t iclass_bits = EXTRACT_FIELD(ir, 28, 31);
    uint32_t insn = 0, first_insn = 0, last_insn = 0;
    uint32_t last_sub = 0, first_sub = 0;
    /* Handle constant extenders (they provide the upper 26 bits) */
    switch (parse_bits) {
        case 0x1:
            break;
        /* endloop */
        case 0x2:
            if (dc->i == 0)
              dc->endloop[0] = true;
            if (dc->i == 1)
              dc->endloop[1] = true;
            break;
        /* End of packet */
        case 0x3:
            packet_end = true;
            break;
        /* Duplex */
        case 0x0:
            dc->duplex = true;
            packet_end = true;
            break;
        default:
            cpu_abort(CPU(dc->cpu),
                    "Hexagon: illegal value for ParseBits=%x\n", parse_bits);
    }
    if (parse_bits != 0x0 && iclass_bits == 0x0) {
        dc->extender_present = true;
        dc->const_ext = EXTRACT_FIELD_2(ir, 0, 13, 16, 27);
        dc->const_ext <<= 6;
        if (dc->new_packet) {
            LOG_DIS("\t");
            handle_packet_begin(dc);
        } else
            LOG_DIS("\t  ");
        LOG_DIS("immext(#%" PRIu32 ")\n", dc->const_ext);
        dc->deps[dc->i].end = tcg_last_op();
        /* TODO: Assert that packet does not contain only an immext */
        return;
    }
    if (dc->duplex) {
        iclass_bits = EXTRACT_FIELD_2(ir, 13, 13, 29, 31);
        assert(iclass_bits < 0xf && "Illegal value for ICLASS bits!\n");
        /* Craft slot 1 sub-instruction */
        first_sub = (ir >> 16) & 0x1fff;
        first_sub |= (first_sub_type[iclass_bits] << 13);
        first_insn = sub_decode(first_sub);
        LOG_DIS("%d ", first_insn);
        /* Craft slot 0 sub-instruction */
        last_sub = ir & 0x1fff;
        last_sub |= (last_sub_type[iclass_bits] << 13);
        last_insn = sub_decode(last_sub);
        LOG_DIS("%d\t", last_insn);
    } else {
        insn = decode(ir);
        LOG_DIS("%d\t", insn);
    }
    if (dc->new_packet) {
        handle_packet_begin(dc);
    }
    else
        LOG_DIS("  ");
    if (dc->duplex) {
        dc->ir = first_sub;
        regs_t new_regs = sub_execute(first_insn, dc);
        regs_append(dc, new_regs);
        LOG_DIS(" ");
        dc->ir = last_sub;
        /* Constant extender must be used only by sub-instruction in slot 1 */
        if (dc->extender_present) {
            dc->extender_present = false;
        }
        new_regs = sub_execute(last_insn, dc);
        regs_append(dc, new_regs);
        dc->duplex = false;
    } else {
        regs_t new_regs = execute(insn, dc);
        regs_append(dc, new_regs);
    }

    /* Reset Constant Extender */
    if (dc->extender_present) {
        dc->extender_present = false;
        dc->const_ext = 0;
    }

#ifdef DUMP_EVERY_INST
            /* Inject CPU dump */
        	TCGv_i32 tmp_0 = tcg_const_i32(1);
        	gen_helper_handle_trap(cpu_env, tmp_0);
        	tcg_temp_free_i32(tmp_0);

            /* Inject stack trace */
        	TCGv_i32 tmp_1 = tcg_const_i32(8);
        	gen_helper_handle_trap(cpu_env, tmp_1);
        	tcg_temp_free_i32(tmp_1);
#endif

    /* Instruction end */
    dc->deps[dc->i].end = tcg_last_op();

    if (packet_end) {
        handle_packet_end(dc);
        dc->new_packet = true;

    }
    /* If instruction is a trap0 or if pc has been written, close block */
    if (ir == 0x5400c000 || dc->pc_written) {
        dc->block_end = true;
        dc->pc_written = false;
    }
    LOG_DIS("\n");

};

/* generate intermediate code for basic block 'tb'.  */
void gen_intermediate_code(CPUState *cs, struct TranslationBlock *tb)
{
    CPUHexagonState *env = cs->env_ptr;
    HexagonCPU *cpu = hexagon_env_get_cpu(env);
    uint32_t pc_start;
    struct DisasContext ctx = { 0 };
    struct DisasContext *dc = &ctx;
    int num_insns;
    int max_insns;
    uint32_t insn;
    uint8_t parse_bits;

    pc_start = tb->pc;
    dc->cpu = cpu;
    dc->tb = tb;
    dc->old_pc = pc_start;
    dc->instruction_pc = pc_start;
    dc->pc = pc_start;
    dc->new_packet = true;
    dc->i = -1;

    if (pc_start & 3) {
        cpu_abort(cs, "Hexagon: unaligned PC=%x\n", pc_start);
    }

    num_insns = 0;
    max_insns = tb_cflags(tb) & CF_COUNT_MASK;
    if (max_insns == 0) {
    max_insns = CF_COUNT_MASK;
    }
    if (max_insns > TCG_MAX_INSNS) {
        max_insns = TCG_MAX_INSNS;
    }

    gen_tb_start(tb);
    do
    {
        if (dc->new_packet) {
            /* Lookahead to find the next packet address */
            target_ulong pc_iter = dc->instruction_pc;
            insn = cpu_ldl_code(env, pc_iter);
            parse_bits = EXTRACT_FIELD(insn, 14, 15);
            while (parse_bits != 0x3 && parse_bits != 0x0) {
                insn = cpu_ldl_code(env, pc_iter);
                parse_bits = EXTRACT_FIELD(insn, 14, 15);
                pc_iter += 4;
            }
            if (pc_iter == dc->instruction_pc)
                pc_iter += 4;
            dc->npc = pc_iter;

            /* Emit an instruction start only when a packet begins */
            tcg_gen_insn_start(dc->pc);
            num_insns++;
            dc->pc = dc->instruction_pc;
        }

        /* Pretty disas.  */
        LOG_DIS("%8.8x:\t", dc->instruction_pc);

        /* Fetch instructions from memory and decode them */
        insn = cpu_ldl_code(env, dc->instruction_pc);
        decode_packet(dc, cs, insn);
        dc->old_pc = dc->instruction_pc;
        dc->instruction_pc += 4;
    } while (!dc->block_end);

    /* Use the hash table to find the next TB */
    tcg_gen_exit_tb(NULL, 0);
    gen_tb_end(tb, num_insns);

    tb->size = dc->instruction_pc - pc_start;
    tb->icount = num_insns;
}

void hexagon_cpu_dump_state(CPUState *cs, FILE *f, fprintf_function cpu_fprintf,
                       int flags)
{
    CPUHexagonState *env = cs->env_ptr;
    int i = 0;

    cpu_fprintf(f, "\n\nIN: PC=%x %s\n",
                env->pc_trace, lookup_symbol(env->pc_trace));
    for (i = 0; i < 32; i++) {
        cpu_fprintf(f, "r%2.2d=%8.8x ", i, env->gpr[i]);
        if ((i + 1) % 4 == 0)
            cpu_fprintf(f, "\n");
        }
    cpu_fprintf(f, "LC0=%8.8x LC1=%8.8x SA0=%8.8x SA1=%8.8x\n", env->lc[0],
                                                                env->lc[1],
                                                                env->sa[0],
                                                                env->sa[1]);
    cpu_fprintf(f, "LPCFG=%8.8x GP=%8.8x ", env->lpcfg, env->cr[11]);
    for (i = 0; i < 4; i++) {
        int8_t p = (env->cr[CR_P] & (0xff << 8 * i)) >> 8 * i;
        cpu_fprintf(f, "p%2.2d=%x ", i, (char) p & 0xff);
    }
    cpu_fprintf(f, "\nPC_written=%x ", env->pc_written);
    cpu_fprintf(f, "evb=%x ", env->sr[16]);
    cpu_fprintf(f, "PC=%x\n", env->cr[9]);
}

void hexagon_tcg_init(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(GPR); i++) {
        GPR[i] = tcg_global_mem_new(cpu_env,
                offsetof(CPUHexagonState, gpr[i]),
                general_regnames[i]);
    }

    for (i = 0; i < ARRAY_SIZE(CR); i++) {
        CR[i] = tcg_global_mem_new_i32(cpu_env,
                offsetof(CPUHexagonState, cr[i]),
                control_regnames[i]);
    }

	for (i = 0; i < ARRAY_SIZE(SR); i++) {
        SR[i] = tcg_global_mem_new_i32(cpu_env,
                offsetof(CPUHexagonState, sr[i]),
                system_regnames[i]);
    }

    for (i = 0; i < ARRAY_SIZE(GPR_new); i++) {
        GPR_new[i] = tcg_global_mem_new(cpu_env,
                offsetof(CPUHexagonState, gpr_new[i]),
                general_regnames_new[i]);
    }

    for (i = 0; i < ARRAY_SIZE(CR_new); i++) {
        CR_new[i] = tcg_global_mem_new(cpu_env,
                offsetof(CPUHexagonState, cr_new[i]),
                control_regnames_new[i]);
    }

    PC_written = tcg_global_mem_new(cpu_env,
                                    offsetof(CPUHexagonState, pc_written),
                                    "pc_written");

    PC_trace = tcg_global_mem_new(cpu_env,
                                  offsetof(CPUHexagonState, pc_trace),
                                  "pc_trace");

    for (i = 0; i < ARRAY_SIZE(SA); i++) {
        SA[i] = tcg_global_mem_new(cpu_env,
                offsetof(CPUHexagonState, sa[i]),
                hwloop_regnames[i]);
    }

    for (i = 0; i < ARRAY_SIZE(LC); i++) {
        LC[i] = tcg_global_mem_new(cpu_env,
                offsetof(CPUHexagonState, lc[i]),
                hwloop_regnames[i+2]);
    }

    LPCFG = tcg_global_mem_new(cpu_env,
                               offsetof(CPUHexagonState, lpcfg),
                               hwloop_regnames[4]);

}

void restore_state_to_opc(CPUHexagonState *env, TranslationBlock *tb,
                          target_ulong *data)
{
}
