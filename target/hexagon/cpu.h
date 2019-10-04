/*
 * Hexagon virtual CPU header
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

#ifndef HEXAGON_CPU_H
#define HEXAGON_CPU_H

#include "qemu-common.h"
#include "cpu-qom.h"

#define TARGET_LONG_BITS 32

#define CPUArchState struct CPUHexagonState

#include "exec/cpu-defs.h"
#include "fpu/softfloat.h"

#define EXCP_CPU_DUMP   1
#define EXCP_HW_EXCP    2
#define EXCP_TRAP_INSN  3

// General Purpose Registers Aliases
#define GPR_SP 29
#define GPR_FP 30
#define GPR_LR 31

// Control Registers Aliases
#define CR_SA0 0
#define CR_LC0 1
#define CR_SA1 2
#define CR_LC1 3
#define CR_P 4
#define CR_reserved 5
#define CR_M0 6
#define CR_M1 7
#define CR_USR 8
#define CR_HTID 8
#define CR_PC 9
#define CR_UGP 10
#define CR_GP 11
#define CR_CS0 12
#define CR_CS1 13
#define CR_UPCYCLELO 14
#define CR_UPCYCLEHI 15
#define CR_FRAMELIMIT 16
#define CR_FRAMEKEY 17
#define CR_PKTCOUNTLO 18
#define CR_PKTCOUNTHI 19
#define CR_UTIMERLO 30
#define CR_UTIMERHI 31

struct CPUHexagonState;
typedef struct CPUHexagonState CPUHexagonState;

struct CPUHexagonState {

    uint32_t gpr[32];
    uint32_t cr[32];
    uint32_t sr[64];

    /* Temporary registers to handle .new predicates and exceptions */
    uint32_t gpr_new[32];
    uint32_t cr_new[32];

    uint32_t pc_written;
    uint32_t pc_trace;

    uint32_t sa[2];
    uint32_t lc[2];
    uint32_t lpcfg;


    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    CPU_COMMON
};

/**
 * HexagonCPU:
 * @env: #CPUHexagonState
 *
 * A Hexagon CPU.
 */
struct HexagonCPU {
    /*< private >*/
    CPUState parent_obj;

    /*< public >*/
    
    /* Microblaze Configuration Settings */
    struct {
        uint32_t base_vectors;
    } cfg;

    CPUHexagonState env;
};

static inline HexagonCPU *hexagon_env_get_cpu(CPUHexagonState *env)
{
    return container_of(env, HexagonCPU, env);
}

#define ENV_GET_CPU(e) CPU(hexagon_env_get_cpu(e))

#define ENV_OFFSET offsetof(HexagonCPU, env)

void hexagon_cpu_do_interrupt(CPUState *cs);
bool hexagon_cpu_exec_interrupt(CPUState *cs, int int_req);
void hexagon_cpu_dump_state(CPUState *cpu,
                            FILE *f,
                            fprintf_function cpu_fprintf,
                            int flags);
hwaddr hexagon_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);
int hexagon_cpu_gdb_read_register(CPUState *cpu, uint8_t *buf, int reg);
int hexagon_cpu_gdb_write_register(CPUState *cpu, uint8_t *buf, int reg);
int hexagon_cpu_handle_mmu_fault(CPUState *cs,
                                  vaddr address,
                                  int size,
                                  int rw,
                                  int mmu_idx);

void hexagon_tcg_init(void);
/* you can call this signal handler from your SIGBUS and SIGSEGV
   signal handlers to inform the virtual CPU of exceptions. non zero
   is returned if the signal was handled by the virtual CPU.  */
int cpu_hexagon_signal_handler(int host_signum, void *pinfo,
                          void *puc);

#define TARGET_PAGE_BITS 12

#define TARGET_PHYS_ADDR_SPACE_BITS 32
#define TARGET_VIRT_ADDR_SPACE_BITS 32

#define CPU_RESOLVING_TYPE TYPE_HEXAGON_CPU

#define cpu_init(cpu_model) cpu_generic_init(TYPE_HEXAGON_CPU, cpu_model)

#define cpu_signal_handler cpu_hexagon_signal_handler

#include "exec/cpu-all.h"

/* Exceptions */
#define EXCP_BREAK    -1

/* MMU modes definitions */
#define MMU_MODE0_SUFFIX _user
#define MMU_USER_IDX        0

target_ulong do_hexagon_semihosting(CPUHexagonState *env);

static inline void cpu_get_tb_cpu_state(CPUHexagonState *env, target_ulong *pc,
                                        target_ulong *cs_base, uint32_t *flags)
{
    *pc = env->cr[CR_PC];
    *cs_base = 0;
    *flags = 0;
}

#endif
