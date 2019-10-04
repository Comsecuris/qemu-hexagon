/*
 * Hexagon helper routines.
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
#include "exec/helper-proto.h"
#include "qemu/host-utils.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "decoder.h"

#define SYSCALL  0
#define CPU_DUMP 1
#define PUTS     2
#define READN    3
#define WRITEN   4
#define EXCEPT   5
#define READ     6
#define WRITE    7
#define STACK    8
#define FWRITE   9
#define EXIT    10

void helper_raise_exception(CPUHexagonState *env, uint32_t index)
{
    CPUState *cs = CPU(hexagon_env_get_cpu(env));
    cs->exception_index = index;
    fprintf(stderr, "Raised exception number %d!", index);
    cpu_dump_state(cs, stderr, fprintf, 0);
    exit(EXIT_SUCCESS);
}

void helper_handle_trap(CPUHexagonState *env, uint32_t index)
{
    // TODO: Switch to semi-hosting syscalls style
    CPUState *cs = CPU(hexagon_env_get_cpu(env));
    FILE *out = 0;
    switch(index) {
        case CPU_DUMP:
            cpu_dump_state(cs, stderr, fprintf, 0);
            break;
        case SYSCALL:
            cs->exception_index = EXCP_TRAP_INSN;
            cpu_loop_exit(cs);
            break;
        case PUTS:
            puts((char *)g2h(env->gpr[0]));
            break;
        case READN:
        {
            int scanned = scanf("\n%d", &env->gpr[0]);
            assert(scanned == 1);
            break;
        }
        case WRITEN:
            fprintf(stderr, "DEBUG:%d\n", env->gpr[28]);
            break;
        case EXCEPT:
            helper_raise_exception(env, env->gpr_new[0]);
            break;
        case READ:
            env->gpr[0] = read(STDIN_FILENO, (void *)g2h(env->gpr[0]), env->gpr[1]);
            break;
        case WRITE:
            env->gpr[0] = write(STDOUT_FILENO, (void *)g2h(env->gpr[0]), env->gpr[1]);
            break;
        case STACK:
            fprintf(stderr, "STACK TRACE:\n");
            for (int i = 0; i < 4; i++) {
                fprintf(stderr, "%#8.8x: ", env->gpr[29] + 4 * (4 * i));
                for (int j = 0; j < 4; j++)
                    fprintf(stderr, "%#8.8x ", *((unsigned int *)g2h(env->gpr[29] + 4 * (4 * i + j))));
                fprintf(stderr, "\n");
            }
            break;
        case FWRITE:
            out = fopen("output", "ab");
            fwrite((void *)g2h(env->gpr[0]), env->gpr[1], 1, out);
            fclose(out);
            break;
        case EXIT:
            exit(EXIT_SUCCESS);
            break;
        default:
            assert(false && "Unhandled trap0 argument!");
    }
}

static inline int div_prepare(CPUHexagonState *env, uint32_t x, uint32_t y)
{
    if (y == 0) {
        helper_raise_exception(env, EXCP_HW_EXCP);
        return 0;
    }
    return 1;
}

uint32_t helper_divu(CPUHexagonState *env, uint32_t x, uint32_t y)
{
    if (!div_prepare(env, x, y)) {
        return 0;
    }
    return x / y;
}

uint32_t helper_mod(uint32_t x, uint32_t y)
{
    return x % y;
}
