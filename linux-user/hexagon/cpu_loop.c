/*
 *  qemu user cpu loop
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "cpu_loop-common.h"

void cpu_loop(CPUHexagonState *env)
{
    CPUState *cs = CPU(hexagon_env_get_cpu(env));
    int trapnr;
    target_siginfo_t info;

    while (1) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr) {
        case 0xaa:
            {
                info.si_signo = TARGET_SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, QEMU_SI_FAULT, &info);
            }
            break;
        case EXCP_TRAP_INSN:
            /* Semihosing syscall.  */
            env->cr[CR_PC] += 4;
            env->gpr[0] = do_hexagon_semihosting(env);
            break;
        default:
            //printf ("Unhandled trap: 0x%x\n", trapnr);
            //cpu_dump_state(cs, stderr, fprintf, 0);
            //exit(EXIT_FAILURE);
            ;
        }
        process_pending_signals (env);
    }
}

void target_cpu_copy_regs(CPUArchState *env, struct target_pt_regs *regs)
{
   for(int i = 0; i < 32; i++) {
       env->gpr[i] = regs->gpr[i];
       env->cr[i] = regs->cr[i];
   }
   for(int i = 0; i < 64; i++) {
       env->sr[i] = regs->sr[i];
   }

    CPUState *cpu = ENV_GET_CPU(env);
    TaskState *ts = cpu->opaque;
    struct image_info *info = ts->info;
    ts->stack_base = info->start_stack;
    ts->heap_base = info->brk;
    /* This will be filled in on the first SYS_HEAPINFO call.  */
    ts->heap_limit = 0;
}
