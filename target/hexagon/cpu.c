/*
 * QEMU Hexagon CPU
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
#include "qapi/error.h"
#include "cpu.h"
#include "qemu-common.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "exec/exec-all.h"

static void hexagon_cpu_set_pc(CPUState *cs, vaddr value)
{
    HexagonCPU *cpu = HEXAGON_CPU(cs);

    cpu->env.cr[CR_PC] = value;
}

static bool hexagon_cpu_has_work(CPUState *cs)
{
    return true;
}

/* CPUClass::reset() */
static void hexagon_cpu_reset(CPUState *s)
{
    HexagonCPU *cpu = HEXAGON_CPU(s);
    CPUHexagonState *env = &cpu->env;

    env->cr[CR_PC] = cpu->cfg.base_vectors;

    /* XXX: HTID is expected to be 1, so we fix it to 1 */
    env->sr[CR_HTID] = 0;
}

static void hexagon_disas_set_info(CPUState *cpu, disassemble_info *info)
{
}

static void hexagon_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    HexagonCPUClass *hexcc = HEXAGON_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    qemu_init_vcpu(cs);

    hexcc->parent_realize(dev, errp);
}

static void hexagon_cpu_initfn(Object *obj)
{
    CPUState *cs = CPU(obj);
    HexagonCPU *cpu = HEXAGON_CPU(obj);
    CPUHexagonState *env = &cpu->env;

    cs->env_ptr = env;
}

static const VMStateDescription vmstate_hexagon_cpu = {
    .name = "cpu",
    .unmigratable = 1,
};

static Property hexagon_properties[] = {
    DEFINE_PROP_UINT32("base-vectors", HexagonCPU, cfg.base_vectors, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static ObjectClass *hexagon_cpu_class_by_name(const char *cpu_model)
{
    return object_class_by_name(TYPE_HEXAGON_CPU);
}

static void hexagon_cpu_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
    HexagonCPUClass *hexcc = HEXAGON_CPU_CLASS(oc);

    hexcc->parent_realize = dc->realize;
    dc->realize = hexagon_cpu_realizefn;

    hexcc->parent_reset = cc->reset;
    cc->reset = hexagon_cpu_reset;

    cc->class_by_name = hexagon_cpu_class_by_name;
    cc->has_work = hexagon_cpu_has_work;
    cc->do_interrupt = hexagon_cpu_do_interrupt;
    cc->cpu_exec_interrupt = hexagon_cpu_exec_interrupt;
    cc->dump_state = hexagon_cpu_dump_state;
    cc->set_pc = hexagon_cpu_set_pc;
    cc->gdb_read_register = hexagon_cpu_gdb_read_register;
    cc->gdb_write_register = hexagon_cpu_gdb_write_register;
    cc->handle_mmu_fault = hexagon_cpu_handle_mmu_fault;
    dc->vmsd = &vmstate_hexagon_cpu;
    dc->props = hexagon_properties;
    cc->gdb_num_core_regs = 32 + 5;
    cc->tcg_initialize = hexagon_tcg_init;

    cc->disas_set_info = hexagon_disas_set_info;
}

static const TypeInfo hexagon_cpu_type_info = {
    .name = TYPE_HEXAGON_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(HexagonCPU),
    .instance_init = hexagon_cpu_initfn,
    .class_size = sizeof(HexagonCPUClass),
    .class_init = hexagon_cpu_class_init,
};

static void hexagon_cpu_register_types(void)
{
    type_register_static(&hexagon_cpu_type_info);
}

type_init(hexagon_cpu_register_types)

int hexagon_cpu_handle_mmu_fault(CPUState *cs,
                                 vaddr address,
                                 int size,
                                 int rw,
                                 int mmu_idx) {
    cs->exception_index = 0xaa;
    cpu_dump_state(cs, stderr, fprintf, 0);
    return 1;
}
