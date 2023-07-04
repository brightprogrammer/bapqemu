#include <stdint.h>

#include "cpu.h"
#include "helper.h"
#include "tracewrap.h"
#include "qemu/log.h"

const char *regs[] = {"r0","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","s8","ra","LO","HI"};
static const int reg_max = sizeof(regs) / sizeof(regs[0]);

void HELPER(trace_newframe)(target_ulong pc)
{
    qemu_trace_newframe(pc, 0);
}

void HELPER(trace_endframe)(CPUMIPSState *env, target_ulong old_pc, uint32_t size)
{
    qemu_trace_endframe(env, old_pc, size);
}

/**
 * Load/Store a value from/to a register
 *
 * @param reg is index into the @c regs array declared at top
 * @param val is value to be stored
 * @param len is length (size) in bytes of val
 * @param ls if 0 means this is a LOAD operation, otherwise STORE operation
 *
 * @return OperandInfo
 * */
OperandInfo * load_store_reg(uint32_t reg, uint64_t val, size_t len, int ls)
{
    RegOperand * ro = g_new(RegOperand,1);
    reg_operand__init(ro);
    ro->name = g_strdup(reg < reg_max ? regs[reg] : "UNKOWN");

    OperandInfoSpecific *ois = g_new(OperandInfoSpecific,1);
    operand_info_specific__init(ois);
    ois->reg_operand = ro;

    OperandUsage *ou = g_new(OperandUsage,1);
    operand_usage__init(ou);
    if (ls == 0)
    {
        ou->read = 1;
    } else {
        ou->written = 1;
    }

    OperandInfo *oi = g_new(OperandInfo,1);
    operand_info__init(oi);
    oi->bit_length = 0;
    oi->operand_info_specific = ois;
    oi->operand_usage = ou;
    oi->value.len = len;
    oi->value.data = g_malloc(oi->value.len);

    // if reg == 0 (means r0), it should always read 0
    if(reg == 0) {
        memset(oi->value.data, 0, sizeof(val));
    } else {
        memcpy(oi->value.data, &val, len);
    }

    return oi;
}

#define LOAD_REG(reg, val)                                              \
    qemu_log("Read from (r%d) register. Val = (u%zu)0x%x\n", reg, val, sizeof(val)*8);       \
    OperandInfo *oi = load_store_reg(reg, val, sizeof(val),  0);        \
    qemu_trace_add_operand(oi, 0x1)

#define STORE_REG(reg, val)                                             \
    qemu_log("Write into (r%d) register. Val = (u%zu)0x%x\n", reg, val, sizeof(val)*8);     \
    OperandInfo *oi = load_store_reg(reg, val, sizeof(val), 1);         \
    qemu_trace_add_operand(oi, 0x2)

void HELPER(trace_load_reg32)(uint32_t reg, uint32_t val)
{
    LOAD_REG(reg, val);
}

void HELPER(trace_store_reg32)(uint32_t reg, uint32_t val)
{
    STORE_REG(val, val);
}

void HELPER(trace_load_reg64)(uint32_t reg, uint64_t val)
{
    LOAD_REG(reg, val);
}

void HELPER(trace_store_reg64)(uint32_t reg, uint64_t val)
{
    STORE_REG(reg, val);
}

//void HELPER(trace_load_eflags)(CPUMIPSState *env)
//{
//        OperandInfo *oi = load_store_reg(REG_EFLAGS, cpu_compute_eflags(env), 0);
//
//        qemu_trace_add_operand(oi, 0x1);
//}
//
//void HELPER(trace_store_eflags)(CPUMIPSState *env)
//{
//        OperandInfo *oi = load_store_reg(REG_EFLAGS, cpu_compute_eflags(env), 1);
//
//        qemu_trace_add_operand(oi, 0x2);
//}
//

/**
 * Load/Store a value from/to a memory region
 *
 * @param addr is address of memory region
 * @param val is value to be stored
 * @param len is length (size) in bytes of val
 * @param ls if 0 means this is a LOAD operation, otherwise STORE operation
 *
 * @return OperandInfo
 * */
OperandInfo * load_store_mem(uint64_t addr, const void *memptr, int ls, int len) {
    // create new memory operand
    MemOperand * mo = g_new(MemOperand,1);
    mem_operand__init(mo);
    mo->address = addr;

    // reg operand? memory operand?
    OperandInfoSpecific *ois = g_new(OperandInfoSpecific,1);
    operand_info_specific__init(ois);
    ois->mem_operand = mo;

    // did we just wrote a value or read value?
    OperandUsage *ou = g_new(OperandUsage,1);
    operand_usage__init(ou);
    if (ls == 0) {
        ou->read = 1;
    } else {
        ou->written = 1;
    }

    // sum up all information
    OperandInfo *oi = g_new(OperandInfo,1);
    operand_info__init(oi);
    oi->bit_length = len*8;
    oi->operand_info_specific = ois;
    oi->operand_usage = ou;
    oi->value.len = len;
    oi->value.data = g_malloc(oi->value.len);
    memcpy(oi->value.data, memptr, len);

    return oi;
}

// TODO : create load/store_mem, u and i, 32 and i64

#define LOAD_MEM(addr, data)                                            \
    qemu_log("Read at addr=0x%x, val=0x%x\n", addr, data);              \
    OperandInfo *oi = load_store_mem(addr, &data, 0, sizeof(data));     \
    qemu_trace_add_operand(oi, 0x1)

#define STORE_MEM(addr, data)                                           \
    qemu_log("Write at addr=0x%x, val=0x%x\n", addr, data);             \
    OperandInfo *oi = load_store_mem(addr, &data, 1, sizeof(data));     \
    qemu_trace_add_operand(oi, 0x1)

void HELPER(trace_load_mem32)(uint64_t  addr, uint32_t val) { LOAD_MEM(addr, val); }
void HELPER(trace_load_mem64)(uint64_t  addr, uint64_t val) { LOAD_MEM(addr, val); }

void HELPER(trace_store_mem32)(uint64_t addr, uint32_t val) { STORE_MEM(addr, val); }
void HELPER(trace_store_mem64)(uint64_t addr, uint64_t val) { STORE_MEM(addr, val); }
