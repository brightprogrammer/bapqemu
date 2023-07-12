#include <stdint.h>

#include "cpu.h"
#include "tracewrap.h"
#include "qemu/log.h"
#include "exec/helper-proto.h"
#include "exec/memop.h"

#define MIPS_INSN_SIZE 4

const char *regs[] = {"r0","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","s8","ra","LO","HI"};
static const int reg_max = sizeof(regs) / sizeof(regs[0]);

void HELPER(trace_newframe)(uint64_t pc) { qemu_trace_newframe(pc, 0); }
void HELPER(trace_endframe)(CPUMIPSState *env, uint64_t pc) { qemu_trace_endframe(env, pc, MIPS_INSN_SIZE); }
void HELPER(trace_mode)(void *mode) { qemu_trace_set_mode(mode); }

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
OperandInfo * build_load_store_reg_op(uint32_t reg, uint64_t val, size_t len, int ls) {
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

/**
 * load/store operations for 32 bit registers
 * function is declared in tracewrap.h and is defined per architecture
 * */
OperandInfo *load_store_reg(uint32_t reg, uint32_t val, int ls) {
    return build_load_store_reg_op(reg, val, sizeof(val), ls);
}
void HELPER(trace_load_reg32)(uint32_t reg, uint32_t val) { load_store_reg(reg, val, 0); }
void HELPER(trace_store_reg32)(uint32_t reg, uint32_t val) { load_store_reg(reg, val, 1); }

#ifdef TARGET_MIPS64
/**
 * load/store operations for 64 bit registers
 * again, declared in tracewrap.h and defined here
 * */
OperandInfo *load_store_reg64(uint32_t reg, uint64_t val, int ls) {
    return build_load_store_reg_op(reg, val, sizeof(val), ls);
}
void HELPER(trace_load_reg64)(uint32_t reg, uint64_t val) { load_store_reg64(reg, val, 0); }
void HELPER(trace_store_reg64)(uint32_t reg, uint64_t val) { load_store_reg64(reg, val, 1); }
#endif

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
OperandInfo * load_store_mem(uint64_t addr, int ls, const void* data, size_t data_size) {
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
    oi->bit_length = data_size*8;
    oi->operand_info_specific = ois;
    oi->operand_usage = ou;
    oi->value.len = data_size;
    oi->value.data = g_malloc(oi->value.len);
    memcpy(oi->value.data, data, data_size);

    return oi;
}

void HELPER(trace_load_mem)(uint32_t addr, uint32_t val, MemOp op) {
    qemu_log("LOAD at 0x%lx size: %d data: 0x%lx\n", (unsigned long) addr, memop_size(op), (unsigned long) val);
    OperandInfo *oi = load_store_mem(addr, 0, &val, memop_size(op));
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_mem)(uint32_t addr, uint32_t val, MemOp op) {
    qemu_log("STORE at 0x%lx size: %d data: 0x%lx\n", (unsigned long) addr, memop_size(op), (unsigned long) val);
    OperandInfo *oi = load_store_mem(addr, 1, &val, memop_size(op));
    qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_load_mem_i64)(uint32_t addr, uint64_t val, MemOp op) {
    qemu_log("LOAD at 0x%lx size: %d data: 0x%llx\n", (unsigned long) addr, memop_size(op), (unsigned long long) val);
    OperandInfo *oi = load_store_mem(addr, 0, &val, memop_size(op));
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_mem_i64)(uint32_t addr, uint64_t val, MemOp op) {
    qemu_log("STORE at 0x%lx size: %d data: 0x%llx\n", (unsigned long) addr, memop_size(op), (unsigned long long) val);
    OperandInfo *oi = load_store_mem(addr, 1, &val, memop_size(op));
    qemu_trace_add_operand(oi, 0x2);
}

#ifdef TARGET_MIPS64
void HELPER(trace_load_mem64)(uint64_t addr, uint64_t val, MemOp op) {
    qemu_log("LOAD at 0x%llx size: %d data: 0x%llx\n", (unsigned long long) addr, memop_size(op), (unsigned long long) val);
    OperandInfo *oi = load_store_mem(addr, 0, &val, memop_size(op));
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_mem64)(uint64_t addr, uint64_t val, MemOp op) {
    qemu_log("STORE at 0x%llx size: %d data: 0x%llx\n", (unsigned long long) addr, memop_size(op), (unsigned long long) val);
    OperandInfo *oi = load_store_mem(addr, 1, &val, memop_size(op));
    qemu_trace_add_operand(oi, 0x2);
}
#endif
