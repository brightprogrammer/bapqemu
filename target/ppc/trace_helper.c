#include "tracewrap.h"
#include "exec/helper-proto.h"

#include "trace_helper.h"


/*
 * QEMUs helper.
 */

void HELPER(trace_newframe)(uint32_t pc)
{
    qemu_trace_newframe(pc, 0);
}

void HELPER(trace_endframe)(CPUPPCState *state, uint32_t pc)
{
    qemu_trace_endframe(state, pc, PPC_INSN_SIZE);
}

void HELPER(trace_load_reg)(uint32_t reg, uint32_t val)
{
    OperandInfo *oi = load_store_reg(reg, val, 0);
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_reg)(uint32_t reg, uint32_t val)
{
    OperandInfo *oi = load_store_reg(reg, val, 1);
    qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_store_crf_reg)(uint32_t crf, uint32_t val)
{
    OperandInfo *oi = load_store_crf_reg(crf, val, 1);
    qemu_trace_add_operand(oi, 0x2);
}

void HELPER(trace_mode)(void *mode) { qemu_trace_set_mode(mode); }

#ifdef TARGET_PPC64
void HELPER(trace_load_reg64)(uint32_t reg, uint64_t val)
{
    OperandInfo *oi = load_store_reg64(reg, val, 0);
    qemu_trace_add_operand(oi, 0x1);
}

void HELPER(trace_store_reg64)(uint32_t reg, uint64_t val)
{
    OperandInfo *oi = load_store_reg64(reg, val, 1);
    qemu_trace_add_operand(oi, 0x2);
}
#endif

/*
 * Build frames
 *
 * Functions to fill the actual frame data.
 */

/**
 * \brief Builds a new register load/store operand and returns it.
 *
 * \param name The register name.
 * \param ls If set to 0 the usage flag is set to "read". Otherwise the usage flag is set to "written".
 * \param data Data written to the register.
 * \param data_size Size of the data in bytes.
 * \return OperandInfo* Pointer to the operand for a BAP frame.
 */
static OperandInfo *build_load_store_reg_op(const char *name, int ls, const void *data, size_t data_size) {
    RegOperand * ro = g_new(RegOperand, 1);
    reg_operand__init(ro);
    ro->name = strdup(name);

    OperandInfoSpecific *ois = g_new(OperandInfoSpecific, 1);
    operand_info_specific__init(ois);
    ois->reg_operand = ro;

    OperandUsage *ou = g_new(OperandUsage, 1);
    operand_usage__init(ou);
    if (ls == 0) {
        ou->read = 1;
    } else {
        ou->written = 1;
    }
    OperandInfo *oi = g_new(OperandInfo, 1);
    operand_info__init(oi);
    oi->bit_length = 0;
    oi->operand_info_specific = ois;
    oi->operand_usage = ou;
    oi->value.len = data_size;
    oi->value.data = g_malloc(oi->value.len);
    memcpy(oi->value.data, data, data_size);

    return oi;
}

OperandInfo *load_store_reg(uint32_t reg, uint32_t val, int ls) {
    const char *name = ppc_gpr_reg_names[reg];
    return build_load_store_reg_op(name, ls, &val, sizeof(val));
}

OperandInfo *load_store_reg64(uint32_t reg, uint64_t val, int ls) {
    const char *name = ppc_gpr_reg_names[reg];
    return build_load_store_reg_op(name, ls, &val, sizeof(val));
}

OperandInfo *load_store_crf_reg(uint32_t crf, uint64_t val, int ls) {
    const char *name = ppc_crf_reg_names[crf];
    return build_load_store_reg_op(name, ls, &val, sizeof(val));
}