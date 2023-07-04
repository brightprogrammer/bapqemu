#pragma once

#include "frame_arch.h"

#if defined(TARGET_MIPS)
const uint64_t frame_arch = frame_arch_mips;
const uint64_t frame_mach = frame_mach_mipsisa32;
#else
const uint64_t frame_arch = frame_arch_mips64;
const uint64_t frame_mach = frame_mach_mipsisa64;
#endif
