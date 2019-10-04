#ifndef HEXAGON_TARGET_SYSCALL_H
#define HEXAGON_TARGET_SYSCALL_H

#define UNAME_MACHINE "hexagon"
#define UNAME_MINIMUM_RELEASE "2.6.32"

/* We use hexagon_reg_t to keep things similar to the kernel sources.  */
typedef uint32_t hexagon_reg_t;

struct target_pt_regs {
        hexagon_reg_t gpr[32];
        hexagon_reg_t cr[32];
        hexagon_reg_t sr[64];
};

#define TARGET_CLONE_BACKWARDS
#define TARGET_MINSIGSTKSZ      2048
#define TARGET_MLOCKALL_MCL_CURRENT 1
#define TARGET_MLOCKALL_MCL_FUTURE  2

#define TARGET_WANT_NI_OLD_SELECT

#endif
