/*
 * vmx.h - header file for USM VMX driver.
 */

#include <linux/mmu_notifier.h>
#include <linux/types.h>
#include <asm/vmx.h>
#include <linux/kvm_types.h>
#include <linux/version.h>

DECLARE_PER_CPU(struct vmx_vcpu *, local_vcpu);

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

struct vmx_capability {
	u32 ept;
	u32 vpid;
	int has_load_efer:1;
};

extern struct vmx_capability vmx_capability;

#define NR_AUTOLOAD_MSRS 8

enum vmx_reg {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
#ifdef CONFIG_X86_64
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
#endif
	VCPU_REGS_RIP,
	NR_VCPU_REGS
};

struct vmx_vcpu {
	struct list_head list;
	int cpu;
	int vpid;
	int launched;

	struct mmu_notifier mmu_notifier;
	spinlock_t ept_lock;
	unsigned long ept_root;
	unsigned long eptp;
	bool ept_ad_enabled;

	u8  fail;
	u64 exit_reason;
	u64 host_rsp;
	u64 regs[NR_VCPU_REGS];
	u64 cr2;

	int shutdown;
	int ret_code;

	struct msr_autoload {
		unsigned nr;
		struct vmx_msr_entry guest[NR_AUTOLOAD_MSRS];
		struct vmx_msr_entry host[NR_AUTOLOAD_MSRS];
	} msr_autoload;

	struct vmcs *vmcs;
	void *syscall_tbl;
	struct dune_config *conf;
};

extern __init int vmx_init(void);
extern void vmx_exit(void);
extern void vmx_cleanup(void);

extern int vmx_launch(struct dune_config *conf, int64_t *ret_code);

extern int vmx_init_ept(struct vmx_vcpu *vcpu);
extern int vmx_create_ept(struct vmx_vcpu *vcpu);
extern void vmx_destroy_ept(struct vmx_vcpu *vcpu);

extern int
vmx_do_ept_fault(struct vmx_vcpu *vcpu, unsigned long gpa,
		 unsigned long gva, int fault_flags);

extern void vmx_ept_sync_vcpu(struct vmx_vcpu *vcpu);
extern void vmx_ept_sync_individual_addr(struct vmx_vcpu *vcpu, gpa_t gpa);

#define vmx_asm1(insn, op1, error_args...)                          \
do {                                    \
    asm_volatile_goto("1: " __stringify(insn) " %0\n\t"             \
                      ".byte 0x2e\n\t" /* branch not taken hint */  \
                      "jna %l[error]\n\t"                           \
                      _ASM_EXTABLE(1b, %l[fault])                   \
                      : : op1 : "cc" : error, fault);               \
    return;                                                         \
error:                                                              \
    insn##_error(error_args);                                       \
    return;                                                         \
fault:                                                              \
    return;                                                         \
} while (0)

#define vmx_asm2(insn, op1, op2, error_args...)                     \
do {                                                                \
    asm_volatile_goto("1: "  __stringify(insn) " %1, %0\n\t"        \
                      ".byte 0x2e\n\t" /* branch not taken hint */  \
                      "jna %l[error]\n\t"                           \
                      _ASM_EXTABLE(1b, %l[fault])                   \
                      : : op1, op2 : "cc" : error, fault);          \
    return;                                                         \
error:                                                              \
    insn##_error(error_args);                                       \
    return;                                                         \
fault:                                                              \
    return;                                                         \
} while (0)

static __always_inline unsigned long vmcs_readl(unsigned long field)
{
    unsigned long value;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
    asm volatile("1: vmread %2, %1\n\t"
            ".byte 0x3e\n\t" /* branch taken hint */
            "ja 3f\n\t"
            "mov %2, %%" _ASM_ARG1 "\n\t"
            "xor %%" _ASM_ARG2 ", %%" _ASM_ARG2 "\n\t"
            "2: call vmread_error\n\t"
            "xor %k1, %k1\n\t"
            "3:\n\t"

            ".pushsection .fixup, \"ax\"\n\t"
            "4: mov %2, %%" _ASM_ARG1 "\n\t"
            "mov $1, %%" _ASM_ARG2 "\n\t"
            "jmp 2b\n\t"
            ".popsection\n\t"
            _ASM_EXTABLE(1b, 4b)
            : ASM_CALL_CONSTRAINT, "=r"(value) : "r"(field) : "cc");
#else
    asm volatile (ASM_VMX_VMREAD_RDX_RAX
            : "=a"(value) : "d"(field) : "cc");
#endif
    return value;
}
