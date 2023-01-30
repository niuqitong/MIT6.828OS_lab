// System call stubs.

#include <inc/syscall.h>
#include <inc/lib.h>

static inline int32_t
syscall(int num, int check, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	int32_t ret;

	// Generic system call: pass system call number in AX,
	// up to five parameters in DX, CX, BX, DI, SI.
	// Interrupt kernel with T_SYSCALL.
	//
	// The "volatile" tells the assembler not to optimize
	// this instruction away just because we don't use the
	// return value.
	//
	// The last clause tells the assembler that this can
	// potentially change the condition codes and arbitrary
	// memory locations.

	asm volatile("int %1\n"
		     : "=a" (ret)
		     : "i" (T_SYSCALL),
		       "a" (num),
		       "d" (a1),
		       "c" (a2),
		       "b" (a3),
		       "D" (a4),
		       "S" (a5)
		     : "cc", "memory");

	if(check && ret > 0)
		panic("syscall %d returned %d (> 0)", num, ret);

	return ret;
}

void
sys_cputs(const char *s, size_t len)
{
	syscall(SYS_cputs, 0, (uint32_t)s, len, 0, 0, 0);
	/*
		800b4b:	55                   	push   %ebp
		800b4c:	89 e5                	mov    %esp,%ebp
		800b4e:	57                   	push   %edi
		800b4f:	56                   	push   %esi
		800b50:	53                   	push   %ebx
			asm volatile("int %1\n"
		800b51:	b8 00 00 00 00       	mov    $0x0,%eax
		800b56:	8b 55 08             	mov    0x8(%ebp),%edx
		800b59:	8b 4d 0c             	mov    0xc(%ebp),%ecx
		800b5c:	89 c3                	mov    %eax,%ebx
		800b5e:	89 c7                	mov    %eax,%edi
		800b60:	89 c6                	mov    %eax,%esi
		800b62:	cd 30                	int    $0x30
			syscall(SYS_cputs, 0, (uint32_t)s, len, 0, 0, 0);
		}
		800b64:	5b                   	pop    %ebx
		800b65:	5e                   	pop    %esi
		800b66:	5f                   	pop    %edi
		800b67:	5d                   	pop    %ebp
		800b68:	c3                   	ret    
	*/
}

int
sys_cgetc(void)
{
	return syscall(SYS_cgetc, 0, 0, 0, 0, 0, 0);
}

int
sys_env_destroy(envid_t envid)
{
	return syscall(SYS_env_destroy, 1, envid, 0, 0, 0, 0);
}

envid_t
sys_getenvid(void)
{
	 return syscall(SYS_getenvid, 0, 0, 0, 0, 0, 0);
}

