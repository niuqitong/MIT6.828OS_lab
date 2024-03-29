/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);			/*It pushes a trap number onto the stack */				\
	jmp _alltraps

/* 伪指令，用于告诉汇编器接下来的代码是可执行的程序代码（即text段） */ 
.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 * 
 */

	TRAPHANDLER_NOEC(th0, 0)
	TRAPHANDLER_NOEC(th1, 1)
	TRAPHANDLER_NOEC(th3, 3)
	TRAPHANDLER_NOEC(th4, 4)
	TRAPHANDLER_NOEC(th5, 5)
	TRAPHANDLER_NOEC(th6, 6)
	TRAPHANDLER_NOEC(th7, 7)
	TRAPHANDLER(th8, 8)
	TRAPHANDLER_NOEC(th9, 9)
	TRAPHANDLER(th10, 10)
	TRAPHANDLER(th11, 11)
	TRAPHANDLER(th12, 12)
	TRAPHANDLER(th13, 13)
	TRAPHANDLER(th14, 14)
	TRAPHANDLER_NOEC(th16, 16)

	TRAPHANDLER_NOEC(timer, IRQ_OFFSET + IRQ_TIMER)
	TRAPHANDLER_NOEC(kbd, IRQ_OFFSET + IRQ_KBD)
	TRAPHANDLER_NOEC(serial, IRQ_OFFSET + IRQ_SERIAL)
	TRAPHANDLER_NOEC(spurious, IRQ_OFFSET + IRQ_SPURIOUS)
	TRAPHANDLER_NOEC(ide, IRQ_OFFSET + IRQ_IDE)
	TRAPHANDLER_NOEC(error, IRQ_OFFSET + IRQ_ERROR)

	
	TRAPHANDLER_NOEC(th48, 48)

/*
 * Lab 3: Your code here for _alltraps
 */

_alltraps: // tf_ss，tf_esp，tf_eflags，tf_cs，tf_eip，tf_err在中断发生时由处理器压入
	pushl %ds
	pushl %es
	pushal
	pushl $GD_KD
	popl %ds
	pushl $GD_KD
	popl %es
	pushl %esp // pass argument to trap() through stack
	call trap