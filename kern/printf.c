// Simple implementation of cprintf console output for the kernel,
// based on printfmt() and the kernel console's cputchar().

#include <inc/types.h>
#include <inc/stdio.h>
#include <inc/stdarg.h>


static void
putch(int ch, int *cnt)
{
	cputchar(ch);
	*cnt++;
}

int
vcprintf(const char *fmt, va_list ap)
{
	int cnt = 0;

	vprintfmt((void*)putch, &cnt, fmt, ap);
	return cnt;
}

int
cprintf(const char *fmt, ...)
{
	// typedef __builtin_va_list va_list;
	va_list ap;

	int cnt;
	
	// #define va_start(ap, last) __builtin_va_start(ap, last)
	va_start(ap, fmt);

	cnt = vcprintf(fmt, ap);

	// #define va_end(ap) __builtin_va_end(ap)
	va_end(ap);

	return cnt;
}

