#include "stdio_impl.h"
#include "pthread_impl.h"

int __lockfile(FILE *f)
{
	int owner = f->lock, tid = __pthread_self()->tid;
	if ((owner & ~MAYBE_WAITERS) == tid)
		return 0;

	while (a_cas(&f->lock, 0, tid));
	return 1;
}

void __unlockfile(FILE *f)
{
	a_swap(&f->lock, 0);
}
