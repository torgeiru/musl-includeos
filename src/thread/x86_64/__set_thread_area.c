#include "pthread_impl.h"

int __set_thread_area(void *p)
{
#define ARCH_SET_FS 0x1002
    return __syscall(SYS_arch_prctl, ARCH_SET_FS, p);
}
