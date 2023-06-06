#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_h

#include "../env/fd_env.h"

/* threads created after calling this will have no capabilities */
void
fd_sandbox_thread_caps( int *    pargc,
                        char *** pargv );

/* fd_sandbox sandboxes the current process. After calling, the process
   has maximally restricted privileges we can enable given the host environment.
   On Linux, seccomp is used to prevent any syscalls except select whitelisted
   ones.
*/
void
fd_sandbox( int *    pargc,
            char *** pargv );

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_h */
