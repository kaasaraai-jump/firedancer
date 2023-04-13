#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_util_private_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_util_private_h

#include "fd_sandbox.h"

int
fd_sandbox_pre_tile_boot( int * pargc,
                          char *** pargv );

int
fd_sandbox_pre_run( int * pargc,
                    char *** pargv );

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_util_private_h */
