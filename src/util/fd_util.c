#include "fd_util.h"
#include "sandbox/fd_sandbox_util_private.h"

void
fd_boot( int *    pargc,
         char *** pargv ) {
  /* At this point, we are immediately after the program start, there is
     only one thread of execution and fd has not yet been booted. */
  fd_log_private_boot  ( pargc, pargv );
  fd_shmem_private_boot( pargc, pargv );
  fd_tile_private_boot_tile_count( pargc, pargv );
  fd_tile_private_boot ( pargc, pargv ); /* The caller is now tile 0 */
}

void
fd_halt( void ) {
  /* At this point, we are immediately before normal program
     termination, and fd has already been booted. */
  fd_tile_private_halt ();
  fd_shmem_private_halt();
  fd_log_private_halt  ();
}

void fd_boot_secure(
  int *    pargc,
  char *** pargv,
  void     (*init_fn) ( int * pargc, char *** pargv, void * data ),
  void *   data
) {

  fd_log_private_boot  ( pargc, pargv );
  fd_shmem_private_boot( pargc, pargv );
  fd_tile_private_boot_tile_count( pargc, pargv );
  init_fn( pargc, pargv, data );
  fd_sandbox_pre_tile_boot ( pargc, pargv );
  fd_tile_private_boot( pargc, pargv );
  fd_sandbox_pre_run( pargc, pargv );
  /* caller is now tile 0 */
}

#if FD_HAS_HOSTED

#include <sched.h>

void fd_yield( void ) { sched_yield(); }

#endif

