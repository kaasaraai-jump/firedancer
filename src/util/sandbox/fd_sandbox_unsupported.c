#include "fd_sandbox_util_private.h"
#include "../log/fd_log.h"


int
fd_sandbox_set_profile( fd_sandbox_profile_t profile ) {
  return 0;
};

int
fd_sandbox_pre_tile_boot( int *    pargc,
                          char *** pargv ) {
  char const * unsafe_notice = fd_env_strip_cmdline_cstr(
    pargc, pargv, 
    "unsafe-no-sandboxing-available", "FD_SANDBOX_UNSUPPORTED",
    NULL
  );

  if ( FD_UNLIKELY( !unsafe_notice || strcmp( unsafe_notice, "1" ) ) ) {
    FD_LOG_ERR(( "sandbox unavailable on this current target - look around where this line was emitted if you need to override" ));
  }

  return 0;
}

int
fd_sandbox_pre_run_boot( int *    pargc,
                         char *** pargv ) {
  return 0;
}