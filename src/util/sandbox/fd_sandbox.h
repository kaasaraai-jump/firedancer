#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_h

#include "../log/fd_log.h"

enum fd_sandbox_profile {
  FD_SANDBOX_PROFILE_COMMON,
  FD_SANDBOX_PROFILE_DISABLED,
};

typedef enum fd_sandbox_profile fd_sandbox_profile_t;

/* fd_sandbox sandboxes the current process. Since sandboxing is
   platform specific, look in fd_sandbox_{platform}.h for 
   more information. Each platform should do as much as it can
   in order to match the intent of the requested profile. 
   
   Firedancer is written in C, a memory-unsafe language. Therefore, we must 
   consider controls that can be levied during firedancer’s execution as a 
   primary component of risk reduction. Sandboxing aims to isolate different 
   Firedancer components from each other as well as from the system. 
   Although we will try to take several preventative steps to reduce the 
   likelihood of memory corruption bugs in the codebase, we acknowledge that,
   even with infinite resources, the number of memory corruption bugs in
   Firedancer at any given time is non-zero and that an exploiter will in 
   some future attempt to weaponize such a bug in main net.

   When starting, before executing any task code and/or processing
   user-provided input, a Firedancer process prepares everything it needs 
   in order to function properly.

   This initialization mostly consists in:
     - Creating new tiles: src/util/tile/fd_tile_threads.cxx:479
     - Opening the relevant workspaces which will be used to perform work and communicate (mmap)

   Immediately after performing those operations, Firedancer must sandbox itself.
*/

/* fd_sandbox_set_profile sets the profile to be used during sandboxing.
   It must be call before `fd_boot` otherwise the default profile will be used.
   The default profile is `FD_SANDBOX_PROFILE_COMMON`. */
void
fd_sandbox_set_profile( fd_sandbox_profile_t profile );

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_h */
