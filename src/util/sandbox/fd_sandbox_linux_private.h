#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_linux_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_linux_h

/* In order to be able to sandbox itself, Firedancer has to be started
   as *root* or have CAP_SYS_ADMIN.

   Here are the mechanisms currently used by Firedancer to achieve sandboxing:
   
   - clearenv
     - What: The environment variable are cleared.
     - Why: Environment variables are commonly used to hold secrets. 
            If Firedancer is compromised, no secret living in the operator’s environment will be leaked.
     - Note: Future desired behavior: `FD_` prefixed environment variables should not be cleared

   - fd_jail_setup_netns
     - What (simplified): The process looses access to network interfaces.
     - What: The process joins a previously configured network namespace. Most processes (exceptions are metrics & RPC) 
             join an empty namespace (loopback is present).
     - Why: Principle of least privilege: in the event where the process was able to interact with a network interface,
            it should not be able to perform any communication.

   - fd_jail_setup_mountns
     - What (simplified): The process gets a restricted view of the filesystem.
     - What: The ends up in a mountns with a root of its own. There is a bind mount at /log for storing logs. (log mount is not yet impl.)
     - Why: Principle of least privilege: the process should only be able to interact with files that it needs to function. 
            Although we could do away with the filesystem altogether (passing log file handles through uds),
            we believe that it’s okay to grant component access to a mount for the purpose of logging.

   - fd_jail_set_resource_limits
     - What: For the time being, the number of concurrently opened files is set to a low number. In the future, more resources types can be limited.
     - Why: Firedancer processes have well understood expected behaviors and resource needs. 
            A process should not be able to exceed those limits, potentially leading to availability issues.
            
   - fd_jail_set_user
     - What: The process drops all of its {real and effective} {user and group} ids to those of a predefined user (or those of nobody).
     - Why: In the case where another control was to fail, the process should be interacting with the system as an unprivileged user.

   - fd_jail_close_non_std_fds
     - What: All file descriptors above a specified number are forcefully closed.
     - Why: Similar to and more impactful than `clearenv`, an operator’s process can have FDs opened that are:
            - 1. not relevant to Firedancer 
            - 2. references to sensitive resources. 
            Those resources should not be made available to Firedancer.

   - fd_jail_seccomp:
     - What: Prevent the usage of most syscall only allowing those explicitly needed by the specific Firedancer sandbox profile.
     - Why: Syscalls are used to interact with the operating system. 
            [There exists close to 400 syscalls](https://github.com/torvalds/linux/blob/v4.17/arch/x86/entry/syscalls/syscall_64.tbl). 
            While running, A Firedancer process requires [14 syscalls](https://github.com/firedancer-io/firedancer/blob/marcus/jailer/src/util/jail/fd_jail.c#L180-L201)
            out of those 400 in order to perform its functions. In order to reduce the exploitable surface by ~96.5%,
            Firedancer will crash if it attempts to use a syscall that is not expected.
     - Note: It also happens that the syscalls that Firedancer is using are ubiquitous and well understood. 
             They have stood the test of time (not that time is an ultimate metric for greatness). 
             We have the luxury of disallowing all of the syscalls that might have received less scrutiny.
*/


#include "fd_sandbox_util_private.h"
#include <linux/filter.h>
#include <stdbool.h>

struct fd_sandbox_profile_linux {
  uint                close_fds_beyond;
  uint                max_open_fds;
  char *              netns;
  struct sock_fprog * seccomp_prog;
};
typedef struct fd_sandbox_profile_linux fd_sandbox_profile_linux_t;

void fd_sandbox_drop_capabilities   ( void );
void fd_sandbox_setup_userns        ( void );
void fd_sandbox_close_fds_beyond    ( uint max_fd );
void fd_sandbox_set_resource_limits ( uint max_open_fds );
void fd_sandbox_setup_netns         ( char * ns_name );
void fd_sandbox_setup_mountns       ( void );
void fd_sandbox_seccomp             ( struct sock_fprog * prog );
void fd_sandbox_drop_ambient_caps   ( void );

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_linux_h */
