#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fd_sandbox_linux_private.h"

#include <errno.h>        /* errno */
#include <fcntl.h>        /* open */
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/seccomp.h>
#include <sched.h>        /* CLONE_*, setns, unshare */
#include <stddef.h>
#include <stdio.h>        /* snprintf */
#include <stdlib.h>       /* clearenv, mkdtemp*/
#include <sys/mount.h>    /* MS_*, MNT_*, mount, umount2 */
#include <sys/prctl.h>
#include <sys/resource.h> /* RLIMIT_*, rlimit, setrlimit */
#include <sys/stat.h>     /* mkdir */
#include <sys/syscall.h>  /* SYS_* */
#include <unistd.h>       /* set*id, sysconf, close, chdir, rmdir syscall */

#include "../log/fd_log.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* seccomp macros */
#define X32_SYSCALL_BIT 0x40000000

#define ALLOW_SYSCALL(name) \
  /* If the syscall does not match, jump over RET_ALLOW */ \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1), \
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#if defined(__i386__)
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR	AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define ARCH_NR AUDIT_ARCH_AARCH64
#else
# error "Target architecture is unsupported by seccomp."
#endif


static fd_sandbox_profile_t selected_profile = FD_SANDBOX_PROFILE_COMMON;

void
fd_sandbox_set_profile( fd_sandbox_profile_t profile ) {
  selected_profile = profile;
}

int
fd_sandbox_pre_tile_boot( int * pargc,
                     char *** pargv ) {
  (void) pargc;
  (void) pargv;

  /* Do not drop capabilities if the sandbox is disabled. */
  if ( selected_profile == FD_SANDBOX_PROFILE_DISABLED ) {
    return 0;
  }

  if ( FD_UNLIKELY( unshare( CLONE_NEWNS ) ) )
    FD_LOG_ERR(( "unshare: (%d) %s", errno, strerror( errno ) ));
  return 0;
}

void fd_sandbox_drop_capabilities( void ) {
  int res = prctl( PR_SET_SECUREBITS,
                    /* SECBIT_KEEP_CAPS off */
                    SECBIT_KEEP_CAPS_LOCKED |
                    SECBIT_NO_SETUID_FIXUP |
                    SECBIT_NO_SETUID_FIXUP_LOCKED |
                    SECBIT_NOROOT |
                    SECBIT_NOROOT_LOCKED |
                    SECBIT_NO_CAP_AMBIENT_RAISE |
                    SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED );

  if ( FD_UNLIKELY( res == -1 ) ) {
    FD_LOG_ERR(( "prctl: %s", strerror( errno ) )); 
  }

  if ( FD_UNLIKELY( setuid( getuid() ) == -1 ) ) {
        FD_LOG_ERR(( "setuid: %s", strerror( errno ) ));
        return;
  }
  FD_LOG_NOTICE(( "sandbox: pre-boot complete" ));
}

int fd_sandbox_linux( const fd_sandbox_profile_linux_t * profile );

void
fd_sandbox_profile_init_common( fd_sandbox_profile_linux_t * profile ) {
  profile->netns            = "fd-netless";
  profile->seccomp_prog     = NULL;
  profile->close_fds_beyond = 3U;
  profile->max_open_fds     = 3U;
}

int
fd_sandbox_pre_run( int *    pargc,
                    char *** pargv ) {
  
  (void) pargc;
  (void) pargv;

  fd_sandbox_profile_linux_t profile;
  switch ( selected_profile ) {
    case FD_SANDBOX_PROFILE_COMMON:
    FD_LOG_NOTICE(( "sandbox profile: common" ));
      fd_sandbox_profile_init_common( &profile );
    break;
    case FD_SANDBOX_PROFILE_DISABLED:
      FD_LOG_NOTICE(( "sandbox disabled by profile" ));
      return 0;
    break;
    default:
    FD_LOG_ERR(( "unknown sandbox profile" ));
  }

  clearenv();
  fd_sandbox_setup_netns( profile.netns );
  fd_sandbox_setup_mountns();
  fd_sandbox_set_resource_limits( profile.max_open_fds );
  fd_sandbox_setup_userns();
  fd_sandbox_close_fds_beyond( profile.close_fds_beyond );
  fd_sandbox_seccomp( profile.seccomp_prog );

  FD_LOG_NOTICE(( "sandbox: post-boot complete" ));
  return 0;
}

void fd_sandbox_setup_userns ( void ) {
  return;
}


void
fd_sandbox_close_fds_beyond( uint target_max_fd ) {
  FD_LOG_INFO(( "closing all fds beyond %d", target_max_fd ));
  long max_fds = sysconf( _SC_OPEN_MAX );
  for ( long fd = max_fds - 1; fd > target_max_fd; fd-- ) {
     close( (int)fd );
  } 
}

void
fd_sandbox_set_resource_limits(uint max_open_fds) {
  FD_LOG_INFO(( "setting resource limits" ));
  struct rlimit l = {
    .rlim_cur = max_open_fds,
    .rlim_max = max_open_fds,
  };

  if ( FD_UNLIKELY( setrlimit(RLIMIT_NOFILE, &l) == -1 ) ) {
    FD_LOG_ERR(( "setrlimit: %s", strerror( errno ) ));
  }
}

void
fd_sandbox_setup_netns( char * ns_name ) {

  // Handle the special case where we just unshare
  if ( FD_LIKELY( !strcmp( "fd-netless", ns_name ))) {
    FD_LOG_DEBUG(( "unsharing netns" ));
    unshare( CLONE_NEWNET );
    return;
  }

  char netns_path[ PATH_MAX ];
  int nsfd;

  FD_LOG_INFO(( "setting up network namespace" ));

  // realize the namespace path
  int reslen = snprintf( netns_path, ARRAY_SIZE(netns_path), "/var/run/netns/%s", ns_name );
  if ( FD_UNLIKELY( (ulong) (reslen + 1) > ARRAY_SIZE(netns_path) ) ) {
    FD_LOG_ERR(( "namespace name too long" ));
  }

  // get a reference to the namespace
  if ( FD_UNLIKELY( ( nsfd = open( netns_path, 0 ) ) == -1 ) ) {
    FD_LOG_ERR(( "netns open: %s", strerror( errno ) ));
  }

  // enter the namespace
  if ( FD_UNLIKELY( setns( nsfd, CLONE_NEWNET ) == -1 ) ) {
    FD_LOG_ERR(( "netns setns: %s", strerror( errno ) ));
  };

  // close the namespace reference
  close( nsfd );
}

void 
fd_sandbox_setup_mountns( void ) {
  if ( FD_UNLIKELY( unshare(CLONE_NEWNS) == -1 ) )
    FD_LOG_ERR(( "unshare: (%d) %s", errno, strerror( errno ) ));

  if ( FD_UNLIKELY( mount( NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) == -1 ) )
    FD_LOG_ERR(( "unshare: %s", strerror( errno ) ));

  // Set this new mountns' root to be a temp directory where the user won't be able to do anything.
  char * chroot_path;
  char * tmp_str = "/tmp/fd-sandbox-XXXXXX";
  char str_buf[ sizeof("/tmp/fd-sandbox-XXXXXX") ];
  memcpy( str_buf, tmp_str, sizeof( "/tmp/fd-sandbox-XXXXXX" ) );
  chroot_path = mkdtemp( str_buf );
  if ( FD_UNLIKELY( chroot_path == NULL ) ) {
    FD_LOG_ERR(( "mkdtemp: (%d) %s", errno, strerror( errno ) ));
  }

  FD_LOG_INFO(( "using %s as root mount", chroot_path ));

  if ( FD_UNLIKELY( mount( chroot_path, chroot_path, NULL, MS_BIND | MS_REC, NULL ) == -1 ) )
    FD_LOG_ERR(( "mount: (%d) %s", errno, strerror( errno ) ));

  if ( FD_UNLIKELY( chdir(chroot_path) == -1 ) ) 
    FD_LOG_ERR(( "cwd: %s", strerror( errno ) ));

  if ( FD_UNLIKELY( mkdir(".old-root", 0600) == -1 ) )
    FD_LOG_ERR(( "mkdir: %s", strerror( errno ) ));

  if ( FD_UNLIKELY( syscall(SYS_pivot_root, "./", ".old-root" ) ) )
    FD_LOG_ERR(( "SYS_pivot_root: %s", strerror( errno ) ));

  if ( FD_UNLIKELY( umount2(".old-root", MNT_DETACH) == -1 ) ) 
    FD_LOG_ERR(( "umount2: %s", strerror( errno ) ));

  if ( FD_UNLIKELY( rmdir(".old-root") == -1 ) )
    FD_LOG_ERR(( "rmdir: %s", strerror( errno ) ));
}


/* seccomp */

void
fd_sandbox_seccomp( struct sock_fprog *prog ) {
    struct sock_filter filter[] = {
      // [0] Validate architecture
      // Load the arch number
      BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, arch ) ) ),
      // Do not jump (and die) if the compile arch is neq the runtime arch.
      // Otherwise, jump over the SECCOMP_RET_KILL_PROCESS statement.
      BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 1, 0 ),
      BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_ALLOW ),

      // [1] Verify that the syscall is allowed
      // Load the syscall
      BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, nr ) ) ),

      // Attempt to sort syscalls by call frequency.
      ALLOW_SYSCALL( writev       ),
      ALLOW_SYSCALL( write        ),
      ALLOW_SYSCALL( fsync        ),
      ALLOW_SYSCALL( gettimeofday ),
      ALLOW_SYSCALL( futex        ),
      // sched_yield is useful for both floating threads and hyperthreaded pairs.
      ALLOW_SYSCALL( sched_yield  ),
      // The rules under this line are expected to be used in fewer occasions.
      // exit is needed to let tiles exit gracefully.
      ALLOW_SYSCALL( exit         ),
      // exit_group is needed to let any tile crash the whole group.
      ALLOW_SYSCALL( exit_group   ),
      // munmap is needed for a clean exit.
      ALLOW_SYSCALL( munmap       ),
      // nanosleep is needed for a clean exit.
      ALLOW_SYSCALL( nanosleep    ),
      ALLOW_SYSCALL( rt_sigaction ),
      ALLOW_SYSCALL( rt_sigreturn ),
      ALLOW_SYSCALL( sync         ),
      // close is needed for a clean exit and for closing logs.
      ALLOW_SYSCALL( close        ),
      ALLOW_SYSCALL( sendto       ),

      // [2] None of the syscalls approved were matched: die
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };

    struct sock_fprog default_prog = {
      .len = ARRAY_SIZE( filter ),
      .filter = filter,
    };

  if ( FD_LIKELY( !prog ) ) {
    FD_LOG_INFO(( "Loading default filter" ));
    prog = &default_prog;
  }

  if ( FD_UNLIKELY( prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) ) ) {
    FD_LOG_ERR(( "prctl( PR_SET_NO_NEW_PRIVS, ... ): %s", strerror( errno ) ));
  }

  if ( FD_UNLIKELY( syscall( SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, prog ) ) ) {
    FD_LOG_ERR(( "syscall( SYS_seccomp, SECCOMP_SET_MODE_FILTER, ... ): %s", strerror( errno ) ));
  }
}
