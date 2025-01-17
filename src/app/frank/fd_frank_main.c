#include "fd_frank.h"

#if FD_HAS_FRANK

#include <stdio.h>
#include <signal.h>

static fd_cnc_t * fd_frank_main_cnc = NULL;

static void
fd_frank_sigaction( int         sig,
                    siginfo_t * info,
                    void *      context ) {
  (void)info;
  (void)context;
  /* FIXME: add support to fd_log for robust logging inside a signal
     handler (i.e. make sure that behavior of calling a log when the
     interrupted thread might be in the middle of preparing a log
     message is well defined) */
  FD_LOG_NOTICE(( "received POSIX signal %i; sending halt to main", sig ));
  if( FD_UNLIKELY( fd_cnc_open( fd_frank_main_cnc ) ) ) { /* logs details */
    FD_LOG_WARNING(( "unable to send halt (fd_cnc_open failed); shutdown will be unclean" ));
    raise( sig ); /* fall back on default handler so thread still terminates */
  }
  fd_cnc_signal( fd_frank_main_cnc, FD_CNC_SIGNAL_HALT );
  fd_cnc_close ( fd_frank_main_cnc );
}

static void
fd_frank_signal_trap( int sig ) {
  struct sigaction act[1];
  act->sa_sigaction = fd_frank_sigaction;
  if( FD_UNLIKELY( sigemptyset( &act->sa_mask ) ) ) FD_LOG_ERR(( "sigempty set failed" ));
  act->sa_flags = (int)(SA_SIGINFO | SA_RESETHAND);
  if( FD_UNLIKELY( sigaction( sig, act, NULL ) ) ) FD_LOG_ERR(( "unable to override signal %i", sig ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_tempo_tick_per_ns( NULL ); /* eat calibration cost at deterministic place */

  FD_LOG_NOTICE(( "app init" ));

  /* Parse command line arguments */

  char const * pod_gaddr = fd_env_strip_cmdline_cstr( &argc, &argv, "--pod", NULL, NULL );

  if( FD_UNLIKELY( !pod_gaddr ) ) FD_LOG_ERR(( "--pod not specified" ));

  /* Load up the configuration for this frank instance */

  FD_LOG_NOTICE(( "using configuration in pod --pod %s at path %s", pod_gaddr, FD_FRANK_CONFIGURATION_PREFIX ));

  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, FD_FRANK_CONFIGURATION_PREFIX );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  uchar const * verify_pods = fd_pod_query_subpod( cfg_pod, "verify" );
  ulong verify_cnt = fd_pod_cnt_subpod( verify_pods );
  FD_LOG_NOTICE(( "%lu verify found", verify_cnt ));

  ulong tile_cnt = 3UL + verify_cnt;
  if( FD_UNLIKELY( fd_tile_cnt()<tile_cnt ) ) FD_LOG_ERR(( "at least %lu tiles required for this config", tile_cnt ));
  if( FD_UNLIKELY( fd_tile_cnt()>tile_cnt ) ) FD_LOG_WARNING(( "only %lu tiles required for this config", tile_cnt ));

  /* Join all IPC objects needed by main */

  char const ** tile_name = fd_alloca( alignof(char const *), sizeof(char const *)*tile_cnt );
  if( FD_UNLIKELY( !tile_name ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  fd_cnc_t ** tile_cnc = fd_alloca( alignof(fd_cnc_t *), sizeof(fd_cnc_t *)*tile_cnt );
  if( FD_UNLIKELY( !tile_cnc ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  do {
    ulong tile_idx = 0UL;

    FD_LOG_NOTICE(( "joining %s.main.cnc", FD_FRANK_CONFIGURATION_PREFIX ));
    tile_name[ tile_idx ] = "main";
    tile_cnc [ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "main.cnc" ) );
    if( FD_UNLIKELY( !tile_cnc[ tile_idx ] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
    tile_idx++;

    FD_LOG_NOTICE(( "joining %s.pack.cnc", FD_FRANK_CONFIGURATION_PREFIX ));
    tile_name[ tile_idx ] = "pack";
    tile_cnc [ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "pack.cnc" ) );
    if( FD_UNLIKELY( !tile_cnc[ tile_idx ] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
    tile_idx++;

    FD_LOG_NOTICE(( "joining %s.dedup.cnc", FD_FRANK_CONFIGURATION_PREFIX ));
    tile_name[ tile_idx ] = "dedup";
    tile_cnc [ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "dedup.cnc" ) );
    if( FD_UNLIKELY( !tile_cnc[ tile_idx ] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
    tile_idx++;

    for( fd_pod_iter_t iter = fd_pod_iter_init( verify_pods ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
      fd_pod_info_t info = fd_pod_iter_info( iter );
      if( FD_UNLIKELY( info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
      char const  * verify_name =                info.key;
      uchar const * verify_pod  = (uchar const *)info.val;

      FD_LOG_NOTICE(( "joining %s.verify.%s.cnc", FD_FRANK_CONFIGURATION_PREFIX, verify_name ));
      tile_name[ tile_idx ] = verify_name;
      tile_cnc [ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( verify_pod, "cnc" ) );
      if( FD_UNLIKELY( !tile_cnc[tile_idx] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
      if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
      tile_idx++;
    }

  } while(0);

  /* Boot all the tiles that main controls */

  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) {
    FD_LOG_NOTICE(( "booting tile %s", tile_name[ tile_idx ] ));

    /* Note: could do this in parallel but one at a time makes
       boot logging easier to read and easier to pass args */

    fd_tile_task_t task;
    switch( tile_idx ) {
    case 0UL: task = main;                 break;
    case 1UL: task = fd_frank_pack_task;   break;
    case 2UL: task = fd_frank_dedup_task;  break;
    default:  task = fd_frank_verify_task; break;
    }

    char * task_argv[3];
    task_argv[0] = (char *)tile_name[ tile_idx ];
    task_argv[1] = (char *)pod_gaddr;
    task_argv[2] = (char *)FD_FRANK_CONFIGURATION_PREFIX;
    if( FD_UNLIKELY( !fd_tile_exec_new( tile_idx, task, 0, task_argv ) ) )
      FD_LOG_ERR(( "fd_tile_exec_new failed" ));

    if( FD_UNLIKELY( fd_cnc_wait( tile_cnc[ tile_idx ], FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )!=FD_CNC_SIGNAL_RUN ) )
      FD_LOG_ERR(( "tile failed to boot in a timely fashion" ));

    /* task_argv safe to reuse at this point */
  }

  /* Boot command and control */

  FD_LOG_INFO(( "main init" ));
  fd_cnc_t * cnc = tile_cnc[ 0 ];
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( tile_cnc[ 0 ] );

  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP    ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT   ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ] ) = 0UL;

  /* Configure normal kill and ctrl-c to do a clean shutdown */

  FD_VOLATILE( fd_frank_main_cnc ) = cnc;
  fd_frank_signal_trap( SIGTERM );
  fd_frank_signal_trap( SIGINT  );

  /* Run command and control */

  FD_LOG_INFO(( "main run" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {
    /* Send diagnostic info */
    fd_cnc_heartbeat( cnc, fd_tickcount() );
    /* Receive command-and-control signals */
    if( FD_UNLIKELY( fd_cnc_signal_query( cnc )==FD_CNC_SIGNAL_HALT ) ) break;
    FD_YIELD(); /* not SPIN_PAUSE as this tile is meant to float and be low resource utilization */
  }

  /* Halt command and control */

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  FD_LOG_INFO(( "main fini" ));

  FD_LOG_NOTICE(( "app fini" ));

  for( ulong tile_idx=tile_cnt; tile_idx>1UL; tile_idx-- ) {
    FD_LOG_NOTICE(( "halting tile %s", tile_name[ tile_idx-1UL ] ));

    /* Note: could do this in parallel too but doing reverse
       one-at-a-time for symmetry with boot */

    if( FD_UNLIKELY( fd_cnc_open( tile_cnc[ tile_idx-1UL ] ) ) ) FD_LOG_ERR(( "fd_cnc_open failed for tile %lu", tile_idx-1UL ));
    fd_cnc_signal( tile_cnc[ tile_idx-1UL ], FD_CNC_SIGNAL_HALT );
    fd_cnc_close ( tile_cnc[ tile_idx-1UL ] );

    int ret;
    if( FD_UNLIKELY( fd_tile_exec_delete( fd_tile_exec( tile_idx-1UL ), &ret ) ) ) FD_LOG_ERR(( "fd_tile_exec_delete failed" ));
    if( FD_UNLIKELY( ret ) ) FD_LOG_ERR(( "unexpected ret (%i)", ret ));
  }

  /* Clean up */

  for( ulong tile_idx=tile_cnt; tile_idx; tile_idx-- ) fd_wksp_pod_unmap( fd_cnc_leave( tile_cnc[ tile_idx-1UL ] ) );
  fd_wksp_pod_detach( pod );
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "unsupported for this build target" ));
  fd_halt();
  return 1;
}

#endif

