#ifndef HEADER_fd_quic_config_h
#define HEADER_fd_quic_config_h

#include <string.h>

#include "../../util/fd_util.h"
#include "../aio/fd_aio.h"


/* forwards */
typedef struct fd_quic_transport_params fd_quic_transport_params_t;
typedef struct fd_quic_host_cfg         fd_quic_host_cfg_t;
typedef struct fd_quic_conn             fd_quic_conn_t;
typedef struct fd_quic_stream           fd_quic_stream_t;


/* callback function prototypes */

/* time function type used internally by quic for scheduling
   returns the time in ns since epoch
   args
     context - any context the clock needs - quic will supply the configured
               value */
typedef ulong (*fd_quic_now_t)( void * context );

/* new connection callback
   a server received a new connection, and completed handshakes */
typedef void (*fd_quic_cb_conn_new_t) ( fd_quic_conn_t * conn,
                                        void *           quic_context );

/* handshake complete callback
   a client completed handshakes */
typedef void (*fd_quic_cb_conn_handshake_complete_t) ( fd_quic_conn_t * conn,
                                                       void *           quic_context );

/* finalized connection callback */
typedef void (*fd_quic_cb_conn_final_t) ( fd_quic_conn_t * conn,
                                          void *           quic_context );

/* new stream callback

   called when the peer creates a new stream

   the user should set "context" within the supplied stream object
   the user should not change other fields

   args
     stream       a pointer to the new stream object
     context      user supplied QUIC context - differs from stream_context, which is
                      per-stream
     type         one of:
                      FD_QUIC_TYPE_UNIDIR - unidirectional stream
                      FD_QUIC_TYPE_BIDIR  - bidirectional stream

   called when the peer creates a new stream */
typedef void (*fd_quic_cb_stream_new_t) ( fd_quic_stream_t * stream,
                                          void *             context,
                                          int                type );


/* stream notify callback

   called when a stream requires notification
   notifications
     FD_QUIC_NOTIFY_END   the stream ended, and no more callbacks will be
                            generated for this stream
                          the stream ptr referenced will be freed after return
     FD_QUIC_NOTIFY_RESET the peer reset the stream (will not send)
     FD_QUIC_NOTIFY_ABORT the peer aborted the stream (will not receive)

   args
     stream         pointer to the new stream object
     context        the user supplied context
     type           one of:
                      FD_QUIC_NOTIFY_END
                      FD_QUIC_NOTIFY_RESET
                      FD_QUIC_NOTIFY_ABORT
   */
typedef void (*fd_quic_cb_stream_notify_t) ( fd_quic_stream_t * stream,
                                             void *             context,
                                             int                type );

/* stream data received callback

   called when new data is received from peer

   each new buffer received in a separate callback

   args
     stream_context        is user supplied stream context set in callback
     stream_id             the quic stream id
     data                  the bytes received
     data_sz               the number of bytes received
     offset                the offset in the strean of the first byte in data
     fin                   bool - true if the last byte of data is the last
                                  byte of the stream
   */
typedef void (*fd_quic_cb_stream_receive_t)( fd_quic_stream_t * stream,
                                             void *             stream_context,
                                             uchar const *      data,
                                             ulong              data_sz,
                                             ulong              offset,
                                             int                fin );


/* parameters used by each host/endpoint */
/* TODO forcing the user to ensure the lifetime of the hostname string
   is not good practice */
struct fd_quic_host_cfg {
  char const * hostname;
  uint         ip_addr;
  ushort       udp_port;
};

/* FIXME: Clearly define the ownership, lifetime, constness, and source of each config param */
/* FIXME: Some of this is filled in by fd_quic_config_from_env, some by the tile, and some by main. */

struct fd_quic_config {
  char                         cert_file  [ PATH_MAX ];  /* certificate file path */
  char                         key_file   [ PATH_MAX ];  /* private key file path */
  char                         keylog_file[ PATH_MAX ];  /* NSS key log file */

  fd_quic_transport_params_t * transport_params;       /* transport parameters for connections */

  ulong                        max_concur_conns;       /* maximum number of concurrent connections */
                                                       /* allowed */

  ulong                        max_concur_conn_ids;    /* maximum number of concurrent connection ids */
                                                       /* allowed per connection */

  uint                         max_concur_streams;     /* maximum number of concurrent streams */
                                                       /* allowed per connection per type (4 types) */

  uint                         max_concur_handshakes;  /* maximum number of concurrent handshake */
                                                       /* allowed per connection */

  ulong                        conn_id_sparsity;       /* sparsity of connection id hash map */
                                                       /* number of slots will be: */
                                                       /*   max_ids * conn_id_sparsity */

  ulong                        max_in_flight_pkts;     /* max in-flight (tx) packets per connection */
                                                       /* this limits the storage required for ack handling */

  ulong                        max_in_flight_acks;     /* max in-flight (tx) acks per connection */

  /* FIXME: use disco's lazy / housekeep semantics for this? */
  /* FIXME: which unit does this field have */
  /* FIXME: how much jitter? */
  ulong                        mean_time_between_svc;  /* mean time between connection servicing */
                                                       /* when idle */

  uchar                        dscp;                   /* differentiated services code point */
                                                       /* set on all IPV4 tx packets */

  /* callbacks */
  fd_quic_cb_conn_new_t                cb_conn_new;
  fd_quic_cb_conn_handshake_complete_t cb_handshake_complete;
  fd_quic_cb_conn_final_t              cb_conn_final;
  fd_quic_cb_stream_new_t              cb_stream_new;
  fd_quic_cb_stream_notify_t           cb_stream_notify;
  fd_quic_cb_stream_receive_t          cb_stream_receive;

  /* clock callback */
  fd_quic_now_t                        now_fn;
  void *                               now_ctx;

  fd_quic_host_cfg_t                   host_cfg;


  /* ALPN string - see ALPN spec */
  uchar const *                        alpns;
  uint                                 alpns_sz;

  /* udp ephemeral port range
     defines the range of ports used as source port on outgoing connections
     a port will be chosen in the half open range [lo,hi) */
  struct {
    ushort                             lo;
    ushort                             hi;
  } udp_ephem;

  /* in lieu of maintaining a full ARP protocol, forward traffic
     to this MAC address
     TODO determine actual requirements here */
  struct {
    /* forward traffic to this MAC address */
    uchar                              default_route_mac[6];

    /* source interface MAC address */
    uchar                              src_mac[6];
  } net;
};
typedef struct fd_quic_config fd_quic_config_t;

#endif

