$(call add-hdrs,fd_quic.h)
$(call add-objs,fd_quic,fd_disco)
$(call make-unit-test,test_quic_tile,test_quic_tile,fd_disco fd_tango fd_quic fd_xdp fd_util)
$(call make-bin,fd_quic_tile,fd_quic_tile,fd_disco fd_tango fd_quic fd_util)