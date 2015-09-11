include ${top_srcdir}/Make_global.am

check_PROGRAMS = nfulnl_test nf-log

nfulnl_test_SOURCES = nfulnl_test.c
nfulnl_test_LDADD = ../src/libnetfilter_log.la
nfulnl_test_LDFLAGS = -dynamic

nf_log_SOURCES = nf-log.c
nf_log_LDADD = ../src/libnetfilter_log.la
nf_log_LDFLAGS = -dynamic -lmnl
if BUILD_NFCT
nf_log_LDFLAGS += $(LIBNETFILTER_CONNTRACK_LIBS)
nf_log_CFLAGS = -DBUILD_NFCT
endif

if BUILD_IPULOG
check_PROGRAMS += ulog_test

ulog_test_SOURCES = ulog_test.c
ulog_test_LDADD = ../src/libnetfilter_log_libipulog.la ../src/libnetfilter_log.la
ulog_test_LDFLAGS = -dynamic
endif
