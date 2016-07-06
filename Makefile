CC = gcc
LIBS = -lvmi -lm
GLIB_CFLAGS = -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include
GLIB_LIBS = -lglib-2.0

PROCESS_LIST = process-list
SYSCALL_LIST = syscall-list
NET_PORT = net-port
SYSCALL_TRACE = syscall-trace
MODULE_LIST = module-list

RM = rm -rf

all: $(MODULE_LIST) $(PROCESS_LIST) $(SYSCALL_LIST) $(NET_PORT) $(SYSCALL_TRACE)

$(MODULE_LIST): $(MODULE_LIST).c
	$(CC) -o $(MODULE_LIST) $(MODULE_LIST).c $(LIBS)

$(PROCESS_LIST): $(PROCESS_LIST).c
	$(CC) -o $(PROCESS_LIST) $(PROCESS_LIST).c $(LIBS)

$(SYSCALL_LIST): $(SYSCALL_LIST).c
	$(CC) -o $(SYSCALL_LIST) $(SYSCALL_LIST).c $(LIBS)

$(NET_PORT): $(NET_PORT).c
	$(CC) -o $(NET_PORT) $(NET_PORT).c $(LIBS)

$(SYSCALL_TRACE): $(SYSCALL_TRACE).c
	$(CC) -o $(SYSCALL_TRACE) $(SYSCALL_TRACE).c $(LIBS)

clean:
	$(RM) $(MODULE_LIST) $(PROCESS_LIST) $(SYSCALL_LIST) $(NET_PORT) $(SYSCALL_TRACE)
