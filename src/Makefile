CC = gcc
LIBS = -lvmi -lm
OPENSSL_LIBS = -lcrypto

RM = rm -rf

MAIN = vmi
PROCESS_LIST = process-list
MODULE_LIST = module-list
SYSCALL_CHECK = syscall-check
NETWORK_CHECK = network-check
SYSCALL_TRACE = syscall-trace
SOCKETAPI_TRACE = socketapi-trace
DRIVERAPI_TRACE = driverapi-trace
PROCESS_BLOCK = process-block
SLEEPAPI_NOP = sleepapi-nop
PROCESS_KILL = process-kill

OBJECTS = $(MAIN).o $(PROCESS_LIST).o $(MODULE_LIST).o $(SYSCALL_CHECK).o \
	$(NETWORK_CHECK).o $(SYSCALL_TRACE).o $(SOCKETAPI_TRACE).o $(DRIVERAPI_TRACE).o \
	$(PROCESS_BLOCK).o $(SLEEPAPI_NOP).o $(PROCESS_KILL).o

$(MAIN): $(OBJECTS)
	$(CC) -o $(MAIN) $(OBJECTS) $(LIBS) $(OPENSSL_LIBS)

$(OBJECTS): $(MAIN).h

.PHONE: clean
clean:
	$(RM) $(MAIN) $(OBJECTS)
