CC = gcc
LIBS = -lvmi -lm
OPENSSL_LIBS = -lcrypto

RM = rm -rf

MAIN = vmi
PROCESS_LIST = process-list
MODULE_LIST = module-list
SYSCALL_CHECK = syscall-check
NETWORK_CHECK = network-check

OBJECTS = $(MAIN).o $(PROCESS_LIST).o $(MODULE_LIST).o $(SYSCALL_CHECK).o $(NETWORK_CHECK).o

$(MAIN): $(OBJECTS)
	$(CC) -o $(MAIN) $(OBJECTS) $(LIBS)

$(OBJECTS): $(MAIN).h

.PHONE: clean
clean:
	$(RM) $(MAIN) $(OBJECTS)
