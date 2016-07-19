CC = gcc
LIBS = -lvmi -lm
OPENSSL_LIBS = -lcrypto

RM = rm -rf

MAIN = vmi
PROCESS_LIST = process-list

OBJECTS = $(MAIN).o $(PROCESS_LIST).o 


$(MAIN): $(OBJECTS)
	$(CC) -o $(MAIN) $(OBJECTS) $(LIBS)

$(MAIN).o: $(PROCESS_LIST).h
$(PROCESS_LIST).o: $(PROCESS_LIST).h


.PHONE: clean
clean:
	$(RM) $(MAIN) $(OBJECTS)
