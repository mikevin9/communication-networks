CC = gcc
OBJS_1 = server.o utils.o
OBJS_2 = client.o utils.o
EXEC_1 = file_server
EXEC_2 = file_client
COMP_FLAG = -std=gnu99 -Wall -g -Wextra -Werror -pedantic-errors

all: $(EXEC_1) $(EXEC_2)

file_server: $(OBJS_1)
	$(CC) utils.o server.o -o $@

file_client: $(OBJS_2)
	$(CC) utils.o client.o -o $@

utils.o: utils.c utils.h
	$(CC) $(COMP_FLAG) -c $*.c

server.o: server.c utils.h
	$(CC) $(COMP_FLAG) -c $*.c

client.o: client.c utils.h
	$(CC) $(COMP_FLAG) -c $*.c

clean:
	rm -f $(OBJS_1) $(OBJS_2) $(EXEC_1) $(EXEC_2)
	