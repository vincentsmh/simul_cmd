COM_SRC = TCP_opt.c crypto_opt.c enc_password.c
COM_OBJ = TCP_opt.o crypto_opt.o enc_password.o
SRV_SRC = cmd_srv.c
CLI_SRC = cmd_cli.c
SRV_BIN = cmd_srv
CLI_BIN = cmd_cli
LIB = -pthread -lssl -lcrypt -lcrypto

.PHONY: all clean $(MODULES)

all:
	gcc -c $(COM_SRC) -Wall
	gcc $(SRV_SRC) $(COM_OBJ) $(LIB) -o $(SRV_BIN) -Wall
	gcc $(CLI_SRC) $(COM_OBJ) $(LIB) -o $(CLI_BIN) -Wall
clean:
	rm -rf cmd_srv cmd_cli *.o
