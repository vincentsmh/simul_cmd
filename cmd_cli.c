/*
 * This client will register itself to the server and wait for incoming
 * command. It will execute it by system call after receieving it.
 *
 * Usage: ./cmd_cli srv_ip srv_port
*/
#include <stdio.h>
#include <stdlib.h>
#include "TCP_opt.h"
#include "color.h"

#define TIMEOUT_TO_CONNECT_SERVER 10

int main( int argv, char **argc )
{
	int sockfd;
	int srv_port;
	int ret;
	char cmd_buf[1024];

	if( argv < 3 ) {
		printf( "Usage: ./cmd_cli srv_ip srv_port\n" );
	}

	sscanf( argc[2], "%d", &srv_port );
	sockfd = connect_TCP( argc[1], srv_port, 0, TIMEOUT_TO_CONNECT_SERVER );
	printf( "[INFO] Connected to %s%s:%d%s\n",
	        U_CYAN, argc[1], srv_port, NONE );

	if( sockfd < 0 ) {
		printf( "[Error] Connect to %s:%d failed.\n", argc[1], srv_port );
		exit(1);
	}

	/* Wait command from the server */
	while(1) {
		ret = recv_data( sockfd, cmd_buf, sizeof(cmd_buf) );
		printf( "[INFO] Receive command: %s%s%s\n",
		        U_GREEN, cmd_buf, NONE );

		if( ret != 0 )
			printf( "[Error] %sReceive data from server failed (%d).%s\n",
			        L_RED, ret, NONE );

		printf( "Executing ... \n" );
		system( cmd_buf );
		printf( "\n" );
	}

}

