#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "TCP_opt.h"
#include "crypto_opt.h"

#define MAX_RETRYTIME 10
#define CMD_EXIT      "exit"
#define CLIENT_SOCKET_UPPER 1000
#define CLIENT_SOCKET_BASE  900

struct incoming_client {
	int  sockfd;
	char ip[16];
	int  port;
	struct incoming_client *next;
};

struct sock_srv_param {
	int port;
	int backlog;
};

static struct incoming_client *cli_head = NULL;
static int on_service = 0;

void print_usage( void )
{
	printf( "Usage: ./cmd_srv port backlog\n" );
	printf( "   - Your command server will bind to the given port with the number of backlog setting.\n" );
}

void clean_client_data( void )
{
	struct incoming_client *cli_ptr = cli_head, *cli_n;

	if( cli_ptr == NULL )
		return;

	do {
		cli_n = cli_ptr;
		close(cli_ptr->sockfd);
		free( cli_ptr );
		cli_ptr = cli_n;
	} while( cli_ptr != cli_head );

	return;
}

/* Socket server for accepting client's connection */
void *sock_srv(void *param)
{
	int sockfd, recfd;
	int client_socket_i = CLIENT_SOCKET_BASE;
	int try_time = 0;
	struct sock_srv_param *srv_p = (struct sock_srv_param *) param;
	struct incoming_client *cli_ptr, *cli_new;
	struct sockaddr_in client_addr;
	socklen_t addr_len;

	/* Create TCP socket server */
	while( (sockfd = create_TCP_ServerSocket(srv_p->port, srv_p->backlog)) < 0 )
	{
		printf( "Create TCP socker server failed.\n" );
		printf( "Sleep 3 seconds and retry...\n" );
		sleep(3);

		try_time++;
		if( try_time >= MAX_RETRYTIME )
		{
			printf( "Tried %d times. Give up!\n", try_time );
			printf( "Please check your network status.\n" );
			close(sockfd);
			exit(EXIT_FAILURE);
		}
	}

	printf( "Command server is working on port: %d\n", srv_p->port );
	addr_len = sizeof(client_addr);
	on_service = 1;

	while( 1 )
	{
		/* Accept incoming connectin */
		if( (recfd = accept(sockfd,
		                   (struct sockaddr *)&client_addr,
		                   &addr_len) ) < 0)
		{
			perror( "Accept connection failed: " );
			clean_client_data();
			exit(EXIT_FAILURE);
		}

		/* Check if on_service */
		if( !on_service ) {
			break;
		}

		/* Allocate data */
		cli_new = (struct incoming_client *) malloc( sizeof(struct incoming_client) );

		if( cli_new == NULL ) {
			printf( "[Error] malloc fail\n" );
			clean_client_data();
			exit(EXIT_FAILURE);
		}

		if( cli_head == NULL ) {
			cli_head = cli_new;
		} else {
			cli_ptr->next = cli_new;
		}

		cli_ptr = cli_new;
		cli_new->sockfd = client_socket_i++;

		if( dup2( recfd, cli_new->sockfd ) == -1 ) {
			perror( "dup2(): ");
		}

		close( recfd );
		cli_new->next = cli_head;
		strcpy( cli_new->ip, inet_ntoa(client_addr.sin_addr) );
		cli_new->port = (int)client_addr.sin_port;

		printf( "\n[INFO] Coming a new client: %s:%d\nCMD: ", 
		        cli_new->ip, cli_new->port );
		fflush( stdout );

		if( client_socket_i == 1000 ) {
			printf( "The server cannot accept more then %d clients.",
			        ( CLIENT_SOCKET_UPPER - CLIENT_SOCKET_BASE ) );
		}
	}

	/* Close socket */
	close(sockfd);
	printf( "[INFO] The socket server is terminated.\n" );
	pthread_exit(0);
}

void terminate_srv( const int port )
{
	int sockfd;

	on_service = 0;
	printf( "[INFO] Start terminating server ... " );
	sockfd = connect_TCP( "127.0.0.1", port, 0, 10);

	if( sockfd < 0 ) {
		printf( "failed (%d).\n", sockfd );
	}

	close(sockfd);
	printf( "Done\n" );
}

void send2clients( const char *cmd )
{
	struct incoming_client *cli_ptr = cli_head;

	if( cli_ptr == NULL ) {
		printf( "[INFO] No clients connect to this server.\n" );
		return;
	}

	if( strlen( cmd ) == 0 ) {
		return;
	}

	/* Send command to all clients */
	printf( "[INFO] Send {%s} to", cmd );

	do {
		send_data( cli_ptr->sockfd, cmd );
		printf( " (%s:%d)", cli_ptr->ip, cli_ptr->port );
		cli_ptr = cli_ptr->next;
	} while( cli_ptr != cli_head );

	printf( "\n" );
	return;
}

int main( int argv, char **argc )
{
	int pthd;
	char cmd[1024], *cmd_ptr;
	char cmd2client[1024];
	struct sock_srv_param ss_p;
	pthread_t sock_srv_t;
	pthread_attr_t attr;

	if( argv < 3 ) {
		print_usage();
		exit( EXIT_SUCCESS );
	}

	sscanf( argc[1], "%d", &ss_p.port );
	sscanf( argc[2], "%d", &ss_p.backlog );

	/* Set pthread detach */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	/* Create the socket server thread */
	if( (pthd = pthread_create( &sock_srv_t,
	                            &attr, sock_srv,
	                            (void*)&ss_p.port)) ) {
		printf( "Create socket server thread failed (%d)\n", pthd );
		exit( EXIT_FAILURE );
	}

	/* Check if the server is working */
	while( on_service == 0 ) {
		sleep(1);
	}

	/* Intractive interface */
	printf( "\nCMD: " );

	while( fgets( cmd, sizeof(cmd), stdin) )
	{
		cmd[ strlen(cmd)-1 ] = '\0';

		if( cmd[0] == '!' ) {
			cmd_ptr = &cmd[1];

			if( strncmp(cmd_ptr, CMD_EXIT, sizeof(cmd)) == 0 ) {
				/* Terminate socket server */
				terminate_srv( ss_p.port );

				/* Clean all client data */
				clean_client_data();
				break;
			}
		} else {
			strcpy( cmd2client, cmd );
			send2clients( cmd2client );
		}

		fflush(stdin);
		fflush(stdout);
		printf( "CMD: " );
	}

	return 0;
}
