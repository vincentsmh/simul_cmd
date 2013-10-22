//#***************************************************************************
//#                        CloudOS 1.0 Security Project
//#          Copyright (c) 2009-2015 by CCMA ITRI. All rights reserved.
//#***************************************************************************
//#
//# Name:
//#     TCP_opt.c
//#
//# Description: 
//#     This program contains several TCP API in common use which are
//#		1) create_TCP_ServerSocket: Create a socket server
//#		2) connect_TCP: Connect to a socket server
//#		3) send_data: send data
//#		4) recv_data: receive data
//#		5) nbsend_data: Non-blocking send data
//#		6) nbrecv_data: Non-blocking receive data
//#
//# Input:
//#
//#
//# Output:
//#
//#
//# Return: 
//#
//#
//# Last Update Date: 03/03/2011 by Vincent Huang <VincentSMHuang@itri.org.tw>
//#
//#****************************************************************************
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include "crypto_opt.h"
extern int h_errno;

#include <errno.h>

#define TCP_ACK        "ACK_OK"
#define SEND_BUF_SIZE  102400 // The value cannot be larger than that on in 
                              // /proc/sys/net/core/wmem_max

// For creating a socket server
int create_TCP_ServerSocket(unsigned short port, unsigned short maxQ)
{
	int sock;
	int sock_opt = 0;
	struct sockaddr_in echoServAddr;

	/* Create socket for incoming connections */
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		return -1;

	/* Construct local address structure */
	memset(&echoServAddr, 0, sizeof(echoServAddr));		/* Zero out structure */
	echoServAddr.sin_family		 = AF_INET;				/* Internet address family */
	echoServAddr.sin_addr.s_addr = htonl(INADDR_ANY);	/* Any incoming interface */
	echoServAddr.sin_port		 = htons(port);			/* Local port */

	// Set socket re-useable (in order to avoid bind problem of socket release)
	if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
				(void *)&sock_opt, sizeof(sock_opt)) == -1 )
    	{
		close( sock );
        return -2;
    	}

	/* Bind to the local address */
	if (bind(sock, (struct sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
	{
		close( sock );
		return -3;
	}

	/* Mark the socket so it will listen for incoming connections */
	if (listen(sock, maxQ) < 0)
	{
		close( sock );
		return -4;
	}

	return sock;
}


int free_and_return(char *p1, char *p2, int rtv)
{
	if( p1 != NULL ) free(p1);
	if( p2 != NULL ) free(p2);
	return rtv;
}


int exit_connect_TCP(int sock, int rtv)
{
	close(sock);
	return rtv;
}

/* Connect to a target host
 * Input:
 * 	char *hn: This can be domain name (like secs.ccma.itri) or IP
 * 	int port: The listening port of the connecting server
 * 	int src_port: If src_port = 0, the host will not assign a source port 
 * 		for connection.  If src_port != 0, the connection will bind to 
 *		source port as src_port.
 * Output:
 *	int: positive value for successful socket connection
 *		 negative value for error
 */
int connect_TCP(const char *hn , const int port, const int src_port, const int sec)
{
	int sock;
	int sock_opt = 1; /* The sock_opt must be a non-zero value to enable 
						 setsockopt */
	int flag;
	int default_timeout_sec = 10;
	int err = 0;
	socklen_t len;
	unsigned long sleep_sec = 0;
	unsigned long sleep_interval = 100000;	// microsecod
	char ip[20];
	struct sockaddr_in serv_addr  = {0};
	struct sockaddr_in local_addr = {0};
	struct hostent *host;
	struct timeval timeout;
	fd_set sockset_r, sockset_w;

	// Set timeout
	timeout.tv_usec = 0;
	if( sec <= 0 ) 
		timeout.tv_sec = default_timeout_sec;
	else
		timeout.tv_sec = sec;

	// Create a reliable, stream socket using TCP
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	// If the source port (src_port has been assigned, bind the socket to the local host
	if( src_port != 0 )
	{
		// Configure local host and port
		local_addr.sin_family	   = AF_INET;
		local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		local_addr.sin_port		   = htons(src_port);

		// Set the socket as reusable
		if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
				&sock_opt, sizeof(sock_opt)) == -1 )
		{
			return exit_connect_TCP(sock, -4);
		}

		// Try to bind with the local address and port until timeout (sec)
		while( bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0 )
		{
			usleep( sleep_interval );
			sleep_sec += sleep_interval;

			if( sleep_sec < sec * 1000000 )
				continue;
			else
				return exit_connect_TCP(sock, -5);
		}
	}

	// Obtain IP from the host domain name
	if( (host = gethostbyname(hn)) == NULL )
		return exit_connect_TCP(sock, -6);
	else
		strncpy(ip, inet_ntoa(*(struct in_addr*)host->h_addr), sizeof(ip));

	// Configure remote host and port
	serv_addr.sin_family      = AF_INET;		// Internet address family
	serv_addr.sin_addr.s_addr = inet_addr(ip);	// Server IP address
	serv_addr.sin_port        = htons(port);	// Server port

	// Set the socket as non-blocking for select timeout testing
	// Retrieve original flag
	if( (flag = fcntl( sock, F_GETFL, 0)) < 0 )
		return exit_connect_TCP(sock, -7);

	// Set non-blocking flag
	if( fcntl( sock, F_SETFL, flag | O_NONBLOCK ) < 0 )
		return exit_connect_TCP(sock, -8);

	while(1)
	{
		// Connect
		if (connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == 0)
		{
			/* Connection successful.  Set the socket back to the original state */
			if( fcntl( sock, F_SETFL, flag ) < 0 )
				return exit_connect_TCP(sock, -9);

			return sock;
		}

		// *** Begin to check the connection ***
		FD_ZERO( &sockset_r );
		FD_ZERO( &sockset_w );
		FD_SET( sock, &sockset_r );
		FD_SET( sock, &sockset_w );

		// Wait for connection
		if( select(sock+1, &sockset_r, &sockset_w, NULL, &timeout) <= 0 )
			return exit_connect_TCP(sock, -10);

		/* If the sockset_r is returned, it means that there has some problem
		   to connect to the serveri.  Retry connection until timeout. */
		if( FD_ISSET(sock, &sockset_r ) )
		{
			// Sleep 0.1 second
			usleep(sleep_interval);

			// Decrease timeout
			if( timeout.tv_usec < sleep_interval )
			{
				if( timeout.tv_sec >= 1 )
				{
					timeout.tv_sec -= 1;
					timeout.tv_usec += 1000000;
				}
				else
					return exit_connect_TCP(sock, -11);
			}

			timeout.tv_usec -= sleep_interval;
			// Go back and retry connection
			continue;
		}

		if( FD_ISSET(sock, &sockset_w ) )
			break;
	}

	// Check socket state
	len = sizeof(err);
	if( getsockopt(sock, SOL_SOCKET, SO_ERROR, (void *) &err, &len) < 0 )
		return exit_connect_TCP(sock, -12);

	if( err != 0 )
		return exit_connect_TCP(sock, -13);
	// *** End of check connection ***

	// Set back to the original flag
	if( fcntl( sock, F_SETFL, flag ) < 0 )
		return exit_connect_TCP(sock, -14);

	return sock;
}


/* Non-blocking send data.
 *	Input:
 *		int sockfd: socket for transmission
 *		char *data: sending data
 *		int size: the size of the sending data
 *		int sec: timeout second
 *		int sec_mode: 0/1 for disable/enable the secure channel
 *	Output:
 *      (int) 0 for success, >0 for failure
 */
int nbsend_data(int sockfd, char *data, int size, int sec, int sec_mode)
{
	int recv_nbytes;
	int sent_nbytes;
	int buf_index;
	int nbytes_size;
	char ack_buf[10], nbytes_buf[20];
	char *key = NULL;
	char *send_buf = NULL;
	struct timeval timeout;
	fd_set sockset;

	// Set timeout 
	timeout.tv_sec = sec;
	timeout.tv_usec = 0;

	// Set socket set
	FD_ZERO( &sockset );
	FD_SET( sockfd, &sockset );

	if( snprintf(nbytes_buf, sizeof(nbytes_buf), "%d", size) < 0 )
		return 1;

	nbytes_size = strlen(nbytes_buf);

	// If under the security mode, send the session key first
	if( sec_mode )
	{
		key = (char *) keygen();

		if( key == NULL )
			return 2;

		// Send session key first
		if( (send_buf = (char *)encrypt_msg(key, strlen(key), MASTER_KEY)) == NULL )
			return free_and_return(key, NULL, 3);

		if( select(sockfd+1, NULL, &sockset, NULL, &timeout) == 0 )
			return free_and_return(key, send_buf, 4);
		else
		{
			if( (sent_nbytes = send(sockfd, send_buf, strlen(key), MSG_NOSIGNAL)) <= 0 )
				return free_and_return(key, send_buf, 5);
		}

		free(send_buf);
		send_buf = NULL;

		// Ack for session key
		if( select(sockfd+1, &sockset, NULL, NULL, &timeout) == 0 )
			return free_and_return(key, send_buf, 6);
		else
		{
			if( (recv_nbytes = recv(sockfd, ack_buf, sizeof(ack_buf), 0)) <= 0 )
				return free_and_return(key, send_buf, 7);
		}
	}

	// Send data size
	if( sec_mode )
		send_buf = encrypt_msg(nbytes_buf, strlen(nbytes_buf), key);
	else
		send_buf = nbytes_buf;

	if( select(sockfd+1, NULL, &sockset, NULL, &timeout) == 0 )
		return free_and_return(key, send_buf, 8);
	else
	{
		if( (sent_nbytes = send(sockfd, send_buf, nbytes_size, MSG_NOSIGNAL)) <= 0 )
			return free_and_return(key, send_buf, 9);
	}

	if( sec_mode )
		free(send_buf);

	// Receive ack for data size
	if( select(sockfd+1, &sockset, NULL, NULL, &timeout) == 0 )
		return 10;
	else
	{
		if( (recv_nbytes = recv(sockfd, ack_buf, sizeof(ack_buf), 0)) <= 0 )
			return 11;
	}

	// Send data (loop)
	buf_index = 0;

	if( sec_mode )
	{
		if( (send_buf = encrypt_msg(data, size, key)) == NULL )
			return free_and_return(key, NULL, 12);
	}
	else
		send_buf = data;

	while( size > 0 )
	{
		if( select(sockfd+1, NULL, &sockset, NULL, &timeout) == 0 )
		{
			if( sec_mode )
				free_and_return(key, send_buf, 0);

			return 13;
		}
		else
		{
			sent_nbytes = send(sockfd, &(send_buf[buf_index]), size, MSG_NOSIGNAL);

			if( sent_nbytes > 0 )
			{
				size -= sent_nbytes;
				buf_index += sent_nbytes;
			}
			// If the return value of send is negative, sleep 1 second and retry.
			else
			{
				if( timeout.tv_sec <= 0 && timeout.tv_usec <= 0 )
					return 14;

				timeout.tv_sec -= 1;
				timeout.tv_usec = 0;
				sleep(1);
			}
		}
	}

	if( sec_mode )
		free_and_return(key, send_buf, 0);

	return 0;
}


// Send data.  This will be block until a receiver ack back.
int send_data( const int sockfd, const char *data )
{
	int nbytes, recv_nbytes, sent_nbytes, buf_index;
	char ack_buf[10], nbytes_buf[20];

	nbytes = strlen(data);
	sprintf(nbytes_buf, "%d", nbytes);
	nbytes_buf[nbytes] = '\0';

	// Send nbytes
	if( (sent_nbytes = send(sockfd, nbytes_buf, strlen(nbytes_buf), 0)) <= 0 )
		return 1;

	// Ack for nbytes
	if( (recv_nbytes = recv(sockfd, ack_buf, sizeof(ack_buf), 0)) < 0 )
		return 2;

	// Send data (loop)
	buf_index = 0;
	while( nbytes > 0 )
	{
		sent_nbytes = send(sockfd, &(data[buf_index]), nbytes, 0);
		if( sent_nbytes  >= 0 )
		{
			nbytes -= sent_nbytes;
			buf_index += sent_nbytes;
		}
	}

	return 0;
}


/* Non-blocking receive data.
 *  Input:
 *      int sockfd: socket for transmission
 *      char *buf: the buffer for filling the received data
 *		int buf_size: the length of the buf
 *      int sec: timeout second
 *      int sec_mode: 0/1 for disable/enable the secure channel
 *      int &recvd_s: will be set as the received data size
 *  Output:
 *      (int) 0 for success, >0 for failure
 */
int nbrecv_data(int sockfd, char *buf, int buf_size, int sec, int sec_mode, int *recvd_s)
{
	int sent_nbytes;
	int recv_nbytes;
	int data_size;
	int buf_index;
	int recv_size;
	char nbytes_buf[20];
	char key_buf[sizeof(MASTER_KEY)+1];
	char *key = NULL;
	char *plaintext = NULL;
	struct timeval timeout;
	fd_set sockset;

	// Set timeout
	timeout.tv_sec = sec;
	timeout.tv_usec = 0;

	// Set socket set
	FD_ZERO( &sockset );
	FD_SET( sockfd, &sockset );

	// If under security mode, receive session key first
	if( sec_mode )
	{
		// Receive nbytes
		if( select(sockfd+1, &sockset, NULL, NULL, &timeout) == 0 )
			return 1;
		else
		{
			//if( (recv_nbytes = recv(sockfd, key_buf, sizeof(MASTER_KEY), MSG_NOSIGNAL)) <= 0 )
			if( (recv_nbytes = recv(sockfd, key_buf, strlen(MASTER_KEY), MSG_NOSIGNAL)) <= 0 )
				return 2;
		}

		key_buf[recv_nbytes] = '\0';

		// Decrypt session key
		//if( (key = decrypt(key_buf, MASTER_KEY, sizeof(MASTER_KEY))) == NULL )
		if( (key = decrypt_msg(key_buf, MASTER_KEY, strlen(MASTER_KEY))) == NULL )
			return 3;

		// Send ack for session key
		if( select(sockfd+1, NULL, &sockset, NULL, &timeout) == 0 )
			return free_and_return(key, NULL, 4);
		else
		{
			if( (sent_nbytes = send(sockfd, TCP_ACK, sizeof(TCP_ACK), MSG_NOSIGNAL)) <= 0 )
				return free_and_return(key, NULL, 5);
		}
	}

	// Receive data size
	if( select(sockfd+1, &sockset, NULL, NULL, &timeout) <= 0 )
		return 6;
	else
	{
		if( (recv_nbytes = recv(sockfd, nbytes_buf, sizeof(nbytes_buf), 0)) <= 0 )
			return 7;
	}
	nbytes_buf[recv_nbytes] = '\0';

	// Decrypt data size
	if( sec_mode )
	{
		if( (plaintext = decrypt_msg(nbytes_buf, key, recv_nbytes)) == NULL )
			return free_and_return(key, NULL, 8);
	}
	else
		plaintext = nbytes_buf;

	sscanf(plaintext, "%d", &data_size);

	if( data_size >= buf_size )
		data_size = buf_size - 1;

	if( sec_mode )
		free(plaintext);

	// Send ack for nbytes
	if( select(sockfd+1, NULL, &sockset, NULL, &timeout) == 0 )
		return 9;
	else
	{
		if( (sent_nbytes = send(sockfd, TCP_ACK, sizeof(TCP_ACK), MSG_NOSIGNAL)) <= 0 )
			return 10;
	}

	// Receive data (loop)
	buf_index = 0;
	*recvd_s = 0;
	while( data_size > 0 )
	{
		// Only receive the remained data
		if( data_size < buf_size ) recv_size = data_size;

		if( select(sockfd+1, &sockset, NULL, NULL, &timeout) <= 0 )
			return 11;
		else
		{
			recv_nbytes = recv(sockfd, &(buf[buf_index]), recv_size, 0);
			if( recv_nbytes > 0 )
			{
				data_size -= recv_nbytes;
				buf_index += recv_nbytes;
			}
			// If the return value less than 0, sleep 1 second and retry
			else
			{
				if( timeout.tv_sec <= 0 && timeout.tv_usec <= 0 )
					return 12;

				timeout.tv_sec -= 1;
				timeout.tv_usec -= 0;
				sleep(1);
			}
		}
	}
	*recvd_s = buf_index;

	// Decrypt data
	if( sec_mode )
	{
		if( (plaintext = decrypt_msg(buf, key, buf_index)) == NULL )
			return free_and_return(key, NULL, 13);

		memcpy(buf, plaintext, buf_index);
	}
	buf[buf_index] = '\0';

	return free_and_return(key, plaintext, 0);
}


// Receive data.  It will be blocked until the sender send some data.
int recv_data(int sockfd, char *buf, int buf_size)
{
	int sent_nbytes, recv_nbytes, data_size=0, buf_index;
	int recv_size;
	char nbytes_buf[20];

	recv_size = buf_size;

	// Receive nbytes
	recv_nbytes = recv(sockfd, nbytes_buf, sizeof(nbytes_buf), 0);
	if( recv_nbytes  < 0 )
		return 1;
	nbytes_buf[recv_nbytes] = '\0';

	sscanf(nbytes_buf, "%d", &data_size);
	if( data_size >= buf_size )
		data_size = buf_size - 1;

	recv_size = data_size;

	// Send ack for nbytes
	sent_nbytes = send(sockfd, TCP_ACK, sizeof(TCP_ACK), 0);
	if( sent_nbytes < 0 )
		return 2;

	// Receive data (loop)
	buf_index = 0;
	while( data_size > 0 )
	{
		// Receive the remained data
		if( data_size < buf_size )
			recv_size = data_size;

		recv_nbytes = recv(sockfd, &(buf[buf_index]), recv_size, 0);
		if( recv_nbytes >= 0 )
		{
			data_size -= recv_nbytes;
			buf_index += recv_nbytes;
		}
	}
	buf[buf_index] = '\0';

	return 0;
}


/* Send a file
   Input:
    1) sockfd: socket ID
    2) timeout: seconds for timeout
    3) sec_mode: security mode 0/1 for disable/enable
    4) fn: the path to the file which will be sent
   Output:
    1: failed to get file size
    2: failed to convert int to string of file size
    3: failed to send file size to the receiver
    4: failed to open the sending file
    5: failed to send file
*/
int send_file(int sockfd, int timeout, int sec_mode, char *fn)
{
	int bytes_read, file_size;
	int sizeof_buf, sizeof_fsbf, sizeof_char;
	char buf[SEND_BUF_SIZE], file_size_bf[64];
	struct stat statbf;
	FILE *fp;

	sizeof_buf = sizeof(buf);
	sizeof_fsbf = sizeof(file_size_bf);
	sizeof_char = sizeof(char);

	// Get file size
	if( stat( fn, &statbf ) == -1 )
		return 1;

	file_size = (int)statbf.st_size;
	if( snprintf( file_size_bf, sizeof_fsbf, "%d", file_size ) < 0 )
		return 2;

	// Send file size to the receiver
	if( nbsend_data(sockfd, file_size_bf, strlen(file_size_bf), timeout, sec_mode) )
		return 3;

	// Read file and send file content to the receiver
	if( (fp = fopen(fn, "rb")) == NULL )
		return 4;

	while( file_size > 0 )
	{
		bytes_read = fread(buf, sizeof_char, sizeof_buf, fp);

		if( bytes_read != 0 )
		{
			if( nbsend_data(sockfd, buf, bytes_read, timeout, sec_mode) )
			{
				fclose(fp);
				return 5;
			}
		}

		file_size -= bytes_read;

		if( feof(fp) )
			break;
	}
	fclose(fp);

	return 0;
}


/* Receive a file
   Input:
    1) sockfd: socket ID
    2) timeout: seconds for timeout
    3) sec_mode: security mode 0/1 for disable/enable
    4) file_name: the received file will be stored as the file name

	Return code:
	 1: failed to receive file size
	 2: failed to convert receive file size from string to integer
	 3: failed to open file for writing
	 4: failed to receive file context
	 5: failed to write the received context to file
*/
int recv_file(int sockfd, int timeout, int sec_mode, char *file_name)
{
	int recvd_s;
	int fs;
	int bytes_written;
	char buf[SEND_BUF_SIZE+1], fs_bf[64];
	FILE *fp;

	// Receiver file size
	if( nbrecv_data(sockfd, fs_bf, sizeof(fs_bf), timeout, sec_mode, &recvd_s) )
		return 1;

	if( sscanf(fs_bf, "%d", &fs) == 0 )
		return 2;

	// Receive and write file
	if( (fp = fopen(file_name, "wb")) == NULL )
		return 3;

	while( fs > 0 )
	{
		if( nbrecv_data(sockfd, buf, sizeof(buf), timeout, sec_mode, &recvd_s) )
		{
			fclose(fp);
			return 4;
		}

		// Check if the end of transmission
		if( strcmp(buf, "T_EOF") == 0 )
			break;

		if( (bytes_written = fwrite(buf, 1, recvd_s, fp)) == -1 )
		{
			fclose(fp);
			return 5;
		}

		fs -= bytes_written;
	}

	fclose(fp);
	return 0;
}
