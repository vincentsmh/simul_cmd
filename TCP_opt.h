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


// For creating a socket server
int create_TCP_ServerSocket(unsigned short port, unsigned short maxQ);

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
int connect_TCP(const char *hn , const int port, const int src_port, const int sec);

/* Non-blocking send data.
 *	Input:
 *		int sockfd: socket for transmission
 *		char *data: sending data
 *		int sec: timeout second
 *		int sec: timeout second
 *		int sec_mode: 0/1 for disable/enable the secure channel
 *	Output:
 *      (int) 0 for success, >0 for failure
 */
int nbsend_data(int sockfd, const char *data, int size, int sec, int sec_mode);

// Send data.  This will be block until a receiver ack back.
int send_data( const int sockfd, const char *data);

/* Non-blocking receive data.
 *  Input:
 *      int sockfd: socket for transmission
 *      char *buf: the buffer for filling the received data
 *		int buf_size: the length of the buf
 *      int sec: timeout second
 *      int sec_mode: 0/1 for disable/enable the secure channel
 *      int *recvd_s: will be set as the received data size
 *  Output:
 *      (int) 0 for success, >0 for failure
 */
int nbrecv_data(int sockfd, char *buf, int buf_size, int sec, int sec_mode, int *recvd_s);

// Receive data.  It will be blocked until the sender send some data.
int recv_data(int sockfd, char *buf, int buf_size);

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
int send_file(int sockfd, int timeout, int sec_mode, char *file);

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
int recv_file(int sockfd, int timeout, int sec_mode, char *file_name);
