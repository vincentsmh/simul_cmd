/*******************************************************************************
 *                        CloudOS 1.0 Security Project
 *           Copyright (c) 2009-2015 by CCMA ITRI. All rights reserved.
 * *****************************************************************************
 * 
 *  Name:
 *      crypto_opt.h
 * 
 *  Description: 
 *      This program contains TCP connection and Crypto API for common use which
 *      are:
 *      1) keygen: randomly generate the session key for encryption
 *      2) encrypt: encrypt a given message
 *      3) decrypt: decrypt a given ciphertext
 *
 *  Input:
 * 
 *  Output:
 * 
 *  Return: 
 * 
 *  Last Update Date: 05/10/2011 by Vincent Huang <VincentSMHuang@itri.org.tw>
 * 
 * ****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "crypto_opt.h"


/*
// Key exchange.  This is used for key exchange receiver.
// role is used to indicate who is issuer and who is receiver
// role = 1 : issuer
// role = 2 : receiver
char *key_exchange_passive(int sockfd, int role)
{
int i, timeout = 3, key_len = sizeof(MASTER_KEY);
char *my_key;
char *cipher;
char their_cipher[key_len+1];
char their_key[key_len+1];

my_key = keygen();

// Encrypt my key
if( (cipher = encrypt(my_key, MASTER_KEY) ) == NULL )
{
free_and_exit(my_key, NULL, NULL);
}

// Exchanging keys
if( role == 1 )
{
// Send my key
if( nbsend_data(sockfd, cipher, key_len, timeout) )
{
free_and_exit(my_key, cipher, NULL);
}

// Receive their key
if( nbrecv_data(sockfd, their_cipher, key_len+1, timeout) )
{
free_and_exit(my_key, NULL, NULL);
}
}
else if( role == 2 )
{
// Receive their key
if( nbrecv_data(sockfd, their_cipher, key_len+1, timeout) )
{
free_and_exit(my_key, NULL, NULL);
}

// Send my key
if( nbsend_data(sockfd, cipher, key_len, timeout) )
{
free_and_exit(my_key, cipher, NULL);
}
}
else
{
free_and_exit(my_key, NULL, NULL);
}

// Decrypt their key
if( (their_key = decrypt(their_cipher, MASTER_KEY, key_len))) == NULL )
{
free_and_exit(my_key, cipher, NULL);
}

// Combine both keys
for( i = 0; i < key_len; i++ )
{
my_key[i] = ((my_key[i] + their_key[i]) % 93) + 33;
}

free_and_exit(cipher, NULL, my_key);
}
 */


// Generate a temprary session key
char *keygen()
{
	int i;
	int key_size;
	unsigned int seed;
	char *key;
	char *mkey;

	key_size = strlen(MASTER_KEY);

	key = (char *) malloc( key_size + 1 );
	if( key == NULL )
		return NULL;

	mkey = (char *) malloc( key_size + 1 );
	if( mkey == NULL )
	{
		free( key );
		return NULL;
	}

	strncpy(mkey, MASTER_KEY, key_size);
	sscanf( MASTER_KEY, "%d", &seed );
	srand( time(NULL) + seed );

	for( i = 0; i < key_size; i++ )
		key[i] = (((rand() % 93) + 33) + mkey[i]) % 93 + 33;

	key[key_size] = '\0';

	free(mkey);
	return key;
}


// Process the given key.  Compress long key to 8 byte-long key
int compress_key(const char *key, DES_cblock *target_key)
{
	int i = 0;
	int rtv = 0;
	int key_len = 0;
	char process_key[9];

	key_len = strlen(key);

	if( key_len < 8 )
		rtv = 1;
	else if( key_len > 8 )
	{
		for( i = 0; i < 8; i++ )
			process_key[i] = key[i];

		for( i = 8; i < key_len; i++ )
			process_key[i % 8] = ((process_key[i % 8] + key[i]) % 93) + 33;
	}
	process_key[8] = '\0';

	if( memcpy( target_key, process_key, 8 ) == NULL )
		rtv = 1;

	return rtv;
}



/* Encrypt a given message
 * Input:
 * 	char *msg
 * 	int  msg_len: the length of msg. User has to assign this value because the
 *                function cannot obtain it whan the given msg is a binary
 *                value.
 * 	char *key: a session key.  It can be a arbitrary length string
 * Output:
 * 	char *ciphertext: the encryption result */
char *encrypt_msg(const char *msg, const int msg_len, const char *key)
{
	int  n=0;
	char *cipher;
	DES_cblock enc_key;
	DES_key_schedule schedule;

	if( (cipher = (char *) malloc( msg_len + 1 )) == NULL )
		return NULL;

	// Prepare the key for use with DES_cfb64_encrypt
	if( compress_key(key, &enc_key) )
	{
		free( cipher );
		return NULL;
	}

	DES_set_odd_parity( &enc_key );

	if( DES_set_key_checked( &enc_key, &schedule ) < 0 )
	{
		if( cipher != NULL)
			free(cipher);
		return NULL;
	}

	// Encryption occurs here
	DES_cfb64_encrypt( (unsigned char *) msg, (unsigned char *) cipher,
			msg_len, &schedule, &enc_key, &n, DES_ENCRYPT );

	return cipher;
}


/* Decrypt a given ciphertext by the given session key
 * Input:
 *	char *cipher: the ciphertext
 * 	char *key: the session key. It can be a arbitrary length string
 * 	int size: the size of returning plaintext
 * Output:
 * 	(char *) a plaintext */
char *decrypt_msg(char *cipher, char *key, const int size)
{
	int n=0;
	char *msg;

	DES_cblock dec_key;
	DES_key_schedule schedule;

	if( (msg = (char *) malloc(size + 1)) == NULL )
		return NULL;

	/* Prepare the key for use with DES_cfb64_encrypt */
	if( compress_key(key, &dec_key) )
	{
		free( msg );
		return NULL;
	}

	DES_set_odd_parity( &dec_key );

	if( DES_set_key_checked( &dec_key, &schedule ) < 0 )
	{
		if( msg != NULL ) free(msg);
			return NULL;
	}

	/* Decryption occurs here */
	DES_cfb64_encrypt( (unsigned char *) cipher, (unsigned char *) msg,
			size, &schedule, &dec_key, &n, DES_DECRYPT );

	msg[size] = '\0';

	return msg;
}
