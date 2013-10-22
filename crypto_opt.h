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
/* The master key!! Each end must include the same master key.*/
#define MASTER_KEY	"LkdQaXWIdHmZbOobT0FkiGnw/4BCI7dAjzQP51G6"

#include <openssl/des.h>

char *keygen();
int compress_key(const char *key, DES_cblock *target_key);
char *encrypt_msg(const char *msg, const int msg_len, const char *key);
char *decrypt_msg(char *cipher, char *key, const int size);
