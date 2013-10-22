#define  RAN_NUM 8 // Define the number of the salt field (up to 16)
#define _XOPEN_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

char* enc_password(const char *passwd)
{
	int  i, tmp;
	char *enc, salt[RAN_NUM + 4], rand_salt[RAN_NUM+1];

	rand_salt[RAN_NUM] = '\0';
	strcpy(salt, "$6$");

	// Randomly generate RAN_NUM chars
	for( i=0; i<RAN_NUM; i++)
	{
		tmp = rand() % 3;

		switch(tmp) {
			case(0): tmp = rand() % 12 + 46; break;
			case(1): tmp = rand() % 26 + 65; break;
			case(2): tmp = rand() % 26 + 97; break;
		}
		rand_salt[i] = (char)tmp;
	}
	strcat(salt, rand_salt);
	strcat(salt, "$");
	enc = crypt(passwd, salt);

	return enc;
}
