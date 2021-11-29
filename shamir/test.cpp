#include "sss.h"
#include "randombytes.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main()
{
	char data[sss_MLEN], restored[sss_MLEN];
	sss_Share shares[5];
	size_t idx;
	int tmp;

	// Read a message to be shared
	strncpy(data, "Tyler Durden isn't real.", sizeof(data));

	// Split the secret into 5 shares (with a recombination theshold of 4)
	sss_create_shares(shares, data, 5, 4);
	
	char buf[1024] = {0};
	memcpy(buf, shares[0], sizeof(shares[0]));
	
	printf("len of buf=%d\n", strlen(buf));


	return 0;
}
