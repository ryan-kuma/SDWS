#include "hazmat.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main()
{
	char secrete[32] = {0};
	sprintf(secrete, "hello world");
	uint8_t n = 10;
	uint8_t k = 4;
	
	sss_Keyshare keyshares[n];

	sss_create_keyshares(keyshares, secrete, n, k);

	for (int i = 0; i < n; i++)
	{
	printf("-------------%d-------------\n",i);
		char buf[34] = {0};
		memcpy(buf, keyshares[i], 33);
		
		printf("len of buf=%ld\n", strlen(buf));
		printf("buf=");
		fwrite(buf,sizeof(char),sizeof(buf),stdout);
		printf("\n");
		
		uint8_t b = 0;
		memcpy(&b, buf, 1);
		printf("index=%d\n", b);
	}


	return 0;
}
