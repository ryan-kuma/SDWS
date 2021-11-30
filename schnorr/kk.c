#include "secp256k1.h"
#include "secp256k1_schnorrsig.h"
//#include "main_impl.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main()
{
	secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_DECLASSIFY);

	unsigned char key[32];
	int i, ret;
	unsigned char msg[32];
	unsigned char sig[64];

	sprintf(msg, "hello world");

	secp256k1_keypair keypair;

	for (i = 0; i < 32; i++)
	{
		key[i] = i + 65;
	}

	ret = secp256k1_keypair_create(ctx, &keypair, key);
	printf("create key=%d\n", ret);

	ret = secp256k1_schnorrsig_sign(ctx, sig, msg, &keypair, NULL);
	printf("create sign=%d\n", ret);

	return 0;
}
