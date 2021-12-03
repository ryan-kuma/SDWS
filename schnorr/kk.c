#include "include/secp256k1.h"
#include "include/secp256k1_schnorrsig.h"
#include "src/group.h"
#include "src/scalar_low.h"
#include "src/eckey.h"
//#include "hash.h"
//#include "main_impl.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main()
{
	secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	unsigned char key[32]; 
	int i, ret;
	unsigned char msg[32];
	unsigned char sig[64];


	sprintf(msg, "hello world");
	sprintf(key, "hello world you see");

	secp256k1_keypair keypair;
	

	ret = secp256k1_keypair_create(ctx, &keypair, key);
	printf("create key=%d\n", ret);
	
	secp256k1_pubkey pubkey;
	secp256k1_keypair_pub(ctx, &pubkey, &keypair);
	printf("pubkey=%s\n", pubkey.data);

	secp256k1_ge ge;
//	secp256k1_pubkey_load(ctx, &ge, &pubkey);
	secp256k1_scalar skk;
//	secp256k1_keypair_load(ctx, &skk, &ge, &keypair);
	printf("pubkey2222=%s\n", ge.y);

	unsigned char secrete[33];
	secp256k1_keypair_sec(ctx, secrete, &keypair);
	printf("secrete =%s\n",secrete);

	ret = secp256k1_schnorrsig_sign(ctx, sig, msg, &keypair, NULL);
	printf("create sign=%d\n", ret);

	
	
	return 0;
}
