#include <stdio.h>
#include "secp256k1.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_extrakeys.h"
#include "../src/scalar_4x64.h"
#include "../src/hash.h"


int main()
{
	unsigned char revocation_basepoint_secret[32] = "12345678123456781234567812345678";
	unsigned char per_commitment_secret[32] = "78123456781234567812345678123456";

	unsigned char revocation_basepoint[32];
	unsigned char per_commitment_basepoint[32];

	unsigned char revocationprikey[32];
	unsigned char revocationpubkey[32];

	secp256k1_keypair  revocation_keypair;
	secp256k1_xonly_pubkey revocation_xonly_pubkey;
	secp256k1_scalar revocation_basepoint_secretkey;

	secp256k1_keypair  per_commitment_keypair;
	secp256k1_xonly_pubkey per_commitment_xonly_pubkey;
	secp256k1_scalar per_commitment_secretkey;

	secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

//generate revocation pubkey and privatekey
	secp256k1_keypair_create(ctx, &revocation_keypair,revocation_basepoint_secret);
	secp256k1_keypair_xonly_pub(ctx, &revocation_xonly_pubkey, NULL, &revocation_keypair);
	secp256k1_xonly_pubkey_serialize(ctx, revocation_basepoint, &revocation_xonly_pubkey);
	secp256k1_keypair_seckey_load(ctx, &revocation_basepoint_secretkey, &revocation_keypair);

//generate per_commitment pubkey and privatekey
	secp256k1_keypair_create(ctx, &per_commitment_keypair, per_commitment_secret);
	secp256k1_keypair_xonly_pub(ctx, &per_commitment_xonly_pubkey, NULL, &per_commitment_keypair);
	secp256k1_xonly_pubkey_serialize(ctx, per_commitment_basepoint, &per_commitment_xonly_pubkey);
	secp256k1_keypair_seckey_load(ctx, &per_commitment_secretkey, &per_commitment_keypair);
	
	secp256k1_sha256 sha;
	secp256k1_scalar e1, e2;
	unsigned char buf[32];
//sha256 hash (revocation_basepoint || per_commitment_point)
	secp256k1_schnorrsig_sha256_tagged(&sha);
	secp256k1_sha256_write(&sha, revocation_basepoint, 32);
	secp256k1_sha256_write(&sha, per_commitment_basepoint, 32);
	secp256k1_sha256_finalize(&sha, buf);
	secp256k1_scalar_set_b32(&e1, buf, NULL);

//sha256 hash (per_commitment_point || revocation_basepoint )
	secp256k1_schnorrsig_sha256_tagged(&sha);
	secp256k1_sha256_write(&sha, per_commitment_basepoint, 32);
	secp256k1_sha256_write(&sha, revocation_basepoint, 32);
	secp256k1_sha256_finalize(&sha, buf);
	secp256k1_scalar_set_b32(&e2, buf, NULL);

//get revocation private key
	secp256k1_scalar e3,e4;
	secp256k1_scalar_mul(&e3, &revocation_basepoint_secretkey, &e1);
	secp256k1_scalar_mul(&e4, &per_commitment_secretkey, &e2);
	secp256k1_scalar_add(&e3, &e3, &e4);
	secp256k1_scalar_get_b32(revocationprikey, &e3);

//get revocation public key
	secp256k1_scalar revocation_basepoint_scalar, per_commitment_point_scalar;
	secp256k1_scalar_setb32(&revocation_basepoint_scalar, revocation_basepoint, NULL);
	secp256k1_scalar_setb32(&per_commitment_point_scalar, per_commitment_basepoint, NULL);
	secp256k1_scalar_mul(&e3, &revocation_basepoint_scalar, &e1); 
	secp256k1_scalar_mul(&e4, &per_commitment_point_scalar, &e2);
	secp256k1_scalar_add(&e3, &e3, &e4);
	secp256k1_scalar_get_b32(revocationpubkey, &e3);

	printf("prikey = %s\n", revocationprikey);
	printf("pubkey = %s\n", revocationpubkey);


	return 0;

}
