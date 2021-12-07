#include "cryptopp/integer.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"

#include "cryptopp/sha.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

using namespace CryptoPP;
using namespace std;

typedef	DL_GroupParameters_EC<ECP> GroupParameters;
typedef DL_GroupParameters_EC<ECP>::Element Element;
int main(int argc, char *argv[])
{
    AutoSeededRandomPool prng;
    GroupParameters group;
    group.Initialize(ASN1::secp256k1());

	string str_n("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
	Integer n(str_n.c_str());

    // private key
    Integer revocation_secret(prng, Integer::One(), n);
    Integer per_commit_secret(prng, Integer::One(), n);

	//public key point
	Element revocation_point = group.ExponentiateBase(revocation_secret);
	Element per_commit_point = group.ExponentiateBase(per_commit_secret);
	
	Integer revocation_point_x = revocation_point.x;
	Integer per_commit_point_x = per_commit_point.x;

	Integer revocation_point_y = revocation_point.y;
	Integer per_commit_point_y = per_commit_point.y;

	ostringstream oss;
	oss<<hex<<revocation_point_x;
	string str_revocation_point = oss.str();
	oss.str("");
	oss<<hex<<per_commit_point_x;
	string str_per_commit_point = oss.str();
	oss.str("");

	cout<<per_commit_point_x<<endl;

	Element pppoint = ECP::Point(per_commit_point_x, per_commit_point_y);
	cout<<pppoint.x<<endl;
/*
	cout<<str_revocation_point<<endl;
	cout<<hex<<revocation_point_y<<endl;
	cout<<per_commit_secret.ByteCount()<<endl;
	cout<<n.ByteCount()<<endl;
	*/
	
	SHA256 hash;
	string hash_revocation_percommit;
	string hash_percommit_revocation;
	
	StringSource s1(str_revocation_point+str_per_commit_point, true, new HashFilter(hash, new HexEncoder(new StringSink(hash_revocation_percommit))));
	StringSource s2(str_per_commit_point+str_revocation_point, true, new HashFilter(hash, new HexEncoder(new StringSink(hash_percommit_revocation))));

	Integer num_hash_revocation_percommit(hash_revocation_percommit.c_str());
	Integer num_hash_percommit_revocation(hash_percommit_revocation.c_str());

	Element v1 = group.GetCurve().ScalarMultiply(revocation_point, num_hash_revocation_percommit);
	Element v2 = group.GetCurve().ScalarMultiply(per_commit_point, num_hash_percommit_revocation);

	Element revocationpubkey_point = group.GetCurve().Add(v1,v2);
	Integer revocationprikey = revocation_secret * num_hash_revocation_percommit + per_commit_secret * num_hash_percommit_revocation;

	revocationprikey = revocationprikey % n;
	
	Element revocationprikey_point = group.ExponentiateBase(revocationprikey);
	cout<<revocationpubkey_point.x<<endl;
	cout<<revocationprikey_point.x<<endl;

	return 0;
}

