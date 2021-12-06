#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>

#include "cryptopp/ida.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include "cryptopp/integer.h"
#include "cryptopp/files.h"

using namespace std;
using namespace CryptoPP;

vector<SecByteBlock> SecretShareBytes(const SecByteBlock& secret, int threshold, int nShares)
{
	AutoSeededRandomPool rng;
	ChannelSwitch *channelSwitch;
cout<<"secret size="<<secret.size()<<endl;
	ArraySource source(secret.data(), secret.size(), false, new SecretSharing(rng, threshold, nShares, channelSwitch = new ChannelSwitch, false));
	vector<ostringstream> shares(nShares);
	vector_member_ptrs<FileSink> arraySinks(nShares);
	string channel;
	for (int i = 0; i < nShares; i++)
	{
		arraySinks[i].reset(new FileSink(shares[i]));

		channel = WordToString<word32>(i);
//		arraySinks[i]->Put((byte*) channel.data(), 4);
		channelSwitch->AddRoute(channel, *arraySinks[i], DEFAULT_CHANNEL);
	}
	source.PumpAll();

	vector<SecByteBlock> ret;
	for (const auto &share : shares)
	{
		const auto &piece = share.str();	
		ret.push_back(SecByteBlock(reinterpret_cast<const byte*>(&piece[0]), piece.size()));
cout<<"piece size="<<piece.size()<<endl;
	}
	
	return move(ret);
}

SecByteBlock SecretRecoverBytes(vector<SecByteBlock> &shares, int threshold)
{
	ostringstream out;
	SecretRecovery recovery(threshold, new FileSink(out),false);

//	SecByteBlock channel(4);
	for (int i = 0; i < threshold; i++)
	{
		ArraySource arraySource(shares[i].data(), shares[i].size(), false);

	//	arraySource.Pump(4);
	//	arraySource.Get(channel, 4);
		string channel = WordToString<word32>(i);
		arraySource.Attach(new ChannelSwitch(recovery, channel));

		arraySource.PumpAll();
	}

	const auto &secret = out.str();
	return SecByteBlock(reinterpret_cast<const byte*>(&secret[0]), secret.size());
}




int main()
{
	Integer max("0x100000000");
	cout<<"max="<<max.MinEncodedSize(Integer::UNSIGNED)<<endl;
	Integer a("0xfff12345");
	Integer b("3");
	cout<<a<<endl;
	cout<<b<<endl;
	Integer c(a*b%max);
	cout<<c<<endl;

SecByteBlock byteSec(4);
size_t encodedSize = a.MinEncodedSize(Integer::UNSIGNED);
cout<<"a size="<<encodedSize<<endl;
byteSec.resize(encodedSize);
a.Encode(byteSec.BytePtr(), encodedSize, Integer::UNSIGNED);

cout<<"----------"<<endl;
for (int i = 0; i < encodedSize; i++)
	printf("%c",byteSec[i]);
	cout<<endl;

Integer modulo("0xffffffff");
Integer minmode("3647176804");
Integer one("0x1");
Integer z("0x1");
while ( z != c && modulo != minmode )
{
	const auto shares =SecretShareBytes(byteSec, 3, 7);
	std::vector<SecByteBlock>  partial;
	for (int i = 0; i < 3; i++)
	{
		Integer tmp;
		tmp.Decode(shares[i].BytePtr(), shares[i].SizeInBytes());
		Integer mul = (tmp * b) % modulo;
		SecByteBlock mulByte(4);
cout<<"tmp"<<i<<"="<<tmp<<"        "<<"mul"<<i<<"="<<mul<<endl;
//		size_t mulsize = mul.MinEncodedSize(Integer::UNSIGNED);
		size_t mulsize = 4;
//		cout<<"mulsize"<<i<<"="<<mulsize<<endl;
		mulByte.resize(4);
		mul.Encode(mulByte.BytePtr(), mulsize, Integer::UNSIGNED);

		partial.push_back(mulByte);
	}
	const auto recovered = SecretRecoverBytes(partial, partial.size());

cout<<"----------"<<endl;
/*
for (int i = 0; i < recovered.size(); i++)
	printf("%c",recovered[i]);
cout<<endl;
*/

z.Decode(recovered.BytePtr(), recovered.SizeInBytes());
cout<<z<<endl;

cout<<c<<endl;
modulo = modulo-one;

};
cout<<"--------------------end---------------------"<<endl;
cout<<"modulo="<<modulo<<endl;

	return 0;
}
