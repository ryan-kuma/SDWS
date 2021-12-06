#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdio>

#include "cryptopp/ida.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include "cryptopp/integer.h"

using namespace std;
using namespace CryptoPP;

vector<string> SecretShareStr(const string& secret, int threshold, int nShares)
{
	AutoSeededRandomPool rng;
	ChannelSwitch *channelSwitch;
	StringSource source(secret, false, new SecretSharing( rng, threshold, nShares, channelSwitch = new ChannelSwitch));

	std::vector<string> shares(nShares);
	vector_member_ptrs<StringSink> strSinks(nShares);
	std::string channel;

	for (int i = 0; i < nShares; i++)
	{
		strSinks[i].reset(new StringSink(shares[i]));
		channel = WordToString<word32>(i);
//		strSinks[i]->Put((const byte *)channel.data(), 4 );
 		channelSwitch->AddRoute(channel, *strSinks[i], DEFAULT_CHANNEL);
	}

	source.PumpAll();
	return shares;
}


string SecretRecoverStr(vector<string>& shares, int threshold)
{
	string recovered;
	SecretRecovery recovery( threshold, new StringSink(recovered));

	vector_member_ptrs<StringSource> strSources(threshold);
//	string channel = WordToString<word32>(4);
//		cout<<"channel="<<channel<<endl;
	for (int i = 0; i < threshold; i++)
	{
		strSources[i].reset(new StringSource(shares[i], false));

	string channel = WordToString<word32>(i);
//		strSources[i]->Pump(4);
//		strSources[i]->Get((byte*)&channel[0], 4 );
		strSources[i]->Attach(new ChannelSwitch( recovery, channel));

		strSources[i]->PumpAll();
	}

	return recovered;
}

int main()
{
	Integer a("123456");
	Integer b("234567");
	cout<<a<<endl;
	cout<<b<<endl;
	cout<<a*b<<endl;

	const string secret = "123456";

    const auto shares = SecretShareStr(secret, 3, 5);
    std::vector<string> partial;
	for (int i = 0; i < 3; i++)
	{
		//string str_shares = shares[i];
		Integer tmp(shares[i].c_str());	
		Integer c(tmp*b);
//		cout<<shares[i]<<endl;
		cout<<tmp<<endl;
		printf("%s\n", shares[i].c_str());
		cout<<c<<endl;
		ostringstream oss;
		oss<<c;
		partial.push_back(oss.str());
	}

    const auto recovered = SecretRecoverStr(partial, partial.size());


	cout<<recovered<<endl;
	cout<<a*b<<endl;
	cout<<secret<<endl;

	return 0;
}
