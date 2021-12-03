#include <string>
#include <vector>
#include <iostream>
#include <iomanip>

#include "cryptopp/ida.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"

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
		strSinks[i]->Put((const byte *)channel.data(), 4 );
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
	string channel = WordToString<word32>(4);
	for (int i = 0; i < threshold; i++)
	{
		strSources[i].reset(new StringSource(shares[i], false));

		strSources[i]->Pump(4);
		strSources[i]->Get((byte*)&channel[0], 4 );
		strSources[i]->Attach(new ChannelSwitch( recovery, channel));

		strSources[i]->PumpAll();
	}

	return recovered;
}

int main()
{
	const string secret = "01020304054548833335465";
    const auto shares = SecretShareStr(secret, 3, 7);
    std::vector<string> partial;
    partial.push_back(shares[6]);
    partial.push_back(shares[3]);
    partial.push_back(shares[5]);
    const auto recovered = SecretRecoverStr(partial, partial.size());

    for (const auto & uch : shares)
		  cout<< uch << " "<<endl;

	cout<<recovered<<endl;
	cout<<secret<<endl;

	return 0;
}
