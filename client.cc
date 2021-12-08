#include "muduo/base/Logging.h"
#include "muduo/base/Atomic.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/EventLoopThread.h"
#include "muduo/net/TcpClient.h"

#include "cryptopp/integer.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"

#include "json.hpp"

#include <stdio.h>
#include <iostream>
#include <sstream>
#include <string>

using namespace muduo;
using namespace muduo::net;

using namespace CryptoPP;

using namespace std;

typedef DL_GroupParameters_EC<ECP> GroupParameters;
typedef DL_GroupParameters_EC<ECP>::Element Element;

class Client
{
public:
	Client(EventLoop* loop,
			const InetAddress& srvaddr,
			const string& name,
			bool nodelay)
		: loop_(loop),name_(name),
		tcpNoDelay_(nodelay),
		client_(loop, srvaddr, name_),
		maxp("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	{
		client_.setConnectionCallback(
			std::bind(&Client::onConnection, this, _1));
		client_.setMessageCallback(
			std::bind(&Client::onMessage, this, _1, _2, _3));

		group.Initialize(ASN1::secp256k1());

	}

	void connect()
	{
		client_.connect();
	}

private:
	void onConnection(const TcpConnectionPtr& conn)
	{
		if (conn->connected())
		{
			if (tcpNoDelay_)
				conn->setTcpNoDelay(true);
			conn_ = conn;
		}
		else 
		{
			conn_.reset();
			cout<<"--------------end---------------"<<endl;
			loop_->quit();
		}
	
	}

	void send(const string &message)
	{
		Timestamp now(Timestamp::now());
		Buffer response;

		int32_t len = message.size();	
		response.append(message.c_str(), len);

		int32_t be32 = muduo::net::sockets::hostToNetwork32(len);

		response.prepend(&be32, sizeof(be32));
		conn_->send(&response);
	}

	void onMessage(const TcpConnectionPtr& conn, Buffer *buf, Timestamp recvTime)
	{
		while (buf->readableBytes() >= sizeof(int32_t)) 
		{
			const void* data = buf->peek();
			int32_t be32 = *static_cast<const int32_t*>(data);
			const int32_t len = muduo::net::sockets::networkToHost32(be32);
			if (len > 65536 || len < 0)
			{
				conn->shutdown();
				break;
			}
			else if (buf->readableBytes() >= len + sizeof(int32_t))
			{
				buf->retrieve(sizeof(int32_t));
				muduo::string message(buf->peek(), len);
				buf->retrieve(len);
				

				//get complete msg
//				cout<<"message="<<message<<endl;
				nlohmann::json j = nlohmann::json::parse(message); 
				int type = j["type"];
				switch(type)
				{
					//get revocation_point_x, per_commit_secret, xi, revocation_secret_piece
					case 1:
					{
						string str_revocation_point_x = j["rpoint_x"].get<string>();
						string str_per_commit_secret = j["psecret_piece"].get<string>();
						int xi = j["x_i"].get<int>();
						string str_rpiece = j["rsecret_piece"].get<string>();
						string str_revocationpubkey = j["rpubkey_x"].get<string>();

						this->revocation_secret_piece = Integer(str_rpiece.c_str());
						this->x_i = xi;
						this->revocation_point_x = Integer(str_revocation_point_x.c_str());
						this->per_commit_secret = Integer(str_per_commit_secret.c_str());
						this->revocation_pubkey = str_revocationpubkey;

//						cout<<"rpointx="<<revocation_point_x<<endl;
//						cout<<"psecret="<<per_commit_secret<<endl;
//						cout<<"xi="<<x_i<<endl;
//						cout<<"rpiece="<<revocation_secret_piece<<endl;
//						cout<<"rpubkey="<<revocation_pubkey<<endl;

						AutoSeededRandomPool prng;
						

						this->r_i = Integer(prng, Integer::One(), maxp);
						this->R_i_point = group.ExponentiateBase(this->r_i);

						
						nlohmann::json jsdic;
						jsdic["type"] = 1;
						jsdic["xi"] = xi;

						ostringstream oss("");
						oss<<R_i_point.x;
						jsdic["Ri_x"] = oss.str();
						oss.str("");
						oss<<R_i_point.y;
						jsdic["Ri_y"] = oss.str();
						oss.str("");

						string msg = jsdic.dump();
						send(msg);
					}
					break;
					case 2:
					{
						string str_rtx = j["rtx"].get<string>();
						string str_R_sum = j["R_sum_x"].get<string>();
						vector<int> x_vec = j["vec_x"].get<vector<int>>();
						
						
						//generate per_commit_point = per_commit_secrete * G
						Element per_commit_point = group.ExponentiateBase(per_commit_secret);

						ostringstream oss("");
						oss<<hex<<revocation_point_x;
						string str_revocation_point_x = oss.str();
						oss.str("");
						oss<<hex<<per_commit_point.x;
						string str_per_commit_point_x = oss.str();;
						oss.str("");
						oss.clear();

						//RPri_j = RSec_j * hash(Rpoint_x || Psec * G);
						SHA256 hash;
						string hash_revocation_percommit;
						StringSource s1(str_revocation_point_x+str_per_commit_point_x, true, new HashFilter(hash, new HexEncoder(new StringSink(hash_revocation_percommit))));

						Integer num_hash_revocaion_percommit(hash_revocation_percommit.c_str());

						Integer revocation_pri_piece = revocation_secret_piece *  num_hash_revocaion_percommit;

						// generate e by hash(R_sum||Rpub||rtx)
						string str_revocation_hash_e;
						StringSource s2(str_R_sum + revocation_pubkey + str_rtx, true, new HashFilter(hash, new HexEncoder(new StringSink(str_revocation_hash_e))));

						Integer revocation_hash_e(str_revocation_hash_e.c_str());


						//generate s_j = r_j + e * RRri_j * multi(x_k/(x_k-x_j))
						Integer mul_piece = revocation_pri_piece;
						Integer mul_dens = Integer::One();
						for (vector<int>::iterator iter = x_vec.begin(); iter != x_vec.end(); iter++)
						{
							int x = *iter;
							if (x == x_i)
								continue;
								
							mul_piece = mul_piece * x;
							mul_dens = mul_dens * (x - x_i);
						}
						mul_piece = mul_piece / mul_dens;
						
						Integer s_i = r_i + (revocation_hash_e * mul_piece) % maxp;

						nlohmann::json jsdic;
						jsdic["type"] = 2;
						jsdic["xi"] = x_i;

						oss<<s_i;
						jsdic["s_i"] = oss.str();
						oss.str("");

						string msg = jsdic.dump();
						send(msg);

						conn->shutdown();
					}
					break;
					default:
					break;
				}


			}
			else
			{
				break;
			}
		}
	}

	EventLoop* loop_;
	const string name_;
	const bool tcpNoDelay_;
	TcpClient client_;
	TcpConnectionPtr conn_;
	Integer maxp;
	GroupParameters group;

	Integer revocation_secret_piece;
	int x_i;
	Integer r_i;
	Element R_i_point;
	Integer revocation_point_x;
	Integer per_commit_secret;
	Integer revocation_prikey_piece;

	string revocation_pubkey;
};

int main(int argc, char **argv)
{
	if (argc > 2)
	{
		bool nodelay = true;
		int port = static_cast<int>(atoi(argv[2]));
//		port = 12358;  //default port
		InetAddress srvaddr(argv[1], port);

		EventLoop loop;

		Client client(&loop, srvaddr, "client", nodelay);
		client.connect();
		
//		CurrentThread::sleepUsec(2000 * 1000);
//		client->disconnect();
		loop.loop();
	}
	else
	{
		printf("%s server_ip port\n", argv[0]);
	}
}


