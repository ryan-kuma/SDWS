#include "muduo/base/Atomic.h"
#include "muduo/base/Thread.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/InetAddress.h"
#include "muduo/net/TcpServer.h"

#include "cryptopp/integer.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"

#include "json.hpp"

#include <sstream>
#include <utility>
#include <stdio.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <iostream>


using namespace muduo;
using namespace muduo::net;
using namespace CryptoPP;
using namespace std;

typedef DL_GroupParameters_EC<ECP> GroupParameters;
typedef DL_GroupParameters_EC<ECP>::Element Element;

class Server
{
public:
	Server(EventLoop* loop, const InetAddress& listenAddr, int n, int k)
	: server_(loop, listenAddr, "server"),revocation_secret_piece(n),piece_n(n),piece_k(k),
		maxp("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
		startTime_(Timestamp::now())
	{
		server_.setConnectionCallback(
			std::bind(&Server::onConnection, this, _1));
		server_.setMessageCallback(
			std::bind(&Server::onMessage, this, _1, _2, _3));


		AutoSeededRandomPool prng;
		GroupParameters group;
		group.Initialize(ASN1::secp256k1());
//generate random secret
		revocation_secret = Integer(prng, Integer::One(), maxp);
		per_commit_secret = Integer(prng, Integer::One(), maxp);

//generate secp256k1 point by secret
		revocation_point = group.ExponentiateBase(revocation_secret);
		per_commit_point = group.ExponentiateBase(per_commit_secret);
	
		secret_sharing(revocation_secret, revocation_secret_piece);

	}

	void start()
	{
		server_.start();
	}

	
private:
//calculate y for x by polynome
	Integer calculate_Y(int x, vector<Integer> &poly)
	{
		Integer y(Integer::Zero());
		Integer tmp(Integer::One());
		for (auto coeff : poly) {
			y = y + (coeff * tmp);
			tmp = tmp * x;
		}
		
		y = y % maxp;
		return y;
	}
//generate sharing piece	
	void secret_sharing(Integer &S, vector<string> &points)
	{
		vector<Integer> poly(piece_k);	
		poly[0] = S;
		AutoSeededRandomPool prng;
		ostringstream oss;

		for (int i = 1; i < piece_k; i++)
		{
			Integer p(prng, Integer::One(), maxp);
			poly[i] = p;
		}
		
		for (int i = 1; i <= piece_n; i++) 
		{
			Integer y = calculate_Y(i, poly);
			string str_y("");
			oss<<y;
			points[i-1] = oss.str();
			oss.str("");
		}
	}

//send revocation_point_x, x_i, revocation_secret_piece and per_commit_secret when client connected
	void onConnection(const TcpConnectionPtr& conn)
	{
		nlohmann::json jsdic;
		jsdic["type"] = 1;

		ostringstream oss("");
		oss<<revocation_point.x;
		string str_revocation_point_x = oss.str();
		oss.str("");
		oss<<per_commit_secret;
		string str_per_commit_secret = oss.str();
		oss.str("");

		jsdic["rpoint_x"] = str_revocation_point_x;
		jsdic["psecret_piece"] = str_per_commit_secret;
		jsdic["x_i"] = 1;
		jsdic["rsecret_piece"] = revocation_secret_piece[0];

		string msg = jsdic.dump();

		//send msg
		processRequest(conn, msg);
	}

	void onMessage(const TcpConnectionPtr& conn, Buffer* buf, Timestamp)
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
cout<<"message="<<message<<endl;				

				nlohmann::json j = nlohmann::json::parse(message);	
				int type = j["type"];

				switch(type)
				{
					//send ctx
					case 1:
					{
					
					}
					break;

					case 2:
					{
					
					}
					break;
					case 3:
					{
					
					}
					break;
					default:
					break;
				}

				processRequest(conn, message);
			}
			else
			{
				break;
			}
		}
		
	}

	bool processRequest(const TcpConnectionPtr& conn, const string& request)
	{
		bool goodRequest = true;

		int32_t len = request.size();

		Buffer response;
		response.append(request.c_str(), len);
		int32_t be32 = muduo::net::sockets::hostToNetwork32(len);
		response.prepend(&be32, sizeof(be32));

		conn->send(&response);

		return goodRequest;
	}

	TcpServer server_;
	Integer revocation_secret;
	Integer per_commit_secret;
	Element revocation_point;
	Element per_commit_point;
	vector<string> revocation_secret_piece;
	int piece_n;
	int piece_k;
	Integer maxp;
	Timestamp startTime_;
};

int main(int argc, char **argv)
{
	if (argc > 3)
	{
		EventLoop loop;
		int port = static_cast<int>(atoi(argv[1]));
		int piece_n = static_cast<int>(atoi(argv[2]));
		int piece_k = static_cast<int>(atoi(argv[3]));

//		port=12358; //default port
		InetAddress listenAddr(port);
		Server srv(&loop, listenAddr, piece_n, piece_k);

		srv.start();
		
		loop.loop();
	}
	else
	{
		printf("%s host_port piece_n piece_k\n", argv[0]);	
	}
}
