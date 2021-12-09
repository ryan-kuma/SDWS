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

#include <sys/time.h>


using namespace muduo;
using namespace muduo::net;
using namespace CryptoPP;
using namespace std;

typedef DL_GroupParameters_EC<ECP> GroupParameters;
typedef DL_GroupParameters_EC<ECP>::Element Element;

//给每个瞭望塔分发revocation_secret分片
static int64_t start_piece_time;
static int64_t end_piece_time;

//leader生成rtx并发送给每个瞭望塔
static int64_t start_rtx_time;
static int64_t end_rtx_time;

//leader接收sj并聚合生成s
static int64_t start_s_time;
static int64_t end_s_time;

static int64_t sum_cost_time;
static int64_t conn_count;

class Server
{
public:
	Server(EventLoop* loop, const InetAddress& listenAddr, int n, int k)
	: server_(loop, listenAddr, "server"),revocation_secret_piece(n),piece_n(n),piece_k(k),
		maxp("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),vec_x(0),
		startTime_(Timestamp::now()), vec_ri(n), vec_Ri(n), vec_sj(n)
	{
		server_.setConnectionCallback(
			std::bind(&Server::onConnection, this, _1));
		server_.setMessageCallback(
			std::bind(&Server::onMessage, this, _1, _2, _3));


		AutoSeededRandomPool prng;
		group.Initialize(ASN1::secp256k1());
//generate random secret
		revocation_secret = Integer(prng, Integer::One(), maxp);
		per_commit_secret = Integer(prng, Integer::One(), maxp);

//generate secp256k1 point by secret
		revocation_point = group.ExponentiateBase(revocation_secret);
		per_commit_point = group.ExponentiateBase(per_commit_secret);
	
		secret_sharing(revocation_secret, revocation_secret_piece);
		
//generate revocation_public_key and revocation_private_key
		ostringstream oss;
		oss<<hex<<revocation_point.x;
		string str_revocation_point_x = oss.str();
		oss.str("");
		oss<<hex<<per_commit_point.x;
		string str_per_commit_point_x = oss.str();
		oss.str("");
		
		SHA256 hash;
		string hash_revocation_percommit;
		string hash_percommit_revocation;

		StringSource s1(str_revocation_point_x+str_per_commit_point_x, true, new HashFilter(hash, new HexEncoder(new StringSink(hash_revocation_percommit))));
		StringSource s2(str_per_commit_point_x+str_revocation_point_x, true, new HashFilter(hash, new HexEncoder(new StringSink(hash_percommit_revocation))));

		num_hash_revocation_percommit = Integer(hash_revocation_percommit.c_str());
		num_hash_percommit_revocation = Integer(hash_percommit_revocation.c_str());

		Element v1 = group.GetCurve().ScalarMultiply(revocation_point, num_hash_revocation_percommit);
		Element v2 = group.GetCurve().ScalarMultiply(per_commit_point, num_hash_percommit_revocation);

		revocation_pubkey_point = group.GetCurve().Add(v1,v2);
		revocation_prikey = revocation_secret * num_hash_revocation_percommit + per_commit_secret * num_hash_percommit_revocation;

//simulate generate random rj and rj*G
		for (int i = 1; i < n; i++)
		{
			Integer tmp_ri(prng, Integer::One(), maxp);	
			Element tmp_Ri = group.ExponentiateBase(tmp_ri);

			vec_ri[i] = tmp_ri;
			vec_Ri[i] = tmp_Ri;
		}

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
		if (!conn->connected()) {
			conn->shutdown();
			return ;
		}

		nlohmann::json jsdic;
		jsdic["type"] = 1;

		/*
		struct timeval tv;
		gettimeofday(&tv, NULL);
		int64_t seconds = tv.tv_sec;
		start_piece_time = seconds * 1000 * 1000 + tv.tv_usec;
		printf("-------------------when connect start send secret piece-----------------------\n");
		printf("start_time:%ldus\n", start_piece_time);
		*/

		ostringstream oss("");
		oss<<revocation_point.x;
		string str_revocation_point_x = oss.str();
		oss.str("");
		oss<<per_commit_secret;
		string str_per_commit_secret = oss.str();
		oss.str("");
		oss<<revocation_pubkey_point.x;
		string str_revocation_pubkey_point_x = oss.str();
		oss.str("");

		jsdic["rpoint_x"] = str_revocation_point_x;
		jsdic["psecret_piece"] = str_per_commit_secret;
		jsdic["x_i"] = 1;
		jsdic["rsecret_piece"] = revocation_secret_piece[0];
		jsdic["rpubkey_x"] = str_revocation_pubkey_point_x;

		string msg = jsdic.dump();

		//record time
		struct timeval tv;
		gettimeofday(&tv, NULL);
		int64_t seconds = tv.tv_sec;
		end_piece_time = seconds * 1000 * 1000 + tv.tv_usec;

//		printf("end_time:%ldus\n", end_piece_time);
//		printf("cost_time:%ldus\n", end_piece_time - start_piece_time);
//		printf("-------------------end send secret piece-----------------------\n");

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

				nlohmann::json j = nlohmann::json::parse(message);	
				int type = j["type"];

				switch(type)
				{
					//send rtx
					case 1:
					{
						/*
						struct timeval tv;
						gettimeofday(&tv, NULL);
						int64_t seconds = tv.tv_sec;
						start_rtx_time = seconds * 1000 * 1000 + tv.tv_usec;
						printf("-------------------start send rtx-----------------------\n");
						printf("start_time:%ldus\n", start_rtx_time);
						*/

						//store array of xi and Sum of Ri
						if (static_cast<int>(vec_x.size()) < piece_k) 
						{
							vec_x.push_back(j["xi"].get<int>());
							Integer Ri_x(j["Ri_x"].get<string>().c_str());
							Integer Ri_y(j["Ri_y"].get<string>().c_str());

							Element Ri = ECP::Point(Ri_x, Ri_y);
							if (vec_x.size() == 1)
							{
								R_sum = Ri;
							}else {
								Element R_add = group.GetCurve().Add(R_sum, Ri);
								R_sum = R_add;
							}

						} 
						//simulate multiple peer
						for (int i = 1; i < piece_k; i++)
						{
							vec_x.push_back(i+1);
							Element R_add = group.GetCurve().Add(R_sum, vec_Ri[i]);
							R_sum = R_add;
						}

						if (static_cast<int>(vec_x.size()) >= piece_k){
						//send rtx Rsum and array of xi when receive complete
							nlohmann::json jsdic;	
							jsdic["type"] = 2;

							AutoSeededRandomPool prng;
							Integer rtx(prng, Integer::One(), maxp);	
							ostringstream oss("");
							oss<<rtx;
							string str_rtx = oss.str();
							jsdic["rtx"] = str_rtx;
							oss.str("");
							oss<<R_sum.x;
							string str_R_sum = oss.str();
							jsdic["R_sum_x"] = str_R_sum; 
							oss.str("");

							jsdic["vec_x"] = vec_x;
							
							string msg = jsdic.dump();
							processRequest(conn, msg);

							/* 
							gettimeofday(&tv, NULL);
							seconds = tv.tv_sec;
							end_rtx_time = seconds * 1000 * 1000 + tv.tv_usec;
							printf(" end_time:%ldus\n", end_rtx_time);
							printf("cost_time:%ldus\n", end_rtx_time - start_rtx_time);
							printf("-------------------end send rtx-----------------------\n");
							*/

							/*
							printf("-------------------start simulate-----------------------\n");
							gettimeofday(&tv, NULL);
							seconds = tv.tv_sec;
							int64_t start_simulate_time = seconds * 1000 * 1000 + tv.tv_usec;
							*/

							//simulate generate sj-----------------------------
							SHA256 hash;
							string str_hash_e;

							oss<<revocation_pubkey_point.x;
							string str_revocation_pubkey_point_x = oss.str();
							oss.str("");

							StringSource s1(str_R_sum + str_revocation_pubkey_point_x + str_rtx, true, new HashFilter(hash, new HexEncoder(new StringSink(str_hash_e))));

							hash_e = Integer(str_hash_e.c_str()); 

							for (int j = 1; j < piece_k; j++)
							{ 
								int x_i = vec_x[j];
								Integer revocation_piece(revocation_secret_piece[j].c_str());
								Integer revocation_pri_piece = revocation_piece * num_hash_revocation_percommit;
								
								Integer mul_piece = revocation_pri_piece;
								Integer mul_dens = Integer::One();
								for (vector<int>::iterator iter = vec_x.begin(); iter != vec_x.end(); iter++)
								{
									int x = *iter;
									if (x == x_i)
										continue;

									mul_piece = mul_piece * Integer(x);
									mul_dens = mul_dens * Integer(x-x_i);
								
								}
								mul_piece = mul_piece / mul_dens;

								Integer s_j = vec_ri[j] + (hash_e * mul_piece) % maxp;
								vec_sj[j] = s_j;
							}
						/*
						gettimeofday(&tv, NULL);
						seconds = tv.tv_sec;
						int64_t end_simulate_time = seconds * 1000 * 1000 + tv.tv_usec;
						printf("cost_time:%ldus\n", end_simulate_time - start_simulate_time);
						printf("-----------------------------end simulate--------------------\n");
						*/

													vec_x.clear();
						}
					}
					break;

					case 2:
					{

						/*
						struct timeval tv;
						gettimeofday(&tv, NULL);
						int64_t seconds = tv.tv_sec;
						start_s_time = seconds * 1000 * 1000 + tv.tv_usec;
						printf("-------------------start generate s-----------------------\n");
						printf("start_time:%ldus\n", start_s_time);
						*/

						int xi = j["xi"].get<int>();
						string str_si = j["s_i"].get<string>();
						Integer si(str_si.c_str());

						Integer sum_s = si; 
						for (int i = 1; i < piece_k; i++)
						{
							sum_s = sum_s + vec_sj[i];
						}

						Integer res_s = (sum_s + hash_e * per_commit_secret *  num_hash_percommit_revocation) % maxp;


						struct timeval tv;
						gettimeofday(&tv, NULL);
						int64_t seconds = tv.tv_sec;
						end_s_time = seconds * 1000 * 1000 + tv.tv_usec;
//						printf(" end_time:%ldus\n", end_s_time);
//						printf("cost_time:%ldus\n", end_s_time - start_s_time);
//						printf("all cost:%ldus\n", end_s_time - end_piece_time);
						sum_cost_time = sum_cost_time + (end_s_time - end_piece_time);
						if (conn_count < 1000)
							conn_count++;
						else {
							printf("avg_cost_time=%ldus\n", sum_cost_time/conn_count);
							conn_count = 1;
						}
//						printf("-------------------end generate s-----------------------\n");

						//verify the sign
						verify_sign(res_s);
//						cout<<"res_s="<<res_s<<endl;
						cout<<"-----------------------------"<<conn_count-1<<"-------------------------"<<endl;
					}
					break;
					default:
					break;
				}

//				processRequest(conn, message);
			}
			else
			{
				break;
			}
		}
		
	}

	void verify_sign(Integer &res)
	{
		Element res_point = group.ExponentiateBase(res);

		Element point_right = group.GetCurve().ScalarMultiply(revocation_pubkey_point, hash_e);
		Element hash_point = group.GetCurve().Add(R_sum, point_right);

		if (hash_point.x.Compare(res_point.x) != 0)
			cout<<"!!!!!!!!!!!!!error!!!!!!!!!!!!!"<<endl;

//cout<<"------------------verify--------------------"<<endl;
//		cout<<"hash_point="<<hash_point.x<<endl;
//		cout<<" res_point="<<res_point.x<<endl;
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
	vector<int> vec_x;
	Element R_sum;
	GroupParameters group;
	Timestamp startTime_;

	Integer num_hash_revocation_percommit;
	Integer num_hash_percommit_revocation;

	Element revocation_pubkey_point; 
	Integer revocation_prikey;
	Integer hash_e;
	//simulata
	vector<Integer> vec_ri;
	vector<Element> vec_Ri;
	vector<Integer> vec_sj;
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

		
		conn_count = 1;
		sum_cost_time = 0;

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
