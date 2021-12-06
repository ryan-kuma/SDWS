#include "muduo/base/Logging.h"
#include "muduo/base/Atomic.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/TcpClient.h"

#include "json.hpp"

#include <stdio.h>
#include <iostream>

using namespace muduo;
using namespace muduo::net;

using namespace std;

class Client
{
public:
	Client(EventLoop* loop,
			const InetAddress& srvaddr,
			const string& name,
			bool nodelay)
		: name_(name),
		tcpNoDelay_(nodelay),
		client_(loop, srvaddr, name_)
	{
		client_.setConnectionCallback(
			std::bind(&Client::onConnection, this, _1));
		client_.setMessageCallback(
			std::bind(&Client::onMessage, this, _1, _2, _3));

		times = 3;
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
				cout<<"message="<<message<<endl;
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

						cout<<"rpointx="<<str_revocation_point_x<<endl;
						cout<<"psecret="<<str_per_commit_secret<<endl;
						cout<<"xi="<<xi<<endl;
						cout<<"rpiece="<<str_rpiece<<endl;
						
						nlohmann::json jsdic;
						jsdic["type"] = "1";
						string msg = jsdic.dump();
						send(msg);
					}
					break;
					case 2:
					break;
					default:
					break;
				}

				conn->shutdown();

			}
			else
			{
				break;
			}
		}
	}

	const string name_;
	const bool tcpNoDelay_;
	TcpClient client_;
	TcpConnectionPtr conn_;
	int times;
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
		Client *client = new Client(&loop, srvaddr, "client", nodelay);
		client->connect();
		
		loop.loop();
	}
	else
	{
		printf("%s server_ip port\n", argv[0]);
	}
}


