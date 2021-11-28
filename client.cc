#include "muduo/base/Logging.h"
#include "muduo/base/Atomic.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/TcpClient.h"

#include <stdio.h>

using namespace muduo;
using namespace muduo::net;

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
			send();
		}
		else 
		{
			conn_.reset();
		}
	
	}

	void send()
	{
		Timestamp now(Timestamp::now());
		Buffer requests;
		
		char buf[256] = "this is client";
		int32_t len = strlen(buf);
		requests.append(buf, len);
		int32_t be32 = muduo::net::sockets::hostToNetwork32(len);

		requests.prepend(&be32, sizeof(be32));
		conn_->send(&requests);
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
				if (message == "end")  {
					if (times > 0)  
					{
						send();
						times--;
					}
					else
					{
						conn->shutdown();
						break;
					}
				}
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
	bool nodelay = true;
	InetAddress srvaddr("127.0.0.1", 10358);

	EventLoop loop;
	Client *client = new Client(&loop, srvaddr, "client", nodelay);
	client->connect();
	
	loop.loop();
}


