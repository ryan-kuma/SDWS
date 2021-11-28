#include "muduo/base/Atomic.h"
#include "muduo/base/Thread.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/InetAddress.h"
#include "muduo/net/TcpServer.h"

#include <utility>
#include <stdio.h>
#include <unistd.h>
#include <string.h>


using namespace muduo;
using namespace muduo::net;

class Server
{
public:
	Server(EventLoop* loop, const InetAddress& listenAddr)
	: server_(loop, listenAddr, "server"),
	startTime_(Timestamp::now())
	{
		server_.setConnectionCallback(
			std::bind(&Server::onConnection, this, _1));
		server_.setMessageCallback(
			std::bind(&Server::onMessage, this, _1, _2, _3));
	}

	void start()
	{
		server_.start();
	}
	
private:
	void onConnection(const TcpConnectionPtr& conn)
	{
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

		char buf[256] = "end";
		int32_t len = strlen(buf);

		Buffer response;
		response.append(buf, len);
		int32_t be32 = muduo::net::sockets::hostToNetwork32(len);
		response.prepend(&be32, sizeof(be32));

		conn->send(&response);

		return goodRequest;
	}

	TcpServer server_;
	Timestamp startTime_;
};

int main(int argc, char **argv)
{
	EventLoop loop;
	InetAddress listenAddr(10358);
	Server srv(&loop, listenAddr);

	srv.start();
	
	loop.loop();
}
