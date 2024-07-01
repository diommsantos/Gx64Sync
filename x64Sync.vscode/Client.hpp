#ifndef CLIENT_H
#define CLIENT_H

#include <asio.hpp>
#include <functional>

using asio::ip::tcp;

class Client
{
public:
	using MessageHandler = std::function<void(const std::string_view)>;
	using Logger = std::function<void(const std::string_view)>;

	Client(Logger callback);

	void start();
	void stop();
	void installMessageHandler(MessageHandler callback);
	void send(const std::string& message);

private:
	Logger loggerCallback_;
	void DataHandler(const asio::error_code& ec, std::size_t bytes_transferred);
    MessageHandler onMessageReceivedCallback_;

	std::string host = "127.0.0.1";  // or "localhost"
	int port = 9100;
	tcp::endpoint ep;
	asio::io_context io_context;
	asio::ip::tcp::socket m_socket;
	asio::streambuf message;

	std::thread m_thread;
    

};

#endif