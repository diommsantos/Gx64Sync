#ifndef CLIENT_H
#define CLIENT_H

#include "ConfigManager.hpp"
#include "asio.hpp"
#include <functional>

using asio::ip::tcp;

class Client
{
public:
	using MessageHandler = std::function<void(const std::string_view)>;
	using Logger = std::function<void(const std::string_view)>;
	using ErrorHandler = std::function<void(Client *client, asio::error_code e)>;

	Client(Logger callback, MessageHandler messageHandlerCallback, ErrorHandler errorCallback);
	~Client();

	bool start();
	void stop();
	void send(const std::string& message);

private:
	Logger loggerCallback_;
	ConfigManager configManager;
	void DataHandler(const asio::error_code& ec, std::size_t bytes_transferred);
    MessageHandler onMessageReceivedCallback_;
	ErrorHandler errorHandlerCallback;

	std::string host = ConfigManager::getConfig("X64SYNC_HOST", std::string("127.0.0.1"));  // or "localhost"
	int port = ConfigManager::getConfig("X64SYNC_PORT", (double) 9100);
	tcp::endpoint ep;
	asio::io_context io_context;
	asio::ip::tcp::socket m_socket;
	asio::streambuf message;

	bool cleanup_before_start{ false };
	std::thread m_thread;
    

};

#endif