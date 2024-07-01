#include "Client.hpp"

Client::Client(Logger callback) : 
    loggerCallback_(callback),
    m_socket(io_context){
}

void Client::start(){
    asio::ip::address addr = asio::ip::address::from_string(host);
    ep = tcp::endpoint(addr, port);
    asio::error_code ec;
    m_socket.connect(ep, ec);
    if (ec) {
        loggerCallback_("Error connecting to server: " + std::string(ec.message()));
    }
    asio::async_read_until(m_socket, message, "\n",
                               std::bind(&Client::DataHandler, 
                                         this, 
                                         std::placeholders::_1, 
                                         std::placeholders::_2));
    m_thread = std::thread([this] { io_context.run(); });
}

void Client::stop() {
    m_thread.~thread();
    m_socket.close();
}

void Client::installMessageHandler(MessageHandler callback){
    onMessageReceivedCallback_ = callback;
}

void Client::send(const std::string& message) {
    asio::error_code ec;
    asio::write(m_socket, asio::buffer(message + "\n"), ec);
    if (ec) {
        loggerCallback_("Error sending message: " + std::string(ec.message()));
    }
}


void Client::DataHandler(const asio::error_code& error, size_t bytes_transferred) {
    if (!error) {
        std::string message_s {std::istreambuf_iterator<char>(&message), 
                                std::istreambuf_iterator<char>() };
        message_s.resize(message_s.size() - 1); //remove the \n                                
        onMessageReceivedCallback_(message_s);
        asio::async_read_until(m_socket, message, "\n",
                               std::bind(&Client::DataHandler, 
                                         this, 
                                         std::placeholders::_1, 
                                         std::placeholders::_2));
    } else {
        loggerCallback_("Error reading message: " + std::string(error.message()));
    }
}
