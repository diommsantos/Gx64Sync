#include "Client.hpp"

Client::Client(Logger callback, MessageHandler messageHandlerCallback, ErrorHandler errorCallback) : 
loggerCallback_(callback),
onMessageReceivedCallback_(messageHandlerCallback),
errorHandlerCallback(errorCallback),
m_socket(io_context)
{
}

Client::~Client() {
    asio::error_code ec;
    m_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    m_socket.close(ec);
    if(m_thread.joinable())
        m_thread.join();
}

bool Client::start(){
    if (std::this_thread::get_id() == m_thread.get_id())
        throw std::runtime_error("Start method can't be called from the Client m_thread!");
    if (cleanup_before_start) {
        m_thread.join();
        io_context.restart();
        cleanup_before_start = false;
    }
    asio::ip::address addr = asio::ip::address::from_string(host);
    ep = tcp::endpoint(addr, port);
    asio::error_code ec;
    m_socket.connect(ep, ec);
    if (ec) {
        loggerCallback_("Client: " + ec.message() + "\n");
        m_socket = asio::ip::tcp::socket(io_context);
        return false;
    }
    asio::async_read_until(m_socket, message, "\n",
                               std::bind(&Client::DataHandler, 
                                         this, 
                                         std::placeholders::_1, 
                                         std::placeholders::_2));
    m_thread = std::thread([this] { io_context.run(); });
    return true;
}

void Client::stop() {
    if (std::this_thread::get_id() == m_thread.get_id())
        throw std::runtime_error("Stop method can't be called from the Client m_thread!");
    try {
        m_socket.shutdown(asio::ip::tcp::socket::shutdown_both);
        m_socket.close();
        m_thread.join();
        io_context.restart();
    }
    catch (asio::system_error ec) {
        loggerCallback_(ec.what());
    }
}

void Client::send(const std::string& message) {
    asio::error_code ec;
    asio::write(m_socket, asio::buffer(message + "\n"), ec);
    if (ec) {
        cleanup_before_start = true;
        m_socket.shutdown(asio::ip::tcp::socket::shutdown_both);
        m_socket.close();
        loggerCallback_("Client: " + ec.message() + "\n");
        errorHandlerCallback(this, ec);
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
    }
    else if (error == asio::error::operation_aborted)
        return;
    else {
        cleanup_before_start = true;
        m_socket.shutdown(asio::ip::tcp::socket::shutdown_both);
        m_socket.close();
        loggerCallback_("Client: " + error.message() + "\n");
        errorHandlerCallback(this, error);
    }
}
