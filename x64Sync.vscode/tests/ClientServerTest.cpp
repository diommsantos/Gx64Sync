
#include <iostream>
#include <string>

#include "asio.hpp"

int main(int argc, char* argv[])
{
    using asio::ip::tcp;
    asio::io_context io_context;
    
    tcp::socket socket(io_context);
    tcp::resolver resolver(io_context);

    asio::connect(socket, resolver.resolve("127.0.0.1", "9100"));
    
    std::string data{"It only works with \\n\n Second line sent"};
    auto result = asio::write(socket, asio::buffer(data));
    
    std::cout << "data sent: " << data.length() << '/' << result << std::endl;

    asio::streambuf response;
    asio::read_until(socket, response, "\n");
    std::cout << "Message sent: " << &response << std::endl;
    asio::error_code ec;
    socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    socket.close();

    return 0;
}