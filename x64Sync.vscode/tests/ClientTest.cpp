#include <iostream>
#define ASIO_ENABLE_LOGGING
#include "..\Client.hpp"

void logger(const std::string_view message) {
    std::cout << "Log: " << message;
}

int main() {

    Client client(logger);

    try {
        client.installMessageHandler(logger);
        client.start(); // Start receiving data
        while (true) {
            // Keep the client running until it's stopped or an error occurs
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            client.send("{\"id\":\"loc\",\"test\":\"test\",\"testInt\":125}");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
