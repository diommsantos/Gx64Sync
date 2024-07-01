#include "SyncHandler.hpp"
//#include "Messages.hpp"
#include <iostream>

void logger(const std::string_view message) {
    std::cout << "Log: " << message;
}

void loggerMessage(const Messages::Test& m){
    std::cout << "Received message: id: " << m.id << " test: " << m.test << " testInt: " << m.testInt <<std::endl;
}

int main(){
    SyncHandler sncHandler(logger);
    Messages::Test test{ "example", 456 };
    Messages::Location loc{ 123334 };
    sncHandler.subscribe<Messages::Test>(loggerMessage);
    sncHandler.start();
    while(true)
    {
        // Keep the client running until it's stopped or an error occurs
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        sncHandler.send(test);
        sncHandler.send(loc);
    }
}