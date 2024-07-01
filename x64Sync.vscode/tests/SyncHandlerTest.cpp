#include "..\SyncHandler.hpp"
#include <iostream>

void logger(const std::string_view message) {
    std::cout << "Log: " << message;
}

void loggerMessage(const Message& m){
    std::cout << "Received message: " << *m.encode() << std::endl;
}

int main(){
    SyncHandler sncHandler(logger);
    LocM test;
    sncHandler.subscribe(LocM::id, loggerMessage);
    sncHandler.start();
    while(true)
    {
        // Keep the client running until it's stopped or an error occurs
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        sncHandler.send(test);
    }
}