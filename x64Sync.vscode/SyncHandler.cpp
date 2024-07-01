#include "SyncHandler.hpp"
#include "rapidjson/document.h"

SyncHandler::SyncHandler(SyncHandler::Logger callback):
loggerCallback_{callback}, session(callback)
{
}

SyncHandler::~SyncHandler(){
    session.stop();
}

void SyncHandler::start(){
    session.installMessageHandler(std::bind(&SyncHandler::MessageHandler, 
                                            this, 
                                            std::placeholders::_1));
    session.start();
}

void SyncHandler::stop(){
    session.stop();
}

void SyncHandler::MessageHandler(const std::string_view encMessage){
    try{
        rapidjson::Document jsonMessage;
        jsonMessage.Parse(encMessage.data(), encMessage.size());
        const std::string_view id {jsonMessage["id"].GetString()};
        std::unique_ptr<Message> message = (Message::decoders[id])(jsonMessage);
        for (Subscriber& subscriber : subscribers[id]){
            subscriber(*message);
        }
    }catch(const std::exception& e){
        loggerCallback_("SyncHandler error: receivedMessage "+std::string(encMessage)
        +" error: "+e.what()+"\n");
    }
}

void SyncHandler::subscribe(const std::string_view id, Subscriber subscriber){
    subscribers[id].push_back(subscriber);
}

void SyncHandler::send(const Message& message){
    session.send(*message.encode());
}