#include "SyncHandler.hpp"

using namespace Messages;

std::vector<std::string_view> SyncHandler::ids{ std::views::keys(Messages::decoders).begin(), std::views::keys(Messages::decoders).end() };

SyncHandler::SyncHandler(SyncHandler::Logger callback):
loggerCallback_{callback}, 
session(callback, std::bind(&SyncHandler::MessageErrorHandler, this, std::placeholders::_1, std::placeholders::_2))
{
}

SyncHandler::~SyncHandler(){
    stop();
}

bool SyncHandler::start(){
    if (active)
        return true;
    if (error) {
        session.stop();
        session.~Client();
        new (&session) Client(loggerCallback_, std::bind(&SyncHandler::MessageErrorHandler, this, std::placeholders::_1, std::placeholders::_2));
        error = false;
    }
    session.installMessageHandler(std::bind(&SyncHandler::MessageHandler, 
                                            this, 
                                            std::placeholders::_1));
    if (!(active = session.start()))
        error = true;
    return active;
}

void SyncHandler::stop(){
    if (!active)
        return;
    session.stop();
    session.~Client();
    new (&session) Client(loggerCallback_, std::bind(&SyncHandler::MessageErrorHandler, this, std::placeholders::_1, std::placeholders::_2));
    active = false;
}

void SyncHandler::MessageHandler(const std::string_view encMessage){
    try{
        Messages::MessageHeader header;
        glz::read < glz::opts{ .error_on_unknown_keys = false } > (header, encMessage.data());
        Message* message = new Message;
        (Messages::decoders[header.id])(*message, encMessage);
        for (Subscriber& subscriber : subscribers[header.id]){
            subscriber(*message);
        }
    }catch(const std::exception& e){
        loggerCallback_("SyncHandler error: receivedMessage "+std::string(encMessage)
        +" error: "+e.what()+"\n");
    }
}

void SyncHandler::MessageErrorHandler(Client* session, asio::error_code) {
    error = true;
    active = false;
}

void SyncHandler::unsubscribe(int subscriberHandle) {
    std::string_view id{ ids[subscriberHandle % ids.size()] };
    subscribers[id].erase(subscribers[id].begin() + subscriberHandle / ids.size());
}

/*template <typename SubscriberType>
void SyncHandler::subscribe(const std::string_view id, SubscriberType subscriber) {
    subscribers[id].push_back(static_cast<Subscriber>(subscriber));
}
*/
/*template <typename MessageType>
void SyncHandler::send(const MessageType& message){
    std::string encMessage{};
    glz::write_json(message, encMessage);
    session.send(encMessage);
}
*/