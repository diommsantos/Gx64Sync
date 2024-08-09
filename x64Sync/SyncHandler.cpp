#include "SyncHandler.hpp"

using namespace Messages;

template <std::size_t index = 0>
requires (index == std::variant_size_v<Message> )
std::vector<std::string_view> getMessageIds() {
    return {};
}

template <std::size_t index = 0>
requires (index < std::variant_size_v<Message> )
std::vector<std::string_view> getMessageIds() {
    std::vector<std::string_view> ids = getMessageIds<index + 1>();
    ids.push_back(std::variant_alternative_t<index, Message>::id);
    return ids;
}

using Decoder = std::function<glz::error_ctx(Messages::Message&, const std::string_view)>;
template <std::size_t index = 0>
    requires (index == std::variant_size_v<Message>)
std::unordered_map<std::string_view, Decoder> getDecoders() {
    return std::unordered_map<std::string_view, Decoder>{};
}

template <std::size_t index = 0>
    requires (index < std::variant_size_v<Message>)
std::unordered_map<std::string_view, Decoder> getDecoders() {
    std::unordered_map<std::string_view, Decoder> decoders = getDecoders<index + 1>();
    using MessageType = std::variant_alternative_t<index, Message>;
    decoders[MessageType::id] = [](Messages::Message& message, const std::string_view encMessage)
        {   
            message = MessageType{}; //dumb initialization otherwise it crashes
            return glz::read < glz::opts{ .error_on_unknown_keys = false }> ((MessageType&) message, encMessage);
        };
    return decoders;
}

std::vector<std::string_view> SyncHandler::ids{ getMessageIds() };
std::unordered_map<std::string_view, SyncHandler::Decoder> SyncHandler::decoders{ getDecoders() };

SyncHandler::SyncHandler(SyncHandler::Logger callback):
loggerCallback_{callback}, 
session(callback,
        std::bind(&SyncHandler::MessageHandler, this, std::placeholders::_1),
        std::bind(&SyncHandler::MessageErrorHandler, this, std::placeholders::_1, std::placeholders::_2))
{
}

void SyncHandler::installStartCallback(std::function<void(void)> callback) {
    startCallbacks.push_back(callback);
}

void SyncHandler::installStopCallback(std::function<void(void)> callback) {
    stopCallbacks.push_back(callback);
}

void SyncHandler::installErrorCallback(std::function<void(void)> callback) {
    errorCallbacks.push_back(callback);
}

void SyncHandler::installClientErrorsCallback(std::function<void(void)> callback) {
    clientErrorsCallbacks.push_back(callback);
}

bool SyncHandler::start(){
    if (active)
        return true;
    if (!(active = session.start()))
        return false;
    for (std::function<void(void)> callback : startCallbacks)
        callback();
    return active;
}

void SyncHandler::stop(){
    if (!active)
        return;
    session.stop();
    active = false;
    for (std::function<void(void)> callback : stopCallbacks)
        callback();
}

void SyncHandler::MessageHandler(const std::string_view encMessage){
    try{
        Messages::MessageHeader header;
        glz::read < glz::opts{ .error_on_unknown_keys = false } > (header, encMessage.data());
        Message message;
        decoders[header.id](message, encMessage);
        for (Subscriber& subscriber : std::views::values(subscribers[header.id])){
            subscriber(message);
        }
    }catch(const std::exception& e){
        loggerCallback_("SyncHandler: " + std::string(e.what()) + "\n");
        for (std::function<void(void)> callback : errorCallbacks)
            callback();
    }
}

void SyncHandler::MessageErrorHandler(Client* session, asio::error_code) {
    active = false;
    for (std::function<void(void)> callback : clientErrorsCallbacks)
        callback();
}

void SyncHandler::unsubscribe(int subscriberHandle) {
    std::string_view id{ ids[subscriberHandle % ids.size()] };
    subscribers[id].erase(subscriberHandle);
}