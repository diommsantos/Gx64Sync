#ifndef SYNCHANDLER_H
#define SYNCHANDLER_H

#include <string>
#include <functional>
#include <memory>
#include "Client.hpp"
#include "Messages.hpp"


class SyncHandler
{
    using Logger = std::function<void(const std::string_view)>;
    using Subscriber = std::function<void(const Messages::Message&)>;
private:
    bool active{ false };
    bool error{ false };
    Logger loggerCallback_;
    Client session;
    void MessageHandler(const std::string_view);
    void MessageErrorHandler(Client* session, asio::error_code);
    static std::vector<std::string_view> ids;
    std::map<std::string_view, std::map<int, Subscriber>> subscribers;

    //SyncHandler State callbacks
    std::vector<std::function<void(void)>> startCallbacks;
    std::vector<std::function<void(void)>> stopCallbacks;
    std::vector<std::function<void(void)>> errorCallbacks;
    std::vector<std::function<void(void)>> clientErrorsCallbacks;

public:
    SyncHandler(Logger callback);
    ~SyncHandler();
    void installStartCallback(std::function<void(void)> callback);
    void installStopCallback(std::function<void(void)> callback);
    void installErrorCallback(std::function<void(void)> callback);
    void installClientErrorsCallback(std::function<void(void)> callback);
    bool start();
    void stop();
    template <typename MessageType>
    int subscribe(std::function<void(const MessageType&)> subscriber) {
        //get subscriberHandle
        auto it = std::find(ids.begin(), ids.end(), MessageType::id);
        int index = std::distance(ids.begin(), it);
        int subscriberHandle = subscribers[MessageType::id].empty() ? index : subscribers[MessageType::id].rbegin()->first + index;

        subscribers[MessageType::id][subscriberHandle] = 
            [subscriber](const Messages::Message& message) { subscriber(std::get<MessageType>(message)); };
        return subscriberHandle;
    };
    void unsubscribe(int subscriberHandle);
    template <typename MessageType>
    void send(const MessageType& message) {
        std::string encMessage{};
        Messages::MessageHeader header{MessageType::id.data()};
        auto jsonMessage = glz::merge{ header, message };
        glz::write_json(jsonMessage, encMessage);
        session.send(encMessage);
    };
};

#endif