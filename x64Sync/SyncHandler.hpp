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
    std::map<std::string_view, std::vector<Subscriber>> subscribers;
public:
    SyncHandler(Logger callback);
    ~SyncHandler();
    bool start();
    void stop();
    template <typename MessageType>
    int subscribe(std::function<void(const MessageType&)> subscriber) {
        subscribers[MessageType::id].push_back(
            [subscriber](const Messages::Message& message) { subscriber(std::get<MessageType>(message)); }
        );

        //get subsceiberHandle
        auto it = std::find(ids.begin(), ids.end(), MessageType::id);
        int index = std::distance(ids.begin(), it);
        return (subscribers[MessageType::id].size() - 1) * ids.size() + index;
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