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
    using Subscriber = std::function<void(const Message&)>;
private:
    Logger loggerCallback_;
    Client session;
    void MessageHandler(const std::string_view);
    std::map<std::string_view, std::vector<Subscriber>> subscribers;
public:
    SyncHandler(Logger callback);
    ~SyncHandler();
    void start();
    void stop();
    void subscribe(const std::string_view id, Subscriber subscriber);
    void send(const Message& message);
};

#endif