#ifndef MESSAGES_H
#define MESSAGES_H

#include <iostream>
#include <string>
#include <string_view>
#include <functional>
#include <memory>
#include <map>
#include "rapidjson/document.h"


class Message 
{
public:
    using Decoder = std::function<std::unique_ptr<Message>(const rapidjson::Document&)>; //possible improvement:
    static std::unordered_map<std::string_view, Decoder> decoders;   //use function pointers instead of std::function

    virtual ~Message() = default;
    virtual std::unique_ptr<std::string> encode() const = 0;
  //std::unique_ptr<LocM> decode(const std::string_view message); 
    //must be in every class inheriting Message!
};

class LocM: public Message
{
public:
    static constexpr std::string_view id {"test"};
    std::string test = "test";
    int testInt = 125;

    ~LocM() override = default; 

std::unique_ptr<std::string> encode() const override {
    std::unique_ptr<std::string> json {new std::string()};

    *json += "{";

    *json += "\"id\":\"" + std::string(id) + "\",";
    *json += "\"test\":\"" + test + "\",";
    *json += "\"testInt\":" + std::to_string(testInt);

    *json += "}";

    return json;
}


static std::unique_ptr<LocM> decode(const rapidjson::Document& message) {
    LocM* nn;
    LocM *m;
    // TODO: parse the 'message' string and populate 'm' object
    return std::unique_ptr<LocM>{new LocM};
}

};

#endif