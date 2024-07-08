#ifndef MESSAGES_H
#define MESSAGES_H

#include <iostream>
#include <string>
#include <string_view>
#include <functional>
#include <memory>
#include <map>
#include "glaze/glaze.hpp"

typedef unsigned long long address;

namespace Messages {

    struct MessageHeader {
        std::string id;
    };

    class Test
    {
    public:
        static constexpr std::string_view id{ "test" };
        std::string test = "test";
        int testInt = 125;
    };

    class Location
    {
    public:
        static constexpr std::string_view id{ "loc" };
        address loc;
    };

    class Base
    {
    public:
        static constexpr std::string_view id{ "base" };
        address base;
    };

    struct Comment
    {
        static constexpr std::string_view id{ "cmmt" };
        std::string modname;
        address rva;
        std::string comment;
    };

    using Message = std::variant<Location, Test, Base, Comment>;
}

#endif
