#ifndef MESSAGES_H
#define MESSAGES_H

#include <iostream>
#include <string>
#include <string_view>
#include <functional>
#include <memory>
#include <map>
#include "glaze/glaze.hpp"

typedef unsigned long long duint;

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
        duint loc;
    };

    class Base
    {
    public:
        static constexpr std::string_view id{ "base" };
        duint base;
    };

    using Message = std::variant<Location, Test, Base>;
    using Decoder = std::function<glz::error_ctx(Message&, const std::string_view)>;
    extern std::unordered_map<std::string_view, Decoder> decoders;
}

#endif
