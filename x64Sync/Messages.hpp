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

    struct Session
    {
        static constexpr std::string_view id{ "session" };
        std::string sessionName;
        std::string programName;
    };

    struct DebbuggerCmd
    {
        enum class CMDTYPE { RUN, PAUSE, STEPINTO, STEPOVER, BREAKPOINT };
        static constexpr std::string_view id{ "dbgcmd" };
        CMDTYPE cmdType;
        std::string modPath;
        address rva;

    };

    struct HyperSyncState
    {
        static constexpr std::string_view id{ "hysyncstate" };
        bool state;
    };

    struct RelativeAddress
    {
        static constexpr std::string_view id{ "rva" };
        std::string modName;
        std::string modHash;
        address rva;
    };
    

    using Message = std::variant<Location, Test, Base, Comment, Session, DebbuggerCmd, HyperSyncState, RelativeAddress>;
}

template <>
struct glz::meta<Messages::DebbuggerCmd::CMDTYPE> {
    using enum Messages::DebbuggerCmd::CMDTYPE;
    static constexpr auto value = enumerate(RUN, PAUSE, STEPINTO, STEPOVER, BREAKPOINT);
};

#endif
