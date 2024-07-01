#include "Messages.hpp"

//manually need to add here the id and the corresponding decode function
std::unordered_map<std::string_view, Message::Decoder> Message::decoders 
{
{LocM::id, LocM::decode}
};
