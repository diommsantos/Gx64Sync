#include "Messages.hpp"


using namespace Messages;

namespace Messages {
	template <typename MessageType>
	glz::error_ctx Decode(Message& message, const std::string_view json) {
		return glz::read < glz::opts{ .error_on_unknown_keys = false } > (message, json);
	}
}
//manually need to add here the id and the corresponding decode function
std::unordered_map<std::string_view, Messages::Decoder> Messages::decoders 
{
{Test::id, Decode<Test>},
{Location::id, Decode<Location>},
{Base::id, Decode<Base>}
};


