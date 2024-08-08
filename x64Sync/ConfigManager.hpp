#ifndef CONFIGMANAGER_H
#define CONFIGMANAGER_H

#include <string>
#include <functional>
#include "glaze/glaze.hpp"

class ConfigManager
{
	using Logger = std::function<void(const std::string_view)>;

public:
	ConfigManager(Logger logger);

	template<typename valueType>
	static valueType getConfig(std::string_view key) {
		return config[key].get<valueType>();
	}

	template<typename valueType>
	static valueType getConfig(std::string_view key, valueType defaultValue) {
		return config.contains(key) ? config[key].get<valueType>() : defaultValue;
	}

private:

	Logger logger;
	static bool active;
	static std::string configFilePath;
	static glz::json_t config;

};


#endif // !CONFIGMANAGER_H
