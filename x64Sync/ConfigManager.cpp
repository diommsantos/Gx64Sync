#include "ConfigManager.hpp"
#include <cstdlib>

bool ConfigManager::active = false;
std::string ConfigManager::configFilePath{};
glz::json_t ConfigManager::config{};

ConfigManager::ConfigManager(Logger logger) :
	logger(logger)
{
	if (active)
		return;
#ifdef _WIN32
	size_t size = 0;
	char* userprofile;
	_dupenv_s(&userprofile, &size, "USERPROFILE");
	configFilePath = userprofile+std::string("\\config.sync");
#else
	//Probably wrong?
	configFilePath = std::string(std::getenv("HOME")) + "/config.sync";
#endif
	glz::error_ctx configError = glz::read_file_json(config, configFilePath, std::string{});
	if (configError.ec == glz::error_code::file_open_failure) {
		logger("ConfigManager: Config file " + configFilePath + " could not be open. Using default configurations.");
	}
	else if (configError)
		logger("ConfigManager: An error occurred while getting the configurations.");
	active = true;
}