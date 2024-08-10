#include "LocationSync.hpp"
#include <functional>
#include "pluginmain.h"
#include "md5.h"

namespace x64Sync { extern std::unordered_map<std::string, duint> fileHashes; }

LocationSync::LocationSync(SyncHandler &sh):
sh{ sh }
{
	sh.installStartCallback([this]() {
		start();
	});
	sh.installStopCallback([this]() {
		stop();
	});
	sh.installClientErrorsCallback([this]() {
		stop();
	});
}

bool LocationSync::start() {
	if (active)
		return active;
	if (!(active = sh.start()))
		return active;
	subscriberHandle = sh.subscribe<Messages::RelativeAddress>(std::bind(&LocationSync::syncRemoteAdress, this, std::placeholders::_1));
	return active;
}

void LocationSync::syncRemoteAdress(const Messages::RelativeAddress& ra) {
	auto it = x64Sync::fileHashes.find(ra.modHash);
	if ( it == x64Sync::fileHashes.end())
		return dprintf("It is not possible to sync the address. The %s module is not loaded!", ra.modName);
	GuiDisasmAt(it->second + ra.rva, it->second + ra.rva);
}

void LocationSync::sendx64DbgLocation() {
	if (!active)
		return;
	duint va = Script::Gui::Disassembly::SelectionGetStart();
	duint modBase = Script::Module::BaseFromAddr(va);
	char modName[32];
	Script::Module::NameFromAddr(modBase, modName);
	auto it = x64Sync::fileHashes.begin();
	while (it != x64Sync::fileHashes.end()) {
		if (it->second == modBase) 
			return sh.send(Messages::RelativeAddress{ modName, it->first, va - modBase});
		it++;
	}
}

void LocationSync::stop() {
	if (!active)
		return;
	sh.unsubscribe(subscriberHandle);
	active = false;
}

static bool lsSendx64DbgLocationCommand(int argc, char** argv) { x64Sync::ls.sendx64DbgLocation(); return true;}

void registerLocationSyncCommands() {
	_plugin_registercommand(pluginHandle, "SyncLocation", lsSendx64DbgLocationCommand, true);
}

void menuAddLocationSync() {
	_plugin_menuaddentry(hMenu, MENU_IDENTIFIERS::LOCATIONSYNC_SYNC_LOCATION, "Sync Location");
}

void menuEntryLocationSync(int hEntry) {
	switch (hEntry)
	{
	case MENU_IDENTIFIERS::LOCATIONSYNC_SYNC_LOCATION: lsSendx64DbgLocationCommand(0, nullptr); break;
	default:
		break;
	}

}