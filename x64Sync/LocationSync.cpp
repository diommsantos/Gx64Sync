#include "LocationSync.hpp"
#include <functional>
#include "pluginmain.h"
#include "md5.h"

namespace x64Sync { extern std::unordered_map<std::string, std::string> fileHashes; }

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
	BridgeList<Script::Module::ModuleInfo> modList;
	Script::Module::GetList(&modList);
	for (int i = 0; i < modList.Count(); i++) {
		if (strcmp(modList[i].path, ra.modPath.data()) == 0) {
			GuiDisasmAt(modList[i].base + ra.modRVA, modList[i].base + ra.modRVA);
			return;
		}
	}
	dprintf("It is not possible to sync the address. The %s module is not loaded!", ra.modPath);
}

void LocationSync::sendx64DbgLocation() {
	if (!active)
		return;
	char modPath[300];
	duint va = Script::Gui::Disassembly::SelectionGetStart();
	DbgFunctions()->ModPathFromAddr(va, modPath, 300);
	sh.send(Messages::RelativeAddress{ modPath, va - Script::Module::BaseFromAddr(va) });
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