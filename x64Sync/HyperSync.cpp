#include "HyperSync.hpp"
#include "LocationSync.hpp"
#include "pluginmain.h"

namespace x64Sync { extern std::unordered_map<std::string, duint> fileHashes; }

HyperSync::HyperSync(SyncHandler& sh, LocationSync& ls):
sh{ sh }, ls{ls}
{
	subscriberHandles[0] = sh.subscribe<Messages::HyperSyncState>(std::bind(&HyperSync::syncHyperSyncState, this, std::placeholders::_1));
	sh.installStopCallback([this]() {
		if (!active) return;
		this->sh.unsubscribe(subscriberHandles[1]);
		active = false; 
		dputs("HyperSync stopped!\n"); 
	});
	sh.installClientErrorsCallback([this]() {
		if (!active) return;
		this->sh.unsubscribe(subscriberHandles[1]);
		active = false;
		dputs("HyperSync stopped!\n");
	});
}

void HyperSync::start() {
	if (active)
		return;
	sh.start();
	ls.stop();
	subscriberHandles[1] = sh.subscribe<Messages::RelativeAddress>(std::bind(&HyperSync::remoteRVAHandler, this, std::placeholders::_1));
	sh.send(Messages::HyperSyncState{ true });
	active = true;
	dputs("HyperSync started!\n");
}

void HyperSync::stop() {
	if (!active)
		return;
	sh.send(Messages::HyperSyncState{ false });
	sh.unsubscribe(subscriberHandles[1]);
	ls.start();
	active = false;
	dputs("HyperSync stopped!\n");
}

bool HyperSync::isActive() {
	return active;
}

void HyperSync::syncHyperSyncState(const Messages::HyperSyncState& hss){
	if (hss.state == true)
		start();
	else
		stop();
}

void HyperSync::remoteRVAHandler(const Messages::RelativeAddress& ra){
	auto it = x64Sync::fileHashes.find(ra.modHash);
	if (it == x64Sync::fileHashes.end())
		dprintf("HyperSync: It is not possible to sync the address. The %s module is not loaded!", ra.modName);
	remoteLocationChange = true;
	GuiDisasmAt(it->second + ra.rva, it->second + ra.rva);
}

void HyperSync::x64DbgRVAHandler(PLUG_CB_SELCHANGED* sel){
	if (!active || sel->hWindow != Script::Gui::DisassemblyWindow)
		return;
	if (remoteLocationChange) {
		remoteLocationChange = false;
		return;
	}
	duint va = Script::Gui::Disassembly::SelectionGetStart();
	duint modBase = Script::Module::BaseFromAddr(va);
	char modName[32];
	Script::Module::NameFromAddr(modBase, modName);
	auto it = x64Sync::fileHashes.begin();
	while (it != x64Sync::fileHashes.end()) {
		if (it->second == modBase)
			return sh.send(Messages::RelativeAddress{ modName, it->first, va - modBase });
		it++;
	}

}

static bool hsStartCommand(int argc, char** argv) { x64Sync::hs.start(); return true; }
static bool hsStopCommand(int argc, char** argv) { x64Sync::hs.stop(); return true; }

void registerHyperSyncCommands() {
	_plugin_registercommand(pluginHandle, "HyperSyncStart", hsStartCommand, true);
	_plugin_registercommand(pluginHandle, "HyperSyncStop", hsStopCommand, false);
}

void menuAddHyperSync() {
	_plugin_menuaddentry(hMenu, MENU_IDENTIFIERS::HYPERSYNC_HYPER_SYNC, "Hyper Sync");
}

void menuEntryHyperSync(int hEntry) {
	switch (hEntry)
	{
	case MENU_IDENTIFIERS::HYPERSYNC_HYPER_SYNC:
		if (!x64Sync::hs.isActive())
			x64Sync::hs.start();
		else
			x64Sync::hs.stop();
		break;
	default:
		break;
	}
}