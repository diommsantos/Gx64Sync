#include "HyperSync.hpp"
#include "pluginmain.h"

HyperSync::HyperSync(SyncHandler& sh):
sh{ sh }
{
	subscriberHandles[0] = sh.subscribe<Messages::HyperSyncState>(std::bind(&HyperSync::syncHyperSyncState, this, std::placeholders::_1));
	sh.installStopCallback([this]() {
		if (!active) return; 
		active = false; 
		dputs("HyperSync stopped!\n"); 
	});
	sh.installClientErrorsCallback([this]() {
		if (!active) return;
		active = false;
		dputs("HyperSync stopped!\n");
	});
}

void HyperSync::start() {
	if (active)
		return;
	sh.start();
	subscriberHandles[1] = sh.subscribe<Messages::RelativeAddress>(std::bind(&HyperSync::remoteRVAHandler, this, std::placeholders::_1));
	sh.send(Messages::HyperSyncState{ true });
	active = true;
	dputs("HyperSync started!\n");
}

void HyperSync::stop() {
	if (!active)
		return;
	sh.send(Messages::HyperSyncState{ false });
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
	BridgeList<Script::Module::ModuleInfo> modList;
	Script::Module::GetList(&modList);
	for (int i = 0; i < modList.Count(); i++) {
		if (strcmp(modList[i].path, ra.modPath.data()) == 0) {
			remoteLocationChange = true;
			GuiDisasmAt(modList[i].base + ra.modRVA, modList[i].base + ra.modRVA);
			return;
		}
	}
	dprintf("HyperSync: It is not possible to sync the address. The %s module is not loaded!", ra.modPath);

}

void HyperSync::x64DbgRVAHandler(PLUG_CB_SELCHANGED* sel){
	if (!active || sel->hWindow != Script::Gui::DisassemblyWindow)
		return;
	if (remoteLocationChange) {
		remoteLocationChange = false;
		return;
	}
	char modPath[300];

	DbgFunctions()->ModPathFromAddr(sel->VA, modPath, 300);
	sh.send(Messages::RelativeAddress{ modPath, sel->VA - Script::Module::BaseFromAddr(sel->VA) });

}

static bool hsStartCommand(int argc, char** argv) { x64Sync::hs.start(); return true; }
static bool hsStopCommand(int argc, char** argv) { x64Sync::hs.stop(); return true; }

void registerHyperSyncCommands() {
	_plugin_registercommand(pluginHandle, "HyperSyncStart", hsStartCommand, true);
	_plugin_registercommand(pluginHandle, "HyperSyncStop", hsStopCommand, false);
}

void menuAddHyperSync() {
	_plugin_menuaddentry(hMenu, HYPER_SYNC_MENU_IDENTIFIERS::START_STOP, "Hyper Sync");
}

void menuEntryHyperSync(int hEntry) {
	switch (hEntry)
	{
	case HYPER_SYNC_MENU_IDENTIFIERS::START_STOP:
		if (!x64Sync::hs.isActive())
			x64Sync::hs.start();
		else
			x64Sync::hs.stop();
	default:
		break;
	}
}