#include "LocationSync.hpp"
#include <functional>
#include "pluginmain.h"

LocationSync::LocationSync(SyncHandler &sh):
sh{ sh }, subscriberHandles(2)
{}

void LocationSync::start() {
	if (active)
		return;
	if (!(active = sh.start()))
		return;
	subscriberHandles[0] = sh.subscribe<Messages::Location>(std::bind(&LocationSync::syncRemoteAdress, this, std::placeholders::_1));
	subscriberHandles[1] = sh.subscribe<Messages::Base>(std::bind(&LocationSync::syncRemoteBase, this, std::placeholders::_1));
	return sendx64DbgBase();
}

void LocationSync::syncRemoteBase(const Messages::Base& mBase) {
	remoteBase = mBase.base;
}

void LocationSync::syncRemoteAdress(const Messages::Location& mLoc) {
	bool res = false;
	SELECTIONDATA selection{ mLoc.loc - remoteBase + currBase, mLoc.loc - remoteBase + currBase };
	res = GuiSelectionSet(GUI_DISASSEMBLY, &selection);
	GuiDisasmAt(selection.start, selection.start);
	if (!res) {
		dputs("Received a request to sync wiht a remote address but an error occurred");
	}
}

void LocationSync::sendx64DbgLocation() {
	bool res = false;
	SELECTIONDATA selection;
	res = GuiSelectionGet(GUI_DISASSEMBLY, &selection);
	if (!res) {
		dputs("An error occurred while syncing the current address");
		return;
	}
	return sh.send(Messages::Location{ selection.start });
}

void LocationSync::sendx64DbgBase() {
	bool res = false;
	duint currBaseAddr;
	duint size;
	SELECTIONDATA selection;
	char modName[200];

	res = GuiSelectionGet(GUI_DISASSEMBLY, &selection);
	res = DbgGetModuleAt(selection.start, modName);
	currBaseAddr = DbgModBaseFromName(modName);
	if (!res) {
		dputs("An error occurred while syncing the base");
		return;
	}
	this->currBase = currBaseAddr;
	return sh.send(Messages::Base{ currBaseAddr });
}

void LocationSync::stop() {
	if (!active)
		return;
	sh.unsubscribe(subscriberHandles[0]);
	sh.unsubscribe(subscriberHandles[1]);
	active = false;
}

static bool lsStartCommand(int argc, char** argv) { x64Sync::ls.start(); return true; }
static bool lsStopCommand(int argc, char** argv) { x64Sync::ls.stop(); return true;}
static bool lsSendx64DbgLocationCommand(int argc, char** argv) { x64Sync::ls.sendx64DbgLocation(); return true;}
static bool lsSendx64DbgBaseCommand(int argc, char** argv) { x64Sync::ls.sendx64DbgBase(); return true;}

void registerLocationSyncCommands() {
	_plugin_registercommand(pluginHandle, "StartLocationSync", lsStartCommand, false);
	_plugin_registercommand(pluginHandle, "StopLocationSync", lsStopCommand, false);
	_plugin_registercommand(pluginHandle, "SyncLocation", lsSendx64DbgLocationCommand, true);
	_plugin_registercommand(pluginHandle, "SyncBase", lsSendx64DbgBaseCommand, true);
}

void menuAddLocationSync() {
	int locSyncMenu = _plugin_menuadd(hMenu, "Location Sync");
	_plugin_menuaddentry(locSyncMenu, LOCATION_SYNC_MENU_IDENTIFIIERS::START, "Start");
	_plugin_menuaddentry(locSyncMenu, LOCATION_SYNC_MENU_IDENTIFIIERS::STOP, "Stop");
	_plugin_menuaddentry(locSyncMenu, LOCATION_SYNC_MENU_IDENTIFIIERS::SYNC_LOCATION, "Sync Location");
	_plugin_menuaddentry(locSyncMenu, LOCATION_SYNC_MENU_IDENTIFIIERS::SYNC_BASE, "Sync Base");
}

void menuEntryLocationSync(int hEntry) {
	switch (hEntry)
	{
	case LOCATION_SYNC_MENU_IDENTIFIIERS::START: lsStartCommand(0, nullptr); break;
	case LOCATION_SYNC_MENU_IDENTIFIIERS::STOP: lsStopCommand(0, nullptr); break;
	case LOCATION_SYNC_MENU_IDENTIFIIERS::SYNC_LOCATION: lsSendx64DbgLocationCommand(0, nullptr); break;
	case LOCATION_SYNC_MENU_IDENTIFIIERS::SYNC_BASE: lsSendx64DbgBaseCommand(0, nullptr); break;
	default:
		break;
	}

}