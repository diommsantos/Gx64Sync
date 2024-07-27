#ifndef HYPERSYNC_H
#define HYPERSYNC_H

#include "Messages.hpp"
#include "SyncHandler.hpp"
#include "pluginmain.h"

class HyperSync
{
public:
	HyperSync(SyncHandler& sh);
	void start();
	void stop();
	bool isActive();
	void x64DbgRVAHandler(PLUG_CB_SELCHANGED* sel);

private:
	SyncHandler& sh;
	bool active{ false };
	int subscriberHandles[2];
	void syncHyperSyncState(const Messages::HyperSyncState& hss);
	void remoteRVAHandler(const Messages::RelativeAddress& ra);

};

//integration with x64Dbg
namespace x64Sync { extern HyperSync hs; }
static bool hsStartCommand(int argc, char** argv);
static bool hsStopCommand(int argc, char** argv);
void registerHyperSyncCommands();

namespace HYPER_SYNC_MENU_IDENTIFIERS {
	enum HYPER_SYNC_MENU_IDENTIFIERS {
		START_STOP = 100,
	};
}

void menuAddHyperSync();
void menuEntryHyperSync(int hEntry);

#endif // !HYPERSYNC_H
