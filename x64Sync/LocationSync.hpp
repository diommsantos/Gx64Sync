#ifndef LOCATIONSYNC_H
#define LOCATIONSYNC_H

#include "Messages.hpp"
#include "SyncHandler.hpp"

class LocationSync
{
public:
	LocationSync(SyncHandler &sh);

	void start();
	void stop();
	void sendx64DbgLocation();
	void sendx64DbgBase();

private:
	SyncHandler &sh;
	bool active = false;
	address currBase;
	address remoteBase;
	void syncRemoteBase(const Messages::Base& mBase);
	void syncRemoteAdress(const Messages::Location& mLoc);
	std::vector<int> subscriberHandles;

};

//integration with x64Dbg
namespace x64Sync { extern LocationSync ls; }
static bool lsStartCommand(int argc, char** argv);
static bool lsStopCommand(int argc, char** argv);
static bool lsSendx64DbgLocationCommand(int argc, char** argv);
static bool lsSendx64DbgBaseCommand(int argc, char** argv);
void registerLocationSyncCommands();

namespace LOCATION_SYNC_MENU_IDENTIFIIERS {
	enum LOCATION_SYNC_MENU_IDENTIFIIERS {
		START,
		STOP,
		SYNC_LOCATION,
		SYNC_BASE
	};
}
void menuAddLocationSync();
void menuEntryLocationSync(int hEntry);
#endif // !LOCATIONSYNC_H
