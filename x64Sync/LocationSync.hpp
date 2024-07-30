#ifndef LOCATIONSYNC_H
#define LOCATIONSYNC_H

#include "Messages.hpp"
#include "SyncHandler.hpp"

class LocationSync
{
public:
	LocationSync(SyncHandler &sh);

	bool start();
	void stop();
	void sendx64DbgLocation();

private:
	SyncHandler &sh;
	bool active = false;
	void syncRemoteAdress(const Messages::RelativeAddress& ra);
	int subscriberHandle;

};

//integration with x64Dbg
namespace x64Sync { extern LocationSync ls; }
static bool lsSendx64DbgLocationCommand(int argc, char** argv);
void registerLocationSyncCommands();

void menuAddLocationSync();
void menuEntryLocationSync(int hEntry);
#endif // !LOCATIONSYNC_H
