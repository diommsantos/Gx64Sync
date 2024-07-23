#include "SyncHandler.hpp"

class DebbugerSync
{
public:
	DebbugerSync(SyncHandler& sh);
	

private:
	SyncHandler& sh;
	void debuggerCmdHandler(const Messages::DebbuggerCmd& dbgCmdM);
};