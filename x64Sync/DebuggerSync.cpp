#include "DebuggerSync.hpp"
#include <functional>
#include "pluginmain.h"

namespace x64Sync { extern std::unordered_map<std::string, duint> fileHashes; }

DebbugerSync::DebbugerSync(SyncHandler &sh):
sh{ sh }
{
	sh.subscribe<Messages::DebbuggerCmd>(std::bind(&DebbugerSync::debuggerCmdHandler, this, std::placeholders::_1));
}

void DebbugerSync::debuggerCmdHandler(const Messages::DebbuggerCmd& dbgCmd) {
	switch (dbgCmd.cmdType)
	{
	case Messages::DebbuggerCmd::CMDTYPE::RUN:
		Cmd("run");
		break;
	case Messages::DebbuggerCmd::CMDTYPE::PAUSE:
		Cmd("pause");
		break;
	case Messages::DebbuggerCmd::CMDTYPE::STEPINTO:
		Cmd("sti");
		break;
	case Messages::DebbuggerCmd::CMDTYPE::STEPOVER:
		Cmd("sto");
		break;
	case Messages::DebbuggerCmd::CMDTYPE::BREAKPOINT:
		std::string cmd("bp ");
		cmd = cmd + +"."+std::to_string(x64Sync::fileHashes[dbgCmd.modHash] + dbgCmd.rva);
		Cmd(cmd.data());
		return;
		
		break;
	}
}