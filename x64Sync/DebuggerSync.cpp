#include "DebuggerSync.hpp"
#include <functional>
#include "pluginmain.h"

DebbugerSync::DebbugerSync(SyncHandler &sh):
sh{ sh }
{
	sh.subscribe<Messages::DebbuggerCmd>(std::bind(&DebbugerSync::debuggerCmdHandler, this, std::placeholders::_1));
}

void DebbugerSync::debuggerCmdHandler(const Messages::DebbuggerCmd& dbgCmdM) {
	switch (dbgCmdM.cmdType)
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
		BridgeList<Script::Module::ModuleInfo> modList;
		Script::Module::GetList(&modList);
		for (int i = 0; i < modList.Count(); i++) {
			if (strcmp(modList[i].path, dbgCmdM.modPath.data()) == 0) {
				//DbgSetCommentAt(modList[i].base + cmmt.rva, cmmt.comment.data());
				cmd = cmd + +"."+std::to_string(modList[i].base + dbgCmdM.rva);
				Cmd(cmd.data());
				return;
			}
		}
		
		break;
	}
}