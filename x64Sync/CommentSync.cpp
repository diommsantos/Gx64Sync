#include "CommentSync.hpp"
#include "pluginmain.h"

CommentSync::CommentSync(SyncHandler& sh) :
sh{sh}
{
	sh.subscribe<Messages::Comment>(std::bind(&CommentSync::syncRemoteComment, this, std::placeholders::_1));
}

void CommentSync::sendx64DbgComment() {
	bool res = false;
	SELECTIONDATA selection;
	char cmmt[5000] = "\0";
	char modPath[300];
	duint currBaseAddr;

	res = GuiSelectionGet(GUI_DISASSEMBLY, &selection);
	DbgGetCommentAt(selection.start, cmmt);
	DbgFunctions()->ModPathFromAddr(selection.start, modPath, 300);
	currBaseAddr = DbgFunctions()->ModBaseFromAddr(selection.start);
	if(!res) {
		dputs("An error occurred while syncing the current comment");
		return;
	}
	sh.send(Messages::Comment{ modPath, selection.start - currBaseAddr, cmmt});
}

void CommentSync::syncRemoteComment(const Messages::Comment& cmmt) {
	BridgeList<Script::Module::ModuleInfo> modList;
	Script::Module::GetList(&modList);
	for (int i = 0; i < modList.Count(); i++) {
		if (strcmp(modList[i].path, cmmt.modname.data()) == 0) {
			DbgSetCommentAt(modList[i].base + cmmt.rva, cmmt.comment.data());
			return;
		}
	}
	dputs("It was not possible to set the comment!");
}

static bool csSendx64DbgCommentCommand(int argc, char** argv) { x64Sync::cs.sendx64DbgComment(); return true; }

void registerCommentSyncCommands() {
	_plugin_registercommand(pluginHandle, "SyncComment", csSendx64DbgCommentCommand, true);
}