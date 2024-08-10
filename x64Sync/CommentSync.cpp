#include "CommentSync.hpp"
#include "pluginmain.h"

namespace x64Sync { extern std::unordered_map<std::string, duint> fileHashes; }

CommentSync::CommentSync(SyncHandler& sh) :
sh{sh}
{
	sh.subscribe<Messages::Comment>(std::bind(&CommentSync::syncRemoteComment, this, std::placeholders::_1));
}

void CommentSync::sendx64DbgComment() {
	bool res = false;
	SELECTIONDATA selection;
	char cmmt[5000] = "\0";
	duint modBase;

	res = GuiSelectionGet(GUI_DISASSEMBLY, &selection);
	DbgGetCommentAt(selection.start, cmmt);
	modBase = DbgFunctions()->ModBaseFromAddr(selection.start);
	if(!res) {
		dputs("An error occurred while syncing the current comment");
		return;
	}
	auto it = x64Sync::fileHashes.begin();
	while (it != x64Sync::fileHashes.end()) {
		if (it->second == modBase)
			return sh.send(Messages::Comment{ it->first, selection.start - modBase, cmmt });
		it++;
	}
}

void CommentSync::syncRemoteComment(const Messages::Comment& cmmt) {
	auto it = x64Sync::fileHashes.find(cmmt.modHash);
	if (it == x64Sync::fileHashes.end())
		return dputs("It was not possible to set the comment!");
	DbgSetCommentAt(it->second + cmmt.rva, cmmt.comment.data());
	
}

static bool csSendx64DbgCommentCommand(int argc, char** argv) { x64Sync::cs.sendx64DbgComment(); return true; }

void registerCommentSyncCommands() {
	_plugin_registercommand(pluginHandle, "SyncComment", csSendx64DbgCommentCommand, true);
}

void menuAddCommentSync() {
	_plugin_menuaddentry(hMenu, MENU_IDENTIFIERS::COMMENTSYNC_SYNC_COMMENT, "Sync Comment");
}

void menuEntryCommentSync(int hEntry) {
	switch (hEntry) 
	{
	case MENU_IDENTIFIERS::COMMENTSYNC_SYNC_COMMENT: csSendx64DbgCommentCommand(0, nullptr); break;
	}
}