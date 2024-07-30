#ifndef COMMENTSYNC_H
#define COMMENTSYNC_H

#include "Messages.hpp"
#include "SyncHandler.hpp"

class CommentSync
{
public:
	CommentSync(SyncHandler& sh);
	void sendx64DbgComment();


private:
	SyncHandler& sh;
	void syncRemoteComment(const Messages::Comment& cmmt);
};

//integration with x64Dbg
namespace x64Sync { extern CommentSync cs; }
static bool csSendx64DbgCommentCommand(int argc, char** argv);
void registerCommentSyncCommands();

void menuAddCommentSync();
void menuEntryCommentSync(int hEntry);

#endif // !COMMENTSYNC_H
