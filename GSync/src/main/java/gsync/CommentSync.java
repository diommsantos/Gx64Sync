package gsync;

import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

public class CommentSync {
		SyncHandler sh;
		CodeViewerService cvs;
		ProgramManager pm;
		
		int sessionHandle;
		
		public CommentSync(SyncHandler sh, CodeViewerService cvs, ProgramManager pm) {
			this.sh = sh;
			this.cvs = cvs;
			this.pm = pm;
			this.sh.subscribe(Messages.Comment.class, this::syncRemoteComment);
		}
		
		public void sendGhidraComment() {
			Address currAddr = cvs.getCurrentLocation().getAddress();
			CodeUnit commentCU = pm.getCurrentProgram().getListing().getCodeUnitAt(currAddr);
			String cmmt = commentCU.getComment(CodeUnit.EOL_COMMENT);
			if(cmmt == null)
				cmmt = "";
			String modname = pm.getCurrentProgram().getExecutablePath().substring(1).replace("/", "\\");
			Address base = pm.getCurrentProgram().getImageBase(); 
			sh.send(new Messages.Comment(modname, currAddr.getOffset()-base.getOffset(), cmmt));
		}
		
		private void syncRemoteComment(Messages.Comment cmmt) {
			Program openpg[] = pm.getAllOpenPrograms();
			int i = 0;
			for(; i < openpg.length; i++) {
				if(openpg[i].getExecutablePath().substring(1).replace("/", "\\").equals(cmmt.modname))
					break;
			}
			if(i == openpg.length)
				return;
			Address commentAddr = openpg[i].getImageBase().add(cmmt.rva);
			CodeUnit commentCU = openpg[i].getListing().getCodeUnitAt(commentAddr);
			int transactionID = openpg[i].startTransaction("Sync Remote Comment");
		    boolean success = false;
		    try {
		        // Set the comment
		        commentCU.setComment(CodeUnit.EOL_COMMENT, cmmt.comment);
		        success = true;
		    } finally {
		        // End the transaction
		    	openpg[i].endTransaction(transactionID, success);
		    }
		}
		
		public List<DockingAction> getActions(String providerName) {
			List<DockingAction> actions = new ArrayList<DockingAction>(5);
			
			actions.add(new DockingAction("Sync Comment", providerName) {
				@Override
				public void actionPerformed(ActionContext context) {
					sendGhidraComment();
				}
			});
			actions.get(0).setMenuBarData(new MenuData(new String[]{"Sync Comment"}, null, "CommentSync"));
			actions.get(0).setEnabled(true);
			actions.get(0).markHelpUnnecessary();
			
			return actions;
		}
}
