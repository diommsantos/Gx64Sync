package gsync;

import java.util.ArrayList;
import java.util.List;
import java.util.NavigableSet;
import java.util.Set;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public class HyperSync {
	
	SyncHandler sh;
	ConsoleService cs;
	CodeViewerService cvs;
	ProgramManager pm;
	GoToService gts;
	
	boolean active = false;
	boolean remoteLocationChange = false;
	int subscriberHandle;
	int sessionHandle;
	
	public HyperSync(SyncHandler sh, ConsoleService cs, CodeViewerService cvs, ProgramManager pm, GoToService gts) {
		this.sh = sh;
		this.cs = cs;
		this.cvs = cvs;
		this.pm = pm;
		this.gts = gts;
		sh.subscribe(Messages.HyperSyncState.class, this::syncHyperSyncState);
	}
	
	public void start() {
		if(active)
			return;
		NavigableSet<Integer> sessionHandles = sh.getAllSessionHandles();
		if(sessionHandles.isEmpty())
			return;
		sessionHandle = sessionHandles.last();
		subscriberHandle = this.sh.subscribe(Messages.RelativeAddress.class, this::remoteRVAHandler);
		active = true;
		sh.send(new Messages.HyperSyncState(true), sessionHandle);
		cs.println("HyperSync: HyperSync started!");
	}
	
	public void stop() {
		if(!active)
			return;
		sh.unsubscribe(subscriberHandle);
		active = false;
		sh.send(new Messages.HyperSyncState(false), sessionHandle);
		cs.println("HyperSync: HyperSync stopped!");
	}
	
	private void syncHyperSyncState(Messages.HyperSyncState hss, int hsSession) {
		if(hss.state == true) {
			sessionHandle = hsSession;
			start();
		}
		else
			stop();
	}
	
	private void remoteRVAHandler(Messages.RelativeAddress ra, int hsSession) {
		if(hsSession != sessionHandle)
			return;
		Program openpg[] = pm.getAllOpenPrograms();
		int i = 0;
		for(; i < openpg.length; i++) {
			if(openpg[i].getExecutablePath().substring(1).replace("/", "\\").equals(ra.modPath))
				break;
		}
		if(i == openpg.length) {
			cs.println(String.format("HyperSync: It is not possible to sync the address. The %s module is not loaded!", ra.modPath));
			return;
		}
		remoteLocationChange = true;
		gts.goTo(openpg[i].getImageBase().add(ra.modRVA));
	}
	
	public void GhidraRVAHandler(ProgramLocation loc) {
		if(!active) 
			return;
		if(remoteLocationChange) {
			remoteLocationChange = false;
			return;
		}
		String modPath = pm.getCurrentProgram().getExecutablePath().substring(1).replace("/", "\\");
		sh.send(new Messages.RelativeAddress(modPath, loc.getAddress().getOffset()-pm.getCurrentProgram().getImageBase().getOffset()), sessionHandle);
	}
	
	public List<DockingAction> getActions(String providerName) {
		List<DockingAction> actions = new ArrayList<DockingAction>(5);
		
		actions.add(new DockingAction("Hyper Sync", providerName) {
			@Override
			public void actionPerformed(ActionContext context) {
				if(!active)
					start();
				else
					stop();
			}
		});
		actions.get(0).setMenuBarData(new MenuData(new String[]{"Hyper Sync"}));
		actions.get(0).setEnabled(true);
		actions.get(0).markHelpUnnecessary();
		
		return actions;
	}
}
