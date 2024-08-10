package gsync;

import java.util.ArrayList;
import java.util.List;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

public class LocationSync {

	SyncHandler sh;
	Logger logger;
	ProgramManager pm;
	CodeViewerService cvs;
	GoToService gts;
	
	private boolean active = false;
	private int sessionHandle;
	private int subscriberHandle;
	
	public LocationSync(Logger logger, SyncHandler sh, ProgramManager pm, CodeViewerService cvs, GoToService gts) {
		LocationSync self = this;
    	this.logger = new Logger() {
        	public void log(String s) {
        		logger.log(self.getClass().getSimpleName()+": "+s);
        	}
        	
        	public void logError(String s) {
        		logger.logError(self.getClass().getSimpleName()+": "+s);
        	}
        	
        	public void logln(String s) {
        		logger.logln(self.getClass().getSimpleName()+": "+s);
        	}
        	
        	public void loglnError(String s) {
        		logger.loglnError(self.getClass().getSimpleName()+": "+s);
        	}
        };
		this.sh = sh;
		this.pm = pm;
		this.cvs = cvs;
		this.gts = gts;
		this.start();
	}
	
	public void start() {
		if(active)
			return;
		this.active = true;
		subscriberHandle = sh.subscribe(Messages.RelativeAddress.class, this::syncRemoteAddress);
	}
	
	public void stop() {
		if(!active)
			return;
		sh.unsubscribe(subscriberHandle);
		this.active = false;
	}
	
	private void syncRemoteAddress(Messages.RelativeAddress ra, int shandle) {
		this.sessionHandle = shandle;
		Program openpg[] = pm.getAllOpenPrograms();
		int i = 0;
		for(; i < openpg.length; i++) {
			if(openpg[i].getExecutableMD5().equals(ra.modHash))
				break;
		}
		if(i == openpg.length) {
			logger.logln(String.format("It is not possible to sync the address. The %s module is not loaded!", ra.modName));
			return;
		}
		gts.goTo(openpg[i].getImageBase().add(ra.rva));
	}
	
	public void sendGhidraLocation(){
		if(!active)
			return;
		String modName = pm.getCurrentProgram().toString();
		long rva = cvs.getCurrentLocation().getAddress().getOffset()-pm.getCurrentProgram().getImageBase().getOffset();
		sh.send(new Messages.RelativeAddress(modName, pm.getCurrentProgram().getExecutableMD5(), rva), sessionHandle);
	}
	
	//GUI stuff (actions and menus)
	public List<DockingAction> getActions(String providerName) {
		List<DockingAction> actions = new ArrayList<DockingAction>(1);
		
		actions.add(new DockingAction("Sync Location", providerName) {
			@Override
			public void actionPerformed(ActionContext context) {
				sendGhidraLocation();
				
			}
		});
		actions.get(0).setMenuBarData(new MenuData(new String[]{"Sync Location"}, null, "1-LocationSync"));
		actions.get(0).setEnabled(true);
		actions.get(0).markHelpUnnecessary();
		
		
		return actions;
	}
}
