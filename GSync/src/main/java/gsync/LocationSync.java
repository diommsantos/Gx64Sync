package gsync;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

public class LocationSync {

	SyncHandler sh;
	Consumer<String> logger;
	ProgramManager pm;
	CodeViewerService cvs;
	GoToService gts;
	
	private boolean active = false;
	private long remoteBase;
	private int sessionHandle;
	private List<Integer> subscriberHandles = new ArrayList<Integer>(2);
	
	public LocationSync(SyncHandler sh, Consumer<String> logger, ProgramManager pm, CodeViewerService cvs, GoToService gts) {
		this.sh = sh;
		this.logger = logger;
		this.pm = pm;
		this.cvs = cvs;
		this.gts = gts;
		this.start();
	}
	
	public void start() {
		if(active)
			return;
		this.active = true;
		subscriberHandles.add(0, sh.subscribe(Messages.Base.class, this::getRemoteBase));
		subscriberHandles.add(1, sh.subscribe(Messages.Location.class, this::getRemoteAddress));
	}
	
	public void stop() {
		if(!active)
			return;
		sh.unsubscribe(subscriberHandles.get(0));
		sh.unsubscribe(subscriberHandles.get(1));
		this.active = false;
	}
	
	private void getRemoteBase(Messages.Base mBase, int shandle) {
		this.sessionHandle = shandle;
		this.remoteBase = mBase.base;
		sh.send(new Messages.Base(pm.getCurrentProgram().getImageBase().getOffset()), sessionHandle);
	}
	
	private void getRemoteAddress(Messages.Location mLoc, int shandle) {
		this.sessionHandle = shandle;
		Address base = pm.getCurrentProgram().getImageBase(); 
		gts.goTo(base.getNewAddress(mLoc.loc-this.remoteBase+base.getOffset()));
	}
	
	public void sendGhidraBase(){
		if(active)
			sh.send(new Messages.Base(pm.getCurrentProgram().getImageBase().getOffset()), sessionHandle);
	}
	
	public void sendGhidraLocation(){
		if(active)
			sh.send(new Messages.Location(cvs.getCurrentLocation().getAddress().getOffset()), sessionHandle);
	}
	
	//GUI stuff (actions and menus)
	public List<DockingAction> getActions(String providerName) {
		List<DockingAction> actions = new ArrayList<DockingAction>(5);
		
		actions.add(new DockingAction("Start Location Sync", providerName) {
			@Override
			public void actionPerformed(ActionContext context) {
				sh.start();
				start();
				
			}
		});
		actions.get(0).setMenuBarData(new MenuData(new String[]{"Location Sync", "Start"}, null, "LocationSync"));
		actions.get(0).setEnabled(true);
		actions.get(0).markHelpUnnecessary();
		
		actions.add(new DockingAction("Stop Location Sync", providerName) {
			@Override
			public void actionPerformed(ActionContext context) {
				stop();
				
			}
		});
		actions.get(1).setMenuBarData(new MenuData(new String[]{"Location Sync", "Stop"}, null, "LocationSync"));
		actions.get(1).setEnabled(true);
		actions.get(1).markHelpUnnecessary();
		
		actions.add(new DockingAction("Sync Location", providerName) {
			@Override
			public void actionPerformed(ActionContext context) {
				sendGhidraLocation();
				
			}
		});
		actions.get(2).setMenuBarData(new MenuData(new String[]{"Location Sync", "Sync Location"}, null, "LocationSync"));
		actions.get(2).setEnabled(true);
		actions.get(2).markHelpUnnecessary();
		
		actions.add(new DockingAction("Sync Base", providerName) {
			@Override
			public void actionPerformed(ActionContext context) {
				sendGhidraBase();
				
			}
		});
		actions.get(3).setMenuBarData(new MenuData(new String[]{"Location Sync", "Sync Base"}, null, "LocationSync"));
		actions.get(3).setEnabled(true);
		actions.get(3).markHelpUnnecessary();
		
		return actions;
	}
}
