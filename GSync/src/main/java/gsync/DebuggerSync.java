package gsync;

import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import gsync.Messages.DebuggerCmd;
import resources.ResourceManager;

public class DebuggerSync {
	SyncHandler sh;
	ProgramManager pm;
	CodeViewerService cvs;
		
	public DebuggerSync(SyncHandler sh, ProgramManager pm, CodeViewerService cvs) {
		this.sh = sh;
		this.pm = pm;
		this.cvs = cvs;
	}
	
	public void run() {
		String modPath = pm.getCurrentProgram().getExecutablePath().substring(1).replace("/", "\\");
		sh.send(new Messages.DebuggerCmd(DebuggerCmd.CMDTYPE.RUN, modPath, -1));
	}
	
	public void pause() {
		String modPath = pm.getCurrentProgram().getExecutablePath().substring(1).replace("/", "\\");
		sh.send(new Messages.DebuggerCmd(DebuggerCmd.CMDTYPE.PAUSE, modPath, -1));
	}
	
	public void setBreakpoint() {
		Address currAddr = cvs.getCurrentLocation().getAddress();
		Address base = pm.getCurrentProgram().getImageBase();
		String modPath = pm.getCurrentProgram().getExecutablePath().substring(1).replace("/", "\\");
		sh.send(new Messages.DebuggerCmd(DebuggerCmd.CMDTYPE.BREAKPOINT, modPath, currAddr.getOffset()-base.getOffset()));
	}
	
	public void stepInto() {
		String modPath = pm.getCurrentProgram().getExecutablePath().substring(1).replace("/", "\\");
		sh.send(new Messages.DebuggerCmd(DebuggerCmd.CMDTYPE.STEPINTO, modPath, -1));
	}
	
	public void stepOver() {
		String modPath = pm.getCurrentProgram().getExecutablePath().substring(1).replace("/", "\\");
		sh.send(new Messages.DebuggerCmd(DebuggerCmd.CMDTYPE.STEPOVER, modPath, -1));
	}
	
	//GUI stuff (actions and menus)
		public List<DockingAction> getActions(String providerName) {
			List<DockingAction> actions = new ArrayList<DockingAction>(5);
			actions.add(new DockingAction("Run", providerName) {
				@Override
				public void actionPerformed(ActionContext context) {
					run();
					
				}
			});
			actions.get(0).setToolBarData(new ToolBarData(ResourceManager.loadImage("images/arrow-run.png")));
			actions.get(0).setEnabled(true);
			actions.get(0).markHelpUnnecessary();
			
			actions.add(new DockingAction("Pause", providerName) {
				@Override
				public void actionPerformed(ActionContext context) {
					pause();
					
				}
			});
			actions.get(1).setToolBarData(new ToolBarData(ResourceManager.loadImage("images/control-pause.png")));
			actions.get(1).setEnabled(true);
			actions.get(1).markHelpUnnecessary();
			
			actions.add(new DockingAction("Step into", providerName) {
				@Override
				public void actionPerformed(ActionContext context) {
					stepInto();
					
				}
			});
			actions.get(2).setToolBarData(new ToolBarData(ResourceManager.loadImage("images/arrow-step-into.png")));
			actions.get(2).setEnabled(true);
			actions.get(2).markHelpUnnecessary();
			
			actions.add(new DockingAction("Step Over", providerName) {
				@Override
				public void actionPerformed(ActionContext context) {
					stepOver();
					
				}
			});
			actions.get(3).setToolBarData(new ToolBarData(ResourceManager.loadImage("images/arrow-step-over.png")));
			actions.get(3).setEnabled(true);
			actions.get(3).markHelpUnnecessary();
			
			actions.add(new DockingAction("Set Breakpoint", providerName) {
				@Override
				public void actionPerformed(ActionContext context) {
					setBreakpoint();
					
				}
			});
			actions.get(4).setToolBarData(new ToolBarData(ResourceManager.loadImage("images/breakpoint.png")));
			actions.get(4).setEnabled(true);
			actions.get(4).markHelpUnnecessary();
		
			return actions;
		}
		
}
