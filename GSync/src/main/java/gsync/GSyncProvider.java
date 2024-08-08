package gsync;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import resources.ResourceManager;

public class GSyncProvider extends ComponentProvider{
	
	private enum STATUS{
		IDLE,
		WAITING_CONNECTION,
		CONNECTED
	}
	
	STATUS status = STATUS.IDLE;
	
	private JPanel panel;
	private JLabel statusArea;
    private JLabel debuggerArea;
    private JLabel programArea;
    
    static Icon idleIcon = new ImageIcon(ResourceManager.loadImage("images/idle_status.png").getImage().getScaledInstance(16, 16, Image.SCALE_SMOOTH));
    static Icon waitingConnectionIcon = new ImageIcon(ResourceManager.loadImage("images/waiting_connection_status.png").getImage().getScaledInstance(16, 16, Image.SCALE_SMOOTH));
    static Icon connectedIcon = new ImageIcon(ResourceManager.loadImage("images/connected_status.png").getImage().getScaledInstance(16, 16, Image.SCALE_SMOOTH));
	static Icon startIcon = new ImageIcon(ResourceManager.loadImage("images/start.png").getImage().getScaledInstance(16, 16, Image.SCALE_SMOOTH));
	static Icon stopIcon = new ImageIcon(ResourceManager.loadImage("images/stop.png").getImage().getScaledInstance(16, 16, Image.SCALE_SMOOTH));
    
	private List<DockingAction> actions = new ArrayList<DockingAction>(20);
	
	protected TreeMap<Integer, Messages.Session> sessionStatus = new TreeMap<Integer, Messages.Session>();
	
	GSyncPlugin gsp;
	

	public GSyncProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		gsp = (GSyncPlugin) plugin;
		sessionStatus.put(-1, new Messages.Session("none", "none"));
		buildPanel();
		gsp.sh.installClientHandlerErrorsCallbacks((sessionHandle) -> {
			sessionStatus.remove(sessionHandle);
			Messages.Session lastSession = sessionStatus.lastEntry().getValue();
			updateSessionArea(lastSession.sessionName, lastSession.programName);
			setStatus(STATUS.WAITING_CONNECTION);
		});
		gsp.sh.installStartCallback(() -> {
			setStatus(STATUS.WAITING_CONNECTION);
			actions.get(0).setToolBarData(new ToolBarData(stopIcon));
		});
		gsp.sh.installStopCallbacks(() -> {
			setStatus(STATUS.IDLE);
			actions.get(0).setToolBarData(new ToolBarData(startIcon));
		});
		gsp.sh.installSessionStartCallbacks((sessionHandle) -> {
			sessionStatus.put(sessionHandle, new Messages.Session("Waiting for debugger session info...", "Waiting for program info..."));
			updateSessionArea("Waiting for debugger session info...", "Waiting for program info...");
			setStatus(STATUS.CONNECTED);
			gsp.sh.send(new Messages.Session("Ghidra", gsp.pm.getCurrentProgram().toString()), sessionHandle);
		});
		gsp.sh.installSessionStopCallbacks((sessionHandle) -> {
			sessionStatus.remove(sessionHandle);
			Messages.Session lastSession = sessionStatus.lastEntry().getValue();
			updateSessionArea(lastSession.sessionName, lastSession.programName);
			if(sessionStatus.size() == 1) 
				setStatus(STATUS.WAITING_CONNECTION);
		});
		gsp.sh.subscribe(Messages.Session.class, this::remoteSessionInfoHandler);
		createActions();
	}
	
	// Customize GUI
	private void buildPanel() {
		GridBagLayout grid = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        panel = new JPanel(grid);
        panel.setFocusable(true);
        
        gbc.insets = new Insets(2, 8, 2, 8);
        gbc.gridx = 0;
        gbc.anchor = GridBagConstraints.SOUTHEAST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;

        statusArea = new JLabel(idleIcon, SwingConstants.LEFT);
        setStatus(STATUS.IDLE);
        panel.add(statusArea, gbc);

        Icon bugIcon = new ImageIcon(ResourceManager.loadImage("images/bug.png").getImage().getScaledInstance(16, 16, Image.SCALE_SMOOTH));
        debuggerArea = new JLabel(bugIcon, SwingConstants.LEFT);
        debuggerArea.setText(String.format("Debugger session: %s", "none"));
        panel.add(debuggerArea, gbc);

        Icon programIcon = ResourceManager.loadImage("images/memory16.gif");
        programArea = new JLabel(programIcon, SwingConstants.LEFT);
        panel.add(programArea, gbc);
        programArea.setText(String.format("Debugger program: %s", "none"));
		setVisible(true);
	}
	
	private void setStatus(STATUS status) {
		String s = "";
		switch(status) {
		case IDLE:
			s = "Idle";
			statusArea.setIcon(idleIcon);
			break;
		case WAITING_CONNECTION:
			s = "Waiting Connection...";
			statusArea.setIcon(waitingConnectionIcon);
			break;
		case CONNECTED:
			s = "Connected";
			statusArea.setIcon(connectedIcon);
			break;
		}
		statusArea.setText(String.format("Status: %s", s));
		this.status = status;
	}
	
	private void updateSessionArea(String sessionName, String programName) {
		debuggerArea.setText(String.format("Debugger session: %s", sessionName));
		programArea.setText(String.format("Debugger program: %s", programName));
	}
	
	private void remoteSessionInfoHandler(Messages.Session mSession, int session) {
		sessionStatus.put(session, mSession); 
		updateSessionArea(sessionStatus.lastEntry().getValue().sessionName, sessionStatus.lastEntry().getValue().programName);
	}
	

	// TODO: Customize actions
	private void createActions() {
		actions.add(new DockingAction("Start/Stop SyncHandler", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if(status == STATUS.IDLE)
					gsp.sh.start();
				else
					gsp.sh.stop();
			}
		});
		actions.get(0).setToolBarData(new ToolBarData(startIcon));
		actions.get(0).setEnabled(true);
		actions.get(0).markHelpUnnecessary();
		
		actions.addAll(gsp.locs.getActions(getName()));
		actions.addAll(gsp.cmmts.getActions(getName()));
		actions.addAll(gsp.dbgs.getActions(getName()));
		actions.addAll(gsp.hs.getActions(getName()));
		
		for(DockingAction action : actions) {
			dockingTool.addLocalAction(this, action);
		}
		
	}
	
	@Override
	public JComponent getComponent() {
		return panel;
	}
}

