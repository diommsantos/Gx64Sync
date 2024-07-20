package gsync;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import resources.Icons;
import resources.ResourceManager;

public class GSyncProvider extends ComponentProvider{
	
	private enum STATUS{
		IDLE,
		WAITING_CONNECTION,
		CONNECTED
	};
	
	private JPanel panel;
	private JLabel statusArea;
    private JLabel debuggerArea;
    private JLabel programArea;
    
    static Icon idleIcon = new ImageIcon(ResourceManager.loadImage("images/idle_status.png").getImage().getScaledInstance(16, 16, Image.SCALE_SMOOTH));
    static Icon waitingConnectionIcon = new ImageIcon(ResourceManager.loadImage("images/waiting_connection_status.png").getImage().getScaledInstance(16, 16, Image.SCALE_SMOOTH));
    static Icon connectedIcon = new ImageIcon(ResourceManager.loadImage("images/connected_status.png").getImage().getScaledInstance(16, 16, Image.SCALE_SMOOTH));
	
	private List<DockingAction> actions = new ArrayList<DockingAction>(20);
	
	GSyncPlugin gsp;
	

	public GSyncProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		gsp = (GSyncPlugin) plugin;
		buildPanel();
	}
	
	public void init() {
		createActions();
		gsp.sh.installClientHandlerErrorsCallbacks((sessionHandle) -> {setStatus(STATUS.WAITING_CONNECTION);});
		gsp.sh.installStartCallback(()->{setStatus(STATUS.WAITING_CONNECTION);});
		gsp.sh.installSessionStartCallbacks((sessionHandle) -> {setStatus(STATUS.CONNECTED);});
		gsp.sh.installSessionStopCallbacks((sessionHandle) -> {setStatus(STATUS.WAITING_CONNECTION);});
		gsp.sh.subscribe(Messages.Session.class, this::remoteSession);
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
	}
	
	private void remoteSession(Messages.Session mSession, int session) {
		statusArea.setText(String.format("Status: %s", "Connected"));
		debuggerArea.setText(String.format("Debugger session: %s", mSession.sessionName));
		programArea.setText(String.format("Debugger program: %s", mSession.programName));
	}
	

	// TODO: Customize actions
	private void createActions() {
		
		actions.addAll(gsp.locs.getActions(getName()));
		actions.addAll(gsp.cmmts.getActions(getName()));
		
		for(DockingAction action : actions) {
			dockingTool.addLocalAction(this, action);
		}
		//dockingTool.setMenuGroup(new String[] {"Location Sync"}, "LocationSync", null);
		
	}
	
	@Override
	public JComponent getComponent() {
		return panel;
	}
}

