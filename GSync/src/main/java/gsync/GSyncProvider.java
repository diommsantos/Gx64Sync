package gsync;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.Icon;
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
	
	private JPanel panel;
	private JLabel statusArea;
    private JLabel debuggerArea;
    private JLabel programArea;
	
	private List<DockingAction> actions = new ArrayList<DockingAction>(20);
	
	GSyncPlugin gsp;


	public GSyncProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		gsp = (GSyncPlugin) plugin;
		buildPanel();
	}
	
	public void init() {
		createActions();
		gsp.sh.installClientHandlerErrorsCallbacks((sessionHandle) -> {resetUI();});
		gsp.sh.installStartCallback(()->{statusArea.setText(String.format("Status: %s", "Waiting Connection..."));});
		gsp.sh.installSessionStartCallbacks((sessionHandle) -> {statusArea.setText(String.format("Status: %s", "Connected"));});
		gsp.sh.installSessionStopCallbacks((sessionHandle) -> {statusArea.setText(String.format("Status: %s", "Waiting Connection..."));});
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

        Icon BROWSER_ICON = ResourceManager.loadImage("images/browser.png");
        statusArea = new JLabel(BROWSER_ICON, SwingConstants.LEFT);
        statusArea.setText(String.format("Status: %s", "idle"));
        panel.add(statusArea, gbc);

        Icon MEMORY_ICON = ResourceManager.loadImage("images/memory16.gif");
        debuggerArea = new JLabel(MEMORY_ICON, SwingConstants.LEFT);
        debuggerArea.setText(String.format("Debugger session: %s", "none"));
        panel.add(debuggerArea, gbc);

        Icon CODE_ICON = ResourceManager.loadImage("images/viewedCode.gif");
        programArea = new JLabel(CODE_ICON, SwingConstants.LEFT);
        panel.add(programArea, gbc);
        programArea.setText(String.format("Debugger program: %s", "none"));
		setVisible(true);
	}
	
	private void remoteSession(Messages.Session mSession, int session) {
		statusArea.setText(String.format("Status: %s", "Connected"));
		debuggerArea.setText(String.format("Debugger session: %s", mSession.sessionName));
		programArea.setText(String.format("Debugger program: %s", mSession.programName));
	}
	
	private void resetUI() {
		statusArea.setText(String.format("Status: %s", "idle"));
		debuggerArea.setText(String.format("Debugger session: %s", "none"));
		programArea.setText(String.format("Debugger program: %s", "none"));
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

