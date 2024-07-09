package gsync;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import resources.Icons;

public class GSyncProvider extends ComponentProvider{
	private JPanel panel;
	private List<DockingAction> actions = new ArrayList<DockingAction>(20);
	
	GSyncPlugin gsp;


	public GSyncProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		gsp = (GSyncPlugin) plugin;
		buildPanel();
	}
	
	public void init() {
		createActions();
	}
	
	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		JTextArea textArea = new JTextArea(5, 25);
		textArea.setEditable(false);
		panel.add(new JScrollPane(textArea));
		setVisible(true);
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

