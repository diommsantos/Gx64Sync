/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package gsync;

import java.awt.BorderLayout;
import java.net.Socket;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here.",
	servicesRequired = {
			ConsoleService.class
	}
)
//@formatter:on
public class GSyncPlugin extends ProgramPlugin {

	GSyncProvider provider;
	
	//SyncHandler
	SyncHandler sh;
	
	//services
	ConsoleService cs;
	ProgramManager pm;
	CodeViewerService cvs;
	GoToService gts;
	
	//Features
	public GSyncOn gsOn;
	public TestSender TS;
	public LocationSync locs;
	public CommentSync cmmts;
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GSyncPlugin(PluginTool tool) {
		super(tool);

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new GSyncProvider(this, pluginName);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();
		
		// TODO: Acquire services if necessary
		cs = tool.getService(ConsoleService.class);
		pm = tool.getService(ProgramManager.class);
		cvs = tool.getService(CodeViewerService.class);
		gts = tool.getService(GoToService.class);
        cs.println("[*] Gsync init");
        sh = new SyncHandler((s)->cs.print(s));
        
        gsOn = new GSyncOn(sh, (s)->cs.print(s));
		TS = new TestSender(sh, (s)->cs.print(s));
        locs = new LocationSync(sh, (s)->cs.print(s), pm, cvs, gts);
        cmmts = new CommentSync(sh, cvs, pm);
        
        provider.init();
	}
	
	@Override
	protected void locationChanged(ProgramLocation loc) {
	}
		
}
