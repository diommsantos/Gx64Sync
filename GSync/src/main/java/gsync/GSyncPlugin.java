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
			ConsoleService.class,
			ProgramManager.class,
			CodeViewerService.class,
			GoToService.class
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
	
	Logger logger = new Logger() {
    	public void log(String s) {
    		cs.print(s);
    	}
    	
    	public void logError(String s) {
    		cs.printError(s);
    	}
    	
    	public void logln(String s) {
    		cs.println(s);
    	}
    	
    	public void loglnError(String s) {
    		cs.printlnError(s);
    	}
    };
	
	//Features
	public LocationSync locs;
	public CommentSync cmmts;
	public DebuggerSync dbgs;
	public HyperSync hs;
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GSyncPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		super.init();
		
		// TODO: Acquire services if necessary
		cs = tool.getService(ConsoleService.class);
		pm = tool.getService(ProgramManager.class);
		cvs = tool.getService(CodeViewerService.class);
		gts = tool.getService(GoToService.class);
        cs.println("GSync init");
        
		sh = new SyncHandler(logger);
        
        locs = new LocationSync(logger, sh, pm, cvs, gts);
        cmmts = new CommentSync(sh, cvs, pm);
        dbgs = new DebuggerSync(sh, pm, cvs);
        hs = new HyperSync(sh, locs, cs, cvs, pm, gts);
        
        String pluginName = getName();
		provider = new GSyncProvider(this, pluginName);
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));

	}
	
	@Override
	protected void locationChanged(ProgramLocation loc) {
		hs.GhidraRVAHandler(loc);
	}
	
	@Override
	protected boolean canClose() {
		sh.stop();
		return true;
	}
		
}
