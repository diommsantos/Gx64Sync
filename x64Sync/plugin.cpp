#include "SyncHandler.hpp"
#include "LocationSync.hpp"
#include "CommentSync.hpp"
#include "DebuggerSync.hpp"
#include "plugin.h"

//x64Sync Plugin Specific variables/functions
namespace x64Sync {

    void x64SyncLogger(std::string_view sv) {
        dputs(sv.data());
    }

    SyncHandler sh{ x64SyncLogger };

    static bool syncHandlerStart(int argc, char** argv) {
        bool res;
        dputs("Connecting...");
        if (res = sh.start())
            dputs("Connection established!");
        else
            dputs("An error occured while establishing the connectiona :(");
        return res; 
    }

    static bool syncHandlerStop(int argc, char** argv) { 
        sh.stop();
        dprintf("%s stopped!", PLUGIN_NAME);
        return true; 
    }

    LocationSync ls{ sh };
    CommentSync cs{ sh };
    DebbugerSync ds{ sh };

}


// Examples: https://github.com/x64dbg/x64dbg/wiki/Plugins
// References:
// - https://help.x64dbg.com/en/latest/developers/plugins/index.html
// - https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html
// - https://x64dbg.com/blog/2016/10/20/threading-model.html
// - https://x64dbg.com/blog/2016/07/30/x64dbg-plugin-sdk.html

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    dprintf("pluginInit(pluginHandle: %d)\n", pluginHandle);

    // Prefix of the functions to call here: _plugin_register
    _plugin_registercommand(pluginHandle, "x64SyncConnect", x64Sync::syncHandlerStart, false);
    _plugin_registercommand(pluginHandle, "x64SyncStop", x64Sync::syncHandlerStop, false);
    registerLocationSyncCommands();
    registerCommentSyncCommands();

    x64Sync::sh.subscribe<Messages::Session>(
        [](const Messages::Session& session) {
            char programName[300];
            Script::Module::GetMainModuleName(programName);
            x64Sync::sh.send(Messages::Session("x64Dbg", programName));
        });
    // Return false to cancel loading the plugin.
    return true;
}

// Deinitialize your plugin data here.
// NOTE: you are responsible for gracefully closing your GUI
// This function is not executed on the GUI thread, so you might need
// to use WaitForSingleObject or similar to wait for everything to close.
void pluginStop()
{
    // Prefix of the functions to call here: _plugin_unregister

    dprintf("pluginStop(pluginHandle: %d)\n", pluginHandle);
}

// Do GUI/Menu related things here.
// This code runs on the GUI thread: GetCurrentThreadId() == GuiGetMainThreadId()
// You can get the HWND using GuiGetWindowHandle()
void pluginSetup()
{
    // Prefix of the functions to call here: _plugin_menu
    menuAddLocationSync();
    menuAddCommentSync();
    dprintf("pluginSetup(pluginHandle: %d)\n", pluginHandle);
}

//Register here the menu actions
extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY * info) {
    menuEntryLocationSync(info->hEntry);
    menuEntryCommentSync(info->hEntry);
}
