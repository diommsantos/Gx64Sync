#include "SyncHandler.hpp"
#include "LocationSync.hpp"
#include "CommentSync.hpp"
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

}


// Examples: https://github.com/x64dbg/x64dbg/wiki/Plugins
// References:
// - https://help.x64dbg.com/en/latest/developers/plugins/index.html
// - https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html
// - https://x64dbg.com/blog/2016/10/20/threading-model.html
// - https://x64dbg.com/blog/2016/07/30/x64dbg-plugin-sdk.html

// Command use the same signature as main in C
// argv[0] contains the full command, after that are the arguments
// NOTE: arguments are separated by a COMMA (not space like WinDbg)
static bool cbExampleCommand(int argc, char** argv)
{
    dprintf("This is not working!!!!");
    if (argc < 3)
    {
        dputs("Usage: " PLUGIN_NAME "expr1, expr2");

        // Return false to indicate failure (used for scripting)
        return false;
    }

    // Helper function for parsing expressions
    // Reference: https://help.x64dbg.com/en/latest/introduction/Expressions.html
    auto parseExpr = [](const char* expression, duint& value)
    {
        bool success = false;
        value = DbgEval(expression, &success);
        if (!success)
            dprintf("Invalid expression '%s'\n", expression);
        return success;
    };

    duint a = 0;
    if (!parseExpr(argv[1], a))
        return false;

    duint b = 0;
    if (!parseExpr(argv[2], b))
        return false;

    // NOTE: Look at x64dbg-sdk/pluginsdk/bridgemain.h for a list of available functions.
    // The Script:: namespace and DbgFunctions()->... are also good to check out.

    // Do something meaningful with the arguments
    duint result = a + b;
    dprintf("$result = 0x%p + 0x%p = 0x%p\n", a, b, result);

    // The $result variable can be used for scripts
    DbgValToString("$result", result);

    return true;
}

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    dprintf("pluginInit(pluginHandle: %d)\n", pluginHandle);

    // Prefix of the functions to call here: _plugin_register
    _plugin_registercommand(pluginHandle, "x64SyncConnect", x64Sync::syncHandlerStart, false);
    _plugin_registercommand(pluginHandle, "x64SyncStop", x64Sync::syncHandlerStop, false);
    registerLocationSyncCommands();
    registerCommentSyncCommands();
    _plugin_registercommand(pluginHandle, "Funciona", cbExampleCommand, true);

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
    dprintf("pluginSetup(pluginHandle: %d)\n", pluginHandle);
}

//Register here the menu actions
extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY * info) {
    if (0 <= info->hEntry <= 4)
        menuEntryLocationSync(info->hEntry);
}
