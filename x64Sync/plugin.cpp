#include "SyncHandler.hpp"
#include "LocationSync.hpp"
#include "CommentSync.hpp"
#include "DebuggerSync.hpp"
#include "HyperSync.hpp"
#include "md5.h"
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
            dputs("An error occured while establishing the connection :(");
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
    HyperSync hs{ sh, ls };

    //this map uses as keys md5 hashes of the loaded modules and as values their base rva
    std::unordered_map<std::string, duint> fileHashes{};

    std::string getMD5FileHash(std::string_view filePath) {
        MD5 fileHash;
        char buffer[1024];
        std::ifstream file(filePath.data(), std::ifstream::binary);

        while (file.good()) {
            file.read(buffer, sizeof(buffer));
            fileHash.add(buffer, file.gcount());
        }

        return fileHash.getHash();
    }

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
    registerHyperSyncCommands();

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
    x64Sync::sh.stop();
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
    menuAddHyperSync();
    dprintf("pluginSetup(pluginHandle: %d)\n", pluginHandle);
}

//Register here the menu actions
extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY * info) {
    menuEntryLocationSync(info->hEntry);
    menuEntryCommentSync(info->hEntry);
    menuEntryHyperSync(info->hEntry);
}

extern "C" __declspec(dllexport) void CBSELCHANGED(CBTYPE cbType, PLUG_CB_SELCHANGED * sel) {
    x64Sync::hs.x64DbgRVAHandler(sel);
}

extern "C" __declspec(dllexport) void CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* procInfo) {
    dprintf("ImageName: %s\n", procInfo->modInfo->ImageName);
    x64Sync::fileHashes[x64Sync::getMD5FileHash(procInfo->modInfo->ImageName)] = procInfo->modInfo->BaseOfImage;
}

extern "C" __declspec(dllexport) void CBEXITPROCESS(CBTYPE cbType, PLUG_CB_EXITPROCESS* procInfo) {
    dprintf("Exiting Process.\n");
    x64Sync::fileHashes.clear();
}

extern "C" __declspec(dllexport) void CBLOADDLL(CBTYPE cbType, PLUG_CB_LOADDLL* dllInfo) {
    dprintf("DllImageName: %s\n", dllInfo->modInfo->ImageName);
    x64Sync::fileHashes[x64Sync::getMD5FileHash(dllInfo->modInfo->ImageName)] = dllInfo->modInfo->BaseOfImage;
}

extern "C" __declspec(dllexport) void CBUNLOADDLL(CBTYPE cbType, PLUG_CB_UNLOADDLL* dllInfo) {
    char modPath[MAX_PATH];
    DbgFunctions()->ModPathFromAddr((duint) dllInfo->UnloadDll->lpBaseOfDll, modPath, MAX_PATH);
    dprintf("Unloaded DllImageName: %s\n", modPath);
    using namespace x64Sync;
    auto it = fileHashes.begin();
    while (it != fileHashes.end()) {
        if ((duint) dllInfo->UnloadDll->lpBaseOfDll == it->second) {
            fileHashes.erase(it);
            break;
        }
        ++it;
    }
}