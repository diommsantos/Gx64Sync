# Design Goals

* Fast
* Fully asynchronous
* Small codebase
* Easily extensible
* Synchronization from the debugger to the disassembler and from disassembler to the debugger

# Build and Debug

## Prerequisites
1. [Microsoft Visual Studio](https://visualstudio.microsoft.com/) (I use the 2022 version but other recent versions should work as well)
2. [Eclipse IDE for JAVA Developers](https://www.eclipse.org/downloads/)

## Debugging GSync

1. Install `GhidraDev` (instructions are available at `GHIDRA_INSTALL_DIR\Extensions\Eclipse\GhidraDev\GhidraDev_README` but exposed here for accessibility)
```
   GhidraDev can be installed into an existing installation of Eclipse the same way most Eclipse plugins are installed. From Eclipse:

    Click Help → Install New Software...
    Click Add...
    Click Archive...
    Select GhidraDev zip file from <GhidraInstallDir>/Extensions/Eclipse/GhidraDev/
    Click OK (name field can be blank)
    Check Ghidra category (or GhidraDev entry)
    Click Next
    Click Next
    Accept the terms of the license agreement
    Click Finish
    Check Unsigned table entry
    Click Trust Selected
    Click Restart Now
```
2. In Eclipse under `File`->`Open Projects from File System...` select the `Gx64Sync\GSync` directory and import it.
3. In Eclipse select `GhidraDev`->`Link Ghidra...` and follow the instructions. 

There should now be a GSync Run Configuration and GSync Debug Configuration in Eclipse that you can use to debug GSync.

### Troubleshooting
To verify that the Eclipse environment is setup correctly, you can open CodeBrowser and select
``File`` -> ``Configure`` -> ``Examples (Configure) `` and check that the `GSyncPlugin` option
exists and is selected. If that is the case ``Window``->``GSyncPlugin`` menu option should exist.

> [!WARNING] 
> When the plugin is built from gradle outside of Eclipse the GSync Run/Debug Configuration stops working, to fix this remove all the files created by
> by gradle while building the plugin.

## Debugging x64Sync

### 64-bit version
1. For debugging the 64-bit version, copy ``GSync\x64Sync\PluginDevHelper.dp64`` to the ``x64DBG_INSTALL_DIR\release\x64\plugins`` folder where ``x64DBG_INSTALL_DIR`` is the installation directory of x64Dbg. See [PluginDevHelper](https://github.com/x64dbg/PluginDevHelper) for more details.
2. Open ``x64Sync.sln`` in Visual Studio and run the x64 Debug Configurations. This should create a `x64\Debug` folder  in the `x64Sync` folder and a `.dp64` file inside.
3. Change directories to the `x64\Debug` folder and run the following command:
   ```
   mklink x64Sync.dp64 x64DBG_INSTALL_DIR\release\x64\plugins\x64Sync
   ```
   Once again ``x64DBG_INSTALL_DIR`` is the installation directory of x64Dbg.
4. In Visual Studio select `Debug`-> `x64Sync Debug Properties`. Verify that ``Configuration:`` is set to ``Debug`` and ``Platform:`` to ``x64``. Under ``Configuration Properties``->``Debugging`` change the command property to ``x64DBG_INSTALL_DIR\release\x64\x64dbg.exe``. 
5. Run the `PluginDevServer.exe`.
6. Start the 64-bit version of x64Debug. 
Your debug configuration is complete, and it should be possible to debug x64Sync from inside Visual Studio.

### 32-bit version
1. For the 32-bit version, copy ``GSync\x64Sync\PluginDevHelper.dp32`` to the ``x64DBG_INSTALL_DIR\release\x32\plugins``.
2. Open ``x64Sync.sln`` in Visual Studio and run the x86 Debug Configurations. This should create a `Debug` folder  in the `x64Sync` folder and a `.dp32` file inside.
3. Change directories to the `Debug` folder and run the following command:
   ```
   mklink x64Sync.dp32 x64DBG_INSTALL_DIR\release\x32\plugins\x64Sync
   ```
   Once again ``x64DBG_INSTALL_DIR`` is the installation directory of x64Dbg.
4. In Visual Studio select `Debug`-> `x64Sync Debug Properties`. Verify that ``Configuration:`` is set to ``Debug`` and ``Platform:`` to ``x32``. Under ``Configuration Properties``->``Debugging`` change the command property to ``x64DBG_INSTALL_DIR\release\x32\x32dbg.exe``. 
5. Run the `PluginDevServer.exe`.
6. Start the 32-bit version of x64Debug. 

### Troubleshooting
> [!WARNING] 
> Do not forget to run `PluginDevServer.exe` and the appropriate version of x64Debug to properly debug x64Sync. 
# Software Architecture

# Extending the functionality of the plugins

# Creating similar plugins for other tools
