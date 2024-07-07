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

This software was built to be as modular (and therefore easily extensible) as possible. 
It is composed of two plugins: a Ghidra plugin (GSync) and an x64Dbg plugin (x64Sync). 
To best understand how this software works we will use the common analogy of a "layered cake" where each layer depends only on the layers below:


![Gx64Sync Image](/docs/Gx64SyncDiagram.png)


## Listener.java, ClientHandler.java and Client.cpp

The Listener.java class, has as its only jobs:
1. Listen for connections
2. When a connection arrives, call a callback to handle it

The ClientHandler.java and Client.cpp, has as its only job:
1. Send plain text messages (a text message in this contex is just a `\n` ended text string) through a connection
2. As soon as a text message arrives through the connection, **asynchronosly** (in order to handle the received message as fast as possible) call a callback with the text message as argument to handle the message 

## SyncHandler.java and SyncHandler.cpp

The SyncHandler classes were designed in order to be extremely easy to use and extend. They work in the following way:

1. There is a file with the given Message types that is possible to send and receive (in SyncHandler.java the file is Messages.java and in SyncHandler.cpp the file is Messages.hpp)
2. If a class wishes to be notified when a given type of message was received, it can register a function to be called each time the message of the given type is received (the arguments to this function are an object of one of the Message types). This process is done through the **subscribe** functions.
3. If a function whishes to send a Message object (an object of one of the types defined in the Messages file) it can do so by calling the **send** functions.

So basically **the SyncHandler classes allow to send and receive asynchronously instantiated classes**. The SyncHandler classes also provide the necessary wiring between the  Listener.java, ClientHandler.java and Client.cpp classes. This classes are the core of plugins.

## GUI and actions/commands

Only at this level of the layered cake is plugin specific code implemented. 
This makes the SyncHandler.java and the SyncHandler.cpp classes extremely portable.

# Extending the functionality of the plugins
Given the architecture of the SyncHandlers to provide new messages to be sent and received it is only necessary to add new classes to the Messages.java and Messages.cpp files. Your new functionality can now use them freely and you can be sure the classes will be well serialized and deserialized.

# Creating similar plugins for other tools

For other debuggers that allow you to write plugins in C++, you can use the SyncHandler class as a starting point since it does not depend on any plugin specific code.
For other disassemblers that allow you to write olugins in Java, likewise the SyncHandler.java is a good starting point.

Furthermore since SncHandler classes can send and receive classes you can even use them in other plugins/programs that are not debuggers or disassemblers.
