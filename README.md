# Gx64Sync

**Gx64Sync** stands for Ghidra-x64Dbg SYNChronization. It is a set
of plugins that help synchronize a debugging x64Dbg session with Ghidra.
The underlying idea is simple: take the best from both worlds (static and
dynamic analysis).

Debuggers and dynamic analysis provide us with:

* local view, with live dynamic context (registers, memory, *etc.*)
* built-in specialized features/API

Disassemblers and static analysis provide us with:

* macro view over modules
* code analysis, signatures, types, *etc.*
* fancy graph view
* decompilation
* persistent storage of knowledge within IDBs/GPRs

**Gx64Sync** is a fork of [ret-sync](https://github.com/bootleg/ret-sync), 
but is totally rewritten from scratch. See [Features](#features) for more
details.


-------------------------------------------------------------------------------
# Table of contents
- [Features](#Features)
- [Usage](#usage)
- [Installation](#installation)
  - [Ghidra plugin](#ghidra-plugin)
  - [x64Dbg plugin](#x64dbg-plugin)
- [TODO](#todo)
- [Known Bugs/Limitations](#known-bugslimitations)
- [Acknowledgments](#Acknowledgments)
-------------------------------------------------------------------------------

# Features
* Fast and fully async
* Allows for synchronization of adresses in both ways (sync addresses from Ghidra to x64Dbg and from x64Dbg to Ghidra)
* Easily extensible, see DEV.md
    
# Usage

![Gx64Sync Demo ](/docs/Gx64SyncDemo.gif)

# Installation

In order for Gx64Sync to function correctly, is necessary to install both the Ghidra plugin and the x64Dbg plugin. 

## Ghidra plugin

### Build the Ghidra extension

Either use the pre-built version from the `ext_ghidra/dist` folder or follow the instruction to build it.
Each extension build only supports the version of Ghidra specified in the plugin's file name.
E.g. `ghidra_9.1_PUBLIC_20191104_retsync.zip` is for Ghidra 9.1 Public.

1. Install Ghidra
2. Install gradle

```bash
apt install gradle
```

3. Build extension for your Ghidra installation (replace `$GHIDRA_DIR` with your installation directory)

```bash
cd ext_ghidra
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_DIR
```

### Install the Ghidra extension

1. From Ghidra projects manager: ``File`` -> ``Install Extensions...``, click on the
   `+` sign and select the `ext_ghidra/dist/ghidra_*_retsync.zip` and click OK.
   This will effectively extract the `retsync` folder from the zip into
   `$GHIDRA_DIR/Extensions/Ghidra/`
2. Restart Ghidra as requested
3. After reloading Ghidra, open a module in CodeBrowser. It should tell you a
   new extension plugin has been detected. Select "yes" to configure it. Then
   tick "RetSyncPlugin" and click OK. The console should show something like:

```
[*] retsync init
[>] programOpened: tm.sys
    imageBase: 0x1c0000000
```

4. From Ghidra CodeBrowser tool: use toolbar icons or shortcuts to enable (``Alt+s``)/disable (``Alt+Shift+s``)/restart (``Alt+r``)
   synchronization.

A status window is also available from ``Windows`` -> ``RetSyncPlugin``. You
generally want to drop it on the side to integrate it with the Ghidra
environment windows.


## x64Dbg Plugin

Based on testplugin,  https://github.com/x64dbg/testplugin. x64dbg support is experimental, however:

1. Build the plugin using the VS solution (optional, see pre-built binaries).
   May you need a different version of the plugin sdk,
   a copy can be found in each release of x64dbg.
   Paste the "``pluginsdk``" directory into "``ext_x64dbg\x64dbg_sync``"
2. Copy the dll (extension is ``.d32`` or ``.dp64``) within x64dbg's plugin directory.


# TODO
- [ ] Improve README.md and DEV.md
- [ ] Get a cooler name than Gx64Sync ;)
- [ ] make a GUI for GSync similar to ret-sync
- [ ] fix x64Dbg closing crash
- [ ] Implement all the features of [ret-sync](https://github.com/bootleg/ret-sync) (comment migration, debugger commands in Ghidra...)
- [ ] Improve logging in GSync and x64Sync
- [ ] Implement HyperSync (fully automatic syncing, that is once an address is highlited,
both in Ghidra or x64Sync, it is synced in the other tool + automatic loading and change of modules in both tools)
- [ ] Automatic C++ virtual methods shenanigans?

Have suggestions? Open an issue or contact me at diommsantos@gmail.com!

# Known Bugs/Limitations

- x64Dbg sometimes crashes when closing
- **THERE IS NO AUTHENTICATION/ENCRYPTION** whatsoever between the parties; you're on your own.

Conflict(s):

- Logitech Updater software is known to use the same default port (9100).

# Acknowledgments
Gx64Sync is powered by and would not be possible without the amazing open sourse projects:
- [ret-sync](https://github.com/bootleg/ret-sync) (provided huge inspiration and innumerous code examples for this project)  
- [asio](https://think-async.com/Asio/asio-1.30.2/doc/) 
- [glaze](https://github.com/stephenberry/glaze)
- [jackson-jr](https://github.com/FasterXML/jackson-jr)


