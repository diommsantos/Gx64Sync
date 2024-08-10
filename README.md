# Gx64Sync

**Gx64Sync** stands for Ghidra-x64Dbg SYNChronization (you can sugest and vote on a new name at [Suggestion for a name](https://github.com/diommsantos/Gx64Sync/issues/3)). It is a set
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
  - [Configuration](#configuration)
- [Installation](#installation)
  - [Ghidra plugin](#ghidra-plugin)
  - [x64Dbg plugin](#x64dbg-plugin)
- [TODO](#todo)
- [Known Bugs/Limitations](#known-bugslimitations)
- [Acknowledgments](#Acknowledgments)
-------------------------------------------------------------------------------

# Features
* Synchronization of addresses in both ways (sync addresses from Ghidra to x64Dbg and from x64Dbg to Ghidra)
* Comment migration both ways
* Debugger commands from ghidra
* Fast and fully asynchronous
* Easily extensible, see [DEV.md](/DEV.md)
* and much more...
    
# Usage

![Gx64Sync Usage](/docs/Gx64Sync_usage.gif)

## Configuration
To configure the IP and ports that GSync and x64Sync use, create a file with the name `config.sync` in your home directory (if you are not sure where to create this file both GSync and x64Sync log the absolute path they are expecting if they don't find this file). This should be a standard json file with any of the properties (propertie omissions are allowed) from the below example inside. Other properties will simply be ignored by GSync and x64Sync.
Example of `config.sync` contents:
```
{
"GSYNC_HOST" = "127.0.0.1",
"GSYNC_PORT" = 9100,
"X64SYNC_HOST" = "127.0.1",
"X64SYNC_PORT" = 9100
}
```

# Installation

In order for Gx64Sync to function correctly, is necessary to install both the Ghidra plugin and the x64Dbg plugin. 

## Ghidra plugin

The Ghidra plugin is tied to the Ghidra version it is being installed on. Currently is necessary to build it;
built plugins will be provided in the future for the latest Ghidra versions. 

### Build the Ghidra extension

1. Install [gradle](https://docs.gradle.org/current/userguide/installation.html#ex-installing-manually)
2. Navigate to the `Gx64Sync\GSync` folder

```bash
cd Gx64Sync\GSync
```
 
3. Build the plugin for your Ghidra installation (replace `$GHIDRA_DIR` with your installation directory).
For example, if you have the following Ghidra installation path `C:\ghidra_11.0.3_PUBLIC` you would run 
``gradle -PGHIDRA_INSTALL_DIR=C:\ghidra_11.0.3_PUBLIC``. 

```bash
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_DIR
```

### Install the Ghidra plguin

1. From Ghidra projects manager: ``File`` -> ``Install Extensions...``, click on the
   `+` sign and select the `Gx64Sync\GSync\dist\ghidra_*_GSync.zip` and click OK.
2. Restart Ghidra as requested
3. After reloading Ghidra, open a module in CodeBrowser. It should tell you a
   new extension plugin has been detected. Select "yes" to configure it. Then
   tick "GSyncPlugin" and click OK. The console should show something like:

```
[*] Gsync init
Server constructor Called!
```

You can check the install path by selecting ``GSync`` under ``File`` -> ``Install Extensions...``, 
and verifying the ``Install Path:`` property.  

### Troubleshooting
To verify the Ghidra plugin is correctly installed, you can open CodeBrowser and select
``File`` -> ``Configure`` -> ``Examples (Configure) `` and check that the `GSyncPlugin` option
exists and is selected. If that is the case ``Window``->``GSyncPlugin`` menu option should exist. 


## x64Dbg Plugin
This plugin has a 32-bit and 64-bit version.
### 64-bit version
1. Copy `Gx64Sync\x64Sync\x64\Release\x64Sync.dp64` to the plugins folder of the 64-bit version of x64Dbg (usually under `x64Dbg\release\x64\plugins`).
### 32-bit version
1. Copy `Gx64Sync\x64Sync\Release\x64Sync.dp32` to the plugins folder of the 32-bit version of x64Dbg (usually under `x64Dbg\release\x32\plugins`).

### Troubleshooting
The plugin should work right out of the box. If it was installed correctly something similar to 
```
[pluginload] x64Sync
[x64Sync] pluginInit(pluginHandle: 2)
[PLUGIN, x64Sync] Command "x64SyncConnect" registered!
[PLUGIN, x64Sync] Command "x64SyncStop" registered!
[PLUGIN, x64Sync] Command "StartLocationSync" registered!
[PLUGIN, x64Sync] Command "StopLocationSync" registered!
[PLUGIN, x64Sync] Command "SyncLocation" registered!
[PLUGIN, x64Sync] Command "SyncBase" registered!
[PLUGIN, x64Sync] Command "Funciona" registered!
[PLUGIN] x64Sync v1 Loaded!
[x64Sync] pluginSetup(pluginHandle: 2)
```
should appear in the log tab of x64Dbg.

# TODO
- [ ] Change the implementation of LocationSync and HyperSync so that they exhange files hashes instead of file paths (see [Remote sync changes in Java code](https://github.com/diommsantos/Gx64Sync/issues/7) as to why)
- [x] Support Comment migration (CommentSync)
- [x] make a GUI for GSync similar to ret-sync
- [x] Implement all the features of [ret-sync](https://github.com/bootleg/ret-sync) (debugger commands in Ghidra...) 
- [ ] Add pre-built GSync plugins for the latest Ghidra versions
- [ ] Improve README.md and DEV.md
- [ ] Get a cooler name than Gx64Sync ;)
- [x] fix x64Dbg closing crash
- [x] Improve logging in GSync and x64Sync
- [x] Implement HyperSync (fully automatic syncing, that is once an address is highlited,
both in Ghidra or x64Sync, it is synced in the other tool)
- [ ] Automatic C++ virtual methods shenanigans?

Have suggestions? Open an issue or contact me at diommsantos@gmail.com!

# Known Bugs/Limitations

- **THERE IS NO AUTHENTICATION/ENCRYPTION** whatsoever between the parties; you're on your own.

Conflict(s):

- Logitech Updater software is known to use the same default port (9100).

# Acknowledgments
Gx64Sync is powered by and would not be possible without the amazing open source projects:
- [ret-sync](https://github.com/bootleg/ret-sync) (provided huge inspiration and innumerous code examples for this project)  
- [asio](https://think-async.com/Asio/asio-1.30.2/doc/) 
- [glaze](https://github.com/stephenberry/glaze)
- [jackson-jr](https://github.com/FasterXML/jackson-jr)


