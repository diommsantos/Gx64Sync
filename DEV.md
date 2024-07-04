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
2. In Eclipse under `File`->`Open Prjects from File System...` select the `Gx64Sync\GSync` directory and import it.
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


# Software Architecture

# Extending the functionaliy of the plugins

# Creating similar plugins for other tools
