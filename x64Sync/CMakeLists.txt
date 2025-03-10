cmake_minimum_required(VERSION 3.20)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(x64Sync)

add_library(x64Sync 
    SHARED
        ConfigManager.cpp
        Client.cpp
        SyncHandler.cpp
        pluginmain.cpp
        plugin.cpp
        md5.cpp
        LocationSync.cpp
        CommentSync.cpp
        DebuggerSync.cpp
        HyperSync.cpp)
        
target_link_directories(x64Sync PRIVATE ".")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(x64Sync PROPERTIES SUFFIX ".dp64")
else()
    set_target_properties(x64Sync PROPERTIES SUFFIX ".dp32")
endif()

# Support PluginDevHelper (https://github.com/x64dbg/PluginDevHelper)
add_custom_command(TARGET x64Sync PRE_LINK COMMAND if exist "\"${CMAKE_SOURCE_DIR}/PluginDevBuildTool.exe\"" ("\"${CMAKE_SOURCE_DIR}/PluginDevBuildTool.exe\"" unload "\"$(TargetPath)\"") else (echo Copy PluginDevBuildTool.exe next to "${CMAKE_SOURCE_DIR}/"))
add_custom_command(TARGET x64Sync POST_BUILD COMMAND if exist "\"${CMAKE_SOURCE_DIR}/PluginDevBuildTool.exe\"" ("\"${CMAKE_SOURCE_DIR}/PluginDevBuildTool.exe\"" reload "\"$(TargetPath)\""))