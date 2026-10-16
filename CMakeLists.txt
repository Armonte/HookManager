# HookManager — layered hooks over SafetyHook (PovertyCaster fork of WistfulHopes/HookManager).
#
# Consume it as a subdirectory / submodule:
#     add_subdirectory(deps/HookManager)
#     target_link_libraries(mytarget PRIVATE HookManager::HookManager)
#
# SafetyHook: HookManager links the first of these that exists --
#   1. HOOKMANAGER_SAFETYHOOK_TARGET (an existing target name, e.g. PovertyCaster's pc_safetyhook amalgam),
#   2. a target named `safetyhook` (upstream SafetyHook already added by the parent project),
#   3. upstream cursey/safetyhook fetched at HOOKMANAGER_SAFETYHOOK_TAG (HOOKMANAGER_FETCH_SAFETYHOOK=ON, the default).
# The pinned tag is the baseline PovertyCaster and ccrollback build against; change it in one place.
cmake_minimum_required(VERSION 3.21)
project(HookManager LANGUAGES C CXX)

set(HOOKMANAGER_SAFETYHOOK_TARGET "" CACHE STRING "An existing SafetyHook target to link instead of fetching one")
option(HOOKMANAGER_FETCH_SAFETYHOOK "Fetch upstream cursey/safetyhook when no SafetyHook target exists" ON)
set(HOOKMANAGER_SAFETYHOOK_TAG "f44cc070a8340f2f26649553c49533475417304d" CACHE STRING "cursey/safetyhook commit to fetch")

add_library(HookManager STATIC HookManager.cpp)
add_library(HookManager::HookManager ALIAS HookManager)
target_include_directories(HookManager PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(HookManager PUBLIC cxx_std_20)   # std::source_location

if(HOOKMANAGER_SAFETYHOOK_TARGET)
    target_link_libraries(HookManager PUBLIC ${HOOKMANAGER_SAFETYHOOK_TARGET})
elseif(TARGET safetyhook)
    target_link_libraries(HookManager PUBLIC safetyhook)
elseif(HOOKMANAGER_FETCH_SAFETYHOOK)
    include(FetchContent)
    set(SAFETYHOOK_FETCH_ZYDIS ON CACHE BOOL "" FORCE)
    FetchContent_Declare(safetyhook
        GIT_REPOSITORY https://github.com/cursey/safetyhook.git
        GIT_TAG        ${HOOKMANAGER_SAFETYHOOK_TAG})
    FetchContent_MakeAvailable(safetyhook)
    target_link_libraries(HookManager PUBLIC safetyhook)
else()
    message(FATAL_ERROR "HookManager: no SafetyHook. Set HOOKMANAGER_SAFETYHOOK_TARGET, add a `safetyhook` target first, "
                        "or enable HOOKMANAGER_FETCH_SAFETYHOOK.")
endif()
