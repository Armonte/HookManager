// HookManager.cpp — PovertyCaster fork of WistfulHopes/HookManager.
// The non-template methods below are unchanged from upstream (both GetHook and
// GetMidHook were already correct here); the dispatcher bug was in the header.
#include "HookManager.hpp"

HookManager* HookManager::Instance = nullptr;
uintptr_t HookManager::Temp = 0;

void HookManager::StaticInitialize()
{
    Instance = new HookManager();
}

void HookManager::StaticFinalize()
{
    delete Instance;
    Instance = nullptr;
}

HookManager* HookManager::GetInstance()
{
    if (!Instance) StaticInitialize();
    return Instance;
}

void* HookManager::GetHook(const uintptr_t HookAddr) const
{
    for (auto& Hook : Hooks)
    {
        // No size/layout difference between ManagedHook templates (Addr is first member),
        // so reinterpret as the void specialization purely to read GetAddr().
        if (static_cast<ManagedHook<&Temp, void>*>(Hook.get())->GetAddr() == HookAddr)
        {
            return Hook.get();
        }
    }
    return nullptr;
}

void* HookManager::GetMidHook(const uintptr_t HookAddr) const
{
    for (auto& MidHook : MidHooks)
    {
        if (static_cast<ManagedMidHook<&Temp>*>(MidHook.get())->GetAddr() == HookAddr)
        {
            return MidHook.get();
        }
    }
    return nullptr;
}
