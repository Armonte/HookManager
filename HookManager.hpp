#pragma once

// ============================================================================
//  HookManager — PovertyCaster fork of WistfulHopes/HookManager
//  Upstream base: 05a02a95247eb5e75aa320fd353e43dd9d54697e
//  Layered hooks over SafetyHook (stacked pre/post callback chains per address).
//
//  Fork changes vs upstream (each tagged `[PC-fork #N]`; see deps/HookManager/UPSTREAM.md):
//    #1  GCC/MinGW conformance: dependent template member call needs `.template`.
//    #2  Mid-hook dispatcher looked up GetHook() (wrong vector) -> GetMidHook().
//    #3  ManagedMidHook::RemoveCallback did push_back instead of erase.
//    #4  Post-callbacks now receive the REAL current return value, not a zeroed T.
//    #5  (TODO, see UPSTREAM.md) calling-convention selector for x86 inline detours
//        (__thiscall/__stdcall/__fastcall). MidHooks are convention-free and cover
//        the majority of MBAACC hook sites in the meantime.
//
//  Verified: builds under i686-w64-mingw32-g++ (GCC 13) -std=c++23, runs as PE32 x86.
// ============================================================================

#include "safetyhook.hpp"

#include <cstdint>
#include <memory>
#include <vector>
#include <stdexcept>
#include <algorithm>

template <uintptr_t* HookAddr, typename T, typename... Args>
class ManagedHook;

template<uintptr_t* HookAddr>
class ManagedMidHook;

class HookManager
{
private:
    static HookManager* Instance;
    HookManager() = default;
    HookManager(const HookManager&) = delete;
    HookManager(HookManager&&) = delete;
    HookManager& operator=(const HookManager&) = delete;
    HookManager& operator=(HookManager&&) = delete;

    ~HookManager() = default;

    std::vector<std::shared_ptr<void>> Hooks{};    // each element is a ManagedHook*
    std::vector<std::shared_ptr<void>> MidHooks{}; // each element is a ManagedMidHook*
    static uintptr_t Temp; // used exclusively for getting hook as templates

public:
    static void StaticInitialize();
    static void StaticFinalize();

    static HookManager* GetInstance();

    template <uintptr_t* HookAddr, typename T, typename... Args>
    ManagedHook<HookAddr, T, Args...>* AddHook()
    {
        if (void* ExistingHook = GetHook(*HookAddr))
            return static_cast<ManagedHook<HookAddr, T, Args...>*>(ExistingHook);

        auto Hook = new ManagedHook<HookAddr, T, Args...>;
        Hooks.push_back(std::shared_ptr<void>(Hook));
        return Hook;
    }

    void* GetHook(const uintptr_t HookAddr) const;

    template <uintptr_t* HookAddr>
    ManagedMidHook<HookAddr>* AddMidHook();

    void* GetMidHook(const uintptr_t HookAddr) const;
};

template <uintptr_t* HookAddr>
ManagedMidHook<HookAddr>* HookManager::AddMidHook()
{
    if (void* MidHook = GetMidHook(*HookAddr)) return static_cast<ManagedMidHook<HookAddr>*>(MidHook);

    auto Hook = new ManagedMidHook<HookAddr>;
    MidHooks.push_back(std::shared_ptr<void>(Hook));
    return Hook;
}

template <uintptr_t* HookAddr, typename T, typename... Args>
class ManagedHook
{
private:
    friend class HookManager;

    uintptr_t Addr{};
    SafetyHookInline Hook;
    std::vector<bool(*)(T&, Args...)> PreCallbacks;
    std::vector<bool(*)(T&, Args...)> PostCallbacks;

    uintptr_t GetAddr() const { return Addr; }

    ManagedHook()
    {
        Addr = *HookAddr;
        Hook = safetyhook::create_inline(reinterpret_cast<void*>(*HookAddr), reinterpret_cast<uintptr_t>(&Execute));
    }

public:
    void AddPreCallback(bool (*Callback)(T&, Args...))  { PreCallbacks.push_back(Callback); }
    void RemovePreCallback(bool (*Callback)(T&, Args...))  { std::erase(PreCallbacks, Callback); }
    void AddPostCallback(bool (*Callback)(T&, Args...)) { PostCallbacks.push_back(Callback); }
    void RemovePostCallback(bool (*Callback)(T&, Args...)) { std::erase(PostCallbacks, Callback); }

    static T Execute(Args... InArgs)
    {
        T ReturnValue = T();

        auto Hook = static_cast<ManagedHook*>(HookManager::GetInstance()->GetHook(*HookAddr));
        if (Hook == nullptr) throw std::runtime_error("Hook not found! This should never happen.");

        bool bSkipOriginal = false;
        for (auto& PreCallback : Hook->PreCallbacks)
        {
            T Temp = T();
            if (PreCallback(Temp, InArgs...))
            {
                bSkipOriginal = true;
                ReturnValue = Temp;
            }
        }
        if (!bSkipOriginal)
        {
            // [PC-fork #1] dependent template member call: GCC/Clang require `.template`.
            ReturnValue = Hook->Hook.template unsafe_call<T>(InArgs...);
        }
        for (auto& PostCallback : Hook->PostCallbacks)
        {
            // [PC-fork #4] post-callbacks see the REAL current return value (upstream
            // handed them a fresh zero-initialized T, hiding the original/prior result).
            T Candidate = ReturnValue;
            if (PostCallback(Candidate, InArgs...))
            {
                ReturnValue = Candidate;
            }
        }
        return ReturnValue;
    }
};

template <uintptr_t* HookAddr, typename... Args>
class ManagedHook<HookAddr, void, Args...>
{
private:
    friend class HookManager;

    uintptr_t Addr{};
    SafetyHookInline Hook;
    std::vector<bool(*)(Args...)> PreCallbacks;
    std::vector<bool(*)(Args...)> PostCallbacks;

    uintptr_t GetAddr() const { return Addr; }

    ManagedHook()
    {
        Addr = *HookAddr;
        Hook = safetyhook::create_inline(reinterpret_cast<void*>(*HookAddr), reinterpret_cast<uintptr_t>(&Execute));
    }

public:
    void AddPreCallback(bool (*Callback)(Args...))  { PreCallbacks.push_back(Callback); }
    void RemovePreCallback(bool (*Callback)(Args...))  { std::erase(PreCallbacks, Callback); }
    void AddPostCallback(bool (*Callback)(Args...)) { PostCallbacks.push_back(Callback); }
    void RemovePostCallback(bool (*Callback)(Args...)) { std::erase(PostCallbacks, Callback); }

    static void Execute(Args... InArgs)
    {
        auto Hook = static_cast<ManagedHook*>(HookManager::GetInstance()->GetHook(*HookAddr));
        if (Hook == nullptr) throw std::runtime_error("Hook not found! This should never happen.");

        bool bSkipOriginal = false;
        for (auto& PreCallback : Hook->PreCallbacks)
        {
            if (PreCallback(InArgs...)) bSkipOriginal = true;
        }
        if (!bSkipOriginal)
        {
            Hook->Hook.unsafe_call(InArgs...);
        }
        for (auto& PostCallback : Hook->PostCallbacks)
        {
            PostCallback(InArgs...);
        }
    }
};

template <uintptr_t* HookAddr>
class ManagedMidHook
{
private:
    friend class HookManager;

    uintptr_t Addr{};
    SafetyHookMid Hook;
    std::vector<void(*)(SafetyHookContext&)> Callbacks;

    uintptr_t GetAddr() const { return Addr; }

    ManagedMidHook()
    {
        Addr = *HookAddr;
        Hook = safetyhook::create_mid(reinterpret_cast<void*>(*HookAddr), [](SafetyHookContext& ctx)
        {
            // [PC-fork #2] mid dispatcher must look up the MidHooks vector, not Hooks.
            auto Hook = static_cast<ManagedMidHook*>(HookManager::GetInstance()->GetMidHook(*HookAddr));
            if (Hook == nullptr) throw std::runtime_error("MidHook not found! This should never happen.");

            for (auto& Callback : Hook->Callbacks)
            {
                Callback(ctx);
            }
        });
    }

public:
    void AddCallback(void(*Callback)(SafetyHookContext&))    { Callbacks.push_back(Callback); }
    // [PC-fork #3] was push_back (a no-op duplicate); must erase.
    void RemoveCallback(void(*Callback)(SafetyHookContext&)) { std::erase(Callbacks, Callback); }
};
