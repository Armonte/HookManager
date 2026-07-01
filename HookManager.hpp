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
//    #5  x86 calling-convention selector for full-function inline detours.
//        ManagedHook now carries a `CallConv` (Cdecl default / Stdcall / Thiscall /
//        Fastcall): the Execute thunk is emitted with the matching attribute and the
//        original is invoked via SafetyHook's unsafe_{call,stdcall,thiscall,fastcall}.
//        This lets COM/vtable methods (D3D9 Present/Reset/EndScene/DrawPrimitive) and
//        non-__cdecl game functions be first-class inline hooks with the full pre/post
//        + return-value chain, not just convention-free mid-hooks.
//          AddHook<&addr, T, Args...>()        -> __cdecl   (unchanged; backward compatible)
//          AddHookCC<&addr, CC, T, Args...>()  -> CC-selected
//        Only the CC-matched Execute thunk is instantiated (member templates + `if
//        constexpr`), so a __thiscall/__fastcall thunk is never emitted for a hook whose
//        argument list can't carry the register args.
//    #6  ManagedDriverHook — a driver/owned inline hook: the detour OWNS the trampoline and drives
//        the original 0..N times (SetDriver() registers the detour body; callOriginal() runs the
//        original once, called as many times as the owner wants). This is the rollback-re-sim /
//        runahead / fast-forward pattern — distinct from ManagedHook (observer pre/post, original
//        once). Tracked in its own DriverHooks vector (AddDriverHook/GetDriverHook), so the
//        netcode-critical frame hook is HookEngine-managed with no raw exception. Reuses #5's
//        attributed thunks. A per-driven-frame observer chain can layer on later unchanged.
//
//  Verified: builds under i686-w64-mingw32-g++ (GCC 13) -std=c++23, runs as PE32 x86.
// ============================================================================

#include "safetyhook.hpp"

#include <cstdint>
#include <memory>
#include <vector>
#include <stdexcept>
#include <algorithm>

// [PC-fork #5] Calling convention of the hooked function's ABI (x86).
enum class CallConv { Cdecl, Stdcall, Thiscall, Fastcall };

template <uintptr_t* HookAddr, CallConv CC, typename T, typename... Args>
class ManagedHook;

// [PC-fork #6] Driver hook -- the detour OWNS the trampoline and drives the original 0..N times.
template <uintptr_t* HookAddr, CallConv CC, typename T, typename... Args>
class ManagedDriverHook;

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

    std::vector<std::shared_ptr<void>> Hooks{};       // each element is a ManagedHook*
    std::vector<std::shared_ptr<void>> MidHooks{};    // each element is a ManagedMidHook*
    std::vector<std::shared_ptr<void>> DriverHooks{}; // [PC-fork #6] each element is a ManagedDriverHook*
    static uintptr_t Temp; // used exclusively for getting hook as templates

public:
    static void StaticInitialize();
    static void StaticFinalize();

    static HookManager* GetInstance();

    // __cdecl inline hook (backward compatible: existing AddHook<&addr, T, Args...>()).
    template <uintptr_t* HookAddr, typename T, typename... Args>
    ManagedHook<HookAddr, CallConv::Cdecl, T, Args...>* AddHook()
    {
        if (void* ExistingHook = GetHook(*HookAddr))
            return static_cast<ManagedHook<HookAddr, CallConv::Cdecl, T, Args...>*>(ExistingHook);

        auto Hook = new ManagedHook<HookAddr, CallConv::Cdecl, T, Args...>;
        Hooks.push_back(std::shared_ptr<void>(Hook));
        return Hook;
    }

    // [PC-fork #5] Convention-selected inline hook (COM/vtable + non-__cdecl functions).
    template <uintptr_t* HookAddr, CallConv CC, typename T, typename... Args>
    ManagedHook<HookAddr, CC, T, Args...>* AddHookCC()
    {
        if (void* ExistingHook = GetHook(*HookAddr))
            return static_cast<ManagedHook<HookAddr, CC, T, Args...>*>(ExistingHook);

        auto Hook = new ManagedHook<HookAddr, CC, T, Args...>;
        Hooks.push_back(std::shared_ptr<void>(Hook));
        return Hook;
    }

    // [PC-fork #6] Driver hook: detour OWNS the trampoline, drives the original 0..N times.
    template <uintptr_t* HookAddr, CallConv CC, typename T, typename... Args>
    ManagedDriverHook<HookAddr, CC, T, Args...>* AddDriverHook()
    {
        if (void* Existing = GetDriverHook(*HookAddr))
            return static_cast<ManagedDriverHook<HookAddr, CC, T, Args...>*>(Existing);

        auto Hook = new ManagedDriverHook<HookAddr, CC, T, Args...>;
        DriverHooks.push_back(std::shared_ptr<void>(Hook));
        return Hook;
    }

    void* GetHook(const uintptr_t HookAddr) const;

    template <uintptr_t* HookAddr>
    ManagedMidHook<HookAddr>* AddMidHook();

    void* GetMidHook(const uintptr_t HookAddr) const;
    void* GetDriverHook(const uintptr_t HookAddr) const;
};

template <uintptr_t* HookAddr>
ManagedMidHook<HookAddr>* HookManager::AddMidHook()
{
    if (void* MidHook = GetMidHook(*HookAddr)) return static_cast<ManagedMidHook<HookAddr>*>(MidHook);

    auto Hook = new ManagedMidHook<HookAddr>;
    MidHooks.push_back(std::shared_ptr<void>(Hook));
    return Hook;
}

// ---------------------------------------------------------------------------
//  ManagedHook — non-void return
// ---------------------------------------------------------------------------
template <uintptr_t* HookAddr, CallConv CC, typename T, typename... Args>
class ManagedHook
{
private:
    friend class HookManager;

    uintptr_t Addr{};   // MUST remain the first member — GetHook() reads it via a reinterpret.
    SafetyHookInline Hook;
    std::vector<bool(*)(T&, Args...)> PreCallbacks;
    std::vector<bool(*)(T&, Args...)> PostCallbacks;

    uintptr_t GetAddr() const { return Addr; }

    // Convention-agnostic body: pre-chain -> original (via the CC-matched trampoline) -> post-chain.
    static T ExecuteImpl(Args... InArgs)
    {
        auto Self = static_cast<ManagedHook*>(HookManager::GetInstance()->GetHook(*HookAddr));
        if (Self == nullptr) throw std::runtime_error("Hook not found! This should never happen.");

        T ReturnValue = T();
        bool bSkipOriginal = false;
        for (auto& PreCallback : Self->PreCallbacks)
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
            // [PC-fork #5] call the original with its real ABI so the stack stays balanced.
            if constexpr (CC == CallConv::Stdcall)
                ReturnValue = Self->Hook.template unsafe_stdcall<T>(InArgs...);
            else if constexpr (CC == CallConv::Thiscall)
                ReturnValue = Self->Hook.template unsafe_thiscall<T>(InArgs...);
            else if constexpr (CC == CallConv::Fastcall)
                ReturnValue = Self->Hook.template unsafe_fastcall<T>(InArgs...);
            else
                ReturnValue = Self->Hook.template unsafe_call<T>(InArgs...);
        }
        for (auto& PostCallback : Self->PostCallbacks)
        {
            // [PC-fork #4] post-callbacks see the REAL current return value.
            T Candidate = ReturnValue;
            if (PostCallback(Candidate, InArgs...))
            {
                ReturnValue = Candidate;
            }
        }
        return ReturnValue;
    }

    // [PC-fork #5] One attributed entry thunk per convention. Member templates so only the
    // CC-matched thunk is ODR-used/instantiated (a __thiscall/__fastcall thunk is never
    // emitted for an argument list that can't carry its register args).
    template <bool = true> static T __cdecl             Execute_cdecl(Args... a)    { return ExecuteImpl(a...); }
    template <bool = true> static T SAFETYHOOK_STDCALL  Execute_stdcall(Args... a)  { return ExecuteImpl(a...); }
    template <bool = true> static T SAFETYHOOK_THISCALL Execute_thiscall(Args... a) { return ExecuteImpl(a...); }
    template <bool = true> static T SAFETYHOOK_FASTCALL Execute_fastcall(Args... a) { return ExecuteImpl(a...); }

    static void* EntryThunk()
    {
        if constexpr (CC == CallConv::Stdcall)       return reinterpret_cast<void*>(&Execute_stdcall<>);
        else if constexpr (CC == CallConv::Thiscall) return reinterpret_cast<void*>(&Execute_thiscall<>);
        else if constexpr (CC == CallConv::Fastcall) return reinterpret_cast<void*>(&Execute_fastcall<>);
        else                                         return reinterpret_cast<void*>(&Execute_cdecl<>);
    }

    ManagedHook()
    {
        Addr = *HookAddr;
        Hook = safetyhook::create_inline(reinterpret_cast<void*>(*HookAddr), EntryThunk());
    }

public:
    void AddPreCallback(bool (*Callback)(T&, Args...))  { PreCallbacks.push_back(Callback); }
    void RemovePreCallback(bool (*Callback)(T&, Args...))  { std::erase(PreCallbacks, Callback); }
    void AddPostCallback(bool (*Callback)(T&, Args...)) { PostCallbacks.push_back(Callback); }
    void RemovePostCallback(bool (*Callback)(T&, Args...)) { std::erase(PostCallbacks, Callback); }
};

// ---------------------------------------------------------------------------
//  ManagedHook — void return
// ---------------------------------------------------------------------------
template <uintptr_t* HookAddr, CallConv CC, typename... Args>
class ManagedHook<HookAddr, CC, void, Args...>
{
private:
    friend class HookManager;

    uintptr_t Addr{};
    SafetyHookInline Hook;
    std::vector<bool(*)(Args...)> PreCallbacks;
    std::vector<bool(*)(Args...)> PostCallbacks;

    uintptr_t GetAddr() const { return Addr; }

    static void ExecuteImpl(Args... InArgs)
    {
        auto Self = static_cast<ManagedHook*>(HookManager::GetInstance()->GetHook(*HookAddr));
        if (Self == nullptr) throw std::runtime_error("Hook not found! This should never happen.");

        bool bSkipOriginal = false;
        for (auto& PreCallback : Self->PreCallbacks)
        {
            if (PreCallback(InArgs...)) bSkipOriginal = true;
        }
        if (!bSkipOriginal)
        {
            if constexpr (CC == CallConv::Stdcall)       Self->Hook.unsafe_stdcall(InArgs...);
            else if constexpr (CC == CallConv::Thiscall) Self->Hook.unsafe_thiscall(InArgs...);
            else if constexpr (CC == CallConv::Fastcall) Self->Hook.unsafe_fastcall(InArgs...);
            else                                         Self->Hook.unsafe_call(InArgs...);
        }
        for (auto& PostCallback : Self->PostCallbacks)
        {
            PostCallback(InArgs...);
        }
    }

    template <bool = true> static void __cdecl             Execute_cdecl(Args... a)    { ExecuteImpl(a...); }
    template <bool = true> static void SAFETYHOOK_STDCALL  Execute_stdcall(Args... a)  { ExecuteImpl(a...); }
    template <bool = true> static void SAFETYHOOK_THISCALL Execute_thiscall(Args... a) { ExecuteImpl(a...); }
    template <bool = true> static void SAFETYHOOK_FASTCALL Execute_fastcall(Args... a) { ExecuteImpl(a...); }

    static void* EntryThunk()
    {
        if constexpr (CC == CallConv::Stdcall)       return reinterpret_cast<void*>(&Execute_stdcall<>);
        else if constexpr (CC == CallConv::Thiscall) return reinterpret_cast<void*>(&Execute_thiscall<>);
        else if constexpr (CC == CallConv::Fastcall) return reinterpret_cast<void*>(&Execute_fastcall<>);
        else                                         return reinterpret_cast<void*>(&Execute_cdecl<>);
    }

    ManagedHook()
    {
        Addr = *HookAddr;
        Hook = safetyhook::create_inline(reinterpret_cast<void*>(*HookAddr), EntryThunk());
    }

public:
    void AddPreCallback(bool (*Callback)(Args...))  { PreCallbacks.push_back(Callback); }
    void RemovePreCallback(bool (*Callback)(Args...))  { std::erase(PreCallbacks, Callback); }
    void AddPostCallback(bool (*Callback)(Args...)) { PostCallbacks.push_back(Callback); }
    void RemovePostCallback(bool (*Callback)(Args...)) { std::erase(PostCallbacks, Callback); }
};

// ---------------------------------------------------------------------------
//  ManagedDriverHook — [PC-fork #6]
//  The detour OWNS the trampoline and drives the original 0..N times. The owner registers ONE driver
//  callback (the detour body) via SetDriver(); inside it, the owner calls callOriginal(args...) as many
//  times as it wants (rollback re-sim / runahead / fast-forward / skip). Distinct from ManagedHook
//  (observer pre/post chain, original once). HookEngine-tracked like every other hook, so there is no raw
//  exception on the netcode-critical frame hook. (A per-driven-frame OBSERVER chain can be layered on
//  later without changing this primitive; the driver itself is singular by nature.)
// ---------------------------------------------------------------------------
template <uintptr_t* HookAddr, CallConv CC, typename T, typename... Args>
class ManagedDriverHook
{
private:
    friend class HookManager;

    uintptr_t Addr{};   // MUST stay first member — GetDriverHook reads it via a reinterpret.
    SafetyHookInline Hook;
    T (*Driver)(Args...) = nullptr;

    uintptr_t GetAddr() const { return Addr; }

    static T ExecuteImpl(Args... InArgs)
    {
        auto Self = static_cast<ManagedDriverHook*>(HookManager::GetInstance()->GetDriverHook(*HookAddr));
        if (Self == nullptr || Self->Driver == nullptr)
            throw std::runtime_error("DriverHook has no driver set! This should never happen.");
        return Self->Driver(InArgs...);
    }

    // [PC-fork #5] attributed entry thunks; only the CC-matched one is instantiated.
    template <bool = true> static T __cdecl             Execute_cdecl(Args... a)    { return ExecuteImpl(a...); }
    template <bool = true> static T SAFETYHOOK_STDCALL  Execute_stdcall(Args... a)  { return ExecuteImpl(a...); }
    template <bool = true> static T SAFETYHOOK_THISCALL Execute_thiscall(Args... a) { return ExecuteImpl(a...); }
    template <bool = true> static T SAFETYHOOK_FASTCALL Execute_fastcall(Args... a) { return ExecuteImpl(a...); }

    static void* EntryThunk()
    {
        if constexpr (CC == CallConv::Stdcall)       return reinterpret_cast<void*>(&Execute_stdcall<>);
        else if constexpr (CC == CallConv::Thiscall) return reinterpret_cast<void*>(&Execute_thiscall<>);
        else if constexpr (CC == CallConv::Fastcall) return reinterpret_cast<void*>(&Execute_fastcall<>);
        else                                         return reinterpret_cast<void*>(&Execute_cdecl<>);
    }

    ManagedDriverHook()
    {
        Addr = *HookAddr;
        Hook = safetyhook::create_inline(reinterpret_cast<void*>(*HookAddr), EntryThunk());
    }

public:
    // Register the single driver callback (the detour body). It calls callOriginal() as needed.
    void SetDriver(T (*fn)(Args...)) { Driver = fn; }

    // Run the original ONCE through the trampoline, with the target's ABI. The owner calls this 0..N
    // times from inside the driver callback (rollback re-sim / runahead / fast-forward / skip).
    T callOriginal(Args... InArgs)
    {
        if constexpr (CC == CallConv::Stdcall)       return Hook.template unsafe_stdcall<T>(InArgs...);
        else if constexpr (CC == CallConv::Thiscall) return Hook.template unsafe_thiscall<T>(InArgs...);
        else if constexpr (CC == CallConv::Fastcall) return Hook.template unsafe_fastcall<T>(InArgs...);
        else                                         return Hook.template unsafe_call<T>(InArgs...);
    }
};

// ---------------------------------------------------------------------------
//  ManagedMidHook (convention-free; unchanged)
// ---------------------------------------------------------------------------
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
