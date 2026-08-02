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
#include <source_location>
#include <thread>   // [PC-fork #7b] name the FAILING CALL SITE, not just the failing address


// ============================================================================
//  [PC-fork #7] INSTALL VERIFICATION — a non-null handle is NOT proof a hook installed.
//
//  safetyhook::create_inline / create_mid are the EASY API: they swallow every error and return an
//  EMPTY hook. AddHook*/AddMidHook then return the ManagedHook object regardless, so the universal
//  `if (h)` check at ~110 call sites across this repo is satisfied whether or not a single byte was
//  written at the target.
//
//  That is not theoretical. A 4-player run hung because ONE instance logged "boot-serialize hook
//  installed" and "Opening.avi-skip hook installed" and then neither callback ever ran: no lock
//  acquire, no release, no AVI skip, and the game state stayed pinned on the very word the skip
//  writes. One silent failure explained all three, and the process looked healthy in its own log for
//  the entire 115 seconds it took to wedge four peers.
//
//  A hook that silently no-ops does not fail loudly, it CHANGES BEHAVIOUR — a missing determinism
//  no-op, a missing input hijack, a missing frame gate. Each of those presents as a desync or a hang
//  with no hint that the hook was responsible.
//
//  Fix, in two halves:
//    * use the EXPECTED-returning API (InlineHook::create / MidHook::create) so the real error type is
//      available instead of a bare empty object, and
//    * publish failures through a sink the host installs once, so EVERY existing call site becomes
//      loud with no edit. Call sites may additionally query installed() when they want to branch.
//  The sink is deliberately a plain function pointer: this header is included at suspended-boot time
//  from DllMain, where anything with a dynamic initializer or an allocation is a hazard.
// ============================================================================
// [PC-fork #7b / task #110] The first live run of the sink above produced:
//     !! HOOK INSTALL FAILED addr=00000000 kind=mid err=FAILED_TO_DECODE_INSTRUCTION
// on all four peers — a mid-hook pointed at address ZERO, i.e. an address global that was never
// resolved. That report is true and useless: `addr` is the one field guaranteed to carry no
// information when the failure is precisely that the address is missing, and nothing else in the
// line distinguishes one of ~110 call sites from another.
//
// So carry the two things that DO identify it:
//   * `slot` — the address of the uintptr_t global the hook reads its target from. Every call site
//     names one as a template argument (AddMidHook<&SomeAddr>()), so this resolves to a symbol.
//   * the call site's file/line/function, via std::source_location defaulted at the FACTORY (not at
//     the constructor, which would only ever report a line inside this header).
struct HookInstallFailure {
    uintptr_t   addr;        // the target that was NOT hooked (0 == the address global was never set)
    const char* kind;        // "inline" | "mid" | "driver"
    unsigned    errorType;   // safetyhook Error::type (see HookInstallErrorName)
    const void* slot;        // &the uintptr_t holding `addr` — identifies WHICH hook, even when addr==0
    const char* file;        // call site
    unsigned    line;
    const char* func;
};

inline void (*&HookInstallFailureSink())(const HookInstallFailure&) {
    static void (*sink)(const HookInstallFailure&) = nullptr;
    return sink;
}

// Names match safetyhook's InlineHook::Error / MidHook::Error enumerators, in declaration order.
inline const char* HookInstallErrorName(unsigned t) {
    static const char* kNames[] = {
        "BAD_ALLOCATION", "FAILED_TO_DECODE_INSTRUCTION", "SHORT_JUMP_IN_TRAMPOLINE",
        "IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE", "UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE",
        "FAILED_TO_UNPROTECT", "NOT_ENOUGH_SPACE",
    };
    return t < (sizeof kNames / sizeof kNames[0]) ? kNames[t] : "UNKNOWN";
}

inline void ReportHookInstallFailure(uintptr_t addr, const char* kind, unsigned errorType,
                                     const void* slot = nullptr,
                                     const std::source_location& loc = std::source_location::current()) {
    if (auto sink = HookInstallFailureSink())
        sink(HookInstallFailure{ addr, kind, errorType, slot,
                                 loc.file_name(), loc.line(), loc.function_name() });
}

// Create an inline detour and REPORT failure instead of swallowing it. Returns an empty hook on
// failure exactly as create_inline did, so behaviour is unchanged for callers that ignore it.
// [PC-fork #164] RETRY A TRANSIENT ALLOCATION FAILURE.
//
// MEASURED 2026-08-01: this install fails intermittently under concurrency — ~2-4% at 24-way parallelism
// (3/72 and 2/96 across two stress sets, headless, tests/hook_smoke_inline). The error is
//     ERR=BAD_ALLOCATION
// i.e. safetyhook could not obtain memory for the TRAMPOLINE. Not a page-protection clash, not an
// undecodable instruction — both of those were ruled out by measurement (the target's prologue was an
// ordinary relocatable `sub esp,0x418; push ebx; push ebp`, and the entry bytes were provably untouched).
//
// The consequences were real, not cosmetic: qoh99's boot-serialize hook at winMain 0x471810 lost this
// draw roughly 1 launch in 6, which left that instance's device init unserialized and re-armed the
// #88/#131 boot-park race the mutex exists to prevent. That instance never opened a window.
//
// A retry is correct HERE and only because the error names a transient resource. BAD_ALLOCATION means
// "no memory right now"; the address space is not full in any lasting sense, and the pressure comes from
// other processes starting at the same moment. Every OTHER error type is structural — retrying an
// undecodable instruction or an out-of-range IP-relative operand would loop and still fail — so they
// short-circuit on the first attempt and report immediately.
//
// This belongs in the fork rather than at the ~110 call sites: it is one property of "install an inline
// hook", every adapter depends on it, and #108 already proved that a per-site convention does not hold.
// The retry count is REPORTED on final failure so a genuinely exhausted address space still looks
// different from a one-off contention loss.
inline SafetyHookInline CreateInlineChecked(void* target, void* dest, const char* kind,
                                            const void* slot = nullptr,
                                            const std::source_location& loc = std::source_location::current()) {
    // 8 attempts with a yield between them. Sized from the measurement, not taste: at a ~3% single-attempt
    // loss the chance of losing 8 independent draws is ~1e-12, while the cost when the first attempt
    // succeeds (the overwhelming case) is exactly zero.
    constexpr int kAttempts = 8;
    unsigned lastErr = 0;
    for (int attempt = 0; attempt < kAttempts; ++attempt) {
        auto r = safetyhook::InlineHook::create(target, dest);
        if (r) return std::move(*r);
        lastErr = r.error().type;
        // Structural errors do not improve by waiting — fail fast and report the real reason.
        if (lastErr != safetyhook::InlineHook::Error::BAD_ALLOCATION) break;
        std::this_thread::yield();
    }
    ReportHookInstallFailure(reinterpret_cast<uintptr_t>(target), kind, lastErr, slot, loc);
    return {};
}

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

    // [PC-fork #7b] Every factory takes a defaulted std::source_location so a failed install can name
    // the CALL SITE. It has to be defaulted HERE and not in the constructors: a default argument is
    // evaluated at the call, so source_location::current() inside a constructor would faithfully report
    // a line inside this header on every one of the ~110 sites — which is what made the first #110
    // report unactionable. Costs nothing at runtime on the success path (three pointers, passed and
    // dropped) and nothing at all in the emitted hook.

    // __cdecl inline hook (backward compatible: existing AddHook<&addr, T, Args...>()).
    template <uintptr_t* HookAddr, typename T, typename... Args>
    ManagedHook<HookAddr, CallConv::Cdecl, T, Args...>* AddHook(
        const std::source_location& Loc = std::source_location::current())
    {
        if (void* ExistingHook = GetHook(*HookAddr))
            return static_cast<ManagedHook<HookAddr, CallConv::Cdecl, T, Args...>*>(ExistingHook);

        auto Hook = new ManagedHook<HookAddr, CallConv::Cdecl, T, Args...>(Loc);
        Hooks.push_back(std::shared_ptr<void>(Hook));
        return Hook;
    }

    // [PC-fork #5] Convention-selected inline hook (COM/vtable + non-__cdecl functions).
    template <uintptr_t* HookAddr, CallConv CC, typename T, typename... Args>
    ManagedHook<HookAddr, CC, T, Args...>* AddHookCC(
        const std::source_location& Loc = std::source_location::current())
    {
        if (void* ExistingHook = GetHook(*HookAddr))
            return static_cast<ManagedHook<HookAddr, CC, T, Args...>*>(ExistingHook);

        auto Hook = new ManagedHook<HookAddr, CC, T, Args...>(Loc);
        Hooks.push_back(std::shared_ptr<void>(Hook));
        return Hook;
    }

    // [PC-fork #6] Driver hook: detour OWNS the trampoline, drives the original 0..N times.
    template <uintptr_t* HookAddr, CallConv CC, typename T, typename... Args>
    ManagedDriverHook<HookAddr, CC, T, Args...>* AddDriverHook(
        const std::source_location& Loc = std::source_location::current())
    {
        if (void* Existing = GetDriverHook(*HookAddr))
            return static_cast<ManagedDriverHook<HookAddr, CC, T, Args...>*>(Existing);

        auto Hook = new ManagedDriverHook<HookAddr, CC, T, Args...>(Loc);
        DriverHooks.push_back(std::shared_ptr<void>(Hook));   // register BEFORE redirecting (ExecuteImpl finds Self)
        Hook->Install();                                       // NOW redirect the target to our entry thunk
        return Hook;
    }

    void* GetHook(const uintptr_t HookAddr) const;

    template <uintptr_t* HookAddr>
    ManagedMidHook<HookAddr>* AddMidHook(const std::source_location& Loc = std::source_location::current());

    void* GetMidHook(const uintptr_t HookAddr) const;
    void* GetDriverHook(const uintptr_t HookAddr) const;
};

template <uintptr_t* HookAddr>
ManagedMidHook<HookAddr>* HookManager::AddMidHook(const std::source_location& Loc)
{
    if (void* MidHook = GetMidHook(*HookAddr)) return static_cast<ManagedMidHook<HookAddr>*>(MidHook);

    auto Hook = new ManagedMidHook<HookAddr>(Loc);
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
    template <bool = true> static T SAFETYHOOK_CCALL     Execute_cdecl(Args... a)    { return ExecuteImpl(a...); }
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

    explicit ManagedHook(const std::source_location& Loc = std::source_location::current())
    {
        Addr = *HookAddr;
        Hook = CreateInlineChecked(reinterpret_cast<void*>(*HookAddr), EntryThunk(), "inline",
                                   HookAddr, Loc);
    }

public:
    // [PC-fork #7] TRUE iff the detour actually took. `this != nullptr` never was evidence of that.
    bool installed() const { return static_cast<bool>(Hook); }

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

    template <bool = true> static void SAFETYHOOK_CCALL     Execute_cdecl(Args... a)    { ExecuteImpl(a...); }
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

    explicit ManagedHook(const std::source_location& Loc = std::source_location::current())
    {
        Addr = *HookAddr;
        Hook = CreateInlineChecked(reinterpret_cast<void*>(*HookAddr), EntryThunk(), "inline",
                                   HookAddr, Loc);
    }

public:
    // [PC-fork #7] TRUE iff the detour actually took. A non-null handle never was evidence of that.
    bool installed() const { return static_cast<bool>(Hook); }

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
        // [PC-fork #6 boot-safety] create_inline() redirects the target the instant it runs, so a game frame
        // can fire before SetDriver() wires the detour body (Driver==null) — or, in principle, before the hook
        // is even registered (Self==null). Throwing here = std::terminate on the game thread. Instead PASS
        // THROUGH: run the original frame so the game boots cleanly until the driver is live. (AddDriverHook
        // now registers BEFORE Install()/create_inline, so Self is non-null; the null branch is last-resort.)
        if (Self == nullptr)
            return T{};
        if (Self->Driver == nullptr)
            return Self->callOriginal(InArgs...);
        return Self->Driver(InArgs...);
    }

    // [PC-fork #5] attributed entry thunks; only the CC-matched one is instantiated.
    template <bool = true> static T SAFETYHOOK_CCALL     Execute_cdecl(Args... a)    { return ExecuteImpl(a...); }
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

    // registration happens in AddDriverHook BEFORE Install(), so the call site has to be STORED here
    // and used later -- unlike the inline hooks, where the ctor installs directly.
    std::source_location Loc{};
    explicit ManagedDriverHook(const std::source_location& L = std::source_location::current())
        : Loc(L) { Addr = *HookAddr; }

    // Redirect the target to our entry thunk. Called by AddDriverHook AFTER this hook is in the manager's
    // registry, so a frame firing the instant the redirect lands finds Self != null (see ExecuteImpl).
    void Install()
    {
        Hook = CreateInlineChecked(reinterpret_cast<void*>(*HookAddr), EntryThunk(), "inline",
                                   HookAddr, Loc);
    }

public:
    // [PC-fork #7] TRUE iff the detour actually took. A non-null handle never was evidence of that.
    // Matters most here: a driver hook that failed to install means the frame is NEVER driven — the
    // netcode simply does not run, and every symptom points somewhere else.
    bool installed() const { return static_cast<bool>(Hook); }

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

    explicit ManagedMidHook(const std::source_location& Loc = std::source_location::current())
    {
        Addr = *HookAddr;
        // [PC-fork #7] expected-returning create + failure report; see CreateInlineChecked's header note.
        auto midResult = safetyhook::MidHook::create(reinterpret_cast<void*>(*HookAddr), [](SafetyHookContext& ctx)
        {
            // [PC-fork #2] mid dispatcher must look up the MidHooks vector, not Hooks.
            auto Hook = static_cast<ManagedMidHook*>(HookManager::GetInstance()->GetMidHook(*HookAddr));
            if (Hook == nullptr) throw std::runtime_error("MidHook not found! This should never happen.");

            for (auto& Callback : Hook->Callbacks)
            {
                Callback(ctx);
            }
        });
        if (midResult) Hook = std::move(*midResult);
        else ReportHookInstallFailure(*HookAddr, "mid", midResult.error().type, HookAddr, Loc);
    }

public:
    // [PC-fork #7] TRUE iff the detour actually took. A non-null handle never was evidence of that.
    bool installed() const { return static_cast<bool>(Hook); }

    void AddCallback(void(*Callback)(SafetyHookContext&))    { Callbacks.push_back(Callback); }
    // [PC-fork #3] was push_back (a no-op duplicate); must erase.
    void RemoveCallback(void(*Callback)(SafetyHookContext&)) { std::erase(Callbacks, Callback); }
};
