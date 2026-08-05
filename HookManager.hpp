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
#include <chrono>   // [#182] escalating retry backoff (see CreateInlineChecked)
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
    // [PC-fork #166] Populated ONLY for kHookErrPrologueMismatch, and meaningless otherwise. The bytes
    // are the whole diagnosis for that failure: "the address is wrong" is unactionable, "wanted
    // 53 55 56 57 8B E9, found 8B 44 24 04 85 C0" tells you immediately that you landed inside another
    // function. `got` points at the live target, so read it before anything else can rewrite it.
    const unsigned char* want   = nullptr;
    const unsigned char* got    = nullptr;
    unsigned             nbytes = 0;
    const char*          what   = nullptr;   // the site's name, from its registration
};

inline void (*&HookInstallFailureSink())(const HookInstallFailure&) {
    static void (*sink)(const HookInstallFailure&) = nullptr;
    return sink;
}

// [PC-fork #189] FAILURES REPORTED BEFORE THE SINK EXISTS WERE DROPPED ON THE FLOOR — INCLUDING THE ONE
// FAILURE THIS WHOLE MECHANISM WAS BUILT FOR.
//
// #182 added a pending buffer so install failures that happen before a LOGGER is wired still reach the log.
// It never fired, because it lives INSIDE the sink (HookEngine's onHookInstallFailure) and the sink itself
// is installed later still, by Driver::initHookEngine(). ReportHookInstallFailure below simply returned
// when the sink was null, so the earliest failures produced nothing anywhere — not the log, not even the
// OutputDebugStringA that was supposed to make it "never silent" (that call is also inside the sink).
//
// MEASURED (2026-08-05, qoh99 4P): the boot-serialize hook at winMain failed to install on p3 at t=31.895s;
// Driver::initHookEngine() had not run yet. The bootmap recorded detourWritten=0 and the page/free-block
// dump, but the safetyhook ERROR TYPE — the one fact that separates a transient BAD_ALLOCATION (retrying is
// right) from a structural error (retrying is pointless) — existed for microseconds inside
// CreateInlineChecked and was then discarded. Two prior investigations wanted exactly that value.
//
// So buffer UPSTREAM of the sink, where the report is actually made. Copying the record by value is safe:
// every pointer in it aims at storage that outlives the process's boot — string literals, the static
// prologue-declaration registry, and the live target address.
inline constexpr int kMaxSinklessFail = 8;
inline int& SinklessFailCount() { static int n = 0; return n; }
inline HookInstallFailure* SinklessFailBuf() { static HookInstallFailure buf[kMaxSinklessFail]; return buf; }

inline void ReportOrBufferHookFailure(const HookInstallFailure& f) {
    if (auto sink = HookInstallFailureSink()) { sink(f); return; }
    if (SinklessFailCount() < kMaxSinklessFail) SinklessFailBuf()[SinklessFailCount()++] = f;
}

// Install the sink and immediately drain anything that failed before it existed. Use this rather than
// assigning HookInstallFailureSink() directly — a bare assignment silently keeps the old drop behaviour.
inline void SetHookInstallFailureSink(void (*sink)(const HookInstallFailure&)) {
    HookInstallFailureSink() = sink;
    if (!sink) return;
    for (int i = 0; i < SinklessFailCount(); ++i) sink(SinklessFailBuf()[i]);
    SinklessFailCount() = 0;
}

// [PC-fork #166] Not a safetyhook error — safetyhook never runs for this one. Deliberately far above
// any enumerator so it can never collide with a future safetyhook error type.
inline constexpr unsigned kHookErrPrologueMismatch = 0xF001;

// Names match safetyhook's InlineHook::Error / MidHook::Error enumerators, in declaration order.
inline const char* HookInstallErrorName(unsigned t) {
    if (t == kHookErrPrologueMismatch) return "PROLOGUE_MISMATCH";
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
    ReportOrBufferHookFailure(HookInstallFailure{ addr, kind, errorType, slot,
                                                  loc.file_name(), loc.line(), loc.function_name() });
}

// ============================================================================
//  [PC-fork #166] EXPECTED-PROLOGUE GUARD — installing is not the same as installing in the RIGHT PLACE.
//
//  #7 (above) closed "the detour was never written". pc/HookSiteWitness.hpp closed it again from the
//  caller's side by proving the entry bytes CHANGED. Neither says anything about WHICH bytes changed,
//  and that is the hole:
//
//      QoH99 has two builds. Code above 0x4736C0 sits 0x20 higher in the December build; data does not
//      move. Point a November address at a December image and the hook lands 0x20 short — inside the
//      previous function, or partway into an instruction. safetyhook decodes whatever is there, writes
//      a perfectly good detour, returns a live hook, and the witness confirms the bytes changed.
//      Seven qoh99 sites did exactly this and EVERY existing check passed.
//
//  The asymmetry is the defect, and it is worth naming precisely: static byte patches have carried a
//  guard for a long time (pc/BytePatchTable.hpp PatchSite::expect — "write only if the site currently
//  holds these"), and that guard is the reason a byte patch cannot land on the wrong build. Hooks had
//  no equivalent. Same hazard, same fix, and it belongs HERE rather than at the ~110 call sites for the
//  same reason #164's retry does: it is one property of "install a hook", every adapter depends on it,
//  and #108 already proved a per-site convention does not hold.
//
//  Shape: an adapter REGISTERS the bytes it expects at a target before installing; the two chokepoints
//  (CreateInlineChecked for all three inline flavours, ManagedMidHook's ctor for mid) refuse to install
//  when they do not match, and report through the same sink as every other install failure — carrying
//  the wanted and found bytes, which is the entire diagnosis.
//
//  OPT-IN, and honestly so. A site with no registration installs exactly as before; the guard cannot
//  retrofit knowledge nobody wrote down. What it must not do is let that look like coverage, so the
//  registry counts guarded vs unguarded installs and HookSitePrologueStats() reports both — an adapter
//  logging "12 hooks, 5 guarded" states the gap instead of implying there isn't one.
//
//  Storage is a fixed-capacity POD array, no allocation and no dynamic initializer, because this header
//  is included at suspended-boot time from DllMain (same constraint as the failure sink).
// ============================================================================
struct HookSitePrologue {
    uintptr_t     addr;        // absolute target VA (base already added — see RegisterHookSitePrologueRva)
    const char*   what;        // the site's name, for the refusal line
    unsigned      n;
    unsigned char bytes[24];   // longest useful prologue; a real one is 5-8
};

struct HookSitePrologueRegistry {
    static constexpr unsigned kMax = 64;
    HookSitePrologue sites[kMax];
    unsigned         count;
    unsigned         dropped;            // registrations refused (table full / byte list too long)
    unsigned         guardedInstalls;    // installs that were checked against a registration
    unsigned         unguardedInstalls;  // installs with no registration — the honest coverage gap
    unsigned         refusedInstalls;    // installs STOPPED by a mismatch
};

inline HookSitePrologueRegistry& HookSitePrologues() {
    static HookSitePrologueRegistry r{};   // POD aggregate, constant-initialized: lands in .bss
    return r;
}

inline const HookSitePrologueRegistry& HookSitePrologueStats() { return HookSitePrologues(); }

// Declare the bytes that MUST be at `addr` for a hook there to be the hook we meant. Returns false if
// the registration itself could not be stored — which the caller must treat as a failure to guard, not
// as a guard that passed.
inline bool RegisterHookSitePrologue(uintptr_t addr, const unsigned char* bytes, unsigned n,
                                     const char* what) {
    auto& reg = HookSitePrologues();
    if (addr == 0 || bytes == nullptr || n == 0 ||
        n > sizeof(HookSitePrologue::bytes) || reg.count >= HookSitePrologueRegistry::kMax) {
        ++reg.dropped;
        return false;
    }
    HookSitePrologue& s = reg.sites[reg.count++];
    s.addr = addr;
    s.what = what;
    s.n    = n;
    for (unsigned i = 0; i < n; ++i) s.bytes[i] = bytes[i];
    return true;
}

inline const HookSitePrologue* FindHookSitePrologue(uintptr_t addr) {
    const auto& reg = HookSitePrologues();
    for (unsigned i = 0; i < reg.count; ++i)
        if (reg.sites[i].addr == addr) return &reg.sites[i];
    return nullptr;
}

// The gate. TRUE means "no objection, go ahead and install".
//
// addr == 0 returns true DELIBERATELY: that is #110's case (an address global that was never resolved),
// and the existing FAILED_TO_DECODE report already names it correctly. Dereferencing zero here would
// replace a good diagnosis with an access violation.
//
// The compare reads the target's bytes directly. That can only fault where safetyhook's own decode
// would fault a moment later on the same address, so it introduces no hazard that was not already there.
inline bool HookSitePrologueOk(uintptr_t addr, const char* kind, const void* slot,
                               const std::source_location& loc = std::source_location::current()) {
    auto& reg = HookSitePrologues();
    if (addr == 0) return true;
    const HookSitePrologue* s = FindHookSitePrologue(addr);
    if (s == nullptr) { ++reg.unguardedInstalls; return true; }

    const auto* live = reinterpret_cast<const unsigned char*>(addr);
    for (unsigned i = 0; i < s->n; ++i) {
        if (live[i] == s->bytes[i]) continue;
        ++reg.refusedInstalls;
        ReportOrBufferHookFailure(HookInstallFailure{ addr, kind, kHookErrPrologueMismatch, slot,
                                                      loc.file_name(), loc.line(), loc.function_name(),
                                                      s->bytes, live, s->n, s->what });
        return false;
    }
    ++reg.guardedInstalls;
    return true;
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
    // [PC-fork #166] Refuse BEFORE anything is written. A hook at the wrong address is worse than no
    // hook: no hook fails loudly at the first missing callback, a wrong one runs foreign code.
    if (!HookSitePrologueOk(reinterpret_cast<uintptr_t>(target), kind, slot, loc)) return {};

    // [#182] THE RETRIES MUST BE SPREAD IN TIME, AND YIELD IS NOT TIME. The loop above used
    // std::this_thread::yield() between attempts, and the sizing argument ("~3% single-attempt loss ->
    // 1e-12 over 8 draws") silently assumes the draws are INDEPENDENT. They are not: yield() returns in
    // microseconds, so all 8 attempts sample essentially one instant, while the contention that causes
    // BAD_ALLOCATION is another process starting simultaneously — a window measured in MILLISECONDS.
    // Eight samples of the same instant is one draw, not eight, which is why the measured failure rate
    // never fell to anything like 1e-12: an 8-run 2-instance soak on 2026-08-04 lost TWO runs (25%) to
    // this exact install, both leaving qoh99's device init unserialized and re-arming the #88 boot-park.
    // Escalating sleeps (1,2,4,8,16,32,64ms; ~127ms worst case, and only on a path that is already
    // failing) actually span the other process's startup. The common case — first attempt succeeds —
    // still costs nothing.
    constexpr int kAttempts = 8;
    unsigned lastErr = 0;
    for (int attempt = 0; attempt < kAttempts; ++attempt) {
        auto r = safetyhook::InlineHook::create(target, dest);
        if (r) return std::move(*r);
        lastErr = r.error().type;
        // Structural errors do not improve by waiting — fail fast and report the real reason.
        if (lastErr != safetyhook::InlineHook::Error::BAD_ALLOCATION) break;
        if (attempt + 1 < kAttempts)
            std::this_thread::sleep_for(std::chrono::milliseconds(1 << attempt));
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
        // [PC-fork #166] The mid path is the OTHER chokepoint — guard it here, not at the call sites.
        // Leaving `Hook` empty is exactly the shape a failed create leaves behind, so installed()
        // already reports this correctly and no downstream code needs to learn a new state.
        if (!HookSitePrologueOk(*HookAddr, "mid", HookAddr, Loc)) return;
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
