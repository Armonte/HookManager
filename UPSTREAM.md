# HookManager — PovertyCaster fork notes (for upstreaming)

Fork of [WistfulHopes/HookManager](https://github.com/WistfulHopes/HookManager).
Upstream base commit: `05a02a95247eb5e75aa320fd353e43dd9d54697e`.

WistfulHopes' layered-hook design (stacked pre/post callback chains over SafetyHook,
keyed by module-relative RVA) is exactly what PovertyCaster needs to let the core, the
per-game adapter, and plugins all hook the same address without clobbering each other.
Upstream is still WIP and MSVC/x64-centric; below are the changes we made to run it under
our 32-bit `i686-w64-mingw32` (GCC 13, C++23) target. **All of #1–#4 are upstreamable as-is.**

All changes are tagged `[PC-fork #N]` in the source.

## #1 — GCC/MinGW conformance: `.template` on dependent member call  *(blocker, upstreamable)*
`ManagedHook::Execute` called `Hook->Hook.unsafe_call<T>(InArgs...)`. Because `unsafe_call`
is a template member and `T` is a dependent type, ISO C++ requires the `.template`
disambiguator: `Hook->Hook.template unsafe_call<T>(InArgs...)`. MSVC accepts the form
without it (non-conforming); GCC and Clang reject it at parse time, so the header does not
compile on any non-MSVC toolchain. One-token fix.

## #2 — Mid-hook dispatcher used the wrong lookup  *(runtime crash, upstreamable)*
`ManagedMidHook`'s `create_mid` trampoline looked the hook up via
`HookManager::GetInstance()->GetHook(*HookAddr)` — but mid-hooks are stored in the
`MidHooks` vector, which `GetHook()` does not search. Result: every mid-hook, when it
fires, finds `nullptr` and `throw`s `"Hook not found"` (verified: process terminates).
Changed to `GetMidHook(*HookAddr)`. After this, mid-hooks work on x86 (verified).

## #3 — `ManagedMidHook::RemoveCallback` never removed  *(bug, upstreamable)*
It did `Callbacks.push_back(Callback)` (a duplicate add) instead of erasing. Changed to
`std::erase(Callbacks, Callback)` to match the inline hook's Remove* methods.

## #4 — Post-callbacks could not see the original return value  *(API limitation, upstreamable)*
The post-callback loop created a fresh `T Temp = T()` and passed that to each callback, so
a post-callback always saw a zero-initialized return regardless of what the original
function (or a prior callback) returned — making "observe/adjust the real return value"
impossible. Changed to pass the current `ReturnValue` (`T Candidate = ReturnValue`), keeping
the "return true to overwrite" semantics. Verified: a post-callback now reads the genuine
original result.

## #5 — Calling-convention selector for x86 inline detours  *(design work, NOT yet done)*
On x86, `ManagedHook`'s detour `static T Execute(Args...)` is `__cdecl`, and
`unsafe_call<T>` uses SafetyHook's default convention. Real target functions are frequently
`__thiscall` (this in `ecx`), `__stdcall` (callee cleans stack), or `__fastcall`. A plain
cdecl detour cannot even represent a `this`-in-`ecx` argument, so inline `ManagedHook` is
currently usable on x86 only for `__cdecl` targets. SafetyHook already exposes
`unsafe_thiscall` / `unsafe_stdcall` / `unsafe_fastcall`; the fork work is to (a) carry a
convention tag (template NTTP or tag type) on `ManagedHook`, (b) emit `Execute` with the
matching `__attribute__((stdcall/fastcall/thiscall))` on x86, and (c) dispatch to the
matching `unsafe_*call`. On x64 this collapses to a no-op (one convention).

**Mitigation:** `ManagedMidHook` is convention-free (it only reads `SafetyHookContext`), so
the bulk of MBAACC's hook sites use mid-hooks and need none of #5. #5 is only required where
we must wrap a full non-cdecl function with typed args + return control.

## Misc robustness
- Added the out-of-line definition `uintptr_t HookManager::Temp = 0;` (upstream relied on it
  never being ODR-used out of line; defining it is strictly safe).
- Added explicit `<cstdint>/<memory>/<vector>/<stdexcept>/<algorithm>` includes rather than
  relying on `safetyhook.hpp` to pull them in transitively.

## Build/run verification
`i686-w64-mingw32-g++ (GCC 13) -std=c++23 -static`, linked against the vendored SafetyHook
amalgam (`deps/safetyhook`). Produces `PE32 Intel 80386`. Smoke test (`tests/hook_smoke`):
inline cdecl pre/post chain ✅, mid-hook chain ✅, all on x86 under WSL interop.
