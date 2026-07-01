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

## #5 — Calling-convention selector for x86 inline detours  *(DONE, upstreamable)*
`ManagedHook` now carries a `CallConv` non-type template param (`Cdecl` default / `Stdcall`
/ `Thiscall` / `Fastcall`). The detour `Execute` is emitted with the matching x86 attribute,
and the original is invoked via SafetyHook's matching `unsafe_{call,stdcall,thiscall,fastcall}`
(selected with `if constexpr`). The four attributed thunks are member templates, so only the
CC-matched one is ODR-used/instantiated — a `__thiscall`/`__fastcall` thunk is never emitted
for an argument list that can't carry its register args.

API: `AddHook<&slot, T, Args...>()` stays `__cdecl` (backward compatible; existing hooks and
the cdecl smoke test are unchanged). `AddHookCC<&slot, CC, T, Args...>()` selects a
convention. This makes COM/vtable methods (D3D9 `Present`/`Reset`/`EndScene`/`DrawPrimitive`)
and non-`__cdecl` game functions first-class inline hooks with the full pre/post + return
chain — no longer limited to convention-free mid-hooks. On x64 the selector collapses to one
convention (no-op).

**Validated** (`tests/hook_smoke/`, all green under i686-w64-mingw32-g++ GCC 13, PE32 x86):
`test_inline.cpp` (cdecl), `test_inline_stdcall.cpp` (stdcall: pre/post chain, correct callee
cleanup, balanced stack across repeated calls), `test_inline_conv.cpp` (thiscall + fastcall —
`__thiscall` on a free function compiles + runs). `ManagedMidHook` remains for convention-free
context hooks. **Ready to upstream to WistfulHopes/HookManager.**

## Misc robustness
- Added the out-of-line definition `uintptr_t HookManager::Temp = 0;` (upstream relied on it
  never being ODR-used out of line; defining it is strictly safe).
- Added explicit `<cstdint>/<memory>/<vector>/<stdexcept>/<algorithm>` includes rather than
  relying on `safetyhook.hpp` to pull them in transitively.

## Build/run verification
`i686-w64-mingw32-g++ (GCC 13) -std=c++23 -static`, linked against the vendored SafetyHook
amalgam (`deps/safetyhook`). Produces `PE32 Intel 80386`. Smoke test (`tests/hook_smoke`):
inline cdecl pre/post chain ✅, mid-hook chain ✅, all on x86 under WSL interop.

## #6 — ManagedDriverHook: driver/owned inline hook  *(DONE, upstreamable)*
`ManagedHook` is an *observer* (pre/post callbacks; the original runs exactly once). Some hooks are
*drivers*: the detour must decide whether/how-many-times the original runs — rollback re-simulation
(run the frame N times), runahead, fast-forward/turbo, frameskip, replay scrubbing. `ManagedDriverHook`
models that: `SetDriver(fn)` registers the single detour body, and inside it the owner calls
`callOriginal(args...)` 0..N times through the trampoline (with the target's ABI, reusing #5's convention
thunks). Tracked in its own `DriverHooks` vector (`AddDriverHook`/`GetDriverHook`), parallel to
`Hooks`/`MidHooks`. This lets the netcode-critical frame hook be HookEngine-managed instead of a raw
`SafetyHookInline` exception. The driver is singular by nature (only one thing decides frame cadence); a
per-driven-frame *observer* callback chain can be layered onto the same primitive later without changing
it. General beyond MBAACC (any frame-driven/rollback/emulator hook wants it). **Validated:**
`tests/hook_smoke/test_driver_hook.cpp` (detour drives the original 3× → sum, repeated, stack sound).
**Ready to upstream to WistfulHopes/HookManager.**
