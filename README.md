# HookManager
A hook manager using SafetyHook. By exposing the HookManager in a DLL, dependent users can hook functions even if another hook has been placed. All placed hooks will execute.

> **This is the PovertyCaster fork** (Armonte/HookManager) of [WistfulHopes/HookManager](https://github.com/WistfulHopes/HookManager),
> shared by PovertyCaster and ccrollback. It builds for 32-bit `i686-w64-mingw32` (GCC 13, C++23) as well as the upstream targets, and adds
> an x86 calling-convention selector (`AddHookCC`), `ManagedDriverHook` (a detour that runs the original 0..N times: rollback
> re-simulation, fast-forward), install-failure reporting, a target-bytes guard, retry of transient trampoline allocation failures,
> and disabled-then-enabled inline installs. Every change is tagged `[PC-fork #N]` in the source; `UPSTREAM.md` explains each one
> and which are upstreamable as-is.
>
> **Using it:** `add_subdirectory(HookManager)` then link `HookManager::HookManager`. It links an existing SafetyHook target
> (`HOOKMANAGER_SAFETYHOOK_TARGET`, or a target named `safetyhook`), else fetches upstream
> [cursey/safetyhook](https://github.com/cursey/safetyhook) at the pinned `HOOKMANAGER_SAFETYHOOK_TAG`. See `CMakeLists.txt`.

## Usage
There are two types of hooks exposed by HookManager: `ManagedHook` for inline hooks, and `ManagedMidHook` for mid-function hooks.

- `ManagedHook`s are registered as templates: a `uintptr_t*` for the original function address (relative to module base), a return type, and forwarded arguments.
- `ManagedHook`s have two callbacks: pre-function and post-function. All pre-function hooks execute before the original function, and all post-function hooks execute after the original function, even if it is not called.
- Both pre and post-callbacks have the original function's return value as a reference in the first argument. This must be specified even if `void`.
- Both pre and post-callbacks return boolean values. If the callback returns true, the return value of the original function is overwritten.
- A pre-callback that returns `true` will skip the original function, even if other hooks return `false`.
- `ManagedMidHook`s are a template with only a `uintptr_t*` for the original function address (relative to module base).
- `ManagedMidHook`s only have one callback, which has a return type of `void` and a singular argument `SafetyHookContext&`.
  - For more information on mid-function hooks in SafetyHook, read [this article](https://aixxe.net/2022/12/safetyhook-midfn-hooking).

After using `HookManager::GetInstance` to get the HookManager singleton, use `AddHook` or `AddMidHook` to register a hook. If a hook with the same template arguments already exists, it will instead return the existing hook.

Once a handle to the hook is obtained, it is highly recommended to save the hook in a variable for future access. Then, callbacks can be added or removed.

- Callbacks can be added to `ManagedHook`s with `AddPreCallback` or `AddPostCallback`. The parameter is a function pointer to your callback.
- Similarly, callbacks can be removed with `RemovePreCallback` or `RemovePostCallback`. Like adding hooks, the parameter is a function pointer to your callback.
- `ManagedMidHook`s can be managed with `AddCallback` and `RemoveCallback`. Similar to the above, the parameter is a function pointer to your callback.
