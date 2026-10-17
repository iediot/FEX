// SPDX-License-Identifier: MIT
#pragma once

/* iOS-Madeira ml2400: PERSISTENT FEX CODE CACHE (opt-in: MADEIRA_FEX_CODE_CACHE=1).
 *
 * FEX re-translates every block on every launch, on the game's own threads, so
 * a new area pays decode + IR + RA + emission again for code that has not
 * changed since the last session. This saves the finished ARM64 code of each
 * block to disk, per guest module, and on a later launch installs it in place of
 * a compile.
 *
 * Why the finished code is safe to reuse on this host (the iOS JIT pool):
 *  - The JIT never emits into the pool. It emits into a heap temp buffer and the
 *    publish step memcpy's the bytes verbatim into the current code buffer
 *    through the RW alias (JIT.cpp, "Migrate the compile output"). A block is
 *    therefore position independent by construction: everything inside it is
 *    PC relative, and everything outside is reached through STATE (x28) --
 *    dispatcher entry points, helper pointers, L1 pointer/mask, callret stack,
 *    TEB via the TSD slot -- never through an embedded host address.
 *  - The only embedded process-specific values are exactly the JIT's own
 *    relocation records, which it produces on every compile (CompileBlock
 *    clears them afterwards): the ExitFunctionLinker literal (a pool address)
 *    and guest RIP literals/moves. The literal is rewritten on install; guest
 *    RIPs stay valid because a cache file only applies to the same module at
 *    the same base (and the x86 immediates of a relocated image depend on the
 *    base anyway, so a rebased image never matches its file).
 *  - Installation goes through the SAME publish tail as a compile
 *    (Arm64JITCore::PublishTempCode): code buffer generation check,
 *    ResetCallRetStack on rollover, ClearCodeCache when full, RW-alias copy,
 *    NtFlushInstructionCache. Nothing about pool aliasing, x18, the guarded
 *    callret stacks or buffer generations changes for a cached block.
 *  - Block linking patches the published copy only; what is saved is the
 *    pristine temp-buffer image captured before publication.
 *
 * What is NOT cached (record refused, the block compiles as before): blocks
 * outside a mapped PE image, custom-IR entrypoints, Mono backpatcher blocks or
 * any block with forced full SMC checks, code in an ml954 sub-floor window
 * (its IR embeds this run's host delta), compiles with EFLAGS.TF set or a
 * MaxInst override, ARM64EC thunk moves, delivery (ml455 unpublished) compiles.
 *
 * Validation, all of it on every install (any failure = normal compile):
 *  - file: magic/version, FEX build (this DLL's PE timestamp + size) and a hash
 *    of every config/host-feature input that changes codegen, module FileId
 *    (name + PE timestamp + size), load base and image size;
 *  - record: XXH3 checksum, internal layout and bounds, tail RIP/size;
 *  - guest: XXH3-128 of every guest byte the block was translated from (hashed
 *    twice at record time, before and after the pages were write-protected),
 *    every byte range inside the module and executable now, the ARM64EC
 *    RtlIsEcCode answers the frontend/JIT relied on, Mono-hack state.
 *  MADEIRA_FEX_CODE_CACHE_VERIFY=1 additionally compiles every would-be hit and
 *  compares it byte for byte with the patched cached copy (and stops using the
 *  module's cache on the first difference).
 *
 * Storage: <dir>\<module>-<fileid>-<base>.mfc, dir = MADEIRA_FEX_CACHE_DIR or
 * C:\users\Public\madeira-fex-cache. Append-only records, each checksummed, so
 * a crash mid-write costs only the torn tail (cut on the next write). Records
 * are read on demand (positional reads), never mapped or held in memory, so a
 * large cache costs no resident memory beyond a small index. File I/O happens
 * only at a lock-free point (CompileBlock entry, before any FEX lock) and at
 * process exit; never under CodeInvalidationMutex except the per-hit read. */

#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/vector.h>

#include <atomic>
#include <cstdint>
#include <utility>

#if defined(FEX_IOS_HOST) && defined(_WIN32)
#define MADEIRA_FEX_CODE_CACHE_BUILD 1
#endif

namespace FEXCore::Context {
class ContextImpl;
}
namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEXCore::MadeiraCache {

// One relocation of a captured block, in the cache's own POD form.
enum class RelocKind : uint32_t {
  ExitLinkerLiteral = 0, // 8-byte literal, Value = RelocNamedSymbolLiteral::NamedSymbol
  GuestRIPLiteral = 1,   // 8-byte literal, Value = absolute guest RIP
  GuestRIPMove = 2,      // padded constant move, Value = absolute guest RIP
};

struct CapturedReloc {
  uint32_t Offset; // from the block start
  uint32_t Kind;
  uint64_t Value;
};

struct GuestRange {
  uint64_t Start;
  uint64_t Size;
};

// Per CPUBackend (= per guest thread) capture state. Never shared.
struct BlockCapture {
  bool Active {};      // armed by CompileBlock for the compile in flight
  bool Valid {};       // the JIT captured a block for Entry
  bool Uncacheable {}; // the JIT emitted something a cache must not keep
  bool Sealed {};      // checked against the published copy, guest bytes hashed
  uint64_t Entry {};
  fextl::vector<uint8_t> Code;
  fextl::vector<CapturedReloc> Relocs;
  fextl::vector<std::pair<uint64_t, uint64_t>> EcQueries; // (address | kind << 63, answer)
  fextl::vector<GuestRange> Ranges;          // decoded guest bytes, snapshotted at seal time
  fextl::vector<uint64_t> CodePages;         // the decoder's page set, same snapshot
  fextl::vector<uint64_t> GuestEntryPoints;  // the decoder's entry set, same snapshot
  uint64_t GuestHash[2] {};
  // Record read buffer for installs, and the record kept for a verify compare.
  fextl::vector<uint8_t> Scratch;
  uint64_t VerifyRIP {};
};

// A block installed from the cache: what CompileBlock needs besides the code.
struct InstalledBlock {
  fextl::set<uint64_t> GuestEntryPoints;
  fextl::vector<uint64_t> CodePages;
  uint64_t StartAddr {};
  uint64_t Length {};
};

#ifdef MADEIRA_FEX_CODE_CACHE_BUILD
extern std::atomic<int> g_State;         // -1 unresolved, 0 off, 1 on
extern std::atomic<bool> g_WorkPending;  // a module load or a flush is waiting for a safe point

bool ResolveEnabled(FEXCore::Context::ContextImpl* CTX);

inline bool Enabled(FEXCore::Context::ContextImpl* CTX) {
  const int S = g_State.load(std::memory_order_relaxed);
  return S < 0 ? ResolveEnabled(CTX) : S == 1;
}

// Only reads the flag when the cache is on; never called with a FEX lock held.
void DoPendingWork(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread);
inline void SafePoint(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread) {
  if (g_WorkPending.load(std::memory_order_relaxed)) [[unlikely]] {
    DoPendingWork(CTX, Thread);
  }
}

// "Preparing game": with MADEIRA_FEX_PRECOMPILE=1 the process's first compile hands
// over to the frontend, which (once per exe) translates every function its x64 images
// list in .pdata into the cache before any guest code runs.
void MaybePrecompile(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread);

// ARM64EC: the frontend and JIT ask RtlIsEcCode while translating; a cached
// block is only valid while every answer is still the same.
enum class EcQueryKind : uint64_t { JitExit = 0, FrontendMultiblock = 1 };
void NoteEcQuery(FEXCore::Core::InternalThreadState* Thread, EcQueryKind Kind, uint64_t Address, bool Answer);
#endif

} // namespace FEXCore::MadeiraCache
