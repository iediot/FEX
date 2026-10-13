// SPDX-License-Identifier: MIT
#pragma once

/* iOS-Madeira ml2400: the CompileBlock-side entry points of the persistent code
 * cache (MadeiraCodeCache.h). Separate from that header because these need the
 * complete CPUBackend, which itself embeds the per-thread BlockCapture. */

#include "Interface/Core/MadeiraCodeCache.h"

#ifdef MADEIRA_FEX_CODE_CACHE_BUILD
#include "Interface/Core/CPUBackend.h"

#include <FEXCore/fextl/memory.h>

namespace FEXCore::Core {
struct DebugData;
}

namespace FEXCore::MadeiraCache {
// Arm (or disarm) the per-thread capture for the compile CompileBlock is about to run.
void ArmCapture(FEXCore::Core::InternalThreadState* Thread, bool Armed);

// Lookup + validation + install through the JIT's publish path. On true the block
// is in the code buffer exactly as a compile would have left it.
bool TryInstall(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, bool MonoBlockNow,
                FEXCore::CPU::CPUBackend::CompiledCode& OutCode, fextl::unique_ptr<FEXCore::Core::DebugData>& OutDebug,
                InstalledBlock& Out);

// After CompileCode, before the block is published to the lookup cache.
void SealCapture(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP,
                 const FEXCore::CPU::CPUBackend::CompiledCode& Code);

// After publication (code pages write-protected): queue the block for the file.
void Record(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP,
            const FEXCore::CPU::CPUBackend::CompiledCode& Code, bool MonoBlockNow);
} // namespace FEXCore::MadeiraCache
#endif
