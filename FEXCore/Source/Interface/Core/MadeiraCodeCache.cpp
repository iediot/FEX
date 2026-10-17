// SPDX-License-Identifier: MIT
/* iOS-Madeira ml2400: persistent FEX code cache. Design, safety argument and
 * the exact list of what is and is not cached: MadeiraCodeCache.h. */

#include "Interface/Core/MadeiraCodeCacheHooks.h"

#ifdef MADEIRA_FEX_CODE_CACHE_BUILD
#include "Interface/Context/Context.h"
#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/Frontend.h"
#include "Interface/Core/JIT/DebugData.h"
#include "Interface/Core/JIT/Relocations.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/DualMap.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/robin_map.h>
#include <FEXCore/fextl/robin_set.h>
#include <FEXCore/fextl/string.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <type_traits>
#include <xxhash.h>

/* File I/O lives in the Windows frontend (Source/Windows/Common/MadeiraCodeCacheIO.cpp,
 * NT calls only), linked into the same DLL as this FEXCore copy. */
extern "C" {
void* MadeiraFexCacheOpen(const char* DosPath, int ForWrite, uint64_t* SizeOut);
int64_t MadeiraFexCacheRead(void* Handle, uint64_t Offset, void* Buffer, uint32_t Size);
int64_t MadeiraFexCacheWrite(void* Handle, uint64_t Offset, const void* Buffer, uint32_t Size);
int MadeiraFexCacheSetEnd(void* Handle, uint64_t Size);
void MadeiraFexCacheClose(void* Handle);
int MadeiraFexCacheMakeDir(const char* DosPath);
void MadeiraFexCacheProcessName(char* Out, uint32_t Size);
// ml954 sub-floor windows (ARM64EC IosJitAlias.cpp; WOW64 Module.cpp stubs).
int IosSubfloorWindowForCode(uint64_t Rip, uint64_t* Low, uint64_t* Size, uint64_t* Real);
uint64_t IosSubfloorToReal(uint64_t Addr);
// This DLL's own image: its PE timestamp/size identify the FEX build.
extern const uint8_t __ImageBase[];
}

namespace FEXCore::MadeiraCache {
std::atomic<int> g_State {-1};
std::atomic<bool> g_WorkPending {false};

namespace {
constexpr uint32_t FILE_MAGIC = 0x4346464d;   // "MFFC"
constexpr uint32_t FILE_VERSION = 3; // 2: guest addresses stored relative to the module base; 3: base-free guest hash
constexpr uint32_t RECORD_MAGIC = 0x314b4c42; // "BLK1"
constexpr uint32_t MAX_RECORD_SIZE = 1u << 20;
constexpr uint64_t MAX_RANGE_SIZE = 1u << 16;
constexpr uint32_t FLAG_MONO_HACKS = 1;
constexpr size_t MAX_PENDING_BYTES = 32u << 20;
constexpr size_t FLUSH_PENDING_BYTES = 4u << 20;
constexpr uint64_t FLUSH_INTERVAL_S = 15;
constexpr uint64_t REPORT_INTERVAL_S = 10;
constexpr size_t SCAN_CHUNK = 2u << 20; // > MAX_RECORD_SIZE: any record fits in one chunk

struct FileHeader {
  uint32_t Magic;
  uint32_t Version;
  uint64_t ConfigHash;
  uint64_t FileId;
  uint64_t FileStartVA;
  uint64_t ImageSize;
  uint64_t Reserved[3];
};
static_assert(sizeof(FileHeader) == 64);

// Followed by: GuestRange[NumRanges], u64 CodePages[], EntryRec[], u64 GuestEntryPoints[],
// RelocRec[], EcRec[], then CodeSize bytes of code padded to 8.
struct RecordHeader {
  uint32_t Magic;
  uint32_t TotalSize;
  uint64_t Checksum; // XXH3_64 of bytes [16, TotalSize), seeded with RecordSeed()
  uint64_t GuestRIP;
  uint64_t GuestHash[2];
  uint32_t Flags;
  uint32_t CodeSize;
  uint16_t NumRanges;
  uint16_t NumCodePages;
  uint16_t NumEntries;
  uint16_t NumGuestEntryPoints;
  uint16_t NumRelocs;
  uint16_t NumEcQueries;
  uint32_t Pad;
};
static_assert(sizeof(RecordHeader) == 64);

struct EntryRec {
  uint64_t Guest;
  uint64_t HostOffset;
};
struct RelocRec {
  uint32_t Offset;
  uint32_t Kind;
  uint64_t Value;
};
struct EcRec {
  uint64_t Query; // address | kind << 63
  uint64_t Answer;
};

enum Reject : int {
  R_CHECKSUM,
  R_LAYOUT,
  R_GUEST_HASH,
  R_NOT_EXEC,
  R_RANGE,
  R_EC,
  R_MONO,
  R_SUBFLOOR,
  R_READ,
  R_INSTALL,
  R_COUNT
};
constexpr const char* RejectNames[R_COUNT] = {"checksum", "layout", "guest-bytes", "not-exec", "range",
                                              "ec",       "mono",   "subfloor",    "read",     "install"};

enum class ModState : int { Requested, Loaded, Poisoned };

struct IndexEntry {
  uint64_t Offset;
  uint32_t Size;
  bool Rejected;
};

struct ModuleCache {
  uint64_t FileId {};
  uint64_t Base {};
  uint64_t Begin {};
  uint64_t End {};
  fextl::string Name;
  fextl::string Path;
  std::atomic<ModState> State {ModState::Requested};

  // Guarded by g_Lock.
  fextl::robin_map<uint64_t, IndexEntry> Index;
  fextl::robin_set<uint64_t> RecordedThisRun;
  fextl::vector<uint8_t> Pending;
  uint32_t PendingBlocks {};
  bool Full {};
  // The file's valid bytes, read once at the safe point: installing a block makes
  // no syscall while compile holds the code invalidation lock (an NtReadFile there
  // deadlocked Steam's dock against a heap-lock holder waiting to invalidate).
  fextl::vector<uint8_t> Data;

  // Owned by the DoPendingWork / final-flush caller (g_Busy).
  void* Writer {};
  bool WriterFailed {};
  bool HeaderOk {};
  uint64_t ValidEnd {};
};

std::shared_mutex g_Lock;
fextl::robin_map<uint64_t, ModuleCache*>* g_Modules;
std::atomic<bool> g_Busy {false};
std::atomic<size_t> g_PendingTotal {0};
std::atomic<uint64_t> g_LastFlushTick {0};
uint64_t g_ConfigHash {};
uint64_t g_MaxFileBytes {256u << 20};
bool g_Verify {};
fextl::string g_Dir;

struct Stats {
  std::atomic<uint64_t> Hits, Misses, NotReady, Recorded, RecordSkipped, Dropped, BytesWritten, BlocksWritten, BlocksLoaded,
    VerifyOk, VerifyBad, InstalledBytes;
  std::atomic<uint64_t> Rejects[R_COUNT];
  std::atomic<uint64_t> LastReportTick;
} g_Stats {};

inline uint64_t Ticks() {
  uint64_t V;
  __asm volatile("isb; mrs %0, cntvct_el0" : "=r"(V));
  return V;
}
inline uint64_t TickFreq() {
  uint64_t V;
  __asm volatile("mrs %0, cntfrq_el0" : "=r"(V));
  return V ? V : 24000000;
}

inline uint64_t Key(uint64_t FileId, uint64_t Base) {
  return FileId ^ ((Base << 21) | (Base >> 43));
}

uint64_t Count(std::atomic<uint64_t>& C) {
  return C.load(std::memory_order_relaxed);
}

void Bump(std::atomic<uint64_t>& C, uint64_t N = 1) {
  C.fetch_add(N, std::memory_order_relaxed);
}

void Report(bool Force) {
  const uint64_t Now = Ticks();
  uint64_t Last = g_Stats.LastReportTick.load(std::memory_order_relaxed);
  if (!Force && Now - Last < REPORT_INTERVAL_S * TickFreq()) {
    return;
  }
  if (!g_Stats.LastReportTick.compare_exchange_strong(Last, Now, std::memory_order_relaxed) && !Force) {
    return;
  }
  fextl::string Rejects;
  for (int i = 0; i < R_COUNT; ++i) {
    if (const uint64_t N = Count(g_Stats.Rejects[i])) {
      Rejects += fextl::fmt::format(" {}={}", RejectNames[i], N);
    }
  }
  LogMan::Msg::EFmt("[fex-cache] ml2400 hits={} ({} KB) misses={} not-loaded={} rejects:{} | recorded={} skipped={} dropped={} "
                    "pending={} KB written={} blocks/{} KB loaded={}{}",
                    Count(g_Stats.Hits), Count(g_Stats.InstalledBytes) / 1024, Count(g_Stats.Misses), Count(g_Stats.NotReady),
                    Rejects.empty() ? " none" : Rejects.c_str(), Count(g_Stats.Recorded), Count(g_Stats.RecordSkipped),
                    Count(g_Stats.Dropped), g_PendingTotal.load(std::memory_order_relaxed) / 1024, Count(g_Stats.BlocksWritten),
                    Count(g_Stats.BytesWritten) / 1024, Count(g_Stats.BlocksLoaded),
                    g_Verify ? fextl::fmt::format(" verify ok={} bad={}", Count(g_Stats.VerifyOk), Count(g_Stats.VerifyBad)) : "");
}

void CountReject(Reject R) {
  Bump(g_Stats.Rejects[R]);
  Report(false);
}

struct Hasher {
  XXH3_state_t* State;
  Hasher() {
    State = XXH3_createState();
    XXH3_64bits_reset(State);
  }
  ~Hasher() {
    XXH3_freeState(State);
  }
  template<typename T>
  void Mix(const T& Value) {
    if constexpr (std::is_arithmetic_v<T> || std::is_enum_v<T>) {
      const uint64_t V = static_cast<uint64_t>(Value);
      XXH3_64bits_update(State, &V, sizeof(V));
    } else {
      const uint64_t Len = Value.size();
      XXH3_64bits_update(State, &Len, sizeof(Len));
      XXH3_64bits_update(State, Value.data(), Value.size());
    }
  }
  uint64_t Digest() {
    return XXH3_64bits_digest(State);
  }
};

/* Everything that can make the same guest bytes translate differently: the FEX
 * build itself, the context's effective codegen config, and the host features.
 * A change in any of them retires every file (header mismatch -> rewritten). */
uint64_t ComputeConfigHash(FEXCore::Context::ContextImpl* CTX) {
  Hasher H;
  H.Mix(FILE_VERSION);
  {
    // e_lfanew -> IMAGE_NT_HEADERS: TimeDateStamp (+8), SizeOfImage (+24+56), CheckSum (+24+64).
    uint32_t Lfanew, TimeDateStamp, SizeOfImage, CheckSum;
    memcpy(&Lfanew, __ImageBase + 0x3c, 4);
    memcpy(&TimeDateStamp, __ImageBase + Lfanew + 8, 4);
    memcpy(&SizeOfImage, __ImageBase + Lfanew + 24 + 56, 4);
    memcpy(&CheckSum, __ImageBase + Lfanew + 24 + 64, 4);
    H.Mix(TimeDateStamp);
    H.Mix(SizeOfImage);
    H.Mix(CheckSum);
  }
  auto& C = CTX->Config;
  H.Mix(C.Is64BitMode());
  H.Mix(C.Multiblock());
  H.Mix(C.MaxInstPerBlock());
  H.Mix(C.TSOEnabled());
  H.Mix(C.VectorTSOEnabled());
  H.Mix(C.MemcpySetTSOEnabled());
  H.Mix(C.SMCChecks());
  H.Mix(C.x87ReducedPrecision());
  H.Mix(C.DisableVixlIndirectCalls());
  H.Mix(C.SmallTSCScale());
  H.Mix(C.StrictInProcessSplitLocks());
  H.Mix(C.MonoHacks());
  H.Mix(C.NeedsPendingInterruptFaultCheck);
  // WOW64 guest window: blocks reach it through REG_GUEST_BASE, only "is there one" shapes codegen.
  H.Mix(CTX->GetGuestBase() != 0);
  H.Mix(CTX->IsAtomicTSOEnabled());
  H.Mix(CTX->IsVectorAtomicTSOEnabled());
  H.Mix(CTX->IsMemcpyAtomicTSOEnabled());
  H.Mix(FEXCore::Config::Get_O0()());
  H.Mix(FEXCore::Config::Get_DISABLEL2CACHE()());
  H.Mix(FEXCore::Config::Get_VOLATILEMETADATA()());
  H.Mix(FEXCore::Config::Get_EXTENDEDVOLATILEMETADATA()());
  H.Mix(FEXCore::Config::Get_HOSTFEATURES()());
  H.Mix(FEXCore::Config::Get_FORCESVEWIDTH()());
  H.Mix(FEXCore::Config::Get_HALFBARRIERTSOENABLED()());
  const auto& F = CTX->HostFeatures;
  for (auto V : {F.DCacheLineSize, F.ICacheLineSize}) {
    H.Mix(V);
  }
  for (bool B : {F.SupportsCacheMaintenanceOps, F.SupportsAES, F.SupportsCRC, F.SupportsCLZERO, F.SupportsAtomics, F.SupportsRCPC,
                 F.SupportsTSOImm9, F.SupportsRAND, F.SupportsAVX, F.SupportsSVE128, F.SupportsSVE256, F.SupportsSHA,
                 F.SupportsPMULL_128Bit, F.SupportsCSSC, F.SupportsFCMA, F.SupportsFlagM, F.SupportsFlagM2, F.SupportsRPRES,
                 F.SupportsPreserveAllABI, F.SupportsAES256, F.SupportsSVEBitPerm, F.SupportsCPUIndexInTPIDRRO, F.SupportsFRINTTS,
                 F.SupportsECV, F.SupportsWFXT, F.Supports3DNow, F.SupportsSSE4a, F.SupportsMOPS, F.PreferZVAForVZero, F.SupportsAFP,
                 F.SupportsFloatExceptions, F.IsInstCountCI}) {
    H.Mix(B);
  }
  H.Mix(F.HostType);
  for (auto MIDR : F.CPUMIDRs) {
    H.Mix(MIDR);
  }
  return H.Digest();
}

fextl::string LowerBaseName(const fextl::string& Path) {
  size_t Slash = Path.find_last_of("\\/");
  fextl::string Name = Slash == fextl::string::npos ? Path : Path.substr(Slash + 1);
  for (auto& c : Name) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')) {
      c = '_';
    }
  }
  if (Name.empty()) {
    Name = "anon";
  }
  return Name;
}

/* Every byte the translation was made from, in decode order, with the ranges
 * themselves mixed in. Reads go through the guest window like the decoder's. */
void HashGuestRanges(FEXCore::Context::ContextImpl* CTX, uint64_t GuestRIP, const GuestRange* Ranges, size_t NumRanges, uint64_t Out[2]) {
  XXH3_state_t* S = XXH3_createState();
  XXH3_128bits_reset(S);
  // Positions relative to the block's RIP, never absolute: the module loads at a new
  // base most launches, and absolute values rejected every record (Detroit, Oct 17:
  // guest-bytes=36558 of 37998 after the exe moved 0xc02f20000 -> 0xc02d20000).
  for (size_t i = 0; i < NumRanges; ++i) {
    const uint64_t Rel[2] = {Ranges[i].Start - GuestRIP, Ranges[i].Size};
    XXH3_128bits_update(S, Rel, sizeof(Rel));
    XXH3_128bits_update(S, reinterpret_cast<const void*>(CTX->GetGuestBase() + Ranges[i].Start), Ranges[i].Size);
  }
  const XXH128_hash_t R = XXH3_128bits_digest(S);
  XXH3_freeState(S);
  Out[0] = R.low64;
  Out[1] = R.high64;
}

bool RangeExecutable(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t Size) {
  // Same walk as Decoder::CheckRangeExecutable, without its per-decoder cache.
  const uint64_t End = Address + Size;
  while (Address < End) {
    auto Info = CTX->SyscallHandler->QueryGuestExecutableRange(Thread, Address);
    if (Info.Size == 0 || Address < Info.Base || Address >= Info.Base + Info.Size) {
      return false;
    }
    Address = Info.Base + Info.Size;
  }
  return true;
}

bool EcAnswer(uint64_t Query) {
#ifdef ARCHITECTURE_arm64ec
  const uint64_t Address = Query & ~(1ULL << 63);
  if (Query >> 63) {
    return RtlIsEcCode(Address); // Frontend multiblock member check
  }
  return Address < FEXCore::CPU::EC_CODE_BITMAP_MAX_ADDRESS && RtlIsEcCode(Address); // JIT ExitFunction
#else
  (void)Query;
  return false;
#endif
}

fextl::string FilePath(const ModuleCache& M) {
  // No load base in the name: records are base-relative, so one file serves every base.
  return fextl::fmt::format("{}\\{}-{:016x}.mfc", g_Dir, M.Name, M.FileId);
}

ModuleCache* FindModule(uint64_t K) {
  if (!g_Modules) {
    return nullptr;
  }
  auto It = g_Modules->find(K);
  return It == g_Modules->end() ? nullptr : It->second;
}

ModuleCache* FindOrRequestModule(const FEXCore::ExecutableFileSectionInfo& Section) {
  const uint64_t K = Key(Section.FileInfo.FileId, Section.FileStartVA);
  {
    std::shared_lock lk(g_Lock);
    if (auto* M = FindModule(K)) {
      return M;
    }
  }
  std::unique_lock lk(g_Lock);
  if (!g_Modules) {
    g_Modules = new fextl::robin_map<uint64_t, ModuleCache*>();
  }
  if (auto* M = FindModule(K)) {
    return M;
  }
  auto* M = new ModuleCache();
  M->FileId = Section.FileInfo.FileId;
  M->Base = Section.FileStartVA;
  M->Begin = Section.BeginVA;
  M->End = Section.EndVA;
  M->Name = LowerBaseName(Section.FileInfo.Filename);
  M->Path = FilePath(*M);
  g_Modules->emplace(K, M);
  g_WorkPending.store(true, std::memory_order_relaxed);
  return M;
}

/* Record checksums are seeded with the file identity, so a record can only ever
 * validate inside a file of the same FEX build/config and module, even if another
 * process rewrites the file under a reader's index. The base is not part of it:
 * records are stored relative to the module base (RebaseRecord). */
uint64_t RecordSeed(const ModuleCache& M) {
  return g_ConfigHash ^ M.FileId;
}

FileHeader ExpectedHeader(const ModuleCache& M) {
  FileHeader H {};
  H.Magic = FILE_MAGIC;
  H.Version = FILE_VERSION;
  H.ConfigHash = g_ConfigHash;
  H.FileId = M.FileId;
  H.FileStartVA = 0; // records are base-relative
  H.ImageSize = M.End - M.Begin;
  return H;
}

/* Index a module's file: header check, then record headers in big sequential
 * reads. Checksums are verified on use, so this touches the file once. */
void LoadModule(ModuleCache& M) {
  const uint64_t T0 = Ticks();
  uint64_t FileSize = 0;
  void* Reader = MadeiraFexCacheOpen(M.Path.c_str(), 0, &FileSize);
  fextl::robin_map<uint64_t, IndexEntry> Index;
  fextl::vector<uint8_t> Data;
  const char* Why = "no file";
  if (Reader && FileSize > g_MaxFileBytes) {
    Why = "file over MADEIRA_FEX_CODE_CACHE_MAX_MB";
  } else if (Reader && FileSize >= sizeof(FileHeader)) {
    Data.resize(FileSize);
    uint64_t Got = 0;
    while (Got < FileSize) {
      const uint32_t Want = static_cast<uint32_t>(std::min<uint64_t>(SCAN_CHUNK, FileSize - Got));
      const int64_t N = MadeiraFexCacheRead(Reader, Got, Data.data() + Got, Want);
      if (N <= 0) {
        break;
      }
      Got += static_cast<uint64_t>(N);
    }
    FileSize = Got;
    Data.resize(Got);
  }
  if (Reader) {
    MadeiraFexCacheClose(Reader);
  }
  if (FileSize >= sizeof(FileHeader) && Data.size() >= sizeof(FileHeader)) {
    FileHeader H {};
    const FileHeader E = ExpectedHeader(M);
    memcpy(&H, Data.data(), sizeof(H));
    if (H.Magic != FILE_MAGIC || H.Version != FILE_VERSION) {
      Why = "bad header";
    } else if (H.ConfigHash != E.ConfigHash) {
      Why = "FEX build or codegen config changed";
    } else if (H.FileId != E.FileId || H.FileStartVA != E.FileStartVA || H.ImageSize != E.ImageSize) {
      Why = "module identity changed";
    } else {
      Why = nullptr;
      M.HeaderOk = true;
      M.ValidEnd = sizeof(FileHeader);
      uint64_t Off = sizeof(FileHeader);
      while (Off + sizeof(RecordHeader) <= FileSize) {
        RecordHeader R;
        memcpy(&R, Data.data() + Off, sizeof(R));
        if (R.Magic != RECORD_MAGIC || R.TotalSize < sizeof(RecordHeader) || R.TotalSize > MAX_RECORD_SIZE || (R.TotalSize & 7) ||
            Off + R.TotalSize > FileSize) {
          break; // torn or foreign tail: everything from here is cut on the next write
        }
        Index[R.GuestRIP + M.Base] = {Off, R.TotalSize, false};
        Off += R.TotalSize;
        M.ValidEnd = Off;
      }
    }
  }
  Data.resize(M.HeaderOk ? M.ValidEnd : 0);
  const size_t N = Index.size();
  {
    std::unique_lock lk(g_Lock);
    M.Data.swap(Data);
    for (auto& [Rip, E] : Index) {
      M.Index.try_emplace(Rip, E);
    }
    M.State.store(ModState::Loaded, std::memory_order_release);
  }
  Bump(g_Stats.BlocksLoaded, N);
  const double Ms = 1000.0 * double(Ticks() - T0) / double(TickFreq());
  if (Why) {
    LogMan::Msg::EFmt("[fex-cache] ml2400 {} base={:#x}: starting empty ({}) {}", M.Name, M.Base, Why, M.Path);
  } else {
    LogMan::Msg::EFmt("[fex-cache] ml2400 {} base={:#x}: loaded {} blocks, {} KB indexed in {:.1f} ms{}", M.Name, M.Base, N,
                      M.ValidEnd / 1024, Ms, M.ValidEnd < FileSize ? " (torn tail ignored)" : "");
  }
}

void FlushModule(ModuleCache& M, const char* Why) {
  fextl::vector<uint8_t> Out;
  uint32_t Blocks;
  {
    std::unique_lock lk(g_Lock);
    if (M.Pending.empty()) {
      return;
    }
    Out.swap(M.Pending);
    Blocks = M.PendingBlocks;
    M.PendingBlocks = 0;
  }
  g_PendingTotal.fetch_sub(Out.size(), std::memory_order_relaxed);
  if (M.State.load(std::memory_order_acquire) == ModState::Poisoned) {
    return;
  }
  if (!M.Writer && !M.WriterFailed) {
    MadeiraFexCacheMakeDir(g_Dir.c_str());
    uint64_t Size = 0;
    M.Writer = MadeiraFexCacheOpen(M.Path.c_str(), 1, &Size);
    if (!M.Writer) {
      M.WriterFailed = true;
      LogMan::Msg::EFmt("[fex-cache] ml2400 {}: cannot open for writing (another process using it, or no space) - not saving {}",
                        M.Name, M.Path);
    } else if (!M.HeaderOk) {
      const FileHeader H = ExpectedHeader(M);
      if (MadeiraFexCacheWrite(M.Writer, 0, &H, sizeof(H)) == sizeof(H)) {
        M.HeaderOk = true;
        M.ValidEnd = sizeof(H);
      } else {
        M.WriterFailed = true;
      }
    }
  }
  if (M.WriterFailed || !M.Writer) {
    Bump(g_Stats.Dropped, Blocks);
    return;
  }
  if (M.ValidEnd + Out.size() > g_MaxFileBytes) {
    std::unique_lock lk(g_Lock);
    M.Full = true;
    Bump(g_Stats.Dropped, Blocks);
    LogMan::Msg::EFmt("[fex-cache] ml2400 {}: file would pass {} MB (MADEIRA_FEX_CODE_CACHE_MAX_MB) - recording stopped", M.Name,
                      g_MaxFileBytes >> 20);
    return;
  }
  const uint64_t At = M.ValidEnd;
  if (MadeiraFexCacheWrite(M.Writer, At, Out.data(), static_cast<uint32_t>(Out.size())) != static_cast<int64_t>(Out.size())) {
    // Possibly a partial record now sits at At; the next load stops there and the next write overwrites it.
    M.WriterFailed = true;
    Bump(g_Stats.Dropped, Blocks);
    LogMan::Msg::EFmt("[fex-cache] ml2400 {}: write of {} KB failed - not saving further", M.Name, Out.size() / 1024);
    return;
  }
  M.ValidEnd = At + Out.size();
  MadeiraFexCacheSetEnd(M.Writer, M.ValidEnd); // cuts any torn tail left by an earlier crash
  // This session's records become installable too (e.g. after a code buffer clear).
  {
    std::unique_lock lk(g_Lock);
    if (M.Data.size() < sizeof(FileHeader)) {
      const FileHeader H = ExpectedHeader(M);
      M.Data.assign(reinterpret_cast<const uint8_t*>(&H), reinterpret_cast<const uint8_t*>(&H) + sizeof(H));
    }
    M.Data.resize(At);
    M.Data.insert(M.Data.end(), Out.begin(), Out.end());
    for (size_t Off = 0; Off + sizeof(RecordHeader) <= Out.size();) {
      RecordHeader R;
      memcpy(&R, Out.data() + Off, sizeof(R));
      M.Index[R.GuestRIP + M.Base] = {At + Off, R.TotalSize, false};
      Off += R.TotalSize;
    }
  }
  Bump(g_Stats.BlocksWritten, Blocks);
  Bump(g_Stats.BytesWritten, Out.size());
  LogMan::Msg::EFmt("[fex-cache] ml2400 {}: wrote {} blocks ({} KB, file {} KB) [{}]", M.Name, Blocks, Out.size() / 1024,
                    M.ValidEnd / 1024, Why);
}

void LoadRequested() {
  fextl::vector<ModuleCache*> ToLoad;
  {
    std::shared_lock lk(g_Lock);
    if (g_Modules) {
      for (auto& [K, M] : *g_Modules) {
        if (M->State.load(std::memory_order_acquire) == ModState::Requested) {
          ToLoad.push_back(M);
        }
      }
    }
  }
  for (auto* M : ToLoad) {
    LoadModule(*M);
  }
}

void FlushAll(const char* Why) {
  fextl::vector<ModuleCache*> Mods;
  {
    std::shared_lock lk(g_Lock);
    if (g_Modules) {
      for (auto& [K, M] : *g_Modules) {
        if (M->State.load(std::memory_order_acquire) != ModState::Requested) {
          Mods.push_back(M);
        }
      }
    }
  }
  for (auto* M : Mods) {
    FlushModule(*M, Why);
  }
  g_LastFlushTick.store(Ticks(), std::memory_order_relaxed);
}

bool ReadRecord(ModuleCache& M, const IndexEntry& E, fextl::vector<uint8_t>& Buf) {
  std::shared_lock lk(g_Lock);
  if (E.Offset + E.Size > M.Data.size()) {
    return false;
  }
  Buf.assign(M.Data.begin() + E.Offset, M.Data.begin() + E.Offset + E.Size);
  return true;
}

/* The exact instructions Arm64Emitter::LoadConstant emits for a 64-bit DOPAD move,
 * which is what InsertGuestRIPMove produces while the cache is on: re-emitting a
 * RIP move for a new base gives the bytes a fresh compile would, so VERIFY still
 * compares byte for byte. */
void EncodeRIPMove(uint32_t Rd, uint64_t C, uint32_t Out[4]) {
  constexpr uint32_t NOP = 0xD503201F, MOVZ = 0xD2800000, MOVK = 0xF2800000, MOVN = 0x92800000, ORR_IMM = 0xB2000000;
  int N = 0;
  auto Emit = [&](uint32_t I) { Out[N++] = I; };
  auto Wide = [&](uint32_t Op, uint64_t Imm, uint32_t Shift) { Emit(Op | ((Shift / 16) << 21) | (uint32_t(Imm & 0xFFFF) << 5) | Rd); };
  if (((~C) >> 16) == 0) {
    Emit(NOP), Emit(NOP), Emit(NOP), Wide(MOVN, ~C, 0);
    return;
  }
  int Required = 0;
  for (int i = 0; i < 4; ++i) {
    Required += ((C >> (i * 16)) & 0xFFFF) != 0;
  }
  uint32_t n, imms, immr;
  if (Required > 1 && ARMEmitter::Emitter::IsImmLogical(C, 64, &n, &imms, &immr)) {
    Emit(NOP), Emit(NOP), Emit(NOP), Emit(ORR_IMM | (n << 22) | (immr << 16) | (imms << 10) | (31u << 5) | Rd);
    return;
  }
  if (((~C) >> 32) == 0) {
    Emit(NOP), Emit(NOP), Wide(MOVN, ~C, 0), Wide(MOVK, C >> 16, 16);
    return;
  }
  int Seg = 0;
  for (; Seg < 4; ++Seg) {
    if ((C >> (Seg * 16)) & 0xFFFF) {
      Wide(MOVZ, C >> (Seg * 16), Seg * 16);
      ++Seg;
      break;
    }
  }
  for (; Seg < 4; ++Seg) {
    if ((C >> (Seg * 16)) & 0xFFFF) {
      Wide(MOVK, C >> (Seg * 16), Seg * 16);
    }
  }
  if (N == 0) {
    Wide(MOVZ, 0, 0);
  }
  while (N < 4) {
    Emit(NOP);
  }
}

/* Moves every guest address in a record between this load (absolute) and the file
 * (relative to the module base). ToFile also proves the block is relocatable: each
 * RIP move must be the padded four-instruction form, and each RIP-derived value must
 * be within 2 GB of the block (a 32-bit masked EntrypointOffset is not). On load the
 * literals are rewritten and the moves re-emitted for this base. */
bool RebaseRecord(uint8_t* Buf, size_t Size, uint64_t Base, bool ToFile) {
  if (Size < sizeof(RecordHeader)) {
    return false;
  }
  RecordHeader H;
  memcpy(&H, Buf, sizeof(H));
  const uint64_t Need = sizeof(RecordHeader) + uint64_t(H.NumRanges) * sizeof(GuestRange) + uint64_t(H.NumCodePages) * 8 +
                        uint64_t(H.NumEntries) * sizeof(EntryRec) + uint64_t(H.NumGuestEntryPoints) * 8 +
                        uint64_t(H.NumRelocs) * sizeof(RelocRec) + uint64_t(H.NumEcQueries) * sizeof(EcRec) + AlignUp(H.CodeSize, 8);
  if (Need != Size || H.TotalSize != Size) {
    return false;
  }
  auto Move = [&](uint64_t V) { return ToFile ? V - Base : V + Base; };
  const uint64_t BlockRIP = H.GuestRIP; // in the frame the record is in now
  auto Near = [&](uint64_t V) { return uint64_t(int64_t(V - BlockRIP) + (int64_t(1) << 31)) < (uint64_t(1) << 32); };
  uint8_t* Cur = Buf + sizeof(RecordHeader);
  auto* Ranges = reinterpret_cast<GuestRange*>(Cur);
  Cur += H.NumRanges * sizeof(GuestRange);
  auto* Pages = reinterpret_cast<uint64_t*>(Cur);
  Cur += H.NumCodePages * 8;
  auto* Entries = reinterpret_cast<EntryRec*>(Cur);
  Cur += H.NumEntries * sizeof(EntryRec);
  auto* EntryPoints = reinterpret_cast<uint64_t*>(Cur);
  Cur += H.NumGuestEntryPoints * 8;
  auto* Relocs = reinterpret_cast<RelocRec*>(Cur);
  Cur += H.NumRelocs * sizeof(RelocRec);
  auto* Ec = reinterpret_cast<EcRec*>(Cur);
  Cur += H.NumEcQueries * sizeof(EcRec);
  uint8_t* Code = Cur;

  for (uint32_t i = 0; i < H.NumRelocs; ++i) {
    auto& R = Relocs[i];
    const auto Kind = static_cast<RelocKind>(R.Kind);
    if (Kind != RelocKind::GuestRIPLiteral && Kind != RelocKind::GuestRIPMove) {
      continue;
    }
    if (ToFile && !Near(R.Value)) {
      return false;
    }
    if (Kind == RelocKind::GuestRIPLiteral) {
      uint64_t V;
      if (uint64_t(R.Offset) + 8 > H.CodeSize) {
        return false;
      }
      memcpy(&V, Code + R.Offset, 8);
      if (V != R.Value) {
        return false;
      }
      R.Value = Move(R.Value);
      memcpy(Code + R.Offset, &R.Value, 8);
    } else {
      uint32_t Old[4], Want[4];
      if (uint64_t(R.Offset) + 16 > H.CodeSize) {
        return false;
      }
      memcpy(Old, Code + R.Offset, 16);
      uint32_t Rd = 32;
      for (uint32_t I : Old) {
        if (I != 0xD503201F) {
          Rd = I & 31;
          break;
        }
      }
      if (Rd == 32) {
        return false;
      }
      if (ToFile) {
        EncodeRIPMove(Rd, R.Value, Want);
        if (memcmp(Old, Want, 16) != 0) {
          return false; // not the padded form: compiled before the cache was on
        }
      }
      R.Value = Move(R.Value);
      if (!ToFile) {
        EncodeRIPMove(Rd, R.Value, Want);
        memcpy(Code + R.Offset, Want, 16);
      }
    }
  }
  for (uint32_t i = 0; i < H.NumEcQueries; ++i) {
    const uint64_t Kind = Ec[i].Query & (1ULL << 63), Addr = Ec[i].Query & ~(1ULL << 63);
    if (ToFile && !Near(Addr)) {
      return false;
    }
    Ec[i].Query = (Move(Addr) & ~(1ULL << 63)) | Kind;
  }
  for (uint32_t i = 0; i < H.NumRanges; ++i) {
    Ranges[i].Start = Move(Ranges[i].Start);
  }
  for (uint32_t i = 0; i < H.NumCodePages; ++i) {
    Pages[i] = Move(Pages[i]);
  }
  for (uint32_t i = 0; i < H.NumEntries; ++i) {
    Entries[i].Guest = Move(Entries[i].Guest);
  }
  for (uint32_t i = 0; i < H.NumGuestEntryPoints; ++i) {
    EntryPoints[i] = Move(EntryPoints[i]);
  }
  H.GuestRIP = Move(H.GuestRIP);
  memcpy(Buf, &H, sizeof(H));
  return true;
}

struct ParsedRecord {
  const RecordHeader* H;
  const GuestRange* Ranges;
  const uint64_t* CodePages;
  const EntryRec* Entries;
  const uint64_t* GuestEntryPoints;
  const RelocRec* Relocs;
  const EcRec* Ec;
  const uint8_t* Code;
};

// Structure, bounds and self-consistency. Everything checked against the CURRENT process is separate.
// Rebased: Buf already went through this (TryInstall, then SealCapture's verify compare).
bool ParseRecord(fextl::vector<uint8_t>& Buf, uint64_t GuestRIP, const ModuleCache& M, ParsedRecord& P, Reject& Why, bool Rebased) {
  Why = R_LAYOUT;
  if (Buf.size() < sizeof(RecordHeader)) {
    return false;
  }
  P.H = reinterpret_cast<const RecordHeader*>(Buf.data());
  const RecordHeader& H = *P.H;
  if (H.Magic != RECORD_MAGIC || H.TotalSize != Buf.size()) {
    return false;
  }
  if (!Rebased) {
    if (XXH3_64bits_withSeed(Buf.data() + 16, Buf.size() - 16, RecordSeed(M)) != H.Checksum) {
      Why = R_CHECKSUM;
      return false;
    }
    if (!RebaseRecord(Buf.data(), Buf.size(), M.Base, false)) {
      return false;
    }
  }
  const uint64_t Need = sizeof(RecordHeader) + uint64_t(H.NumRanges) * sizeof(GuestRange) + uint64_t(H.NumCodePages) * 8 +
                        uint64_t(H.NumEntries) * sizeof(EntryRec) + uint64_t(H.NumGuestEntryPoints) * 8 +
                        uint64_t(H.NumRelocs) * sizeof(RelocRec) + uint64_t(H.NumEcQueries) * sizeof(EcRec) + AlignUp(H.CodeSize, 8);
  using JITCodeHeader = FEXCore::CPU::CPUBackend::JITCodeHeader;
  using JITCodeTail = FEXCore::CPU::CPUBackend::JITCodeTail;
  if (Need != H.TotalSize || H.GuestRIP != GuestRIP || H.NumRanges == 0 || H.NumEntries == 0 ||
      H.CodeSize < sizeof(JITCodeHeader) + sizeof(JITCodeTail) || (H.CodeSize & 3)) {
    return false;
  }
  const uint8_t* Cur = Buf.data() + sizeof(RecordHeader);
  P.Ranges = reinterpret_cast<const GuestRange*>(Cur);
  Cur += H.NumRanges * sizeof(GuestRange);
  P.CodePages = reinterpret_cast<const uint64_t*>(Cur);
  Cur += H.NumCodePages * 8;
  P.Entries = reinterpret_cast<const EntryRec*>(Cur);
  Cur += H.NumEntries * sizeof(EntryRec);
  P.GuestEntryPoints = reinterpret_cast<const uint64_t*>(Cur);
  Cur += H.NumGuestEntryPoints * 8;
  P.Relocs = reinterpret_cast<const RelocRec*>(Cur);
  Cur += H.NumRelocs * sizeof(RelocRec);
  P.Ec = reinterpret_cast<const EcRec*>(Cur);
  Cur += H.NumEcQueries * sizeof(EcRec);
  P.Code = Cur;

  uint32_t TailOff;
  memcpy(&TailOff, P.Code, sizeof(TailOff));
  if (TailOff > H.CodeSize - sizeof(JITCodeTail) || (TailOff & 7)) {
    return false;
  }
  JITCodeTail Tail;
  memcpy(&Tail, P.Code + TailOff, sizeof(Tail));
  if (Tail.Size != H.CodeSize || Tail.RIP != GuestRIP) {
    return false;
  }
  bool HasEntry = false;
  for (uint32_t i = 0; i < H.NumEntries; ++i) {
    const auto& E = P.Entries[i];
    if (E.HostOffset < sizeof(JITCodeHeader) || E.HostOffset >= TailOff || (E.HostOffset & 3) || E.Guest < M.Begin || E.Guest >= M.End) {
      return false;
    }
    HasEntry |= E.Guest == GuestRIP;
  }
  if (!HasEntry) {
    return false;
  }
  for (uint32_t i = 0; i < H.NumRelocs; ++i) {
    const auto& R = P.Relocs[i];
    switch (static_cast<RelocKind>(R.Kind)) {
    case RelocKind::ExitLinkerLiteral:
      if (R.Value != uint64_t(FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol::SYMBOL_LITERAL_EXITFUNCTION_LINKER) ||
          uint64_t(R.Offset) + 8 > H.CodeSize) {
        return false;
      }
      break;
    case RelocKind::GuestRIPLiteral: {
      // RebaseRecord wrote the literal for this base. A mismatch means a corrupt record.
      uint64_t V;
      if (uint64_t(R.Offset) + 8 > H.CodeSize) {
        return false;
      }
      memcpy(&V, P.Code + R.Offset, 8);
      if (V != R.Value) {
        return false;
      }
      break;
    }
    case RelocKind::GuestRIPMove:
      if (uint64_t(R.Offset) + 16 > H.CodeSize) {
        return false;
      }
      break;
    default: return false;
    }
  }
  Why = R_RANGE;
  for (uint32_t i = 0; i < H.NumRanges; ++i) {
    const auto& R = P.Ranges[i];
    if (R.Size == 0 || R.Size > MAX_RANGE_SIZE || R.Start < M.Begin || R.Start + R.Size > M.End) {
      return false;
    }
  }
  for (uint32_t i = 0; i < H.NumCodePages; ++i) {
    const uint64_t Page = P.CodePages[i];
    if ((Page & (FEXCore::Utils::FEX_PAGE_SIZE - 1)) || Page + FEXCore::Utils::FEX_PAGE_SIZE <= M.Begin || Page >= M.End) {
      return false;
    }
  }
  for (uint32_t i = 0; i < H.NumGuestEntryPoints; ++i) {
    if (P.GuestEntryPoints[i] < M.Begin || P.GuestEntryPoints[i] >= M.End) {
      return false;
    }
  }
  return true;
}

// Against the current process: guest bytes, executability, EC answers, Mono state.
bool StillValid(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread, const ParsedRecord& P,
                bool MonoBlockNow, Reject& Why) {
  const RecordHeader& H = *P.H;
  Why = R_MONO;
  const bool MonoNow = CTX->AreMonoHacksActive();
  if (MonoBlockNow || ((H.Flags & FLAG_MONO_HACKS) != 0) != MonoNow) {
    return false;
  }
  for (uint32_t i = 0; i < H.NumRanges; ++i) {
    // ml954: a sub-floor image's bytes are read from its backing, not the guest address.
    if (IosSubfloorToReal(P.Ranges[i].Start) != P.Ranges[i].Start) {
      Why = R_SUBFLOOR;
      return false;
    }
    if (!RangeExecutable(CTX, Thread, P.Ranges[i].Start, P.Ranges[i].Size)) {
      Why = R_NOT_EXEC;
      return false;
    }
  }
  Why = R_GUEST_HASH;
  uint64_t Hash[2];
  HashGuestRanges(CTX, H.GuestRIP, P.Ranges, H.NumRanges, Hash);
  if (Hash[0] != H.GuestHash[0] || Hash[1] != H.GuestHash[1]) {
    return false;
  }
  Why = R_EC;
  for (uint32_t i = 0; i < H.NumEcQueries; ++i) {
    if (EcAnswer(P.Ec[i].Query) != (P.Ec[i].Answer != 0)) {
      return false;
    }
  }
  return true;
}

void MarkRejected(ModuleCache& M, uint64_t GuestRIP) {
  std::unique_lock lk(g_Lock);
  if (auto It = M.Index.find(GuestRIP); It != M.Index.end()) {
    It->second.Rejected = true;
  }
}

void Poison(ModuleCache& M, const fextl::string& Why) {
  M.State.store(ModState::Poisoned, std::memory_order_release);
  LogMan::Msg::EFmt("[fex-cache] ml2400 {}: cache DISABLED for this module: {}", M.Name, Why);
}

/* Apply the install-time relocations to a copy (verify compare uses the same). */
void PatchRelocs(FEXCore::Context::ContextImpl* CTX, const ParsedRecord& P, uint8_t* Code) {
  for (uint32_t i = 0; i < P.H->NumRelocs; ++i) {
    const auto& R = P.Relocs[i];
    if (static_cast<RelocKind>(R.Kind) == RelocKind::ExitLinkerLiteral) {
      const uint64_t V = FEXCore::CPU::GetNamedSymbolLiteral(*CTX, FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol::SYMBOL_LITERAL_EXITFUNCTION_LINKER);
      memcpy(Code + R.Offset, &V, 8);
    }
    // Guest RIP literals/moves were rewritten for this base by RebaseRecord.
  }
}
} // namespace

bool ResolveEnabled(FEXCore::Context::ContextImpl* CTX) {
  static std::mutex InitLock;
  std::scoped_lock lk(InitLock);
  int S = g_State.load(std::memory_order_relaxed);
  if (S >= 0) {
    return S == 1;
  }
  const char* E = getenv("MADEIRA_FEX_CODE_CACHE");
  bool On = E && E[0] == '1';
  // Steam's own processes stay uncached (dockhost.exe is Madeira's dock, which loads
  // steamclient64.dll): with the cache on, the dock deadlocked at
  // start (a new thread holding the code lock waited on the process heap, whose
  // holder waited to invalidate code: stuck on "Loading Steam", Oct 17). The game
  // is what gains from the cache. MADEIRA_FEX_CODE_CACHE_STEAM=1 includes them.
  if (On) {
    char Name[64];
    MadeiraFexCacheProcessName(Name, sizeof(Name));
    const char* S = getenv("MADEIRA_FEX_CODE_CACHE_STEAM");
    if ((!S || S[0] != '1') && (!strncmp(Name, "steam", 5) || !strcmp(Name, "dockhost.exe") || !strcmp(Name, "gameoverlayui.exe"))) {
      LogMan::Msg::EFmt("[fex-cache] ml2400 off for {} (Steam client process)", Name);
      On = false;
    }
  }
  if (On) {
    const char* Dir = getenv("MADEIRA_FEX_CACHE_DIR");
    g_Dir = (Dir && Dir[0]) ? Dir : "C:\\users\\Public\\madeira-fex-cache";
    while (!g_Dir.empty() && (g_Dir.back() == '\\' || g_Dir.back() == '/')) {
      g_Dir.pop_back();
    }
    if (const char* Max = getenv("MADEIRA_FEX_CODE_CACHE_MAX_MB"); Max && atoi(Max) > 0) {
      g_MaxFileBytes = uint64_t(atoi(Max)) << 20;
    }
    const char* V = getenv("MADEIRA_FEX_CODE_CACHE_VERIFY");
    g_Verify = V && V[0] == '1';
    g_ConfigHash = ComputeConfigHash(CTX);
    g_LastFlushTick.store(Ticks(), std::memory_order_relaxed);
    LogMan::Msg::EFmt("[fex-cache] ml2400 on: dir={} config={:016x} max={} MB per module{}", g_Dir, g_ConfigHash, g_MaxFileBytes >> 20,
                      g_Verify ? " VERIFY (every hit is also compiled and compared)" : "");
  }
  g_State.store(On ? 1 : 0, std::memory_order_release);
  return On;
}

void DoPendingWork(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread) {
  if (g_Busy.exchange(true, std::memory_order_acquire)) {
    return; // another thread is at it; the flag stays set for whatever it leaves
  }
  g_WorkPending.store(false, std::memory_order_relaxed);
  LoadRequested();
  const size_t Pending = g_PendingTotal.load(std::memory_order_relaxed);
  if (Pending >= FLUSH_PENDING_BYTES || (Pending && Ticks() - g_LastFlushTick.load(std::memory_order_relaxed) >= FLUSH_INTERVAL_S * TickFreq())) {
    FlushAll("periodic");
  }
  g_Busy.store(false, std::memory_order_release);
}

void NoteEcQuery(FEXCore::Core::InternalThreadState* Thread, EcQueryKind Kind, uint64_t Address, bool Answer) {
  auto& C = Thread->CPUBackend->MadeiraCapture;
  if (C.Active) {
    C.EcQueries.emplace_back(Address | (static_cast<uint64_t>(Kind) << 63), Answer ? 1 : 0);
  }
}

void ArmCapture(FEXCore::Core::InternalThreadState* Thread, bool Armed) {
  auto& C = Thread->CPUBackend->MadeiraCapture;
  C.Active = Armed;
  C.Valid = false;
  C.Sealed = false;
  C.Uncacheable = false;
  C.EcQueries.clear();
  C.Ranges.clear();
}

bool TryInstall(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, bool MonoBlockNow,
                FEXCore::CPU::CPUBackend::CompiledCode& OutCode, fextl::unique_ptr<FEXCore::Core::DebugData>& OutDebug,
                InstalledBlock& Out) {
  auto& C = Thread->CPUBackend->MadeiraCapture;
  C.VerifyRIP = 0;
  auto Section = CTX->SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
  if (!Section || Section->FileStartVA == 0 || Section->FileInfo.FileId == 0 || Section->FileInfo.FileId == ~0ULL) {
    return false;
  }
  ModuleCache* M = FindOrRequestModule(*Section);
  const ModState St = M->State.load(std::memory_order_acquire);
  if (St != ModState::Loaded) {
    if (St == ModState::Requested) {
      Bump(g_Stats.NotReady);
    }
    return false;
  }
  IndexEntry E;
  {
    std::shared_lock lk(g_Lock);
    auto It = M->Index.find(GuestRIP);
    if (It == M->Index.end() || It->second.Rejected) {
      Bump(g_Stats.Misses);
      Report(false);
      return false;
    }
    E = It->second;
  }
  if (!ReadRecord(*M, E, C.Scratch)) {
    CountReject(R_READ);
    return false;
  }
  ParsedRecord P;
  Reject Why;
  if (!ParseRecord(C.Scratch, GuestRIP, *M, P, Why, false)) {
    MarkRejected(*M, GuestRIP);
    CountReject(Why);
    return false;
  }
  {
    uint64_t Low, Size, Real;
    if (IosSubfloorWindowForCode(GuestRIP, &Low, &Size, &Real)) {
      CountReject(R_SUBFLOOR);
      return false;
    }
  }
  if (!StillValid(CTX, Thread, P, MonoBlockNow, Why)) {
    // Different guest bytes: let this run record the current version (a later record for the
    // same RIP wins on the next load). Executability, EC and Mono state are transient: no mark.
    if (Why == R_GUEST_HASH) {
      MarkRejected(*M, GuestRIP);
    }
    CountReject(Why);
    return false;
  }
  if (g_Verify) {
    C.VerifyRIP = GuestRIP; // compile normally; SealCapture compares
    return false;
  }

  fextl::vector<std::pair<uint64_t, uint32_t>> Entries;
  Entries.reserve(P.H->NumEntries);
  for (uint32_t i = 0; i < P.H->NumEntries; ++i) {
    Entries.emplace_back(P.Entries[i].Guest, static_cast<uint32_t>(P.Entries[i].HostOffset));
  }
  fextl::vector<uint64_t> LinkerLiterals;
  for (uint32_t i = 0; i < P.H->NumRelocs; ++i) {
    if (static_cast<RelocKind>(P.Relocs[i].Kind) == RelocKind::ExitLinkerLiteral) {
      LinkerLiterals.push_back(P.Relocs[i].Offset);
    }
  }
  OutDebug = fextl::make_unique<FEXCore::Core::DebugData>();
  OutCode = Thread->CPUBackend->InstallCachedCode(GuestRIP, P.Code, P.H->CodeSize, LinkerLiterals, Entries, OutDebug.get());
  if (!OutCode.BlockBegin || !OutCode.EntryPoints.contains(GuestRIP)) {
    OutDebug.reset();
    CountReject(R_INSTALL);
    return false;
  }
  Out.GuestEntryPoints.clear();
  for (uint32_t i = 0; i < P.H->NumGuestEntryPoints; ++i) {
    Out.GuestEntryPoints.insert(P.GuestEntryPoints[i]);
  }
  Out.CodePages.assign(P.CodePages, P.CodePages + P.H->NumCodePages);
  uint64_t Lo = ~0ULL, Hi = 0;
  for (uint32_t i = 0; i < P.H->NumRanges; ++i) {
    Lo = std::min(Lo, P.Ranges[i].Start);
    Hi = std::max(Hi, P.Ranges[i].Start + P.Ranges[i].Size);
  }
  Out.StartAddr = Lo;
  Out.Length = Hi - Lo;
  Bump(g_Stats.Hits);
  Bump(g_Stats.InstalledBytes, P.H->CodeSize);
  Report(false);
  return true;
}

/* Right after a normal compile, before publication makes the block reachable:
 * the captured image must be exactly what was published (and nothing linked yet),
 * and the guest bytes are hashed for the first time. */
void SealCapture(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP,
                 const FEXCore::CPU::CPUBackend::CompiledCode& Code) {
  auto& C = Thread->CPUBackend->MadeiraCapture;
  if (!C.Active || !C.Valid) {
    return;
  }
  C.Active = false;
  if (C.Entry != GuestRIP || !Code.BlockBegin || Code.Size != C.Code.size() ||
      memcmp(FEXCore::DualMap::WriteAddr(Code.BlockBegin), C.Code.data(), C.Code.size()) != 0) {
    C.Valid = false;
    return;
  }
  /* The decoder state must still be this compile's: an ml455 delivery compile
   * nested inside it would have redecoded on this thread. Its entry block is
   * GuestRIP and its entry set contains GuestRIP, or nothing is recorded. */
  const auto* BI = Thread->FrontendDecoder->GetDecodedBlockInfo();
  C.Ranges.clear();
  bool HasEntryBlock = false;
  for (const auto& B : BI->Blocks) {
    if (B.ForceFullSMCDetection) {
      C.Uncacheable = true;
    }
    HasEntryBlock |= B.Entry == GuestRIP;
    if (B.Size) {
      C.Ranges.push_back({B.Entry, B.Size});
    }
  }
  if (C.Ranges.empty() || !HasEntryBlock || !BI->EntryPoints.contains(GuestRIP)) {
    C.Valid = false;
    return;
  }
  C.CodePages.assign(BI->CodePages.begin(), BI->CodePages.end());
  C.GuestEntryPoints.assign(BI->EntryPoints.begin(), BI->EntryPoints.end());
  HashGuestRanges(CTX, GuestRIP, C.Ranges.data(), C.Ranges.size(), C.GuestHash);
  C.Sealed = true;

  if (g_Verify && C.VerifyRIP == GuestRIP) {
    C.VerifyRIP = 0;
    ParsedRecord P;
    Reject Why;
    auto Section = CTX->SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    ModuleCache* M = Section ? FindOrRequestModule(*Section) : nullptr;
    if (!M || !ParseRecord(C.Scratch, GuestRIP, *M, P, Why, true)) {
      return;
    }
    fextl::vector<uint8_t> Patched(P.Code, P.Code + P.H->CodeSize);
    PatchRelocs(CTX, P, Patched.data());
    const bool Same = Patched.size() == C.Code.size() && memcmp(Patched.data(), C.Code.data(), Patched.size()) == 0;
    if (Same) {
      Bump(g_Stats.VerifyOk);
      Report(false);
      return;
    }
    Bump(g_Stats.VerifyBad);
    size_t At = 0;
    while (At < std::min(Patched.size(), C.Code.size()) && Patched[At] == C.Code[At]) {
      ++At;
    }
    LogMan::Msg::EFmt("[fex-cache] ml2400 VERIFY MISMATCH rip={:#x} cached={} B fresh={} B first difference at +{:#x}", GuestRIP,
                      Patched.size(), C.Code.size(), At);
    Poison(*M, fextl::fmt::format("verify mismatch at rip {:#x}", GuestRIP));
    Report(true);
  }
}

/* After publication: the pages are write-protected now, so hashing again and
 * getting the same answer means the bytes did not change under the compile. */
void Record(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP,
            const FEXCore::CPU::CPUBackend::CompiledCode& Code, bool MonoBlockNow) {
  auto& C = Thread->CPUBackend->MadeiraCapture;
  if (!C.Sealed) {
    return;
  }
  C.Sealed = false;
  C.Valid = false;
  if (C.Uncacheable || MonoBlockNow) {
    Bump(g_Stats.RecordSkipped);
    return;
  }
  {
    uint64_t Low, Size, Real;
    if (IosSubfloorWindowForCode(GuestRIP, &Low, &Size, &Real)) {
      Bump(g_Stats.RecordSkipped);
      return;
    }
  }
  auto Section = CTX->SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
  if (!Section || Section->FileStartVA == 0 || Section->FileInfo.FileId == 0 || Section->FileInfo.FileId == ~0ULL) {
    return;
  }
  ModuleCache* M = FindOrRequestModule(*Section);
  if (M->State.load(std::memory_order_acquire) == ModState::Poisoned) {
    return;
  }
  for (const auto& R : C.Ranges) {
    if (R.Start < M->Begin || R.Start + R.Size > M->End || R.Size > MAX_RANGE_SIZE || IosSubfloorToReal(R.Start) != R.Start) {
      Bump(g_Stats.RecordSkipped);
      return;
    }
  }
  for (uint64_t Page : C.CodePages) {
    if (Page + FEXCore::Utils::FEX_PAGE_SIZE <= M->Begin || Page >= M->End) {
      Bump(g_Stats.RecordSkipped);
      return;
    }
  }
  for (uint64_t EP : C.GuestEntryPoints) {
    if (EP < M->Begin || EP >= M->End) {
      Bump(g_Stats.RecordSkipped);
      return;
    }
  }
  for (const auto& [Guest, Host] : Code.EntryPoints) {
    if (Guest < M->Begin || Guest >= M->End) {
      Bump(g_Stats.RecordSkipped);
      return;
    }
  }
  if (C.Code.size() > MAX_RECORD_SIZE / 2 || C.Ranges.size() > 0xffff || C.CodePages.size() > 0xffff ||
      Code.EntryPoints.size() > 0xffff || C.GuestEntryPoints.size() > 0xffff || C.Relocs.size() > 0xffff || C.EcQueries.size() > 0xffff) {
    Bump(g_Stats.RecordSkipped);
    return;
  }
  uint64_t Again[2];
  HashGuestRanges(CTX, GuestRIP, C.Ranges.data(), C.Ranges.size(), Again);
  if (Again[0] != C.GuestHash[0] || Again[1] != C.GuestHash[1]) {
    Bump(g_Stats.RecordSkipped);
    return;
  }
  {
    std::shared_lock lk(g_Lock);
    if (M->Full || M->RecordedThisRun.contains(GuestRIP)) {
      return;
    }
    if (auto It = M->Index.find(GuestRIP); It != M->Index.end() && !It->second.Rejected) {
      return; // the file has it; a stale copy fails its guest hash and is replaced via Rejected
    }
  }
  if (g_PendingTotal.load(std::memory_order_relaxed) >= MAX_PENDING_BYTES) {
    Bump(g_Stats.Dropped);
    g_WorkPending.store(true, std::memory_order_relaxed);
    return;
  }

  RecordHeader H {};
  H.Magic = RECORD_MAGIC;
  H.GuestRIP = GuestRIP;
  H.GuestHash[0] = C.GuestHash[0];
  H.GuestHash[1] = C.GuestHash[1];
  H.Flags = CTX->AreMonoHacksActive() ? FLAG_MONO_HACKS : 0;
  H.CodeSize = static_cast<uint32_t>(C.Code.size());
  H.NumRanges = static_cast<uint16_t>(C.Ranges.size());
  H.NumCodePages = static_cast<uint16_t>(C.CodePages.size());
  H.NumEntries = static_cast<uint16_t>(Code.EntryPoints.size());
  H.NumGuestEntryPoints = static_cast<uint16_t>(C.GuestEntryPoints.size());
  H.NumRelocs = static_cast<uint16_t>(C.Relocs.size());
  H.NumEcQueries = static_cast<uint16_t>(C.EcQueries.size());
  H.TotalSize = static_cast<uint32_t>(sizeof(RecordHeader) + H.NumRanges * sizeof(GuestRange) + H.NumCodePages * 8 +
                                      H.NumEntries * sizeof(EntryRec) + H.NumGuestEntryPoints * 8 + H.NumRelocs * sizeof(RelocRec) +
                                      H.NumEcQueries * sizeof(EcRec) + AlignUp(H.CodeSize, 8));
  fextl::vector<uint8_t> Rec(H.TotalSize, 0);
  uint8_t* Cur = Rec.data() + sizeof(RecordHeader);
  auto Put = [&Cur](const void* Src, size_t Size) {
    memcpy(Cur, Src, Size);
    Cur += Size;
  };
  Put(C.Ranges.data(), C.Ranges.size() * sizeof(GuestRange));
  Put(C.CodePages.data(), C.CodePages.size() * 8);
  for (const auto& [Guest, Host] : Code.EntryPoints) {
    const EntryRec E {Guest, static_cast<uint64_t>(Host - Code.BlockBegin)};
    Put(&E, sizeof(E));
  }
  Put(C.GuestEntryPoints.data(), C.GuestEntryPoints.size() * 8);
  for (const auto& R : C.Relocs) {
    const RelocRec RR {R.Offset, R.Kind, R.Value};
    Put(&RR, sizeof(RR));
  }
  for (const auto& [Q, A] : C.EcQueries) {
    const EcRec ER {Q, A};
    Put(&ER, sizeof(ER));
  }
  Put(C.Code.data(), C.Code.size());
  memcpy(Rec.data(), &H, sizeof(H));
  if (!RebaseRecord(Rec.data(), Rec.size(), M->Base, true)) {
    Bump(g_Stats.RecordSkipped);
    return;
  }
  memcpy(&H, Rec.data(), sizeof(H));
  H.Checksum = XXH3_64bits_withSeed(Rec.data() + 16, Rec.size() - 16, RecordSeed(*M));
  memcpy(Rec.data(), &H, sizeof(H));

  bool Due = false;
  {
    std::unique_lock lk(g_Lock);
    if (!M->RecordedThisRun.insert(GuestRIP).second) {
      return;
    }
    M->Pending.insert(M->Pending.end(), Rec.begin(), Rec.end());
    M->PendingBlocks++;
    const size_t Total = g_PendingTotal.fetch_add(Rec.size(), std::memory_order_relaxed) + Rec.size();
    Due = Total >= FLUSH_PENDING_BYTES || Ticks() - g_LastFlushTick.load(std::memory_order_relaxed) >= FLUSH_INTERVAL_S * TickFreq();
  }
  Bump(g_Stats.Recorded);
  if (Due) {
    g_WorkPending.store(true, std::memory_order_relaxed);
  }
  Report(false);
}
} // namespace FEXCore::MadeiraCache

/* Process exit (ARM64EC ProcessTerm / WOW64 BTCpuProcessTerm): write what is
 * pending. Waits briefly for a safe-point worker that is already writing. */
extern "C" void MadeiraFexCodeCacheProcessTerm() {
  using namespace FEXCore::MadeiraCache;
  if (g_State.load(std::memory_order_acquire) != 1) {
    return;
  }
  bool Owned = false;
  for (int i = 0; i < 2000 && !(Owned = !g_Busy.exchange(true, std::memory_order_acquire)); ++i) {
    for (int j = 0; j < 1000; ++j) {
      __asm volatile("yield");
    }
  }
  if (!Owned) {
    // A safe-point worker is still mid-write (its thread is being terminated with us): leave the file to it.
    Report(true);
    return;
  }
  LoadRequested(); // a module first seen moments ago still gets its records written
  FlushAll("exit");
  Report(true);
  g_Busy.store(false, std::memory_order_release);
}
#endif
