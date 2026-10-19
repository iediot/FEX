// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/fextl/list.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <type_traits>

/* iOS-Madeira pns2 (pool null-safety): a failed pooled claim recovers or ends the process with a clear
 * message; it never hands out a buffer whose Ptr is NULL.
 *
 * In the iOS ARM64EC module FEXCore::Allocator::VirtualAlloc returns nullptr once the host-only FEX
 * arena is exhausted (AllocatorHooks.h, ml799), and ClaimBufferImpl recorded that nullptr as a claimed
 * buffer. DualIntrusiveAllocatorThreadPool then set List = nullptr + 8 MiB and
 * IREmitter::ResetWorkingList stored to 0x800010 (AV at libarm64ecfex.dll+0xfe770). The Frontend
 * decoder buffer and the JIT temp buffer take the same unchecked path.
 *
 * On by default only in the iOS ARM64EC module. -DFEX_IOS_POOL_NULL_SAFETY=0 opts out; =1 opts another
 * build in. With it off, this header compiles to exactly the code it had before. */
#ifndef FEX_IOS_POOL_NULL_SAFETY
#if defined(FEX_IOS_HOST) && defined(ARCHITECTURE_arm64ec)
#define FEX_IOS_POOL_NULL_SAFETY 1
#else
#define FEX_IOS_POOL_NULL_SAFETY 0
#endif
#endif

#if FEX_IOS_POOL_NULL_SAFETY
#include <thread>
#if defined(FEX_IOS_HOST) && defined(_WIN32)
// The same declaration as JIT.cpp's ml460 one (JIT.cpp includes this header, so it must match exactly).
extern "C" int32_t NtTerminateProcess(void* ProcessHandle, int32_t ExitStatus);
#endif
#endif

namespace FEXCore::Utils {
/**
 * @brief An intrusive thread pool allocator
 *
 * Requires coordination between the allocator and its clients to efficiently share memory allocations between threads.
 *
 * The `Client` in this case referring to the location in code allocating a `MemoryBuffer` from the allocator.
 *   - The client must `Claim` a buffer to allocate it
 *   - In claiming a buffer, the allocator is passed a `BufferOwnedFlag` that is updated by both the allocator and client.
 *   - When the client is done with the buffer it must `Disown` or `Unclaim` the buffer.
 *     - `Disown` the buffer when it is expected to be used again soon.
 *       - This is relatively cheap.
 *     - `Unclaim` when the buffer won't be used again for an extended period.
 *       - This is expensive and requires a mutex shared between threads
 *     - `PoolBufferWithTimedRetirement` helper class provided to help with this.
 *
 * Once the client has disowned a buffer then the allocator is free to reclaim the buffer when another thread is trying to `Claim` a new buffer.
 * The buffer getting claimed from a disowned client must have had its last use greater than the defined `DURATION` before it has a chance to get
 * reclaimed by the Allocator.
 *
 * During buffer reclaiming is also when unclaimed buffers get freed. This means active threads are able to clean up idle thread's unused memory.
 */
class IntrusivePooledAllocator {
public:
  struct MemoryBuffer;
  /**
   * @brief Container for tracking the buffers
   *
   * We're using fextl::list explicitly because its iterators aren't invalidated when the list is adjusted.
   * if we had list types that we can atomically erase and append elements then unclaiming could be made cheaper.
   */
  using ContainerType = fextl::list<MemoryBuffer*>;
  /**
   * @brief steady_clock to ensure long running applications don't hit any timeskip problems.
   */
  using ClockType = std::chrono::steady_clock;
  /**
   * @brief Atomic flag state for letting the client know if it owns the buffer
   */
  enum class ClientFlags : uint32_t {
    FLAG_FREE = 0,
    FLAG_OWNED = 1,
    FLAG_DISOWNED = 3,
  };

  using BufferOwnedFlag = std::atomic<ClientFlags>;

  struct MemoryBuffer : public FEXCore::Allocator::FEXAllocOperators {
    MemoryBuffer(void* Ptr, size_t Size, std::chrono::time_point<ClockType> LastUsed)
      : Ptr {Ptr}
      , Size {Size}
      , LastUsed {LastUsed} {}

    void* Ptr;
    size_t Size;
    std::atomic<std::chrono::time_point<ClockType>> LastUsed;
    BufferOwnedFlag* CurrentClientOwnedFlag {};
  };
  // Ensure that the atomic objects of MemoryBuffer are lock free
  static_assert(decltype(MemoryBuffer::LastUsed) {}.is_always_lock_free, "Oops, needs to be lock free");
  static_assert(std::remove_pointer<decltype(MemoryBuffer::CurrentClientOwnedFlag)>::type {}.is_always_lock_free, "Oops, needs to be lock "
                                                                                                                  "free");

  /**
   * @brief Lets the client easily check if they own the buffer or not
   *
   * @param CurrentClientFlag Client owned flag
   *
   * @return Is the client buffer owned at the point of checking
   */
  static bool IsClientBufferOwned(BufferOwnedFlag& CurrentClientFlag) {
    return CurrentClientFlag.load() == ClientFlags::FLAG_OWNED;
  }

  /**
   * @brief Lets the client easily check if the buffer was freed
   *
   * @param CurrentClientFlag Client owned flag
   *
   * @return Is the client buffer owned at the point of checking
   */
  static bool IsClientBufferFree(BufferOwnedFlag& CurrentClientFlag) {
    return CurrentClientFlag.load() == ClientFlags::FLAG_FREE;
  }

  /**
   * @brief Allocates and claims a buffer that is tracked from the thread pool
   *
   * @param Size
   * @param CurrentClientFlag
   *
   * Once a buffer is claimed, the pool allocator can not reclaim this buffer until it is "Disowned"
   *
   * @return iterator to the internal tracking container
   */
  ContainerType::iterator ClaimBuffer(size_t Size, BufferOwnedFlag* CurrentClientFlag) {
    std::unique_lock lk {AllocationMutex};
    auto Buffer = ClaimBufferImpl(Size);
#if FEX_IOS_POOL_NULL_SAFETY
    if (Buffer == ClaimedBuffers.end()) {
      Buffer = ClaimBufferAfterAllocFailure(lk, Size);
    }
#endif
    (*Buffer)->CurrentClientOwnedFlag = CurrentClientFlag;
    CurrentClientFlag->store(ClientFlags::FLAG_OWNED);
    return Buffer;
  }

  /**
   * @brief Immediately release the buffer back to the allocator, given it has not been reclaimed
   *
   * @param Buffer - The iterator that was previously given with ClaimBuffer
   */
  void UnclaimBuffer(const ContainerType::iterator& Buffer, BufferOwnedFlag* ClientFlag) {
    // Transition the buffer to free, unclaiming if it wasn't free prior.
    if (ClientFlag->exchange(ClientFlags::FLAG_FREE) != ClientFlags::FLAG_FREE) {
      std::unique_lock lk {AllocationMutex};
      UnclaimBufferImpl(Buffer);
    }
  }

  /**
   * @brief Set internal flags of buffer claiming that the buffer is relinquished ownership
   *
   * @param Buffer - The iterator that was previously given with ClaimBuffer
   *
   * Once the buffer is disowned, the allocator can take back ownership of the buffer at any time
   *
   * Use ReownOrClaimBuffer if you want to attempt reusing a buffer being held on to.
   */
  void DisownBuffer(ContainerType::iterator Buffer) {
    // Client still owns the buffer but isn't using it
    // Allows us to claim it back if necessary
    (*Buffer)->LastUsed.store(ClockType::now(), std::memory_order_relaxed);
    (*Buffer)->CurrentClientOwnedFlag->store(ClientFlags::FLAG_DISOWNED);
  }

  /**
   * @brief Try to reown a buffer that was previously disowned
   *
   * @param Buffer - The buffer we previously disowned
   * @param Size - The size of the buffer
   * @param CurrentClientFlag - The client tracked flag
   *
   * Once DisownBuffer has been called, it is unsafe to use the buffer until it has been reowned
   * Always reown a buffer before use!
   *
   * @return The original buffer passed in on successful reown, otherwise std::nullopt
   */
  std::optional<ContainerType::iterator> TryToReownBuffer(const ContainerType::iterator& Buffer, size_t Size, BufferOwnedFlag* CurrentClientFlag) {
    ClientFlags Expected = ClientFlags::FLAG_DISOWNED;
    if (!CurrentClientFlag->compare_exchange_strong(Expected, ClientFlags::FLAG_OWNED)) {
      return std::nullopt;
    }

    // If we managed to change the flag from DISOWNED to OWNED then we have successfully reclaimed
    // Finish setting up state
    (*Buffer)->LastUsed.store(ClockType::now(), std::memory_order_relaxed);
    return Buffer;
  }

  /**
   * @brief Try to reown a buffer that was previously disowned, failing that, claim a new buffer
   *
   * @param Buffer - The buffer we previously disowned
   * @param Size - The size of the buffer
   * @param CurrentClientFlag - The client tracked flag
   *
   * Once DisownBuffer has been called, it is unsafe to use the buffer until it has been reowned
   * Always reown a buffer before use!
   *
   * @return The original buffer passed in on successful reown, otherwise a new buffer
   */
  ContainerType::iterator ReownOrClaimBuffer(const ContainerType::iterator& Buffer, size_t Size, BufferOwnedFlag* CurrentClientFlag) {
    auto Reowned = TryToReownBuffer(Buffer, Size, CurrentClientFlag);
    if (Reowned) {
      return Reowned.value();
    }

    // Couldn't reclaim, just get a new buffer
    return ClaimBuffer(Size, CurrentClientFlag);
  }

  virtual ~IntrusivePooledAllocator() = default;

  // XXX: Is this a good amount?
  /**
   * @brief Duration before the allocator will reclaim buffers that the client claimed AND disowned
   *
   * Pool allocator will not attempt to reclaim client owned buffers, would be unsafe to do so.
   */
  constexpr static std::chrono::duration DURATION {std::chrono::seconds(5)};

protected:
#if FEX_IOS_POOL_NULL_SAFETY
  IntrusivePooledAllocator() {
    // One line per process, so a device log shows that this build carries pns2.
    static std::atomic<bool> Announced {};
    if (!Announced.exchange(true, std::memory_order_relaxed)) {
      LogMan::Msg::IFmt("[pool-null] armed: a failed pool claim reclaims, retries, then ends the process rev=pns2");
    }
  }
#else
  IntrusivePooledAllocator() = default;
#endif

  ContainerType::iterator ClaimBufferImpl(size_t Size) {
    auto BuffersEnd = UnclaimedBuffers.end();
    ContainerType::iterator BestFit = BuffersEnd;
    ContainerType::iterator UnsizedFit = BuffersEnd;

    auto Now = ClockType::now();
    // Move any expired ClaimedBuffers to UnclaimedBuffers
    {
      // Spin the non-owned buffers and see if we can take ones past the period
      for (auto it = ClaimedBuffers.begin(); it != ClaimedBuffers.end();) {
        // 1) Can't take anything that the client has still claimed
        // 2) Needs to still be last used beyond our time threshold
        // 3) Only take the oldest buffer
        if ((*it)->CurrentClientOwnedFlag->load() == ClientFlags::FLAG_DISOWNED) {
          auto UsedTime = (*it)->LastUsed.load(std::memory_order_relaxed);
          if ((Now - UsedTime) >= DURATION) {
            ClientFlags Expected = ClientFlags::FLAG_DISOWNED;
            if ((*it)->CurrentClientOwnedFlag->compare_exchange_strong(Expected, ClientFlags::FLAG_FREE)) {
              // We managed to take away ownership
              // Put it back in the regular pool and come back to it
              (*it)->CurrentClientOwnedFlag = nullptr;
              UnclaimedBuffers.emplace_back(*it);
              it = ClaimedBuffers.erase(it);
              continue;
            }
          }
        }

        ++it;
      }
    }

    // Find an unclaimed buffer that is >= Size and Free up to one unclaimed buffer that has expired
    {
      // Walk all the allocations and find a buffer that fits
      for (auto it = UnclaimedBuffers.begin(); it != BuffersEnd; ++it) {
        if ((*it)->Size == Size) {
          BestFit = it;
          break;
        }

        if ((*it)->Size > Size) {
          UnsizedFit = it;
        }
      }

      // If we didn't have an exact fit then use an unsized fit
      if (BestFit == BuffersEnd) {
        BestFit = UnsizedFit;
      }

      // Free up to one unclaimed buffer that has expired
      {
        std::chrono::time_point<ClockType> LRUTime {};
        ContainerType::iterator LastUsed = BuffersEnd;

        // Walk all the allocations and find a buffer to erase
        for (auto it = UnclaimedBuffers.begin(); it != UnclaimedBuffers.end(); ++it) {
          // Ensure that the LRU value is past our duration threshold and isn't the one we are claiming
          // Also only select a single memory region
          if (it != BestFit) {
            auto UsedTime = (*it)->LastUsed.load(std::memory_order_relaxed);
            if ((Now - UsedTime) >= DURATION && UsedTime > LRUTime) {
              LastUsed = it;
              LRUTime = UsedTime;
            }
          }
        }

        // If we found a buffer then free it
        if (LastUsed != BuffersEnd) {
          Free((*LastUsed)->Ptr, (*LastUsed)->Size);
          delete *LastUsed;
          UnclaimedBuffers.erase(LastUsed);
        }
      }

      if (BestFit != UnclaimedBuffers.end()) {
        MemoryBuffer* Buffer = *BestFit;
        UnclaimedBuffers.erase(BestFit);
        return ClaimedBuffers.emplace(ClaimedBuffers.end(), Buffer);
      }
    }

    // Need to allocate a new buffer, couldn't fit
    auto Data = Alloc(Size);
#if FEX_IOS_POOL_NULL_SAFETY
    if (!Data) {
      // Never record a NULL buffer. Take back what idle clients hold, then try the allocation once more.
      if (auto Reclaimed = EmergencyReclaimLocked(Size); Reclaimed != ClaimedBuffers.end()) {
        static std::atomic<uint32_t> Reuses {};
        const uint32_t Reuse = Reuses.fetch_add(1, std::memory_order_relaxed) + 1;
        if (Reuse <= 8 || (Reuse % 1024) == 0) {
          LogMan::Msg::EFmt("[pool-null] {} allocation of {:#x} bytes failed; reusing an idle thread's buffer (reuse {}) rev=pns2",
                            PoolName(), Size, Reuse);
        }
        return Reclaimed;
      }
      Data = Alloc(Size);
      if (!Data) {
        return ClaimedBuffers.end();
      }
    }
#endif
    return ClaimedBuffers.emplace(ClaimedBuffers.end(), new MemoryBuffer {Data, Size, ClockType::now()});
  }

#if FEX_IOS_POOL_NULL_SAFETY
  /**
   * @brief Called with AllocationMutex held after Alloc(Size) failed: take back every buffer no client is using
   *
   * The expiry pass in ClaimBufferImpl only takes disowned buffers that have been idle for DURATION. That wait
   * is a reuse heuristic, not a safety requirement: the DISOWNED -> FREE compare-exchange below is the same
   * handshake, so a client that re-owns first keeps its buffer, and one that loses sees FLAG_FREE and claims anew.
   *
   * @return A claimed buffer of at least Size. Otherwise ClaimedBuffers.end(), after every unclaimed buffer
   * has been released so that its address space can satisfy the next allocation.
   */
  ContainerType::iterator EmergencyReclaimLocked(size_t Size) {
    for (auto it = ClaimedBuffers.begin(); it != ClaimedBuffers.end();) {
      ClientFlags Expected = ClientFlags::FLAG_DISOWNED;
      if ((*it)->CurrentClientOwnedFlag->compare_exchange_strong(Expected, ClientFlags::FLAG_FREE)) {
        (*it)->CurrentClientOwnedFlag = nullptr;
        UnclaimedBuffers.emplace_back(*it);
        it = ClaimedBuffers.erase(it);
        continue;
      }
      ++it;
    }

    // Smallest unclaimed buffer that fits.
    auto Fit = UnclaimedBuffers.end();
    for (auto it = UnclaimedBuffers.begin(); it != UnclaimedBuffers.end(); ++it) {
      if ((*it)->Size >= Size && (Fit == UnclaimedBuffers.end() || (*it)->Size < (*Fit)->Size)) {
        Fit = it;
      }
    }

    if (Fit != UnclaimedBuffers.end()) {
      MemoryBuffer* Buffer = *Fit;
      UnclaimedBuffers.erase(Fit);
      return ClaimedBuffers.emplace(ClaimedBuffers.end(), Buffer);
    }

    // Nothing fits: release them all.
    for (auto it : UnclaimedBuffers) {
      Free(it->Ptr, it->Size);
      delete it;
    }
    UnclaimedBuffers.clear();
    return ClaimedBuffers.end();
  }

  /**
   * @brief Called with AllocationMutex held (through lk) when ClaimBufferImpl could not produce a buffer
   *
   * Sleeps with the mutex released so other threads can finish with, disown, unclaim or free their buffers,
   * and retries for a little longer than DURATION. If that fails, it logs and terminates the process rather
   * than return a buffer that would be written through at NULL.
   *
   * @return A claimed buffer, with lk locked again. Never returns ClaimedBuffers.end().
   */
  ContainerType::iterator ClaimBufferAfterAllocFailure(std::unique_lock<std::mutex>& lk, size_t Size) {
    constexpr auto RetrySleep = std::chrono::milliseconds(50);
    constexpr auto RetryWindow = std::chrono::duration_cast<std::chrono::milliseconds>(DURATION + std::chrono::seconds(1));

    // Bound the log under a storm of failing threads; the fatal line below is always written.
    static std::atomic<uint32_t> Events {};
    const uint32_t Event = Events.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool Report = Event <= 32 || (Event % 256) == 0;
    if (Report) {
      LogMan::Msg::EFmt("[pool-null] {} claim of {:#x} bytes failed: the allocation returned NULL and no idle buffer "
                        "fits; retrying for up to {} ms (event {}) rev=pns2",
                        PoolName(), Size, RetryWindow.count(), Event);
    }

    const auto Start = ClockType::now();
    uint32_t Attempts {};
    do {
      lk.unlock();
      std::this_thread::sleep_for(RetrySleep);
      lk.lock();
      ++Attempts;
      auto Buffer = ClaimBufferImpl(Size);
      if (Buffer != ClaimedBuffers.end()) {
        if (Report) {
          LogMan::Msg::EFmt("[pool-null] {} claim of {:#x} bytes recovered after {} retries (event {}) rev=pns2", PoolName(), Size,
                            Attempts, Event);
        }
        return Buffer;
      }
    } while (ClockType::now() - Start < RetryWindow);

    // Let the other threads of this process keep using the pool while this one dies.
    lk.unlock();
    LogMan::Msg::EFmt("[pool-null] FATAL: {} could not get {:#x} bytes after {} retries over {} ms; the FEX host arena is "
                      "exhausted. Terminating the process (STATUS_NO_MEMORY) instead of writing through a NULL buffer "
                      "(event {}) rev=pns2",
                      PoolName(), Size, Attempts, RetryWindow.count(), Event);
#if defined(FEX_IOS_HOST) && defined(_WIN32)
    /* Not an exception. One raised here (ForcedAssert's hlt, as ERROR_AND_DIE does) is delivered to the guest
     * while this thread still holds the shared CodeInvalidationMutex: the guest's vectored handlers run, their
     * code is compiled under delivery (UNPUB-COMPILE), that compile needs this same exhausted pool, and the
     * thread recurses into this wait again, 6 s per level, with the process's JIT frozen. This is the ml460
     * situation (JIT.cpp, IosCountUnpubBailOrTerminate): at exhaustion the process cannot deliver its own
     * exception, so end it. */
    NtTerminateProcess(reinterpret_cast<void*>(-1), static_cast<int32_t>(0xC0000017)); // STATUS_NO_MEMORY
#endif
    ERROR_AND_DIE_FMT("[pool-null] {} exhausted ({:#x} bytes) rev=pns2", PoolName(), Size);
  }
#endif

  void UnclaimBufferImpl(ContainerType::iterator Buffer) {
    (*Buffer)->CurrentClientOwnedFlag = nullptr;
    UnclaimedBuffers.emplace_back(*Buffer);
    ClaimedBuffers.erase(Buffer);
  }

  void FreeAllBuffers() {
    for (auto it : UnclaimedBuffers) {
      Free(it->Ptr, it->Size);
      delete it;
    }

    for (auto it : ClaimedBuffers) {
      Free(it->Ptr, it->Size);
      delete it;
    }

    UnclaimedBuffers.clear();
    ClaimedBuffers.clear();
  }

  /**
   * @brief List of buffers that this pool allocator itself owns
   */
  ContainerType UnclaimedBuffers;

  /**
   * @brief List of buffers that are client claimed
   */
  ContainerType ClaimedBuffers;

  /**
   * @brief Mutex to ensure thread safety while shuffling buffers around and allocating
   */
  std::mutex AllocationMutex;

#if FEX_IOS_POOL_NULL_SAFETY
  /**
   * @brief VirtualAlloc reports failure as nullptr on Windows and as MAP_FAILED elsewhere
   */
  static bool VirtualAllocFailed(const void* Ptr) {
#ifdef _WIN32
    return Ptr == nullptr;
#else
    return Ptr == nullptr || Ptr == MAP_FAILED;
#endif
  }
#endif

private:
#if FEX_IOS_POOL_NULL_SAFETY
  /**
   * @brief Name used in the pns2 diagnostics
   */
  virtual const char* PoolName() const {
    return "FEXMem_pool";
  }
#endif

  /**
   * @brief Allocates the buffer
   *
   * @param Size of the object to allocate
   *
   * @return pointer
   */
  virtual void* Alloc(size_t Size) = 0;
  /**
   * @brief Frees the buffer
   *
   * @param Ptr buffer pointer
   * @param Size buffer size
   */
  virtual void Free(void* Ptr, size_t Size) = 0;
};

/**
 * @brief Thread pool allocator that allocates and frees objects using malloc
 */
class PooledAllocatorMalloc final : public IntrusivePooledAllocator {
public:
  PooledAllocatorMalloc() = default;

  virtual ~PooledAllocatorMalloc() {
    FreeAllBuffers();
  }

private:
  void* Alloc(size_t Size) override {
    return FEXCore::Allocator::malloc(Size);
  }

  void Free(void* Ptr, size_t Size) override {
    FEXCore::Allocator::free(Ptr);
  }
};

/**
 * @brief Thread pool allocator that allocates and frees objects that uses mmap
 */
class PooledAllocatorVirtual final : public IntrusivePooledAllocator {
public:
  PooledAllocatorVirtual() = default;
  PooledAllocatorVirtual(const char* Name)
    : Name {Name} {}

  virtual ~PooledAllocatorVirtual() {
    FreeAllBuffers();
  }

private:
#if FEX_IOS_POOL_NULL_SAFETY
  const char* PoolName() const override {
    return Name ? Name : "FEXMem_pool";
  }
#endif

  void* Alloc(size_t Size) override {
    auto Result = FEXCore::Allocator::VirtualAlloc(Size);
#if FEX_IOS_POOL_NULL_SAFETY
    if (VirtualAllocFailed(Result)) {
      return nullptr;
    }
#endif
    if (Name) {
      FEXCore::Allocator::VirtualName(Name, Result, Size);
    }
    return Result;
  }

  void Free(void* Ptr, size_t Size) override {
    FEXCore::Allocator::VirtualFree(Ptr, Size);
  }

  const char* Name {};
};

/**
 * @brief Thread pool allocator that allocates and frees objects that uses mmap, with a guard page.
 *
 * The last page of the size provided has the guard.
 */
class PooledAllocatorVirtualWithGuard final : public IntrusivePooledAllocator {
public:
  PooledAllocatorVirtualWithGuard() = default;
  PooledAllocatorVirtualWithGuard(const char* Name)
    : Name {Name} {}

  virtual ~PooledAllocatorVirtualWithGuard() {
    FreeAllBuffers();
  }

private:
#if FEX_IOS_POOL_NULL_SAFETY
  const char* PoolName() const override {
    return Name ? Name : "FEXMem_pool";
  }
#endif

  void* Alloc(size_t Size) override {
    auto Ptr = FEXCore::Allocator::VirtualAlloc(Size);
#if FEX_IOS_POOL_NULL_SAFETY
    // Without this, the guard page below would be set at NULL + Size, on whatever happens to be mapped there.
    if (VirtualAllocFailed(Ptr)) {
      return nullptr;
    }
#endif
    uintptr_t LastPageAddr = AlignDown(reinterpret_cast<uintptr_t>(Ptr) + Size - 1, FEXCore::Utils::FEX_PAGE_SIZE);
    if (!FEXCore::Allocator::VirtualProtect(reinterpret_cast<void*>(LastPageAddr), FEXCore::Utils::FEX_PAGE_SIZE,
                                            FEXCore::Allocator::ProtectOptions::None)) {
      LogMan::Msg::EFmt("Failed to mprotect last page of code buffer.");
    }
    if (Name) {
      FEXCore::Allocator::VirtualName(Name, Ptr, Size);
    }
    return Ptr;
  }

  void Free(void* Ptr, size_t Size) override {
    FEXCore::Allocator::VirtualFree(Ptr, Size);
  }

  const char* Name {};
};

/**
 * @brief Wrapper around the pool allocator for delayed pool reclaiming
 *
 * This is expected to be used in high frequency buffer temporary usage.
 * Instead of quickly unclaiming and reclaiming the buffer while the the code is hot,
 * This instead will do the cheap operation of disowning the buffer until the code path cools down enough.
 * Once the code path stops disowning the codepath more times than `PeriodFrequency` during `PeriodMS` then
 * it will immediately unclaim.
 *
 * Implications:
 *   - The object will always be claimed for at *least* `PeriodFrequency`
 *   - The object will still *always* be disowned after each temporary use
 *     - This allows the pool allocator to reclaim a buffer from a sleeping thread
 *
 * Performance characteristics:
 *  - Disowning is cheap.
 *    - Last-used timestamp update
 *    - atomic_bool clear to signify it is disowned
 *
 *  - Reowning is relatively cheap (When buffer is still owned).
 *    - atomic_bool load to check if the object is still owned
 *      - atomic<uint32_t> CAS to change the object to `OWNED` state
 *        - Resolves a race condition where the `Allocator` can be in the process of reclaiming the buffer from the client
 *      - Last-used timestamp update
 *      - atomic_bool<relaxed> set to signify owned
 *      - atomic<uint32_t> set to change object to `OWNED` state
 *    - When object isn't owned, then allocate a new buffer from the pool
 *
 *  - Unclaiming is fairly costly
 *    - Requires owning a mutex, shared between all threads using the `Allocator`
 *    - Updating two fextl::list containers to give the ownership back to the `Allocator`
 *
 *  - Claiming is very costly
 *    - Requires owning a mutex, shared between all threads using the `Allocator`
 *    - Scans two fextl::list containers to find the best fit buffer
 *    - Or allocates another buffer when that fails
 *    - Frees stale buffers opportunistically
 */
template<typename Type, size_t PeriodMS, size_t PeriodFrequency>
class PoolBufferWithTimedRetirement final {
  // If the delayed object reclaimer is more than the thread pool allocator's duration then the pool allocator would always need to reclaim
  // the buffer rather than giving it back.
  static_assert(std::chrono::duration(std::chrono::milliseconds(PeriodMS)) <= IntrusivePooledAllocator::DURATION, "DeplayedObjectReclaimer "
                                                                                                                  "period needs to be "
                                                                                                                  "lower or equal to the "
                                                                                                                  "pool allocator "
                                                                                                                  "duration");

public:
  PoolBufferWithTimedRetirement(IntrusivePooledAllocator& Allocator, size_t Size)
    : ThreadAllocator {Allocator}
    , Size {Size} {}

  ~PoolBufferWithTimedRetirement() {
    UnclaimBuffer();
  }

  struct AllocationInfo {
    Type Ptr;
    size_t Size;
  };

  /**
   * @brief Return the owned buffer or allocate another one from the `Allocator`
   *
   * The buffer is guaranteed to have at least `Size` bytes of data.
   * The initial data in the buffer is undefined, even when the buffer is just reowned.
   *
   * @param NewSize Optional new size for managed data
   *
   * @return A usable pointer of type `Type` and the size of the backing store.
   */
  AllocationInfo ReownOrClaimBufferWithSize(std::optional<size_t> NewSize = std::nullopt) {
    // Check if we can cheaply re-own a previous buffer
    std::optional Buffer =
      IntrusivePooledAllocator::IsClientBufferOwned(ClientOwnedFlag) ? Info : ThreadAllocator.TryToReownBuffer(Info, Size, &ClientOwnedFlag);

    // Ensure the now owned buffer has enough space. If not, unclaim it and proceed to claim a new one
    if (NewSize && Buffer && (**Buffer)->Size < NewSize.value()) {
      UnclaimBuffer();
      Buffer.reset();
    }

    // Claim a new buffer if needed
    Size = NewSize.value_or(Size);
    if (!Buffer) {
      Buffer = ThreadAllocator.ClaimBuffer(Size, &ClientOwnedFlag);
    }

    Info = *Buffer;

    // Putting a memset here is very handy for using thread sanitizer to find buffer usage races
    // Leaving this here for future excavation that will definitely occur here
    // memset((*Info)->Ptr, 0, Size);

    return {
      .Ptr = reinterpret_cast<Type>((*Info)->Ptr),
      .Size = (*Info)->Size,
    };
  }

  Type ReownOrClaimBuffer(std::optional<size_t> NewSize = std::nullopt) {
    return ReownOrClaimBufferWithSize(NewSize).Ptr;
  }

  /**
   * @brief Disown or unclaim the buffer, letting the `Allocator` know it can reclaim the buffer
   *
   * Once the `ReownOrClaimBuffer` function has been used, this must be called to let the `Allocator` know it is safe to reclaim a buffer.
   *
   * This will first Disown the buffer; which is cheap.
   *
   * If the frequency of use is below the threshold then immediately `UnclaimBuffer` so that `Allocator` can reuse it.
   */
  void DelayedDisownBuffer() {
    LOGMAN_THROW_A_FMT(FEXCore::Utils::IntrusivePooledAllocator::IsClientBufferOwned(ClientOwnedFlag), "Tried to disown buffer when client "
                                                                                                       "doesn't own it");

    // Always disown but not always unclaim
    // Disowning = cheap, unclaiming = expensive
    ThreadAllocator.DisownBuffer(Info);

    auto Now = std::chrono::steady_clock::now();
    if ((Now - Previous) >= std::chrono::duration(std::chrono::milliseconds(PeriodMS))) {
      if (CountPer < PeriodFrequency) {
        // Only unclaim the buffer if our buffer usage isn't excessive in the last period
        UnclaimBuffer();
      }
      CountPer = 0;
      Previous = Now;
    }
    ++CountPer;
  }

  /**
   * @brief Completely unclaim the buffer
   *
   * Useful if it is known that the buffer won't be used again for a period and can be given back
   * to the `Allocator` immediately.
   *
   * Necessary if an object is going to be freed from memory, so the `Allocator` can't update the `ClientOwnedFlag`
   *
   * Only use in that edge case! Otherwise use `DelayedDisownBuffer`
   */
  void UnclaimBuffer() {
    ThreadAllocator.UnclaimBuffer(Info, &ClientOwnedFlag);
  }

private:
  // Thread allocator
  FEXCore::Utils::IntrusivePooledAllocator& ThreadAllocator;

  // Buffer size
  size_t Size;

  // Buffer ownership tracking
  FEXCore::Utils::IntrusivePooledAllocator::ContainerType::iterator Info {};
  FEXCore::Utils::IntrusivePooledAllocator::BufferOwnedFlag ClientOwnedFlag {FEXCore::Utils::IntrusivePooledAllocator::ClientFlags::FLAG_FREE};

  // Threshold counting
  uint64_t CountPer {};
  std::chrono::steady_clock::time_point Previous;
};
} // namespace FEXCore::Utils
