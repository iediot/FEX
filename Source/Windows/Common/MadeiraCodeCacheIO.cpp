// SPDX-License-Identifier: MIT
/* iOS-Madeira ml2400: file I/O for the persistent FEX code cache
 * (FEXCore/Source/Interface/Core/MadeiraCodeCache.h).
 *
 * NT calls only (ntdll is always there; no dependency on the CRT's file layer
 * or kernel32 being initialized at the point FEX first compiles). Every handle
 * is synchronous and every transfer positional, so concurrent readers on one
 * handle never share a file pointer. Sharing rules carry the one-writer policy:
 * readers open with read|write sharing, the writer with read sharing only, so a
 * second process running the same module can still read the cache but its
 * writer open fails and it simply does not save. */

#include <cstdint>
#include <cstring>

#include <windows.h>
#include <winternl.h>

#include "Handle.h"
#include "Priv.h"

namespace {
bool OpenNt(const char* DosPath, ACCESS_MASK Access, ULONG Share, ULONG Disposition, ULONG Options, HANDLE* Out) {
  char NtPath[1024];
  const size_t Len = strlen(DosPath);
  if (Len == 0 || Len + 5 > sizeof(NtPath)) {
    return false;
  }
  memcpy(NtPath, "\\??\\", 4);
  memcpy(NtPath + 4, DosPath, Len + 1);
  ScopedUnicodeString Path(NtPath);
  OBJECT_ATTRIBUTES Attr;
  InitializeObjectAttributes(&Attr, &*Path, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
  IO_STATUS_BLOCK IOSB;
  HANDLE Handle = INVALID_HANDLE_VALUE;
  const NTSTATUS Status =
    NtCreateFile(&Handle, Access | SYNCHRONIZE, &Attr, &IOSB, nullptr, FILE_ATTRIBUTE_NORMAL, Share, Disposition, Options | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
  if (!NT_SUCCESS(Status)) {
    return false;
  }
  *Out = Handle;
  return true;
}
} // namespace

extern "C" {
// ForWrite == 0: existing file, read-only. ForWrite == 1: open or create, read+write, sole writer.
void* MadeiraFexCacheOpen(const char* DosPath, int ForWrite, uint64_t* SizeOut) {
  HANDLE Handle;
  const bool Ok = ForWrite ? OpenNt(DosPath, FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN_IF,
                                    FILE_NON_DIRECTORY_FILE, &Handle) :
                             OpenNt(DosPath, FILE_READ_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                                    FILE_NON_DIRECTORY_FILE, &Handle);
  if (!Ok) {
    return nullptr;
  }
  FILE_STANDARD_INFORMATION Info {};
  IO_STATUS_BLOCK IOSB;
  if (!NT_SUCCESS(NtQueryInformationFile(Handle, &IOSB, &Info, sizeof(Info), FileStandardInformation))) {
    NtClose(Handle);
    return nullptr;
  }
  if (SizeOut) {
    *SizeOut = static_cast<uint64_t>(Info.EndOfFile.QuadPart);
  }
  return Handle;
}

int64_t MadeiraFexCacheRead(void* Handle, uint64_t Offset, void* Buffer, uint32_t Size) {
  IO_STATUS_BLOCK IOSB;
  LARGE_INTEGER At;
  At.QuadPart = static_cast<LONGLONG>(Offset);
  const NTSTATUS Status = NtReadFile(Handle, nullptr, nullptr, nullptr, &IOSB, Buffer, Size, &At, nullptr);
  if (!NT_SUCCESS(Status)) {
    return -1;
  }
  return static_cast<int64_t>(IOSB.Information);
}

int64_t MadeiraFexCacheWrite(void* Handle, uint64_t Offset, const void* Buffer, uint32_t Size) {
  IO_STATUS_BLOCK IOSB;
  LARGE_INTEGER At;
  At.QuadPart = static_cast<LONGLONG>(Offset);
  const NTSTATUS Status = NtWriteFile(Handle, nullptr, nullptr, nullptr, &IOSB, Buffer, Size, &At, nullptr);
  if (!NT_SUCCESS(Status)) {
    return -1;
  }
  return static_cast<int64_t>(IOSB.Information);
}

int MadeiraFexCacheSetEnd(void* Handle, uint64_t Size) {
  FILE_END_OF_FILE_INFORMATION Info;
  Info.EndOfFile.QuadPart = static_cast<LONGLONG>(Size);
  IO_STATUS_BLOCK IOSB;
  return NT_SUCCESS(NtSetInformationFile(Handle, &IOSB, &Info, sizeof(Info), FileEndOfFileInformation)) ? 1 : 0;
}

void MadeiraFexCacheClose(void* Handle) {
  if (Handle) {
    NtClose(Handle);
  }
}

// Creates every missing directory of DosPath ("C:\a\b\c"); existing ones are fine.
// Lower-case ASCII file name of this process's image ("steam.exe"), or "" if unknown.
void MadeiraFexCacheProcessName(char* Out, uint32_t Size) {
  Out[0] = 0;
  const auto* Params = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;
  if (!Params || !Params->ImagePathName.Buffer || !Size) {
    return;
  }
  const WCHAR* Path = Params->ImagePathName.Buffer;
  const size_t Len = Params->ImagePathName.Length / sizeof(WCHAR);
  size_t Start = 0;
  for (size_t i = 0; i < Len; i++) {
    if (Path[i] == L'\\' || Path[i] == L'/') {
      Start = i + 1;
    }
  }
  uint32_t o = 0;
  for (size_t i = Start; i < Len && o + 1 < Size; i++) {
    const WCHAR C = Path[i];
    Out[o++] = (C >= L'A' && C <= L'Z') ? char(C - L'A' + 'a') : (C < 0x80 ? char(C) : '?');
  }
  Out[o] = 0;
}

int MadeiraFexCacheMakeDir(const char* DosPath) {
  char Path[1024];
  const size_t Len = strlen(DosPath);
  if (Len == 0 || Len + 1 > sizeof(Path)) {
    return 0;
  }
  memcpy(Path, DosPath, Len + 1);
  bool Ok = true;
  for (size_t i = 3; i <= Len; ++i) { // skip "C:\"
    if (Path[i] != '\\' && Path[i] != '/' && Path[i] != '\0') {
      continue;
    }
    const char Saved = Path[i];
    Path[i] = '\0';
    HANDLE Handle;
    Ok = OpenNt(Path, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, &Handle);
    if (Ok) {
      NtClose(Handle);
    }
    Path[i] = Saved;
  }
  return Ok ? 1 : 0;
}
}
