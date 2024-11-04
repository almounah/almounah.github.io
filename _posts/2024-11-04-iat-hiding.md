---
title: "Malware with Go - 2: IAT Hiding"
image:
  path: cov.png
layout: "post"
media_subpath: /assets/posts/2024-11-04-maldev-go-2/
categories: [ "Malware" ]
tags: [ "Malware", "go", "windows" ]
---

I will show how to modify Go toolchain to make the Import Address Table (IAT) of Go executables more empty. I will then analyse how this affects malware detection.

## Exposing Go IAT

To show what we need to do, lets first compile a small basic binary with Go for windows.

```go
package main

import (
        "fmt"
)

func main()  {
    fmt.Println("Hey")
}
```

We compile with
```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o main.exe main.go
```

When we analyse the binary with `dumpbin` we see the following:

![](main_import.png)

This seems weird, because I am just using a print in my code. I never used VirtualAlloc, neither ever freed any allocated memory (even when I code in C I never free :( )

So what is actually happening here ?

Well, Go embeds his runtime along with a debugger and a memory manager with each exe. For these to work properly, Go need to use all the imported functions from kernel32.dll.

## And, why should I care ?

Normally you shouldn't care. And you are right. Any exe will import some functions and have a non empty IAT.

That being said, some AV/EDR use the IAT to pinpoint some malicious pattern that can be used in code. While IAT is not at the core of AV/EDR decision making, it surely has its role.

So by controlling what functions are in the IAT, we hope to make the binary less detectable.


## How to proceed ?

Well, there is no way around it, we NEED to tamper the Go toolchain.

The idea is to code two function, `GetModuleHandleReplace` and `GetProcAddressReplace`, then use them in the Go Toolchain instead of the import from kernel32.dll.

We will call this new version of go `evil-go`.

Note that `evil-go` will be made for Windows, no guaranty that `evil-go` will even let you compile stuff for linux anymore.


## Pinpointing the KERNEL32.DLL imports in Go Toolchain

Lets go straight to the point, they are here [https://github.com/golang/go/blob/master/src/runtime/os_windows.go](https://github.com/golang/go/blob/master/src/runtime/os_windows.go)

More precisely, in the comments.

```go
//go:cgo_import_dynamic runtime._GetSystemInfo GetSystemInfo%1 "kernel32.dll"
```

For example, the above line will load the address of GetSystemInfo winapi from the virtual memory of the process and then write this address in the variable `runtime._GetSystemInfo`.

This will result in `GetSystemInfo` to be in the IAT of the Go binary.

What we will do is delete the `cgo_import_dynamic` line, and replace it with:

```go
_GetSystemInfo = stdFunction(unsafe.Pointer(GetProcAddressReplace(GetModuleHandleReplace("kernel32.dll"), "GetSystemInfo")))
```

We will put the above line at the beginning of `os_init()` function in go (this is where everything starts).

We shall do that for all the function that we want to delete from IAT. All the function can be replaced except for `TLSAlloc`. If you replace it with this method the generated Go binaries will not run. 

Now we just have to code `GetProcAddressReplace` and `GetModuleHandleReplace` in go.

## Coding GetModuleHandleReplace

This function will return the Handle of a given module. Here it is only used for Kernel32.dll.

```go
func GetModuleHandleReplace(wantedModule string) (e HANDLE) {
	ppeb_uintptr := GetPEB()

	ppeb := PPEB64(unsafe.Pointer(uintptr(ppeb_uintptr)))

	pLdr := ppeb.LoaderData
	pListEntry := pLdr.InMemoryOrderModuleList.Flink
	pListEntryStart := pLdr.InMemoryOrderModuleList.Blink

	for pListEntry != pListEntryStart {
		pDte := PLDR_DATA_TABLE_ENTRY(unsafe.Pointer(pListEntry))
		if areEqual(&pDte.FullDllName, wantedModule) {
			return HANDLE(unsafe.Pointer(pDte.InInitializationOrderLinks.Flink))
		}

		pListEntry = pListEntry.Flink
	}
	pDte := PLDR_DATA_TABLE_ENTRY(unsafe.Pointer(pListEntry))
	if areEqual(&pDte.FullDllName, wantedModule) {
		return HANDLE(unsafe.Pointer(pDte.InInitializationOrderLinks.Flink))
	}
	return 0
}
```

The full implementation can be found above. This was largely inspired from Vx-underground replacement functions.

In the above code `areEqual` compare a windows UNICODE_STRING to a string.

`GetPEB` return the process PEB by reading an offset from GS register:

```go
// +build !noasm
#include "textflag.h"

// func GetPEB() uintptr
TEXT ·GetPEB(SB),NOSPLIT|NOFRAME,$0-8
    PUSHQ   CX
    MOVQ    0x60(GS), CX   
    MOVQ    CX, ret+0(FP) 
    POPQ   CX
    RET

```


## Coding GetProcAddressReplace

This function will take the handle of a module, and an windows API name, then return the address of this windows API in the handle.

```go
func GetProcAddressReplace(hModule HANDLE, winApiName string) uintptr {
	pBase := unsafe.Pointer(hModule)
	pImgDosHeader := PIMAGE_DOS_HEADER(pBase)
	if pImgDosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		println("Messed Up Getting the DosHeader")
	}

	pImgNtHdrs := PIMAGE_NT_HEADERS32(unsafe.Pointer(uintptr(pBase) + uintptr(pImgDosHeader.E_lfanew)))
	if pImgNtHdrs.Signature != IMAGE_NT_SIGNATURE {
		println("Messed Up getting NTHeader")
	}

	if pImgNtHdrs.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 {
		pImgNtHdrs64 := PIMAGE_NT_HEADERS64(unsafe.Pointer(pImgNtHdrs))
		ImgOptHdr := pImgNtHdrs64.OptionalHeader
		if ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
			println("Messed Up getting Image Optional Header for x64 arch")
		}
		pImgExportDir := PIMAGE_EXPORT_DIRECTORY(unsafe.Pointer(uintptr(pBase) + uintptr(ImgOptHdr.DataDirectory.VirtualAddress)))

		numFunction := pImgExportDir.NumberOfFunctions

		AddressOfFuntionList := unsafe.Slice((*DWORD)(unsafe.Pointer(uintptr(pBase)+uintptr(pImgExportDir.AddressOfFunctions))), pImgExportDir.NumberOfFunctions)
		AddressOfNamesList := unsafe.Slice((*DWORD)(unsafe.Pointer(uintptr(pBase)+uintptr(pImgExportDir.AddressOfNames))), pImgExportDir.NumberOfFunctions)
		AddressOfNameOrdinalList := unsafe.Slice((*WORD)(unsafe.Pointer(uintptr(pBase)+uintptr(pImgExportDir.AddressOfNameOrdinals))), pImgExportDir.NumberOfFunctions)

		for i := DWORD(0); i < numFunction; i++ {
			functionNameRVA := AddressOfNamesList[i]

			if areEqual2(uintptr(pBase), functionNameRVA, winApiName) {
				return uintptr(pBase) + uintptr(AddressOfFuntionList[AddressOfNameOrdinalList[i]])
			}
		}

	}
	return 0
}
```

Again the above implementation is very inspired from VX-underground. I don't treat 32 bit cases (as you see from my big if, I gave up after)

The function `areEqual2` take a base address, an RVA and a target string then compare them.

## Results

The above 2 function were tested against the reald `GetModuleHandle` and `GetProcAddress` given in the official windows API. They return the same value (which is nice).

After integrating these 2 functions in the toolchains as mentionned above, we can recompile the Go toolchain (a bootstrap bash file is given). 

`evil-go` is born.

Then we can take the same go code that prints "hey" and compile it with `evil-go` this time.

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 ./evil-go build -ldflags="-s -w" -trimpath -o evilmain.exe main.go
```

The exe executes, but this time the IAT only contains TLSAlloc.

![](evilmain_import.png)


## Amazing, so cool, but was it worth it ?

Well, lets check with our baby shellcode loader. This was presented in another post in this blog. It is the classic malware that does a virtualAllocEx, WriteProcessMemory and createThreadEx with some VirtualProtectEx along the way.

Sadly, the amazing baby shellcode loader that I presented that was only detected by 11 AV is now detected by 40 AV (Yeah, only noobs upload their binaries to VirusTotal, so please don't do it).

However, what I did not tell you, is that at the time, the same code compiled with evil-go was detected by 6 AV. Now it is detected by 27 AV.

This might seems confusing. Here is a recap:

| **Time**          | **Baby Shellcode with Go** | **Same Baby Shellcode with evil-go** |
|-------------------|----------------------------|--------------------------------------|
| **On upload**     | Detected by 11 AV          | Detected by 6 AV                     |
| **10 Days Later** | Detected by 40 AV          | Detected by 27 AV                    |


And of course this will change through time as AV learn and learn. I will put the link to the virustotal sample here as well as screenshots at the time of this blog writing:

[Baby Shellcode with Go](https://www.virustotal.com/gui/file/81a91aa1563edf718c4da382f986ff8bdcfa04b14937dfbdb29449ffc97353a4/details)

![](valloc_vtot.png)

[Baby Shellcode with evil-go](https://www.virustotal.com/gui/file/4ff318eeb1fef890fbcbcd354be61887cae065fc9cac9620a0cceaa1839ca3ff/details)

![](evilvalloc_vtot.png)

## Conclusion

So it is cool. It was worth it. But it is not sufficient to always bypass AV.

At least now we have control over IAT in Go, which is quite nice.

