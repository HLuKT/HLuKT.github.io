---
layout: post
title: 使用 Visual Studio 和 C++ 创建 Shellcode
categories: C\C++
description: 使用 Visual Studio 和 C++ 创建 Shellcode
keywords: C\C++,Shellcode
---

# 使用 Visual Studio 和 C++ 创建 Shellcode

## 1.所需工具和软件

- Visual Studio 2022
- LordPE（PE 查看器/编辑器）
- 010Editor（十六进制编辑器）

## 2.创建空项目

1.打开 Visual Studio 20

2.创建两个空的 C++ 项目

3.命名一个 `code_gen `和另一个 `code_tester`

4.将 `code_gen` 配置类型设置为“动态库 (.dll)”

5.将 `code_tester` 配置类型设置为“应用程序 (.exe)”

6.将项目设置为 x64 Release 模式

## 3.将 Dynamic-Library 配置为独立 API 的 PE 文件

 `code_gen `依赖于 CRT 和 Windows Kernel，按照以下步骤使其独立。

1.添加一个 .cpp（不是 .c）文件到 `code_gen `并写入以下代码：

```cpp
// code.cpp
extern "C" bool _code()
{
    return true;
}
```

2.打开`code_gen `项目属性并配置以下选项：

高级 > 使用调试库：否

高级 > 全程序优化：无全程序优化

C/C++ > 常规 > 调试信息格式：无

C/C++ > 常规 > SDL 检查：否 (/sdl-)

C/C++ > 代码生成 > 启用 C++ 异常：否

C/C++ > 代码生成 > 运行时库：多线程 (/MT)

C/C++ > 代码生成 > 安全检查：禁用安全检查 (/GS-)

C/C++ > 语言 > C++ 语言标准：ISO C++17 标准 (/std:c++17)

C/C++ > 语言 > 符合模式：否 (/permissive)

链接器 > 输入 > 附加依赖项：空

链接器 > 输入 > 附加依赖项 > 取消选中从父项或项目默认设置继承

链接器 > 输入 > 忽略所有默认库：是 (/NODEFAULTLIB)

链接器 > 调试 > 生成调试信息：否

链接器 > 调试 > 生成映射文件：是 (/MAP)

链接器 > 系统 > 子系统：本机 (/SUBSYSTEM:NATIVE)

链接器 > 优化 > 引用：否 (/OPT:NOREF)

链接器 > 高级 > 入口点：_code

链接器 > 高级 > 无入口点：是（/NOENTRY）

> 通过将入口点属性更改为 _code，可以防止仅生成资源 DLL，还可以设置编译器不要使用 CRT 入口点

## 4.配置 Tester 应用程序

Tester 不需要任何特殊配置，目前我们只关注代码生成、操作和执行。

在 `code_tester `中添加一个 main.cpp 文件，并写入以下代码：

```cpp
// main.cpp
#include <windows.h>
#include <iostream>
using namespace std;

int main()
{
    return EXIT_SUCCESS;
}
```

## 5.基本使用

将 _code 函数更改为：

```cpp
extern "C" int _code(int x, int y)
{
    return x * y + (x + y);
}
```

编译，得到 DLL

![DLLandMAP](https://HLuKT.github.io/images/posts/blog/CreateShellcode/DLLandMAP.png)

我们只需要 .dll 和 .map 文件，我们的 DLL 文件包含汇编的 x64 机器代码，我们的映射文件包含有关链接器使用的地址的信息，但映射文件中最重要的是代码在我们的代码映射的虚拟内存空间中的地址和偏移量。

1.使用 LordPE 打开 code_gen.dll

![DataDirectory](https://HLuKT.github.io/images/posts/blog/CreateShellcode/DataDirectory.png)

可见，DLL 没有导入/导出地址表 (IAT/EAT)，我们不需要资源、调试两个部分，一个包含文件版本等默认资源，一个包含调试目录数据。我们需要查找的代码位于包含 .text 段中。

查看 .text 段虚拟地址和原始地址

![SectionTable](https://HLuKT.github.io/images/posts/blog/CreateShellcode/SectionTable.png)

2.使用 010Editor 打开 code_gen.dll

![010Offset](https://HLuKT.github.io/images/posts/blog/CreateShellcode/010Offset.png)