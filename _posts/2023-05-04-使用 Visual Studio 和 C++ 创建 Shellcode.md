---
layout: post
title: 使用 Visual Studio 和 C++ 创建 Shellcode
categories: C\C++
description: 使用 Visual Studio 和 C++ 创建 Shellcode
keywords: C\C++,Shellcode
---

使用 Visual Studio 和 C++ 创建 Shellcode

# 基本方法

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

### 1.创建 cpp 文件

添加一个 .cpp（不是 .c）文件到 `code_gen `并写入以下代码：

```cpp
// code.cpp
extern "C" bool _code()
{
    return true;
}
```

### 2.配置项目属性

打开`code_gen `项目属性并配置以下选项：

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

### 1.使用 LordPE 打开 code_gen.dll

![DataDirectory](https://HLuKT.github.io/images/posts/blog/CreateShellcode/DataDirectory.png)

可见，DLL 没有导入/导出地址表 (IAT/EAT)，我们不需要资源、调试两个部分，一个包含文件版本等默认资源，一个包含调试目录数据。我们需要查找的代码位于包含 .text 段中。

查看 .text 段虚拟地址和原始地址

![SectionTable](https://HLuKT.github.io/images/posts/blog/CreateShellcode/SectionTable.png)

### 2.使用 010Editor 打开 code_gen.dll

![010Offset](https://HLuKT.github.io/images/posts/blog/CreateShellcode/010Offset.png)

C3 opcode 表示 RETURN，表明它是我们函数的结尾，不需要 zero bytes (\0)

### 3.复制为C代码

选中字节并从菜单栏编辑 -> 复制为 -> 复制为C代码，并粘贴到 main.cpp 中，代码如下所示：

```cpp
// main.cpp
#include <windows.h>
#include <iostream>
using namespace std;

unsigned char hexData[9] = {
    0x8D, 0x42, 0x01, 0x0F, 0xAF, 0xC1, 0x03, 0xC2, 0xC3
};

int main()
{
    return EXIT_SUCCESS;
}
```

### 4.创建函数类型定义

创建函数类型定义，在全局范围内添加这段代码：

```cpp
typedef int(*_code_t)(int, int);
```

### 5.将原始代码访问标志设置为可执行

将原始代码访问标志设置为可执行，以便 CPU 可以执行它，在 main 中添加此代码：

```c++
    DWORD old_flag;
    VirtualProtect(hexData, sizeof hexData, PAGE_EXECUTE_READWRITE, &old_flag);
```

### 6.执行代码

最后一步是执行，在返回前添加以下代码：

```cpp
    _code_t fn_code = (_code_t)(void*)hexData;
    int x = 500; int y = 1200;
    printf("Result of function : %d\n", fn_code(x, y));
```

### 7.运行程序

构建 `code_tester `并运行，代码如下：

```cpp
// main.cpp
#include <windows.h>
#include <iostream>
using namespace std;
typedef int(*_code_t)(int, int);

unsigned char hexData[9] = {
    0x8D, 0x42, 0x01, 0x0F, 0xAF, 0xC1, 0x03, 0xC2, 0xC3
};

int main()
{
    DWORD old_flag;
    VirtualProtect(hexData, sizeof hexData, PAGE_EXECUTE_READWRITE, &old_flag);
    _code_t fn_code = (_code_t)(void*)hexData;
    int x = 500; int y = 1200;
    printf("Result of function : %d\n", fn_code(x, y));
    return EXIT_SUCCESS;
}
```

运行结果如下：

![Result](https://HLuKT.github.io/images/posts/blog/CreateShellcode/Result.png)

# 进阶方法

在上面的简单实现中，涉及到的代码十分基础，但当涉及到更复杂的代码，如压缩、加密、许可证检查等时，我们需要 .map 文件使得代码可以在任何地址获取其偏移量。

同样，在基本方法中，我们没有使用任何 CRT 或 Windows API，但在实际使用情况中，我们非常需要它们，所以我们也必须解决这个问题。

接下来将创建两个shellcode，一个用于加密缓冲区，一个用于解密缓冲区。

## 1.添加AES加密库

克隆[tiny-AES-c](https://github.com/kokke/tiny-AES-c)AES加密库，复制aes.c 和 aes.h到项目中。

## 2.添加头文件

将代码.cpp更改为：

```cpp
// code.cpp
extern "C"
{
    #include "aes.h"
    bool _encrypt(void* data, size_t size)
    {
        // Encryption Code Area //
        return true;
    }
}
```

## 3.添加加密代码

编写加密代码并且不要在堆栈上使用任何数据，编译后DLL文件中不得有.data部分

以下是加密代码：

```cpp
// code.cpp
extern "C"
{
#include "aes.h"
    bool _encrypt(void* data, size_t size)
    {
        // 在堆上分配空间
        struct AES_ctx ctx;
        unsigned char key[32] = {
        0xBB, 0x17, 0xCA, 0x8C, 0x69, 0x7F, 0xA1, 0x89,
        0x3B, 0xCF, 0xA8, 0x12, 0x34, 0x6F, 0xB6, 0xE8,
        0x79, 0x89, 0xDA, 0xD0, 0x0B, 0xA9, 0xA1, 0x1B,
        0x5B, 0x38, 0xD0, 0x4A, 0x20, 0x4D, 0xB8, 0x0E };
        unsigned char iv[16] = {
        0xA3, 0xF3, 0xD4, 0xC5, 0x5E, 0xCD, 0x41, 0xA6,
        0x22, 0xC9, 0x8D, 0xE5, 0xA3, 0xBB, 0x29, 0xF1 };

        // 初始化加密上下文
        AES_init_ctx_iv(&ctx, key, iv);

        // Encrypt buffer
        AES_CBC_encrypt_buffer(&ctx, (uint8_t*)data, size);
        return true;
    }
}
```

## 4.编译后查看code_gen.dll

![Addrdata](https://HLuKT.github.io/images/posts/blog/CreateShellcode/Addrdata.png)

可见，DLL中添加了一个 .rdata 段，该部分由 `tiny-aes-c` 为 `sbox `和 `rsbox` 查找表生成，没有这些数据就无法使机器代码工作。

## 5.合并区段

```cpp
#pragma comment(linker, "/merge:.rdata=.text")
```

## 6.再次编译

再次编译，用LordPE打开code_gen.dll：

![pdata](https://HLuKT.github.io/images/posts/blog/CreateShellcode/pdata.png)

可知 .rdata 段合并到了 .text 段

## 7.将 .text 段复制为 C 代码

使用 010Editor 打开 code_gen.dll，Ctrl+G 跳转到 .text 段，Ctrl+Shift+A 输入 .text 段原始大小，选中字节并从菜单栏编辑 -> 复制为 -> 复制为C代码，粘贴到头文件并添加到 code_tester 项目中。

> 为了便于代码提取，可以直接右键单击 LordPE 中的 .text 并选择 16进制编辑区段，可能会产生额外的大小，所以最好手动输入区段大小。

## 8.添加Shellcode

将 `code_tester` main.cpp 文件更改为：

```
// main.cpp
#include <windows.h>
#include <stdio.h>
#include <fstream>
#include <vector>
#include"Shellcode.h"
using namespace std;
typedef bool(*_encrypt)(void*, size_t);

#define ENC_SC_RAW hexData
#define FUNCTION_OFFSET 0x1220

int main(int argc, char* argv[])
{
    // 检查命令参数个数
    if (argc != 4) return EXIT_FAILURE;

    // 获取命令参数
    char* input_file = argv[1];
    char* process_mode = argv[2];
    char* output_file = argv[3];

    // 更改内存属性为可读可写可执行
    DWORD old_flag;
    VirtualProtect(ENC_SC_RAW, sizeof ENC_SC_RAW, PAGE_EXECUTE_READWRITE, &old_flag);

    // 声明加密函数
    _encrypt encrypt = (_encrypt)(void*)&ENC_SC_RAW[FUNCTION_OFFSET];

    // 将输入文件读入 vector 缓冲区
    ifstream input_file_reader(argv[1], ios::binary);
    vector<uint8_t> input_file_buffer(istreambuf_iterator<char>(input_file_reader), {});

    //向输入文件数据添加填充，此处采用 00 填充
    for (size_t i = 0; i < 16; i++)
        input_file_buffer.insert(input_file_buffer.begin(), 0x0);
    for (size_t i = 0; i < 16; i++) input_file_buffer.push_back(0x0);

    // 加密文件缓冲区
    if (strcmp(process_mode, "-e") == 0) encrypt(input_file_buffer.data(),
        input_file_buffer.size());

    // 将加密缓冲区保存到输出文件
    fstream file_writter;
    file_writter.open(output_file, ios::binary | ios::out);
    file_writter.write((char*)input_file_buffer.data(), input_file_buffer.size());
    file_writter.close();

    // 代码执行成功
    printf("OK"); return EXIT_SUCCESS;
}
```

## 9.获取地址偏移量

用文本编辑器打开code_gen.map，找到shellcode中 `_encrypt `函数的地址偏移量，搜索 `_encrypt`，可知虚拟偏移量是 0x2220。

![VirOffset](https://HLuKT.github.io/images/posts/blog/CreateShellcode/VirOffset.png)

## 10.计算实际偏移量

返回 LordPE 并检查 .text 段的虚拟地址，即 0x1000，减去虚拟地址，得到 0x12C0，即实际的偏移量，替换代码中的值：

```cpp
#define FUNCTION_OFFSET 0x1220
```

## 11.编译并测试加密

```cpp
code_tester.exe 1.jpg -e encrypted.jpg
```

## 12.生成解密Shellcode

步骤如下：

1.生成解密Shellcode

使用 `AES_CBC_decrypt_buffer`而不是 `AES_CBC_encrypt_buffer`

```cpp
	// Decrypt buffer
	AES_CBC_decrypt_buffer(&ctx, (uint8_t*)data, size);
```

2.修改类型定义

```cpp
typedef bool(*_crypt)(void*, size_t);
```

以下是 main.cpp 代码：

```
// main.cpp
#include <windows.h>
#include <stdio.h>
#include <fstream>
#include <vector>
#include"Encrypt.h"
#include"Decrypt.h"
using namespace std;
typedef bool(*_crypt)(void*, size_t);

#define ENC_SC_RAW EncryptData
#define DEC_SC_RAW DecryptData
#define FUNCTION_OFFSET 0x1220

int main(int argc, char* argv[])
{
    // 检查命令参数个数
    if (argc != 4) return EXIT_FAILURE;

    // 获取命令参数
    char* input_file = argv[1];
    char* process_mode = argv[2];
    char* output_file = argv[3];

    // 判断模式
    if (strcmp(process_mode, "-e") != 0 &&
        strcmp(process_mode, "-d") != 0) return EXIT_FAILURE;

    // 更改内存属性为可读可写可执行
    DWORD old_flag;
    VirtualProtect(ENC_SC_RAW, sizeof ENC_SC_RAW, PAGE_EXECUTE_READWRITE, &old_flag);
    VirtualProtect(DEC_SC_RAW, sizeof DEC_SC_RAW, PAGE_EXECUTE_READWRITE, &old_flag);

    // 声明加密函数
    _crypt encrypt = (_crypt)(void*)&ENC_SC_RAW[FUNCTION_OFFSET];
    _crypt decrypt = (_crypt)(void*)&DEC_SC_RAW[FUNCTION_OFFSET];

    // 将输入文件读入 vector 缓冲区
    ifstream input_file_reader(argv[1], ios::binary);
    vector<uint8_t> input_file_buffer(istreambuf_iterator<char>(input_file_reader), {});

    //向输入文件数据添加填充，此处采用 00 填充
    if (strcmp(process_mode, "-d") == 0) goto SKIP_PADDING;
    for (size_t i = 0; i < 16; i++)
        input_file_buffer.insert(input_file_buffer.begin(), 0x0);
    for (size_t i = 0; i < 16; i++) input_file_buffer.push_back(0x0);


    // 加密/解密文件缓冲区
    SKIP_PADDING:
    if (strcmp(process_mode, "-e") == 0) encrypt(input_file_buffer.data(),
        input_file_buffer.size());
    if (strcmp(process_mode, "-d") == 0) decrypt(input_file_buffer.data(),
        input_file_buffer.size());

    // 将加密缓冲区保存到输出文件
    fstream file_writter;
    file_writter.open(output_file, ios::binary | ios::out);
    if (strcmp(process_mode, "-e") == 0)
        file_writter.write((char*)input_file_buffer.data(), input_file_buffer.size());
    if (strcmp(process_mode, "-d") == 0)
        file_writter.write((char*)&input_file_buffer[16],
            input_file_buffer.size() - 32);
    file_writter.close();

    // 代码执行成功
    printf("OK"); return EXIT_SUCCESS;
}
```

## 13.编译并测试解密

```cpp
code_tester.exe encrypted.jpg -d decrypted.jpg
```

解密成功！