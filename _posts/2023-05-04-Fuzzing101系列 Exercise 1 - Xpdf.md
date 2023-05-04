---
layout: post
title: Fuzzing101系列 Exercise 1 - Xpdf
categories: Fuzz
description: Fuzz-AFL
keywords: fuzz,漏洞,自动化软件测试
---

Fuzzing技术

CVE-2019-13288 是一个漏洞，它可能会通过精心制作的文件导致无限递归。由于程序中每个被调用的函数都会在栈上分配一个栈帧，如果一个函数被递归调用这么多次，就会导致栈内存耗尽和程序崩溃。因此，远程攻击者可以利用它进行 DoS 攻击。

# Fuzzing101系列 Exercise 1 - Xpdf

## 下载并构建目标

### 为要fuzzing 的项目创建新目录

```
cd $HOME
mkdir fuzzing_xpdf && cd fuzzing_xpdf/
```

### 安装make 和 gcc

```
sudo apt install build-essential
```

### 下载 Xpdf 3.02

```
// error：Connection Refused 网页直接下载再拖进来
wget https://dl.xpdfreader.com/old/xpdf-3.02.tar.gz
tar -xvzf xpdf-3.02.tar.gz
```

### 构建 Xpdf

```
cd xpdf-3.02
sudo apt update && sudo apt install -y build-essential gcc
./configure --prefix="$HOME/fuzzing_xpdf/install/"
make
make install
```

### 对 Xpdf 进行测试，下载一些 PDF 示例

```
cd $HOME/fuzzing_xpdf
mkdir pdf_examples && cd pdf_examples
wget https://github.com/mozilla/pdf.js-sample-files/raw/master/helloworld.pdf
wget http://www.africau.edu/images/default/sample.pdf
wget https://www.melbpc.org.au/wp-content/uploads/2017/10/small-example-pdf-file.pdf
```

### 测试 pdfinfo 二进制文件

```
$HOME/fuzzing_xpdf/install/bin/pdfinfo -box -meta $HOME/fuzzing_xpdf/pdf_examples/helloworld.pdf
```

## 安装AFL++

### 安装依赖项

```
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 || sudo apt-get install -y lld llvm llvm-dev clang 
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev
```

### 检验和构建AFL++

```
cd $HOME
git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus
export LLVM_CONFIG="llvm-config-11"
make distrib
sudo make install
```

执行`afl-fuzz`，查看是否安装成功

## AFL++

AFL 是一个覆盖引导的fuzzer，这意味着它为每个变异的输入收集覆盖信息，以便发现新的执行路径和潜在的错误。当源代码可用时，AFL 可以使用检测，在每个基本块（函数、循环等）的开头插入函数调用。

### 为目标应用程序启用插桩，需要清理所有之前编译的目标文件和可执行文件

```
rm -r $HOME/fuzzing_xpdf/install
cd $HOME/fuzzing_xpdf/xpdf-3.02/
make clean
```

### 使用 afl-clang-fast 编译器构建 xpdf

```
export LLVM_CONFIG="llvm-config-11"
CC=$HOME/AFLplusplus/afl-clang-fast CXX=$HOME/AFLplusplus/afl-clang-fast++ ./configure --prefix="$HOME/fuzzing_xpdf/install/"
make
make install
```

### 运行 Fuzzer

```
afl-fuzz -i $HOME/fuzzing_xpdf/pdf_examples/ -o $HOME/fuzzing_xpdf/out/ -s 123 -- $HOME/fuzzing_xpdf/install/bin/pdftotext @@ $HOME/fuzzing_xpdf/output
```

每个选项的简要说明:

- -i 表示我们必须放置输入用例的目录(a.k.a 文件示例)
- -o 表示 AFL + + 将存储变异文件的目录

- -s 表示要使用的静态随机种子

- @@是占位符目标的命令行，AFL 将用每个输入文件名替换它


fuzzer会为每个不同的输入文件将运行以下命令

```
$HOME/fuzzing_xpdf/install/bin/pdftotext <input-file-name> $HOME/fuzzing_xpdf/output
```

```
报错信息如下：
[-] Hmm, your system is configured to send core dump notifications to an
    external utility. This will cause issues: there will be an extended delay
    between stumbling upon a crash and having this information relayed to the
    fuzzer via the standard waitpid() API.
    If you're just testing, set 'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1'.

    To avoid having crashes misinterpreted as timeouts, please log in as root
    and temporarily modify /proc/sys/kernel/core_pattern, like so:

    echo core >/proc/sys/kernel/core_pattern

[-] PROGRAM ABORT : Pipe at the beginning of 'core_pattern'
         Location : check_crash_handling(), src/afl-fuzz-init.c:2236
```

出现错误，根据提示，执行以下操作：

```
sudo su
echo core >/proc/sys/kernel/core_pattern
exit
```

可以在`$HOME/fuzzing_xpdf/out/` 目录中找到这些崩溃文件。一旦发现第一次崩溃，就可以停止fuzzer。



# 界面信息介绍

> **process timing：执行时间信息**
>
> run time：运行总时间
>
> last new find：距离最近一次发现新路径的时间
>
> last saved crash：距离最近一次保存程序崩溃的时间
>
> last saved hang：距离最近一次保存挂起的时间
> **overall results：**
>
> cycles done：运行的总周期数
>
> corpus count：语料库计数
>
> saved crashes：保存的程序崩溃个数
>
> saved hang：保存的挂起个数
> **cycle progress：**
>
> now processing：当前的测试用例ID（所在输入队列的位置）
>
> runs timed out：超时数量
> **map coverage：**覆盖率
>
> map density：目前已经命中多少分支元组，与位图可以容纳多少的比例
>
> count coverage：位图中每个被命中的字节平均改变的位数
> **stage progress：**
>
> now trying: 指明当前所用的变异输入的方法
>
> stage execs: 当前阶段的进度指示
>
> total execs: 全局的进度指示
>
> exec speed: 执行速度
> **findings in depth：种子变异产生的信息**
>
> favored items: 基于最小化算法产生新的更好的路径
>
> new edges on: 基于更好路径产生的新边
>
> total crashes: 基于更好路径产生的崩溃
>
> total tmouts: 基于更好路径产生的超时 包括所有超时的超时
> **fuzzing strategy yields： 进一步展示了AFL所做的工作，在更有效路径上得到的结果比例，对应上面的now trying**
>
> bit flips: 比特位翻转，例如：
>
> bitflip 1/1，每次翻转1个bit，按照每1个bit的步长从头开始
>
> bitflip 2/1，每次翻转相邻的2个bit，按照每1个bit的步长从头开始
>
> …
>
> byte flips: 字节翻转
>
> arithmetics: 算术运算，例如：
>
> arith 16/8，每次对16个bit进行加减运算，按照每8个bit的步长从头开始，即对文件的每个word进行整数加减变异
>
> know ints: 用于替换的基本都是可能会造成溢出的数，例：
>
> interest 16/8，每次对16个bit进替换，按照每8个bit的步长从头开始，即对文件的每个word进行替换
>
> dictionary: 有以下子阶段：
>
> user extras (over)，从头开始，将用户提供的tokens依次替换到原文件中
>
> user extras (insert)，从头开始，将用户提供的tokens依次插入到原文件中
>
> auto extras (over)，从头开始，将自动检测的tokens依次替换到原文件中
>
> 其中，用户提供的tokens，是在词典文件中设置并通过-x选项指定的，如果没有则跳过相应的子阶段。
>
> havoc：顾名思义，是充满了各种随机生成的变异，是对原文件的“大破坏”。具体来说，havoc包含了对原文件的多轮变异，每一轮都是将多种方式组合（stacked）而成
>
> splice：在任意选择的中点将队列中的两个随机输入拼接在一起.
>
> py/custom/req：
>
> trim：修建测试用例使其更短，但保证裁剪后仍能达到相同的执行路径
>
> eff
>
> **item geometry：**
>
> levels: 表示测试等级
>
> pending: 表示还没有经过fuzzing的输入数量
>
> pend fav: 表明fuzzer感兴趣的输入数量
>
> own finds: 表示在fuzzing过程中新找到的，或者是并行测试从另一个实例导入的数量
>
> imported: n/a表明不可用，即没有导入
>
> stability: 表明相同输入是否产生了相同的行为，一般结果都是100%

# 漏洞详情 ： [CVE-2019-13288](https://www.cvedetails.com/cve/CVE-2019-13288/)

在 Xpdf 4.01.01 中，Parser.cc 中的 Parser：：getObj（） 函数可能会通过构建的文件导致无限递归。远程攻击者可利用此漏洞进行 DoS 攻击。这类似于CVE-2018-16646。

![xpdf.png](https://HLuKT.github.io/images/posts/blog/Fuzz/xpdf.png)

## 重现崩溃

　在`$HOME/fuzzing_xpdf/out/default/crashes`目录下找到 crash 对应的文件。文件名类似于`id:000000,sig:11,src:004891+003832,time:5049275,execs:1211155,op:splice,rep:16`

![out.png](https://HLuKT.github.io/images/posts/blog/Fuzz/out.png)

将此文件作为输入传递给 pdftotext

`$HOME/fuzzing_xpdf/install/bin/pdftotext '/home/fuzz/fuzzing_xpdf/out/default/crashes/<your_filename>' $HOME/fuzzing_xpdf/output`
　它将导致段错误segmentation fault并导致程序崩溃。

### 调试

使用 gdb 找出程序因该输入而崩溃的原因。

首先使用调试信息重建 Xpdf 来获得符号堆栈跟踪：

```bash
rm -r $HOME/fuzzing_xpdf/install

cd $HOME/fuzzing_xpdf/xpdf-3.02/

make clean

CFLAGS="-g -O0" CXXFLAGS="-g -O0" ./configure --prefix="$HOME/fuzzing_xpdf/install/"

make

make install
```

然后使用GDB，输入`run`，gdb收到了`Program received signal SIGSEGV, Segmentation fault.`，说明程序crash

```bash
gdb --args $HOME/fuzzing_xpdf/install/bin/pdftotext $HOME/fuzzing_xpdf/out/default/crashes/id:000000,sig:11,src:004891+003832,time:5049275,execs:1211155,op:splice,rep:16 $HOME/fuzzing_xpdf/output
```

输入`bt`回溯查看栈帧，发现进入了 Parser::getObj 和 XRef::fetch 的无限递归调用，这正是 CVE-2019-13288 中提到的，而 hangs 主要就是递归漏洞，与我们收集到的 crash 一致。可以发现 Parser::getObj 与 Xref::fetch 互相循环递归调用，具体最终的递归是从 getObj 开始的，那么显然它的实现存在问题。

![crash.png](https://HLuKT.github.io/images/posts/blog/Fuzz/crash.png)

