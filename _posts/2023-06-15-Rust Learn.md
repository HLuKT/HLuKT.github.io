---
layout: post
title: Rust Learn
categories: Rust
description: Rust Learn
keywords: Rust
---

# Rust Learn

## Trait

### trait对象动态分发

```rust
// trait对象动态分发
trait Vehicle {
    fn run(&self);
}
// Car是实现了Vehicle trait的类型
// 只有一个字段表示车牌号
struct Car(u32);
impl Vehicle for Car {
    fn run(&self) {
        println!("car:{}",self.0)
    }
}

// truck是实现了Vehicle trait的类型
// 只有一个字段表示车牌号
struct Truck(u32);
impl Vehicle for Truck {
    fn run(&self) {
        println!("Truck:{}",self.0);
    }
}

fn main(){
    let car = Car(1111);
    let truck = Truck(2222);

    let vehicle1:&dyn Vehicle = &car;
    let vehicle2:&dyn Vehicle = &truck;

    vehicle1.run();
    vehicle2.run();
}
```

### 常见的 trait

#### Display

```RUST
// std::fmt::Display: 格式化打印用户友好字符串。
use std::fmt;
struct Person{
    name:String,
    age:u32,
}
impl fmt::Display for Person {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,"{}({} years)",self.name,self.age)
    }
}
fn main(){
    let _t = Person{
        name:"lll".to_string(),
        age:18,
    };
    println!("P:{}",_t)
}
```

#### Debug

```rust
// std::fmt::Debug: 格式化打印调试字符串。
#[derive(Debug)]
struct Person{
    name:String,
    age:u32,
}
fn main(){
    let person = Person {
        name: "lll".to_string(),
        age: 18,
    };
    println!("Person: {:?}", person);// Person: Person { name: "lll", age: 18 }
}
```

#### PartialEq、Eq

```rust
// std::cmp::PartialEq: 比较值相等。
// std::cmp::Eq: 类型完全相等关系。
#[derive(PartialEq,Eq)]
struct Point{
    x:i32,
    y:i32,
}
fn main(){
    let point1 = Point { x: 2, y: 3 };
    let point2 = Point { x: 2, y: 3 };
    let point3 = Point { x: 4, y: 5 };

    println!("point1 == point2: {}", point1 == point2);
    println!("point1 == point3: {}", point1 == point3);
}
```

#### PartialOrd、Ord

##### e.g.1

```rust
// std::cmp::PartialOrd: 比较值顺序。
// std::cmp::Ord: 类型完全顺序关系。
#[derive(PartialEq, Eq, PartialOrd, Ord)]  // 部分相等性-https://course.rs/difficulties/eq.html
struct Point {
    x: i32,
    y: i32,
}
fn main(){
    let point1 = Point { x: 2, y: 3 };
    let point2 = Point { x: 4, y: 5 };
    let point3 = Point { x: 2, y: 6 };

    println!("point1 < point2: {}", point1 < point2);
    println!("point1 > point2: {}", point1 > point2);
    println!("point1 <= point3: {}", point1 <= point3);
    println!("point1 >= point3: {}", point1 >= point3);
}
```

##### e.g.2

```rust
use std::fmt::Display;
struct Pair<T> {
    x: T,
    y: T,
}

impl<T> Pair<T> {
    fn new(x: T, y: T) -> Self {
        Self { x, y }
    }
}

impl<T: Display + PartialOrd> Pair<T> {
    fn cmp_display(&self) {
        if self.x >= self.y {
            println!("The largest member is x = {}", self.x);
        } else {
            println!("The largest member is y = {}", self.y);
        }
    }
}
fn main() {
    let pair = Pair::new(10, 5);
    pair.cmp_display();
}
```



#### Clone

```rust
// std::clone::Clone: 创建类型副本。
#[derive(Clone)]
struct Point {
    x: i32,
    y: i32,
}

fn main() {
    let point1 = Point { x: 2, y: 3 };
    let point2 = point1.clone();

    println!("point1: x = {}, y = {}", point1.x, point1.y);
    println!("point2: x = {}, y = {}", point2.x, point2.y);
}
```

#### Add

```rust
// std::ops::Add: 定义加法操作。
use std::ops::Add;
struct Point {
    x: i32,
    y: i32,
}
impl Add for Point {
    type Output = Point;

    fn add(self, other: Point) -> Point {
        Point {
            x: self.x + other.x,
            y: self.y + other.y,
        }
    }
}
fn main(){
    let point1 = Point{x:2,y:5};
    let point2 = Point{x:6,y:8};

    let sum = point1+point2;
    println!("sum:x={},y={}",sum.x,sum.y);
}
```

#### Mul

```rust
// std::ops::Mul: 定义乘法操作。
use std::ops::Mul;
struct Point {
    x: i32,
    y: i32,
}
impl Mul for Point {
    type Output = Point;

    fn mul(self, other: Point) -> Point {
        Point {
            x: self.x * other.x,
            y: self.y * other.y,
        }
    }
}
fn main(){
    let point1 = Point{x:2,y:5};
    let point2 = Point{x:6,y:8};

    let sum = point1*point2;
    println!("sum:x={},y={}",sum.x,sum.y);
}
```

#### Iterator

```rust
// std::iter::Iterator: 实现迭代器。
struct  Counter{
    count:u32,
}
impl Iterator for Counter {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        self.count+=1;
        if self.count<6 {
            Some(self.count)
        }
        else {
            None
        }
    }
}
fn main(){
    let mut counter = Counter{count:0};
    // 使用 for循环迭代Counter
    for num in counter {
        println!("nNum:{}",num);
    }
}
```

## 错误处理

### 栈回溯

```rust
// backtrace 栈展开(栈回溯)
// $env:RUST_BACKTRACE=1 ; cargo run
fn main() {
    let v = vec![1, 2, 3];
    v[99];
}
```

### 不可恢复的错误

unwrap 和 expect

```rust
fn main() {
	use std::net::IpAddr;
	let home: IpAddr = "127.0.0.1".parse().unwrap();
    // let home: IpAddr = "127.0.0.1".parse().expect("fail");
}
```

### 可恢复的错误

Result<T, E> 是一个枚举类型，定义如下

> enum Result<T, E> {
>     		Ok(T),
>     		Err(E),
> 		}

泛型参数 T 代表成功时存入的正确值的类型，存放方式是 Ok(T)，E 代表错误时存入的错误值，存放方式是 Err(E)。

```
use std::{fs::File, io};
use std::io::Read;

fn readfile1() -> Result<String,io::Error>{
    let file = File::open("path.txt");

    let mut f = match file {
        Ok(file) => file,
        Err(e)=>return Err(e),
    };

    let mut s = String::new();
    match f.read_to_string(&mut s) {
        Ok(_) => Ok(s),
        Err(e) => Err(e),
    }
}
fn readfile2() -> Result<String,io::Error>{
    let mut file1 = File::open("path")?;
    let mut s = String::new();
    file1.read_to_string(&mut s)?;
    Ok(s)
}

fn readfile3() -> Result<String,io::Error>{
    let mut s = String::new();
    File::open("path")?.read_to_string(&mut s)?;
    Ok(s)
}

use std::fs;
fn readfile4() -> Result<String,io::Error>{
    fs::read_to_string("path")
}

fn last_char_of_first_line(text: &str) -> Option<char> {
    text.lines().next()?.chars().last()
}

// fn main() {
//     //let _f = File::open("path.txt").unwrap();
//     //let _f = File::open("path.txt").expect("fail");

//     // let rfile = readfile();
//     // let _result = match rfile {
//     //     Ok(_)=>{println!("ok");}
//     //     Err(_e)=>{println!("err");}
//     // };
//         let text = "Hello\nWorld\n123";
//         let last_char = last_char_of_first_line(text);
    
//         match last_char {
//             Some(c) => println!("Last char of the first line: {}", c),
//             None => println!("Text is empty or the first line is empty."),
//         }
// }

use std::error::Error;
fn main() -> Result<(),Box<dyn Error>>{
    let f = File::open("path")?;
    Ok(())
}
```

## 包和模块

### 包 Crate

创建一个库类型的 Package

```rust
cargo new --lib restaurant
```

### 模块 Module

#### src/lib.rs

```rust
/* 模块1
mod front_of_house{
    pub mod hosting{
        pub fn add_to_waitlist(){

        }
        fn seat_at_table(){

        }
    }
    mod serving{
        fn take_order(){

        }
        fn serve_order() {
            self::back_of_house::cook_order()
            //back_of_house::cook_order()
        }
        mod back_of_house{
            fn fix_incorrect_order(){
                cook_order();
                super::serve_order();
            }
            pub fn cook_order(){
        
            }
        }
        fn take_payment() {
            
        }
    }
}

pub fn eat_at_restaurant(){
    crate::front_of_house::hosting::add_to_waitlist();
    front_of_house::hosting::add_to_waitlist();
}
*/

/* 模块与文件分离 */

mod front_of_house;

pub use front_of_house::hosting;

pub fn eat_at_restaurant() {
    hosting::add_to_waitlist();
    hosting::add_to_waitlist();
    hosting::add_to_waitlist();
}
```

#### src/front_of_house.rs

```rust
pub mod hosting;
pub mod serving;
```

##### src/front_of_house/hosting.rs

```rust
pub fn add_to_waitlist() {}
```

### 避免同名引用

#### 模块::函数

```rust
use std::fmt;
use std::io;

fn function1() -> fmt::Result {
    // --snip--
}

fn function2() -> io::Result<()> {
    // --snip--
}
```

#### as别名引用

```rust
use std::fmt::Result;
use std::io::Result as IoResult;

fn function1() -> Result {
    // --snip--
}

fn function2() -> IoResult<()> {
    // --snip--
}
```

#### 受限的可见性

```rust
// 一个名为 `my_mod` 的模块
mod my_mod {
    // 模块中的项默认具有私有的可见性
    fn private_function() {
        println!("called `my_mod::private_function()`");
    }

    // 使用 `pub` 修饰语来改变默认可见性。
    pub fn function() {
        println!("called `my_mod::function()`");
    }

    // 在同一模块中，项可以访问其它项，即使它是私有的。
    pub fn indirect_access() {
        print!("called `my_mod::indirect_access()`, that\n> ");
        private_function();
    }

    // 模块也可以嵌套
    pub mod nested {
        pub fn function() {
            println!("called `my_mod::nested::function()`");
        }

        #[allow(dead_code)]
        fn private_function() {
            println!("called `my_mod::nested::private_function()`");
        }

        // 使用 `pub(in path)` 语法定义的函数只在给定的路径中可见。
        // `path` 必须是父模块（parent module）或祖先模块（ancestor module）
        pub(in crate::my_mod) fn public_function_in_my_mod() {
            print!("called `my_mod::nested::public_function_in_my_mod()`, that\n > ");
            public_function_in_nested()
        }

        // 使用 `pub(self)` 语法定义的函数则只在当前模块中可见。
        pub(self) fn public_function_in_nested() {
            println!("called `my_mod::nested::public_function_in_nested");
        }

        // 使用 `pub(super)` 语法定义的函数只在父模块中可见。
        pub(super) fn public_function_in_super_mod() {
            println!("called my_mod::nested::public_function_in_super_mod");
        }
    }

    pub fn call_public_function_in_my_mod() {
        print!("called `my_mod::call_public_funcion_in_my_mod()`, that\n> ");
        nested::public_function_in_my_mod();
        print!("> ");
        nested::public_function_in_super_mod();
    }

    // `pub(crate)` 使得函数只在当前包中可见
    pub(crate) fn public_function_in_crate() {
        println!("called `my_mod::public_function_in_crate()");
    }

    // 嵌套模块的可见性遵循相同的规则
    mod private_nested {
        #[allow(dead_code)]
        pub fn function() {
            println!("called `my_mod::private_nested::function()`");
        }
    }
}

fn function() {
    println!("called `function()`");
}

fn main() {
    // 模块机制消除了相同名字的项之间的歧义。
    function();
    my_mod::function();

    // 公有项，包括嵌套模块内的，都可以在父模块外部访问。
    my_mod::indirect_access();
    my_mod::nested::function();
    my_mod::call_public_function_in_my_mod();

    // pub(crate) 项可以在同一个 crate 中的任何地方访问
    my_mod::public_function_in_crate();

    // pub(in path) 项只能在指定的模块中访问
    // 报错！函数 `public_function_in_my_mod` 是私有的
    //my_mod::nested::public_function_in_my_mod();
    // 试一试 ^ 取消该行的注释

    // 模块的私有项不能直接访问，即便它是嵌套在公有模块内部的

    // 报错！`private_function` 是私有的
    //my_mod::private_function();
    // 试一试 ^ 取消此行注释

    // 报错！`private_function` 是私有的
    //my_mod::nested::private_function();
    // 试一试 ^ 取消此行的注释

    // 报错！ `private_nested` 是私有的
    //my_mod::private_nested::function();
    // 试一试 ^ 取消此行的注释
}
```

## 注释和文档

### 包和模块级别的注释

```rust
/*! lib包是world_hello二进制包的依赖包，
 里面包含了compute等有用模块 */

pub mod front_of_house;
/* 
        再为该包根的子模块 src/front_of_house.rs 添加注释：
        //! 计算一些你口算算不出来的复杂算术题
        /// `add_one`将指定值加1
        ///
*/
```

### 代码注释

```rust
// 块注释

/* */ 行注释
```

### 文档注释

#### 文档块注释

~~~rust
// 文档块注释/* ..... */
/** `add` 将指定值加2
```
let arg = 5;
let answer = my_crate::add(arg);

assert_eq!(7, answer);
```
*/
pub fn add(x: i32) -> i32 {
    x + 2
}
~~~

#### 文档行注释

```rust
// 带测试用例的文档测试 文档行注释 ///
/// `add_one` 将指定值加1
///
/// # Examples11
///
/// ```
/// let arg = 5;
/// let answer = world_hello::compute::add_one(arg);
///
/// assert_eq!(6, answer);
/// ```
pub fn add_one(x: i32) -> i32 {
    x + 1
}
```

### 文档测试

#### 造成 panic 的文档测试

```rust
// 造成 panic 的文档测试    should_panic
/// # Panics
///
/// The function panics if the second argument is zero.
///
/// ```rust,should_panic
/// // panics on division by zero
/// world_hello::compute::div(10, 0);
/// ```
pub fn div(a: i32, b: i32) -> i32 {
    if b == 0 {
        panic!("Divide-by-zero error");
    }

    a / b
}
```

#### 保留测试，隐藏文档

```rust
// 保留测试，隐藏文档
/// ```
/// # // 使用#开头的行会在文档中被隐藏起来，但是依然会在文档测试中运行
/// # fn try_main() -> Result<(), String> {
/// let res = world_hello::compute::try_div(10, 0)?;
/// # Ok(()) // returning from try_main
/// # }
/// # fn main() {
/// #    try_main().unwrap();
/// #
/// # }
/// ```
pub fn try_div(a: i32, b: i32) -> Result<i32, String> {
    if b == 0 {
        Err(String::from("Divide-by-zero"))
    } else {
        Ok(a / b)
    }
}
```

### 文档注释中的代码跳转

#### 跳转到标准库

```rust
// 跳转到标准库
/// `add_one` 返回一个[`Option`]类型
pub fn add_one(x: i32) -> Option<i32> {
    Some(x + 1)
}
```

#### 使用路径的方式跳转

```rust
// 使用路径的方式跳转
use std::sync::mpsc::Receiver;

/// [`Receiver<T>`]   [`std::future`].
///
///  [`std::future::Future`] [`Self::recv()`].
pub struct AsyncReceiver<T> {
    sender: Receiver<T>,
}

impl<T> AsyncReceiver<T> {
    pub async fn recv() -> T {
        unimplemented!()
    }
}
```

#### 使用完整路径跳转到指定项

```rust
// 使用完整路径跳转到指定项
pub mod a {
    /// `add_one` 返回一个[`Option`]类型
    /// 跳转到[`crate::MySpecialFormatter`]
    pub fn add_one(x: i32) -> Option<i32> {
        Some(x + 1)
    }
}

pub struct MySpecialFormatter;
```

#### 同名项的跳转

```rust
// 同名项的跳转

/// 跳转到结构体  [`Foo`](struct@Foo)
pub struct Bar;

/// [`Foo`](struct@Foo)
/// 跳转到同名函数 [`Foo`](fn@Foo)
pub struct Foo {}

/// 跳转到同名宏 [`foo!`]
pub fn Foo() {}

#[macro_export]
macro_rules! foo {
  () => {}
}
```

### 文档搜索别名

```rust
// 文档搜索别名
#[doc(alias = "x")]
#[doc(alias = "big")]
pub struct BigX;

#[doc(alias("y", "big"))]
pub struct BigY;
```

## 格式化输出

- print! 将格式化文本输出到标准输出，不带换行符
- println! 同上，但是在行的末尾添加换行符
- format! 将格式化文本输出到 String 字符串
- eprint!，eprintln! 仅应该被用于输出错误信息和进度信息

### Display

#### 为自定义类型实现 Display 特征

```rust
// 为自定义类型实现 Display 特征
struct PersonInfo {
    name: String,
    age: u8,
}

use std::fmt;
impl fmt::Display for PersonInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "姓名{}，年龄{}",
            self.name, self.age
        )
    }
}
fn main() {
    let p = PersonInfo {
        name: "sunface".to_string(),
        age: 18,
    };
    println!("{}", p);
}

```

#### 为外部类型实现 Display 特征

```rust
// 为外部类型实现 Display 特征
 struct Array(Vec<i32>);

 use std::fmt;
 impl fmt::Display for Array {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
         write!(f, "数组是：{:?}", self.0)
     }
 }
 fn main() {
     let arr = Array(vec![1, 2, 3]);
     println!("{}", arr);
 }
```

### 位置参数

占位符(索引从 0 开始)：

```rust
fn main() {
    println!("{}{}", 1, 2); // =>"12"
    println!("{1}{0}", 1, 2); // =>"21"
    // => Alice, this is Bob. Bob, this is Alice
    println!("{0}, this is {1}. {1}, this is {0}", "Alice", "Bob");
    println!("{1}{}{0}{}", 1, 2); // => 2112
}
```

### 具名参数

为参数指定名称：

```rust
fn main() {
    println!("{argument}", argument = "test"); // => "test"
    println!("{name} {}", 1, name = 2); // => "2 1"
    println!("{a} {c} {b}", a = "a", b = 'b', c = 3); // => "a 3 b"
}
```

**带名称的参数必须放在不带名称参数的后面**

### 格式化参数

```rust
fn main() {
    let v = 3.1415926;
    // Display => 3.14
    println!("{:.2}", v);
    // Debug => 3.14
    println!("{:.2?}", v);
}
```

### 填充和对齐

#### 字符串填充

字符串格式化默认使用空格进行填充，并且进行左对齐。

```rust
fn main() {
    //-----------------------------------
    // 以下全部输出 "Hello x    !"
    // 为"x"后面填充空格，补齐宽度5
    println!("Hello {:5}!", "x");
    // 使用参数5来指定宽度
    println!("Hello {:1$}!", "x", 5);
    // 使用x作为占位符输出内容，同时使用5作为宽度
    println!("Hello {1:0$}!", 5, "x");
    // 使用有名称的参数作为宽度
    println!("Hello {:width$}!", "x", width = 5);
    //-----------------------------------

    // 使用参数5为参数x指定宽度，同时在结尾输出参数5 => Hello x    !5
    println!("Hello {:1$}!{}", "x", 5);
}
```

#### 数字填充

数字格式化默认也是使用空格进行填充，但与字符串左对齐不同的是，数字是右对齐。

```rust
fn main() {
    // 宽度是5 => Hello     5!
    println!("Hello {:5}!", 5);
    // 显式的输出正号 => Hello +5!
    println!("Hello {:+}!", 5);
    // 宽度5，使用0进行填充 => Hello 00005!
    println!("Hello {:05}!", 5);
    // 负号也要占用一位宽度 => Hello -0005!
    println!("Hello {:05}!", -5);
}
```

#### 对齐

```rust
fn main() {
    // 以下全部都会补齐5个字符的长度
    // 左对齐 => Hello x    !
    println!("Hello {:<5}!", "x");
    // 右对齐 => Hello     x!
    println!("Hello {:>5}!", "x");
    // 居中对齐 => Hello   x  !
    println!("Hello {:^5}!", "x");

    // 对齐并使用指定符号填充 => Hello x&&&&!
    // 指定符号填充的前提条件是必须有对齐字符
    println!("Hello {:&<5}!", "x");
}
```

#### 精度

精度可以用于控制浮点数的精度或者字符串的长度

```rust
fn main() {
    let v = 3.1415926;
    // 保留小数点后两位 => 3.14
    println!("{:.2}", v);
    // 带符号保留小数点后两位 => +3.14
    println!("{:+.2}", v);
    // 不带小数 => 3
    println!("{:.0}", v);
    // 通过参数来设定精度 => 3.1416，相当于{:.4}
    println!("{:.1$}", v, 4);

    let s = "hi我是Sunface孙飞";
    // 保留字符串前三个字符 => hi我
    println!("{:.3}", s);
    // {:.*}接收两个参数，第一个是精度，第二个是被格式化的值 => Hello abc!
    println!("Hello {:.*}!", 3, "abcdefg");
}
```

#### 进制

可以使用 # 号来控制数字的进制输出：

- #b, 二进制
- #o, 八进制
- #x, 小写十六进制
- #X, 大写十六进制
- x, 不带前缀的小写十六进制

```rust
fn main() {
    // 二进制 => 0b11011!
    println!("{:#b}!", 27);
    // 八进制 => 0o33!
    println!("{:#o}!", 27);
    // 十进制 => 27!
    println!("{}!", 27);
    // 小写十六进制 => 0x1b!
    println!("{:#x}!", 27);
    // 大写十六进制 => 0x1B!
    println!("{:#X}!", 27);

    // 不带前缀的十六进制 => 1b!
    println!("{:x}!", 27);

    // 使用0填充二进制，宽度为10 => 0b00011011!
    println!("{:#010b}!", 27);
}
```

#### 指数

```rust
fn main() {
    println!("{:2e}", 1000000000); // => 1e9
    println!("{:2E}", 1000000000); // => 1E9
}
```

#### 指针地址

```rust
let v= vec![1, 2, 3];
println!("{:p}", v.as_ptr()) // => 0x600002324050
```

#### 转义

```rust
fn main() {
    // "{{" 转义为 '{'   "}}" 转义为 '}'   "\"" 转义为 '"'
    // => Hello "{World}" 
    println!(" Hello \"{{World}}\" ");

    // 下面代码会报错，因为占位符{}只有一个右括号}，左括号被转义成字符串的内容
    // println!(" {{ Hello } ");
    // 也不可使用 '\' 来转义 "{}"
    // println!(" \{ Hello \} ")
}
```

### 在格式化字符串时捕获环境中的值

输出一个函数的返回值

```rust
/* 以前的写法
	fn get_person() -> String {
	    String::from("sunface")
	}
	fn main() {
	    let p = get_person();
	    println!("Hello, {}!", p);                // implicit position
	    println!("Hello, {0}!", p);               // explicit index
	    println!("Hello, {person}!", person = p);
	}
*/

fn get_person() -> String {
    String::from("sunface")
}
fn main() {
    let person = get_person();
    println!("Hello, {person}!");
}
```

