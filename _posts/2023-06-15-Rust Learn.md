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

