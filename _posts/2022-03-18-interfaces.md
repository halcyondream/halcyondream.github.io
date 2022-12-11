# Introduction

The heart of interfaces is abstraction: making black boxes. In Java, interfaces are an inbuilt data structure. Java interfaces are basically a collection of method signatures: denoting the purpose (name), inputs (paramters), and outputs (return value). Interfaces follow very specific rules. 

- You cannot make instances of interfaces (using the `new` keyword)
- Interfaces can only use abstract methods (name, input, and output types)
- Interfaces cannot have concrete methods
- Interfaces can have static constants, but not variables

A veteran programmer will make the most of those rules as they design their code. Doing so is the heart of design patterns. And design patterns are really the key to maintanable, scalable code. It will help you use polymorphism without introducing the problems of multiple inheritance. You'll want this as your code matures.

However, a junior engineer may find interfaces useless. After all, can't concrete and abstract classes do the same thing? And why are the rules so strict? That's weird, right?

The answer is: not really&mdash;to all of the above. To fully appreciate interfaces, let's back up and cover a short history of abstract functions in math, their relationship in programming languages, and how they have become the cornerstone of interfaces in modern languages.

This walkthrough is meant for emerging developers. If you write software, this will help you understand some reasons for design patterns. If you audit software (for example, if your job is validating SAST results), this may help you understand why your clients are writing code a certain way. Likewise, it may help you give advice if you notice that bugs are derived from bad software deisgn.

This covers the topic of "abstract behavior versus implementation" across a few subjects. So, a few programming languages are explored.

However, the big idea of interfaces is "abstract behaviors. Remember that. The key to understanding this is to also understand the goals of abstraction, in general. Abstraction is a crucial part of modern computer science and IT. As time goes on, we should consider that abstraction will only play a greater role in our computing systems. 

# Functions in math

First, defer to Wikipedia's article on functions. They start with two pretty good illustrations. The first illustration is a basic "x implies f(x)" visual:

!["x implies f(x)" is an example of a function name without an implementation. Source: Wikipedia.](/assets/2022-03-18/function.PNG)

Based solely on this example, can you tell me how "f(x)" is defined? Of course not. **f(x)** could be defined as **x**<sup>**2**</sup>, or **x+1**, or any number of definitions. The point is, we don't really know. And, for the sake of abstraction, we don't really care. Not yet.

Back to Wikipedia. Scroll down a bit, and observe the next image. 

![A function is named and given an implementation. Source: Wikipedia.](https://upload.wikimedia.org/wikipedia/commons/thumb/3/3b/Function_machine2.svg/1024px-Function_machine2.svg.png)

A function **f** just accepts some input and returns some output. We don't really care how it makes that output. 

By the way, this kind of thinking, about abstraction, was really important to Alan Turing when he was formalizing [Oracle machines](https://en.wikipedia.org/wiki/Oracle_machine). These machines accept some input and provide some output. In Turing's view, *how* they produce the output regardless of implementation. 

![Turing's Oracle machine is a black box. Source: Wikipedia.](https://upload.wikimedia.org/wikipedia/commons/thumb/f/f6/Blackbox.svg/1920px-Blackbox.svg.png)

*(As a side note, "Oracles" are commonly used in cybersecurity literature to refer to something that can break a security system, but lacks an implementation; they are used to describe flaws in a system that could be exploited under the wrong conditions.)*

To recap, we can look at math functions as composed of two parts. When we know what some function means (like **f(x) = x<sup>2</sup>**), we could call that the *implementation* of the function. Otherwise, it is left abstract.

# C prototypes

With this generalization in mind, we should appreciate C's prototypes. These are just method signatures (name, inputs, and output type), which are completely separate from any actual implementation.

Let's look at an [example](https://www.programiz.com/c-programming/c-user-defined-functions):

```c
int addNumbers(int a, int b);         // function prototype
```

In and of itself, we do not know *how* the `addNumbers` function actually adds numbers. The intuition is that it should add its parameters, `a` and `b`, and then return the sum as an `int` (integer). 

But...does it have to? After all, we have not formally defined this function's behavior. Maybe it just adds two numbers and returns them. Maybe, it runs some low-level, assembly-like approach of calculating the sum by only using the successor function. Maybe, it adds the numbers, creates ten more numbers, does nothing with them, and then returns the value of one of those numbers. Maybe, it scrapes your hardware information, reaches out to a remote endpoint, and sends it to a remote server... 

We could do this all day. The point is, the prototype tells you nothing about how the function will work. Instead, the programmer does that. And the programmer can let it do whatever they want.

For the record, the simplest implementation might look like this:

```c
/*
 * Return the sum of two values, a and b.
 */
int addNumbers(int a, int b){
	return a + b;
}
```

And you would call this function exactly like you'd expect:

```c
n = 1;
n = 2;
addNumbers(n, m);  // Returns 3.
```

## C structures

C developers had an interesting problem. If you were writing code for a *lot* of data fields, how would you do this? The `addNumbers` function only takes two parameters, and it doesn't update anything. What if you needed to update fifty data fields? The novice C developer used "global variables," and this is universally considered as one fo the worst things you can do. Another approach was to make a data structure (a `struct`), and write functions/prototypes, which accepted a pointer to this struct, and performed some logic based on the structure's values. 

```c
struct Rectangle {
	int width;
	int height;
	...
} rectangle_t;

// Prototype to operate on rectangles.
int get_area(rectangle_t* rect);
...
	
int set_values(rectangle_t* rect, int width, int height){
	rect->width = width;
	...
}
```

This avoids global variables. However, pointer logic is really confusing to look at, and there is lots of room for error. This led to confusing code. 

# C++ classes

C++ brought classes and objects&mdash;and all the problems of inheritance and abstraction&mdash;to programming. Objects sought to solve some issues that people hated about C.

Objects just wrap up (encapsulate) the data fields and some functions. In this way, you could define a data type that has any number of fields (internal variables) and functionality (methods/behaviors). Methods usually perform logic directly on those internal fields, or retrieve the values that are set for a data field. 

A class is the "blueprint" for an object. 

In C++, a [class might look like the following](https://www.cplusplus.com/doc/tutorial/classes/):

```c++
class Rectangle {

	private:
	  	int width, height;

	public:
		void set_values (int, int);
    
  	int area (void);
};
```

These are remarkably similar to C structs, but there are some notable differences. Scope (public vs private) is denoted with keywords; you can hide methods or data fields. Scope can protect certain class members from being accessed or modified directly. Instead, you can use methods to control how those fields are accessed or modified.

This is why you'll sometimes hear "accessors" called "getters," and "mutators" called "setters."

Finally, notice that `set_values` and `area` are prototypes. They have not been implemented. C++ offers a couple ways to implement prototypes. The most common way (noted in the linked article) looks something like this:

```c++
void Rectangle::set_values(int width, int height){
	this.width = width;
	this.height = height;
}
```

Most C++ developers will implement a function by using the class' scope (in this case, `Rectangle::`) before the prototype's name. The rest of the signature matches the class definition. 

You can also implement a method directly in the class definition:

```c++
class Rectangle {
	...
    public:
		void set_values (int width, int height){
            this.width = width;
            this.height = height;
        }
    ...
```

The benefit of classes is readability when you actually use them.

```c++
int main(){
	Rectangle rect = new Rectangle();
	w = 100;
	h = 230;
	rect.set_values(100, 230);
}
```

## Problems with Multiple Inheritance

C++ brough meaningful data structures: fields with methods. A subclass can inherit the superclass' functionality by extending it. In C++, this looks like:

```c++
// Polygon is a SUPERclass...
class Polygon {
  protected:
    int width, height;
	
  public:
	void set_values (int a, int b){ 
		width=a; height=b;
	}
 };

// Rectangle is one SUBclas. It inherits Polygon's members.
class Rectangle: public Polygon {
  public:
	int area (){ 
		return width * height;
	}
 };

// Triangle is another subclass of the Polygon...
class Triangle: public Polygon {
  public:
	int area (){
		return width * height / 2;
	}
};
```

In this example, **Rectangle** and **Triangle** classes externd the functionality of the **Polygon**; they *inherit* the polygon's data fields and methods. Inheritance is usually fine so long as *one subclass inherits only one superclass.* Both Rectangle and Triangle inherit only the Polygon. So, this is fine.

### The Diamond Problem

However, C++ also allows a subclass to inherit *multiple superclasses*. This is usually called "multiple inheritance." Although there are some benefits to this, if done poorly, multiple inheritance will create even more problems. Thus, your code will suck. This is the heart of the [diamond problem](https://web.archive.org/web/20051024230813/http://www.objectmentor.com/resources/articles/javacpp.pdf).

Let's start by validating some benefits behind multiple inheritance. The single greatest benefit is **polymorphism**. A polymorphic class will inherit the properties of another type. When the subclass inherits multiple types, it gets their data types. It also gets their data fields and methods.

However, this can introduce an insidious problem. In fact, this problem is so fatal to your code design, that it inspired the Java developers to create a new data structure: the interface. 

Before we talk about interfaces, let's talk about the problem.

Consider this really simple example, a good illustration of bad design:

```c++
#include <iostream>
using namespace std;

class A {
    public:
    	int i;
    	void f(){
        	cout << "A" << endl;
        }
};

class B : public A {
    public:
    	int x;
    	void f(){
            cout << "B" << endl;
        }
};

class C : public A {
    public:
    	int y;
    	void f(){
            cout << "C" << endl;
        }
};

class D : B, C {
};
```

We can demonstrate these behaviors with a simple main function:

```c++
int main()
{
    A atype;
    B btype;
    C ctype;

    atype.f();
    btype.f();
    ctype.f();

    return 0;
}
```

The output is exactly what you'd expect. Each subclass prints its own definition of the function `f`:

```
A
B
C
```

Okay, the bad. Types A and B are concrete classes. They provide new instance variables and methods with implementation (not prototypes, the abstract method signatures we talked about earlier). Multiple inheritance from concrete classes is a bad idea. To appreciate why, let's consider some problems:

**There are new variables**. Unlike constants, these values will change. This means, for this new C type, the developer needs to keep track of all the variables in the superclasses (A, B, and C) in addition to the ones they define in the new subclass (D). By the end of the inheritance chain, class D has inherited the variables *i*, *x*, and *y*. If a subclass inherits more concrete superclasses, it will also inherit more variables. So, this problem just gets worse.

**Classes A, B, and C all provide different definitions for the function `f`**. Because D inherits all of them, the compiler has no idea which function definition it should use. The compiler will throw an error.

To illustrate this, we can modify the main function to create a D and call its function *f*:

```c++ 
D dtype;
dtype.f();
```

The error is exactly what you'd expect:

```
main.cpp:50:11: error: request for member ‘f’ is ambiguous
   50 |     dtype.f();
      |           ^
main.cpp:15:11: note: candidates are: ‘void A::f()’
   15 |      void f(){
      |           ^
main.cpp:31:11: note:                 ‘void C::f()’
   31 |      void f(){
      |           ^
main.cpp:23:11: note:                 ‘void B::f()’
   23 |      void f(){
      |           ^
```

When you diagram these, it creates a diamond-like shape.

![The diamond problem](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8e/Diamond_inheritance.svg/800px-Diamond_inheritance.svg.png)

This is the "diamond problem."

There are a few ways to mitigate the problem. One such mitigation is a kind of "best practice" for languages that let you perform multiple inheritance. The rules are simple: 

- If you are implementing more than one superclass (multiple inheritance), then *the superclasses should not implement any methods.* Instead, they should provide a set of abstract methods. 
- Likewise, if superclasses must be used for multiple inheritance, do not provide that object any variables. If you must define values, they must be constants.
- Finally, these superclasses (of abstract methods and no variables) should not themselves derive from any previous class. They should be the highest class in that inheritance heirarchy.

The deeper issues may not seem obvious right now. However, as your code base increases, these issues will expand, and these root issues can break your application. They require more time to maintain, and they do not scale at all for new features. This will steal your joy.

So, as a best practice, if you need multiple inheritance, inherit from a superclass with abstract methods and no variables. In the long run, this produces the most readable, scalable, and maintanable way to provide common functionality and to create a class that has multiple types.

### Mitigating the diamond problem

Let's try to rework the code from earlier in a way that respects this best practice, but still yields a C class with multiple inheritance.

```c++

#include <iostream>
using namespace std;

class A {
    public:
        void f();
};

class B {
    public:
        static const int X = 12;
};

class C {
    public:
        static const int Y = 13;
};

class D : public A, B, C {
    public:
        void f(){
            cout << "D" << endl;
        }
};

int main() {
    D dtype;
    dtype.f();
    
    return 0;
}
```

The output:

```
D
```

There are drawbacks to this approach:

- You have to implement each method in the concrete classes. If you don't have a strategy for this, it can lead to duplicate code.
- Implementation takes place in the subclass, which is concrete. We need to implement a subclass for any class that inherits an interface.

But that's it. 

In Java, this is the foundation of an interface. Java differentiates these "collections of method sigantures" from concrete implementation. Behaviors should be abstract; they should remain separate from the implementation.

This should sound a lot like C prototypes. This should sound a lot like the discussion on math functions from earlier. Interfaces are just abstraction.

By the way, if you want class D to use concrete implementations of A, B, or C, use composition. That is, make subclasses of A, B, and C; set internal variables of types A, B, or C; and initialize those variables to instances of the *subclasses* you made. 

```c++
class ConcreteA : public A {
};

class D : public A, B, C {
    
    private:
        A composite_a;
    
    public: 
        D(){
            this->composite_a = ConcreteA();
        }
        void f(){
            cout << "D" << endl;
        }
};

```

The next section shows an example of composition as a way to build on interface design.

# Interfaces are sets of behavior

For concrete and abstract classes, Java enforces the single-inheritance rule. You can only inherit properties and implementations from *one* superclass. Junior engineers typically rely on abstraction and inheritance because it is intuitive.

Because they focus on inheritance, they might neglect polymorphism. The rules for interfaces are noted at the [beginning of this document](#introduction). (They are up there in case you forget them.) You can implement any number of interfaces, but you have to define the methods; you can only define abstract methods (signatures) and constants; you can't use variables or method implementations. 

These reason behind these rules are seldom appreciated in introduction-level Java courses, univerisity or otherwise. However, in the previous section, we saw the issues that can happen when we use multiple inheritance with concrete methods. We are determined to write good code; and if we can't write good code, we should strive to follow good design principles.

The book *Head-First Design Principles* illustrates the use of interfaces versus concrete classes when you're expanding some code logic. This is a great section with great examples. I could not do it justice here. 

The big idea is this: interfaces should define behaviors, not implementation. Abstract method signatures, like prototypes, provide you with a common means to interact with objects that implement them. Who cares about implementation?

Chapter 1 of the Head-First book provides a better illustration that uses Java. Highly recommend reading that. Here, we will use pseudocode instead of Java&mdash;largely for copyright reasons. 

## Interfaces as pseudocode: an example

First, we define the behaviors as interfaces.

```pseudocode
interface QuackBehavior:
	abstract method quack()
	
interface FlyBehavior:
	abstract method fly()
```

Using these behavior sets, we can abstractly define a duck:

```pseudocode
abstract class Duck:
	QuackBehavior quackBehavior
	FlyBehavior flyBehavior
	
	implement method flyBehavior():
		this.flyBehavior.fly()
	
	implement method quackBehavior()
		this.quackBehavior.quack()
		
	implement method setQuackBehavior(QuackBehavior qb):
		this.quackBehavior = qb
```

Any Duck-type should have behavior for flying and quacking. However, we will use composition to make instance variables for the behaviors. 

For the sake of conversation, I added the `setQuackBehavior` method to illustrate a best practice. Here, we could update the duck's quack behavior to any class that implements the QuackBehavior interface. *We do not define the parameter based on an abstract or concrete class.* The reason? Interfaces are independent of implementation. We only want the behavior as it is noted in the abstract method's signature. Later, we pass the concrete type as an *argument.* Here, we declare the interface type as the *parameter.*

> On the related note, we would *never* want to declare a concrete type as a method *parameter*. Why? This limits you to only passing concrete types. This creates a kind of codependency on implementation. It gets harder and harder to maintain this kind of code. It is the first step towards bad, spaghetti code. *Do not declare concrete types as method parameters&mdash;ever.*

We also include subclasses for cases where they don't quack or fly (like a rubber duck).

```pseudocode
concrete class LoudQuack implements QuackBehavior:
	implement method quack():
		print("QUACK!")
		
concrete class Squeak implements QuackBehavior:
	implement method quack():
		print("squeak.")

concrete class NoQuack implements QuackBehavior:
	implement method quack():
		print("*silence*")

// Implement more quack behaviors...
```

And a similar set of classes for flying behaviors:

```pseudocode
concrete class FlyingDuck implements FlyBehavior:
	implement method fly():
		print("The duck flies high.")

concrete class CantFly implements FlyBehavior:
	implement method fly():
		print("The duck cannot fly.")

// Implement more flying behaviors...
```

We will use these implementations in our specific ducks.

Finally, we can make specific ducks that use a variety of behaviors. Consider two examples:

- A mallard duck can quack (loudly) and fly
- A toy, rubber duck can squeak and not fly at all

We could implement them as such:

```pseudocode
concrete class MallardDuck extends Duck:
	constructor MallardDuck():
		this.flyBehavior = FlyingDuck()
		this.quackBehavior = LoudQuack()
		

concrete class RubberDuck extends Duck:
	constructor RubberDuck():
		this.flyBehavior = CantFly()
		this.quackBehavior = Squeak()
```

Note that we initialize these ducks using the superclass, but creating an instance of the subclass. The general form is like:

```pseudocode
Superclass variableName = new Subclass()

// or...

Interface variableName = new Subclass()
```

Since our ducks are subclasses of the Duck superclass, we will use the first form to make new instances. For example, a mallard duck is created and used like this:

```pseudocode
Duck mallardDuck = new MallardDuck()
mallardDuck.quack()
mallardDuck.fly()
```

The output for a mallard duck's behaviors:

```
QUACK!
The duck flies high.
```

We can do the same thing for a toy rubber duck, which neither quacks nor flies.

```pseudocode
Duck rubberDuck = new RubberDuck
```

The output:

```
squeak.
This duck cannot fly.
```

# Other considerations

This walkthrough covers best practices for abstracting behaviors. You can apply this to other languages. For example, Python's inheritance very closely resembles C++. Like the previous C++ examples, just because you *can* use bad inheritance, doesn't mean you *should*. Python doesn't give you interfaecs in the same way that Java does, but you can use objects to get the same result.

```python
from abc import ABC, abstractmethod


class QuackBehavior(ABC):
	def quack() -> None:
		pass
	
	
class FlyBehavior(ABC):
	def fly() -> None:
		pass

	
class Duck(ABC):
	
	quack_behavior: QuackBehaviorInterface
	fly_behavior: FlyBehaviorInterface
	
	@abstractmethod
	def quack(self) -> None: 
		self.quack_behavior.quack()
	
	@abstractmethod
	def fly(self) -> None:
		self.fly_behavior.fly()
		

class MallardDuck(Duck):
	...
```

You get the idea. Python does not have interfaces, but we can still leverage good design principles; we leverage polymorphism without the diamond problem.

Interfaces appear in a very different form in Go. They are literally just collections of method signatures&mdash;there are no other rules. A structure (`struct`) implements the interface when you implement each method from the interface; then, the structure gains that type, and achieves polymorphism. (Go has its own rules and is not an object-oriented language. I will refrain from going much further than this.)

Finally, we should consider abstraction as a general concept. Unless you are writing raw binary code, you are probably using some kind of abstraction. Black boxes exist everywhere; they are the point of many APIs. 

# Closing thoughts

This reminds me a lot of Touring's ideas, the black box and the Oracle machine. The implementation doesn't matter. You give some input and get some output. We should consider if the future of software engineering will get farther and farther from the "low levels," from bytecode and assembly. 

We might also consider whether languages like C, Java, or Python will become obsolete some day; perhaps the next generation of languages will resemble Turing's idea of input-output. Perhaps, software development will just become the composition of interfaces, the inner-workings of which we know absolutely nothing.