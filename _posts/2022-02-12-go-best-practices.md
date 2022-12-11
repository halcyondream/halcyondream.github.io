# Best practices for Go

*Happy 2022! I'm rolling in the new year with another hot take on Go. If you're already familiar with Go, secure programming, and other best practices, skip down to the "References."*

In another discussion post, I discussed some basics of the Go programming language. This post just provides a couple of "best practices" for writing Go.

## Good program design

From an application-security point of view, we want to write programs that are:

- **Scalable**. Packages should contain content that can grow with time without destroying functionality. This allows the developer to implement better security mechanisms when needed.
- **Testable**. All components of a system should be testable in a way that does not rely on external dependencies (like databases or network connections). This allows a developer to test the security or integrity of each part of the system independent of the whole application.
- **Secure**. The code should follow the most recent best practices for security. A code base that is already scalable and testable will allow for better security integration over time.

Much of the literature about secure coding practices centers around object-oriented languages. In his book, *Working With Legacy Code*, Michael Feathers offers a wealth of insight on practices to deter "code rot." He argues that "legacy code" is really any code that has not been tested. This may seem like a controversial meaning. However, this is the essence of code rot, and code rot is the state of legacy code. Anyone in the software industry knows that, as time goes on, it is less and less likely that *anyone* will test code that "just works." Therein lies the issue.

The book provides ways to design and implement good test cases. Feathers offers examples (UML diagrams) of what effective test cases might look like. He argues that testing each part of the code base in the smallest amount of time (1/100th of a second) is a best-case scenario. Although the book discusses objects and inheritance, it also offers some insight on how to plan good interfaces. We can take particular note of this since Go uses interfaces.

We should note that the takeaway is not to "write objects or interfaces for test cases." Rather, we should consider that, if we write scalable, testable code to begin with, we can perform meaningful tests on it later on. Put another way, this is our deterrence to allowing our code to lapse into a legacy state, one where we neither understand its structure nor appreciate its purpose.

## Go uses interfaces, not objects

First, we should recognize that Go uses objects, not interfaces. The documentation describes interfaces as a "collection of method signatures." (The other article on Go provides some insight on how to implement a Go interface.)

Since there are no objects in Go, realize that inheritance does not exist. This presents Go developers with a unique situation. Consider that many resources on effective software development rely on some kind of object-oriented approach. Other bodies of literature focus more on "structures and functions" as separate entities, with a structure (or object functioning as one) passed as an argument.

Go interfaces are somewhere between "objects" and "functions and structures." 

On one hand, they provide a wrapper for structures to implement their functionality. You can declare a structure, use that structure to implement a method, and then call that method using dot-notation. This should strike you as similar to Java. 

On the other hand, you cannot "inherit" another structure's properties: its data fields and implemented methods. Consider how this may affect testing. When writing test cases, you may need to write test cases for three components: structures; interfaces; and structures that implement interfaces. Consider also how this affects scalability. You can't extend a structure or an interface with a simple keyword.

## Best practices

Francesc Flores offers twelve "best practices" for writing Go. This is on slide 34 (of 36).

> 1. Avoid nesting by handling errors first
> 2. Avoid repetition when possible
> 3. Important code goes first
> 4. Document your code
> 5. Shorter is better
> 6. Packages with multiple files
> 7. Make your packages "go get"-able
> 8. Ask for what you need
> 9. Keep independent packages independent
> 10. Avoid concurrency in your API
> 11. Use goroutines to manage state
> 12. Avoid goroutine leaks