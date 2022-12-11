---
layout: post
title: Using a macro to get an array length in C
date: 2021-07-01 15:57:00 -0400

---

# Abstract

This post explores why a function-like macro is an acceptable approach for getting an array's length in a beginner- or intermediate-level C programming course. Most modern programming languages use some kind of overarching, type-agnostic solution to get the number of elements in an array ([Python's `len()` function][4] or Java's `length` method, to name some examples). C does not offer such a function. To complicate matters, C's `sizeof` operator only returns the *byte size* of its argument, not the number of elements in an array. One can use basic division to get the number of elements in the array: by dividing an array's byte size by the byte size of any element in that array. Writing this math as a macro provides a data-type-agnostic solution for an array of any native data type. It also avoids issues that arise while trying to implement the same logic within a function. While there are likely better solutions, this solution should be acceptable for a beginner-level C programming class, where restrictions are strong. Typically, any "Intro to C" course will cover macros and functions. It is no great stretch of logic to combine the two concepts in order to determine this solution. The macro definition and its usage is given in the [next section](#len(array)-as-a-macro).

# LEN(array) as a macro

Function-like macro to get the length of any array of any native data
type.

    #define LEN(array) ((int)sizeof(array) / (int)sizeof((array)[0]))

**Params**: 

​	`array` - Any array of any length

**Returns**: 

​	An integer that denotes the length of the array

**Caution**: 

This solution works for native data types. It has *not* been
tested for *other* data types (example, a size_t or other). Using it for
such a data type may cause undefined behavior.

# Technical explanation:

Recall that the `sizeof` operator can be used to get the size in bytes of its argument. This can be useful to get the size of any element of the array.

    sizeof(array[i]) => typesize 

Consider this use for any element in an integer array named `somearray`:

    sizeof(somearray[0]) => 4

Now, recall that C has no native way to get the length of an array. The `sizeof` operator might appear to provide this information, but it has a completely different purpose. Instead, it yields the size of total contiguous memory for its argument. For arrays, it returns the size of memory used in the array, and NOT the number of elements. 

```
sizeof(somearray) => arraysize (in bytes)
```

Note that `arraysize` is defined by the amount of elements multiplied by the size of each element (the array's data type).

    elements * typesize = arraysize

For example, an integer array of two elements would yield `sizeof(array) => 8`. Observe:

    2 * 4 == 8

One could reform the mathematic logic to get the number of elements in an array:

    (arraysize / typesize) == elements 

For example, the two-element integer array would resolve like so:

    (8 / 4) == 2 

The `sizeof` operator can be used to implement that logic:

    sizeof(array)/sizeof(array[0]) == elements 

It cannot be overstated how misleading the `sizeof` operator is in the modern programming ecosystem. Most modern programming languages use some kind of overarching, type-agnostic solution to get the number of elements in any array. For example, Python offers `len()` in stdlib. Java arrays have a built-in `.length` method for this task.

At first, a function seemed like the best way to implement this approach. All attempts to solve this with a function ended with catastrophic failure. The only way to pass an array of any element is by passing it as a void pointer, like `const void *array`. Unfortunately, this also produces undefined behavior. For example, the first subscripted subscripted element (`array[0]`) would return a `sizeof(array[0]) -> 1` for any data type. This is an obvious problem for a data type like an integer, which should yield a value of 4. To replicate the problem, try the following implementation, which should yield undefined behavior:

    // BAD Example!
    int len(const void *array){
        return (int)sizeof(array)/(int)sizeof(array[0]);
    }

Now, recall that macros simply expand and replace a given text where the macro is used. Because it simply expands the text in-place, there is no need to worry about pointer parameters. Assuming all logic errors are tested in the expanded form, macros also eliminate the need to worry about data types used. 

# Example of implementation 

The `LEN` macro can be implemented and used in a simple C program. An example is provided:

```c
#include <stdio.h>
// Other include statements go here...

/** Declare the macro with the name "LEN". **/
#define LEN(array) ((int)sizeof(array)/(int)sizeof(array[0]))

// Other header information goes here...

/** main will be used to demonstrate the LEN macro. **/
int main(){
	
    // Initialize an array without specifying the size.
    int some_array[] = {0, 12, 3, 1443, 2343};
    
    // Prints the number "5" to the console.
    printf("%d\n", LEN(some_array));    
}
```

It is worth noting that the name `LEN` is arbitrary. A programmer could label this something more meaningful: `ARRAY_LEN`, for example. This tells anyone using the macro that they should pass an array as its argument. Otherwise, undefined behavior may occur.

# Conclusions

Writing the formula as a macro solved the "use any data type" problem. Macros simply replace text at a given place in the code. Thus, it expands the `LEN(array)` text to become the form that yields the array elements: that is, it calls each `sizeof`, casts both return values to integers, and then divides those values. Because it is simple text expansion, the data type of the argument `array` does not matter at all. It also completely bypasses the need for a pointer (and, thus, bypasses all the issues surrounding such an approach).

# Further research

The most glaring oversight of this article is the test cases. The `LEN` macro was tested only for a handful of native data types: int arrays, string-literal arrays (`char *array[]` types), and floats. There may be serious issues when returning the elements in non-native C arrays. A programmer should test that case before using this approach for such a data type.

This approach casts to integer (4-bytes) types. The `sizeof` operator typically returns a `long` integer type. This may introduce some problems for arrays of enormous size. As noted in the [technical description](#technical-description), this approach is really intended for a programmer with certain constraints. It is *rare* that a beginner-level C course would give a programmer an array that exceeded the maximum integer size. However, if that scale of elements is used, this macro may need to be modified without the cast to an `int`.

Finally, the scale of knowledge expected when using such a macro is worth reemphasizing. It is entirely possible for a veteran programmer to implement a much better approach: perhaps one that is more *rigorous* for *any given data type*; used in a function (as opposed to a macro) which does *not* experience the issues of passing and using array pointers; or any number of solutions to issues that are not noted in this article. This article was written specifically for a beginner-level C class, and it works to accomplish goals in that scope of knowledge.

# References:

<sup>1</sup>	[Discussion on macros and data types][1]

<sup>2</sup>	[Finding an array's length in C][2]

<sup>3</sup>	[Problems with pointers and `sizeof` in C][3]

<sup>4</sup>	[Python's `len()` function][4]

<!-- Links -->

[1]: https://www.geeksforgeeks.org/interesting-facts-preprocessors-c/	"Discussion on macros and data types"
[2]: https://stackoverflow.com/a/37539	"Finding an array's length in C"
[3]: https://stackoverflow.com/questions/492384/how-to-find-the-sizeof-a-pointer-pointing-to-an-array	"Problems with pointers and sizeof in C"
[4]: https://www.w3schools.com/python/ref_func_len.asp	"Python's len() function"
