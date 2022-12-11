# Overview

This document explains how to implement an iterative mergesort on a linked list. There are many references to the recursive mergesort on a linked list. An iterative approach is often used to sort an array, but sparse resources even attempt to explore this topic for such a data structure.^[The reasons why are not explored here.]

The implementation is based on one provided by GeeksForGeeks (noted in the acknowledgements). In particular, this implementation seeks to improve their solution: by streamlining code and renaming variables wherever appropriate. The pseudocode used for this implementation borrows notations from Python3 and Golang.

## The data structures

The *Node* data structure^[In an object-oriented language, a programmer would implement this as a class definition.] is at the heart of this algorithm:

```
structure Node {
	data: number
	next: Node
}
```

When initialized, a *Node* type is usually given a value for its data, and the *next* field is set to *NULL* (or *None* here). For example, a constructor might apply the following logic to each new instance of a node:

```
function initialize_node(new_node, data) {
	new_node→data := data
	new_node→next := None
}
```

In itself, note that the *Node* type has no way to keep track of values at either endpoint (at the start or end). So, a second structure holds the *head* and *tail* nodes for a given list.^[The original article uses four values  across the program: two *start* and two *end* variables. This approach is logically the same. It is the author's opinion that a structure which holds the head and tail references is easier to read and follow. However, there is nothing stopping a programmer from using four separate variables if they so choose.]

```
structure LinkedList {
	head: Node 
	tail: Node
}
```

# Algorithm

As with any mergesort, this algorithm uses two functions: a "[merge](#merge-and-sort-each-left,-right-partition)" (which merges and sorts the decomposed sublists); and a "[mergesort](#the-mergesort-function)" (which decomposes parts into sublists, then calls on "merge" to recompose them in order).

```
    Input: head (LinkedList), length (integer)
   Output: None
Procedure: Perform the merge-sort algorithm on all nodes
		   linked to the head
```

## Merge and sort each *left*, *right* partition

The *mergePartitions* function will merge and sort a given left and right part. Both *left* and *right* are linked lists. This appends everything to the left node, so the function returns nothing. 

```pseudocode
function mergePartitions(left, right) {
	
	// Swap the left, right nodes if the left's first value is larger.
	if left→head→data > right→head→data:
		swapNodes(left, right)
	
	// Endpoint of the right partition.
	part_end := right→tail→next
	
	// Loop while the left and right parts are in their own ranges.
	while left→head ≠ left→tail and right←head ≠ part_end→tail:
		
		// If the right's data is greater, insert the left part
		// to the node just after the right's head.
		if left→head→data > right→head→data:
			temp := right→head→next
			right→head→next := left→head→next
			left→head→next := right→head
			right→head := temp
        
		// Move to the next node in the left part.
		left→head := left→head→next
		
	// If the left part exhausted first, add the right near the
	// beginning of left.
	if left→head = left→tail:
		left→head→next := right→head
}
```

First, this algorithm swaps all values of *left* and *right* if the value of the left head is greater than the value of the right head. ***TODO: Why?*** Next, it stores the tail of the right part in the *part_end* variable. This provides a terminating value for the right part.

The loop continues while two conditions are true: 1)  the left part's head is not equal to its own tail; and 2) the right part's head has not passed its terminating node (*part_end*'s *tail*). On each iteration, it tests that the data of the left partition's head is greater than the data of the right partition's head. If so, it appends the right head as the next node of the left head, and then assigns the right head as the node of the right head's next value. Also on each loop, the left head points to its successor node.

After the loop, it tests if the left the left head has ended. If so, the next value of the left's head is set to the right partition's head: that is, it assumes the remaining nodes in the right partition have *data* greater-than or equal-to the last *data* in the *left* partition. If not, it assumes that the *right* partition exhausted itself; because all nodes in *right* have already been inserted into *left*, the algorithm does not need to do anything else.^[This differs from array-based merge sort, where the final values in the right partition would need to be appended to the sorted list.]

Once all nodes are added to *left*, this function ends. The *left* partition now has all nodes from *left* and *right* in the correct order.

## The mergesort function

The actual merge sort function accepts a node's *head* and the length of that entire list. It sorts head in-line and thus returns nothing.

```pseudocode
function MergeSort(head, length) {
	
	if head is Nil or length < 2:
		return None
		
	left  := new LinkedList
	right := new LinkedList
	
	decompose := length
	
	while decompose < length:
		
		left→head := head
		
		while left→head:
			
			left→tail := left→head
			
			right→head := left→tail→next
			
			if right→head is Nil:
				break
			
			right→tail := right→head
			
			temp := right→tail→next
			
			merge_partitions(left, right)
			
			if gap = 1:
				head := left→head
				
			else:
				previous_end_node := right→tail
			
			previous_end_node := right→tail
			left→head := temp
			
			decompose := decompose / 2
		
		previous_end_node→next := left→head
}
```

First, the *left* and *right* parts are initialized as an empty [*LinkedList* type](#the-data-structures).^[This is in lieu of having four different variables --- two start and two end nodes --- for each left and right part.] The *merge_sort* works by aliasing the left partition's *head* to the reference of the given *head*; thus, all operations on *left→head* apply directly to the *head* itself.

The *decompose* variable controls the outer loop. At the end of each inner loop, *decompose* shrinks logarithmically: by $log_{2}n$, where $n$ is the list's $length$. Thus, the total number of outer loops is kept in logarithmic time: $O(logN)$.^[The source implementation did the opposite: increasing a variable called "gap" in exponential time until its value exceeded the list length. Note that the goal is fundamentally the same. The author finds this approach more intuitive because merge sort is often discussed in the context of "breaking down and merging together;" the language of decay, rather than growth, better alludes to this idea.]

During each outer loop, the left partition's *head* is assigned to the parameter's *head* node. Again, this means that all sorting operations which occur on the left partition will also occur on the main *head*. Likewise, for the first inner loop, *head* is also aliased to the left's head. By the end of this, anything which happens to *left* will ultimately happen to *head*.

The inner *while* loop.

# Acknowledgements

This paper was based on the solutions implemented here: https://www.geeksforgeeks.org/iterative-merge-sort-for-linked-list/

The iterative algorithm mentioned here was explored, but issues with the implementation led to the author abandoning this approach. This could be https://www.baeldung.com/cs/merge-sort-linked-list