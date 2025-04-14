<p align="center"> 
<img src="https://github.com/bookworm6914/tech_book_notes/blob/main/Advanced Python Tips - A Simple Book on Advanced Python concepts 2020.PNG">
</p>

# Advanced Python Tips - A Simple Book on Advanced Python concepts
## Written by Rahul Agarwal, independently published, 2019
[**Amazon URL**](https://www.amazon.com/Advanced-Python-Tips-explained-Simply/dp/1077001339/)

### page8
** This book is about efficient and readable code. **

## Chapter 1: Minimize for loop usage in Python

### page10
```
x = [1,3,5,7,9]
sum_squared = 0
for y in x:
    sum_squared+=y**2
```
or
```
x = [1,3,5,7,9]
sum_squared = sum([y**2 for y in x])
```
This is called List Comprehension. What about **if-else**?
```
x = [1,2,3,4,5,6,7,8,9]
squared_cubed = [y**2 if y%2==0 else y**3 for y in x]
--------------------------------------------
[1, 4, 27, 16, 125, 36, 343, 64, 729]
```

### page13
Dictionary Comprehension:
```
x = [1,2,3,4,5,6,7,8,9]
{k:k**2 for k in x}
---------------------------------------------------------
{1: 1, 2: 4, 3: 9, 4: 16, 5: 25, 6: 36, 7: 49, 8: 64, 9: 81}


x = [1,2,3,4,5,6,7,8,9]
{k:k**2 for k in x if x%2==0}
---------------------------------------------------------
{2: 4, 4: 16, 6: 36, 8: 64}


x = [1,2,3,4,5,6,7,8,9]
{k:k**2 if k%2==0 else k**3 for k in x}
---------------------------------------------------------
{1: 1, 2: 4, 3: 27, 4: 16, 5: 125, 6: 36, 7: 343, 8: 64, 9: 729}
```

### Rule
**Use List Comprehensions and Dict comprehensions when you need a for loop. Use enumerate if you need array index.**


## Chapter 2: Python defaultdict and Counter

### page16
To count the occurrance of the words in a sentence or paragraph:
```
# method 1

from collections import defaultdict

word_count_dict = defaultdict(int)
for w in text.split(" "):
    word_count_dict[w]+=1


# method 2

from collections import Counter
word_count_dict = Counter()
for w in text.split(" "):
    word_count_dict[w]+=1

word_count_dict.most_common(10)
---------------------------------------------------------------
[('I', 3), ('to', 2), ('the', 2)]
```


## Chapter 3: *args, **kwargs, decorators for Data Scienঞsts

### page21
What are `*args`?
In simple terms, you can use `*args` to give an arbitrary number of inputs to your function.

Please note that we can use `*args` or `*argv` or `*anyOtherName` to do this. It is the `*` that matters.
```
def adder(*args):
    result = 0
    for arg in args:
        result+=arg
    return result

adder(1,2)
adder(1,2,3)
adder(1,2,5,7,8,9,100)
```
This is how the python print() frunction can take so many arguments.


### page23
What are `**kwargs`?
In simple terms, you can use `**kwargs` to give an arbitrary number of Keyworded inputs to your function and access them using a dictionary.
```
def myprint(name,age):
print(f'{name} is {age} years old')

# to deal with a group of users:

def myprint(**kwargs):
    for k,v in kwargs.items():
        print(f'{k} is {v} years old')

# sample usage:
myprint(Sansa=20,Tyrion=40,Arya=17)
Output:-----------------------------------
Sansa is 20 years old
Tyrion is 40 years old
Arya is 17 years old
```

### page25
What are Decorators?
In simple terms: Decorators are functions that wrap another function thus modifying its behavior.

original function:
```
import time
def somefunc(a, b):
    print("somefunc begins")
    start_time = time.time()
    output = a + b
    print("somefunc ends in ",time.time()-start_time, "secs")
    return output

out = somefunc(4, 5)
OUTPUT:
-------------------------------------------
somefunc begins
somefunc ends in 9.5367431640625e-07 secs


# use decprator
import time
from functools import wraps
def timer(func):
    @wraps(func)
    def wrapper(a, b):
        print(f"{func.__name__!r} begins")
        start_time = time.time()
        result = func(a,b)
        print(f"{func.__name__!r} ends in {time.time()-start_time} secs")
        return result

    return wrapper

@timer
def somefunc(a, b):
    output = a + b
    return output


a = somefunc(4,5)
Output
---------------------------------------------
'somefunc' begins
'somefunc' ends in 2.86102294921875e-06 secs
```

### page28
What if our function takes three arguments? Or many arguments?
```
import time
from functools import wraps
def timer(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print(f"{func.__name__!r} begins")
        start_time = time.time()
        result = func(*args, **kwargs)
        print(f"{func.__name__!r} ends in {time.time()-start_time} secs")
        return result

    return wrapper
```


## Chapter 4: Use Itertools, Generators, and Generator Expressions

### page36
Put simply Generators provide us ways to write iterators easily using the yield statement.
```
def triplet(n): # Find all the Pythagorean triplets between 1 and n
    for a in range(n):
        for b in range(a):
            for c in range(b):
                if a*a == b*b + c*c:
                    yield(a, b, c)


triplet_generator = triplet(1000)
for x in triplet_generator:
    print(x)
------------------------------------------------------------
(5, 4, 3)
(10, 8, 6)
(13, 12, 5)
(15, 12, 9)
.....
```


## Chapter 5: How and Why to use f strings in Python3?

### page43
`f` strings in Python that was introduced in Python **3.6**.
For example:
```
print(f"I am {name}. I am {age} years old")
```

### page47
more examples:
```
    print(f"{data['name']} has {totalFruits(apples,oranges)} fruits")
```
