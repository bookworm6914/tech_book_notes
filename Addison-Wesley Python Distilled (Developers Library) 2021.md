<p align="center"> 
<img src="https://github.com/bookworm6914/tech_book_notes/blob/main/Addison-Wesley Python Distilled (Developers Library) 2021.PNG">
</p>

# Python Distilled (Developers Library)
## Published by Addison-Wesley, 2021 
[**Amazon URL**](https://www.amazon.com/Python-Essential-Reference-Developers-Library/dp/0134173279/)

## page73
### Operations on iterables

| operations | note |
| ---------- | ---- |
| for vars in s: | iteration |
| v1, v2, ... = s | variable unpacking |
| x in s, x not in s | membership |
| [a, *b, c] {a, *b, c} (a, *b, c) | expansion in list, set or tuple literals |

For example,
```aiignore
items = [1, 2, 3, 4, 5]
a, b, *extra = items                # a = 1, b = 2, extra = [3,4,5]
*extra, a, b = items                # extra = [1,2,3], a = 4, b = 5
a, *extra, b = items                # a = 1, extra = [2,3,4], b = 5
```

## page76
### functions consume iterables

| operations | note |
| ---------- | ---- |
| list(s)    | create a list from s |
| tuple(s)   | create a tuple |
| set(s) | create a set |
| min(s [, key]) | minimum item in s |
| max(s [, key]) | maximum item in s |
| any(s) | true if any item  in s is true |
| all(s) | true if all items in s is true |
| sum(s [, initial]) | sum of all items with an optional initial value |
| sorted(s [, key]) | create a sorted list |

## page77
### operations on sequences

| operations | note |
| ---------- | ---- |
| s + r | concatenation |
| s * n, n * s | make n copies of s, where n is an integer |
| s[i] | indexing |
| s[i:j] | slicing |
| s[i:j:strike] | extended slicing |
| len(s) | length |

## page79
### operations on mutable sequences

| operations | note |
| ---------- | ---- |
| s[i] = x | assignment |
| s[i:j] = r | slice assignment |
| s[i:j:stride] = r | extended slice assignment |
| del s[i] | delete an element |
| del s[i:j] | delete a slice |
| del s[i:j:stride] | delete an extended slice |

## page 81
### operations on sets
| operations | note |
|------------| ---- |
| s \| t | union of a and t |
| s & t | intersetction of s and t |
| s - t | set difference (items in s but not in t) |
| s ^ t | symmetric difference (items NOT in both s and t) |
| len(s) | size of the set |
| item in s, item not in s | membership test |
| s.add(item) | add an item to set s |
| s.remove(item) | remove item from s if it exists, otherwise an error |
| s.discard(item) | discard item from s if it exists |

### operations on maps
| operations | note |
| ---------- | ---- |
| x = m[key] | index by key |
| m[key] = x | assignment by key |
| del m[key] | delete an item by key |
| k in m | membership test |
| len(m) | size of the map |
| m.keys() | return list of keys |
| m.values() | return list of values |
| m.items() | return pairs of (key, value) |

## page101
```
try:
    do something
except (TypeError, ValueError) as e:
    # Handle Type or Value errors
    ...

file = open('foo.txt', 'rt')
try:
    # Do some stuff
    ...
finally:
    file.close()
    # File closed regardless of what happened
```

Exceptions are organized into a hierarchy via inheritance. Instead of writing code that is concerned with very specific errors, it might be easier to focus on more general categories of errors instead. 
```
try:
    item = items[index]
except IndexError: # Raised if items is a sequence
    ...
except KeyError: # Raised if items is a mapping
    ...
```
Could be rewritten to be more generic:
```
try:
    item = items[index]
except LookupError:
    ...
```

## page104
### Exception Categories

| Exception class | note |
| ---------- | ---- |
| BaseException | root class of all exceptions |
| Exception | base class of all program-related errors |
| ArithmaticError | base class of all math-related errors |
| ImportError | base class of all import-related errors |
| LookupError | base class of all container lookup errors |
| OSError | base class of all OS-related errors. IOError and EnvironmentError are aliases |
| ValueError | base class of all value-related errors, including Unicode |
| UnicodeError |  base class for a Unicode string encoding related errors |

The BaseException class is rarely used directly in exception handling because it matches all possible exceptions whatsoever. 

## page105
### other built-in exceptions

| Exception class | note |
| ---------- | ---- |
| AssertionError | failed assert statement |
| AttributeError | bad attribute lookup on an object |
| EOFError | End Of File |
| MemoryError | recoverable out of memory error |
| NameError | name not found in the local or global namespace |
| NotImplementedError | unimplemented feature |
| RuntimeError | a generic "domething bad happens" error |
| TypeError | operations applied to an object of the wrong type |
| UnboundLocalError | usage of a local vatiable before a value is assigned |

## page106
### Exceptions Used for Control Flow

| Exception class | note |
| ---------- | ---- |
| SystemExit | raised to indicate program exit |
| KeyboardInterrupt | raised when a program is interrupted via Control-C |
| StopIteration | raised to signal end of iteration |

## page107
define custom Exceptions:
```
class DeviceError(Exception):
    def __init__(self, errno, msg):
        self.args = (errno, msg)
        self.errno = errno
        self.errmsg = msg

# Raises an exception (multiple arguments)
raise DeviceError(1, 'Not Responding')
```

## page113
exception traceback:
```
import traceback
try:
    spam()
except Exception as e:
    tblines = traceback.format_exception(type(e), e, e.__traceback__)
    tbmsg = ''.join(tblines)
    print('It failed:')
    print(tbmsg)
```

## page114
Exception handling is one of the most difficult things to get right in larger programs. Certain rules:
* not catch exceptions that can’t be directly handled at that specific location in the code. 
* When catching errors, try to make your except clauses as narrow as reasonable.
* Finally, if explicitly raising an exception, consider making your own exception types.

## page133
### object protocol

| Merhods | note |
| ---------- | ---- |
|__new__(cls [, *args [, **kwargs]]) | a static method called to create a new instance |
| __init__(self [, *args [, **kwargs]]) | called to initialize a new instance after it's been created |
| __del__(self) | called to destroy an instance |
| __repr__(self) | create a string representation |

## page135
### number protocol

## page138
### comparison protocol

## page141
### conversion protocol

## page142
### container protocol
| Merhods | note |
| ---------- | ---- |
| __len__(self) | return length of self |
| __get_item__(self, key) | return self[key] |
| __set_item__(self, key, value) | set self[key] = value |
| __del_item__(self, key) | delete self[key] |
| __contains__(self, obj) | return boolean of obj in self? |

## page146
### attribute protocol
| Merhods | note |
| ---------- | ---- |
| __getattribute__(self, name) | return attribute self.name |
| __getattr__(self, name) | return attribute self.name if not found via __getattribute__() |
| __setattr__(self, name, value) | set attribute self.name = value |
| __delattr__(self, name) | delete attribute self.name |

## page147
### Context Manager Protocol
```
with context [ as var]:
    statements
```

| Merhods | note |
| ---------- | ---- |
| __enter__(self) | called when entering a new context. The return value is the "var" after the "as" specifier |
| __exit__(self, type, value, tb) | Called when leaving a context. If an exception occurred: type, value, tb are set to have the exception type, value and traceback info |

## page152
### Variadic Arguments
```
def product(first, *args):
    result = first
    for x in args:
        result = result * x
    return result
```

> product(10, 20) # -> 200

> product(2, 3, 4, 5) # -> 120

## page164
Use of **"global"** statement is a poor python style.

## page166

| Merhods | note |
| ---------- | ---- |
| sys.getrecursionlimit() | returns the current maximum recursion depth |
| sys.setrecursionlimit() | change the value. The default value is 1000 |

## page167
`lambda args: expression`

## page180
### decorators
A decorator is a function that creates a wrapper around another function. 
```
from functools import wraps

def trace(func):
    @wraps(func)
    def call(*args, **kwargs):
        print('Calling', func.__name__)
        return func(*args, **kwargs)

    return call

# Example use
@trace
def square(x):
    return x * x

@decorator1
@decorator2
def func(x):
    pass

func = decorator1(decorator2(func))
```
In class definitions, decorators such as @classmethod and @staticmethod often have to be placed so that they are at the outermost level. 
```
class SomeClass(object):
    @classmethod            # Yes
    @trace
    def a(cls):
        pass

    @trace                  # No. Fails.
    @classmethod
    def b(cls):
        pass
```

## page192
### Frame atttributes

| Attributes | note |
| ---------- | ---- |
| f.f_back | previous stack frame (toward the caller) |
| f.f_code | code object been executed |
| f.f_locals | directory of local variables --- locals() |
| f.f_globals | directory of global variables --- globals() |
| f.f_builtins | directory used for built-in names |
| f.f_lineno | line number |
| f.f_lasti | current instruction. This is an index into the bytecode string of f.f_code |
| f.f_trace | function called at start of each source code line |

Examples:
```aiignore
import sys

def grok(a):
    b = a * 10
    print(sys._getframe(0).f_locals) # myself
    print(sys._getframe(1).f_locals) # my caller
```
Another one:
```aiignore
import inspect

def spam(x, y):
    z = x + y
    grok(z)

def grok(a):
    b = a * 10

    # outputs: {'a':5, 'b':50 }
    print(inspect.currentframe().f_locals)

    # outputs: {'x':2, 'y':3, 'z':5 }
    print(inspect.currentframe().f_back.f_locals)

spam(2, 3)
```
