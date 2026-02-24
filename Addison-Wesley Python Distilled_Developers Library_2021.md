<p align="center"> 
<img src="https://github.com/bookworm6914/tech_book_notes/blob/main/Addison-Wesley Python Distilled_Developers Library_2021.PNG">
</p>

# Python Distilled (Developers Library)
## Published by Addison-Wesley, 2021 
[**Amazon URL**](https://www.amazon.com/Python-Essential-Reference-Developers-Library/dp/0134173279/)
[**Original Book Notes**](Addison-Wesley Python Distilled_Developers Library_2021_original_notes.txt)


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

## page196
### async functions and await

## page199
## If a function uses the yield keyword, it defines an object known as a generator.
```
def countdown(n):
    print('Counting down from', n)
    while n > 0:
        yield n         # a generator object is created here
        n -= 1

c = countdown(10)
next(c)
```
When **next()** is called, the generator function executes statements until it reaches a yield statement.
The **yield** statement returns a result at which point execution of the function is suspended until **next()** is invoked again.
While it’s suspended, the function retains all of its local variables and execution environment. When resumed, execution continues with the statement following the **yield**.

**next()** is a shorthand for invoking the *__next__()* method on a generator.

## page204

Normally a generator function executes only once.
If you want to an object that allows repeated iteration, define it as a class and make the __iter__() method a generator.
```
class countdown:
    def __init__(self, start):
        self.start = start

    def __iter__(self):
        n = self.start
        while n > 0:
            yield n
            n -= 1
```
An essential feature of generators is that a function involving yield never executes by itself—it always has to be driven by some other code using a forloop or explicit next() calls. 

This makes it somewhat difficult to write library functions involving yield as calling a generator function is not enough to make it execute. To address this, the yield from statement can be used.
```aiignore
def countup(stop):
    n = 1
    while n <= stop:
        yield n
        n += 1

def countdown(start):
    n = start
    while n > 0:
        yield n
        n -= 1

def up_and_down(n):
    yield from countup(n)
    yield from countdown(n)
```

## page210
### enhanced generator 

## page222
### Attribute access
There are only 3 basic operations on an instance: get, set and delete.
> getattr()   setattr()   hasattr()   delattr()

## page247
### Private attributes: name the object with leading underscore _xxx
Attributes with double leading underscores **__** are invisible in child classes
  - This ensures that private names used in a superclass won’t be overwritten by identical names in a child class.
 
## page270
### class decorators

## page299
### dynamic class creation

## page308
### Built-in Objects for Instances and Classes
  - attributes of types

| Attributes | note |
| ---------- | ---- |
| cls.__name__ | class name |
| cls.__module__ | module name in which the class is defined |
| cls.__qualname__ | Fully Qualified class name |
| cls.__bases__ | tuple of base classes |
| cls.__mro__ | method resolution order tuple |
| cls.__dict__ | directory that holds class methods and variables |
| cls.__doc__ | documentation string |
| cls.__annotations__ | directory of class type hints |
| cls.__abstractmethods__ | set of abstract method names (may be undefined if there aren't any) |

  - Instance attributes

| Attributes | note |
| ---------- | ---- |
| i.__class__ | class to which the instance belongs |
| i.__dict__ | directory holding instance data (if defined) |

## page311
In executing an import, a number of things happen:
1. The module source code is located. If it can’t be found, an ImportError exception is raised.
2. A new module object is created. This object serves as a container for all of the global definitions contained within the module. It’s sometimes referred to as a "namespace."
3. The module source code is executed within the newly created module namespace.
4. If no errors occur, a name is created within the caller that refers to the new module object. This name matches the name of the module, but without any kind of file suffx. 
    For example, if the code is found in a file module.py, the name of the module is module.

Semantically, the statement from module import name performs a name copy from the module cache to the local namespace. 
  - That is, Python first executes import module behind the scenes. Afterwards, it makes an assignment from the cache to a local name such as name = sys.modules['module'].name.

A common confusion is thinking that the from form of import is more efficient — possibly only loading part of a module. This is not the case.
  - Whenever a module is loaded, the entire module is loaded and stored in the cache.

## page317
### Circular Imports - try to stay away from it

## page319
### Module Reloading and Unloading
```
>>> import module
>>> import importlib
>>> importlib.reload(module)
```

## page321
When importing modules, the interpreter searches the list of directories in sys.path
  - The first entry in sys.path is often an empty string '', which refers to the current working directory. 

## page332
### Module attributes

| Attributes | note |
| ---------- | ---- |
| __name__ | full module name |
| __doc__ | documentation string |
| __dict__ | module directory |
| __file__ | file name of current module's source .py |
| __package__ | name of enclosing package |
| __path__ | list of sub-directories to search for sub modules of a package |
| __annotations__ | module-level type hints |

## page334
### deploy python packages

## page337
### data representation: bytes vs. text

| data | type | Note |
| ---------- | ---- | ---- |
| bytes | bytes | an immutable string of integer byte values |
| | bytearray | a mutable byte array that behaves much like the combination of a byte-string and a list |
| text | str | an array of Unicode code points |

## page339
### common encodings for text

| Name | note |
| ---------- | ---- |
| ascii | character values in the range of [0x00, 0x7f] |
| latin1 | character values in the range of [0x00, 0xff]   also known as 'iso-8859-1' |
| utf-8 | variable-length encoding that allows all Unicode characters to be represented |
| cp1252 | a common text encoding on Windows |
| macroman | a common text encoding on Mac |

The encoding methods accept an optional errors argument that specifies behavior in the presence of encoding errors.

| Error handling option | note |
| ---------- | ---- |
| strict | raise a UnicodeError exception for both encoding and decoding errors (default) |
| ignore | ignore invalid chars |
| replace | replace invalid chars with a replacement char: U + FFFD in Unicode, b'?' in bytes |
| backslashreplace | replace invalid chars with a Python character escape sequence. e.g. the char U + 1234 is replaced by '\u1234' (encoding only) |
| xmlcharrefreplace | replace invalid chars with an XML charcter reference.          e.g. the char U + 1234 is replaced by '&#4660;' (encoding only) |
| surrogateescape | replace any invalid chars '\xhh' with U + DChh on decoding, replace U + DChh with '\xhh' on encoding |

## page343
### string formatting codes

| Codes | note |
| ---------- | ---- |
| d | decimal integer or long integer |
| b | binary integer  or long integer |
| o | octal integer   or long integer |
| x | hexidecimal int or long integer |
| X | hexidecimal int |
| f,F | floating point as [-]m.dddddd |
| e | floating point as [-]m.dddddd +/- xx |
| E | floating point as [-]m.ddddddE +/- xx |
| g,G | use e or E for exponents less than [nd]4 or greater than the precision; otherwise use f |
| n | same as g except that the current locale setting determines the decimal point character |
| % | times 100 and display in f format with '%' at the end |
| s | string, same as str() |
| c | single character |

## page358
### file I/O methods

## page367
### Object Serialization
```
import pickle

obj = SomeObject()
with open(filename, 'wb') as file:
    pickle.dump(obj, file) # Save object on f

with open(filename, 'rb') as file:
    obj = pickle.load(file) # Restore the object

---For network programming, it is common to use pickle to create byte-encoded messages.

obj = SomeObject()

# Turn an object into bytes
data = pickle.dumps(obj)
...

# Turn bytes back into an object
obj = pickle.loads(data)
```

## page369
### Blocking Operations and Concurrency
```
sock.setblocking(False)

def reader1(sock):
    try:
        data = sock.recv(8192)
        print('reader1 got:', data)
    except BlockingIOError:
        pass

def reader2(sock):
    try:
        data = sock.recv(8192)
        print('reader2 got:', data)
    except BlockingIOError:
        pass
```

## page371
### I/O Polling
Instead of relying upon exceptions and spinning, it is possible to poll I/O channels to see if data is available. The select or selectors module can be used for this purpose.
```
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE

def run(sock1, sock2):
    selector = DefaultSelector()
    selector.register(sock1, EVENT_READ, data=reader1)
    selector.register(sock2, EVENT_READ, data=reader2)

    # Wait for something to happen
    while True:
        for key, evt in selector.select():
            func = key.data
            func(key.fileobj)
```
In this code, the loop dispatches the **reader1()** and **reader2()** functions as a callback whenever I/O is detected on the appropriate socket. 

The **selector.select()** operation itself blocks, waiting for I/O to occur. Thus, unlike the previous example, it won’t make the CPU furiously spin.

This approach to I/O is the foundation of many so-called "async" frameworks such as asyncio although you usually don’t see the inner workings of the socalled "event loop."

## page372
### threading
```
import threading

def reader1(sock):
    while (data := sock.recv(8192)):
        print('reader1 got:', data)

def reader2(sock):
    while (data := sock.recv(8192)):
        print('reader2 got:', data)

t1 = threading.Thread(target=reader1, args=[sock1]).start()
t2 = threading.Thread(target=reader2, args=[sock2]).start()

# Wait for the threads to finish
t1.join()
t2.join()
```

## page373
### async I/O
```
import asyncio

async def reader1(sock):
    loop = asyncio.get_event_loop()
    while (data := await loop.sock_recv(sock, 8192)):
        print('reader1 got:', data)

async def reader2(sock):
    loop = asyncio.get_event_loop()
    while (data := await loop.sock_recv(sock, 8192)):
        print('reader2 got:', data)

async def main(sock1, sock2):
    loop = asyncio.get_event_loop()
    t1 = loop.create_task(reader1(sock1))
    t2 = loop.create_task(reader2(sock2))

    # Wait for the tasks to finish
    await t1
    await t2
...
# Run it
asyncio.run(main(sock1, sock2))
```

## page374
### example on using asyncio

## page375
## binascii module: convert binary data into various text-based representations such as hexadecimal and base64

## page376
### cgi module: deal with static web pages

## page377
### configparser module: parse .INI files

## page378
### csv module

## page380
## errno module
## fcntl module: perform low-level I/O control operations on Unix using the fcntl() and ioctl() system calls, file locking etc.

## page381
## hashlib module: compute cryptographic hash values such as MD5, SHA-1, and so forth
## http package

## page382
### io module

## page383
### json module
### logging module

## page385
### os module
### os.path module

## page386
### pathlib module

## page387
### re module

## page388
### shutil module
#### select module

## page390
### smtp module
### socket module

## page393
### struct module: convert data between Python and binary data structures (represented as Python byte strings)

## page394
### subprocess module

## page395
### tempfile module
### textwrap module: format text to fit a specific terminal width

## page396
### threading module

## page399
### time module

## page400
#### urllib module

## page401
#### unicodedata module

## page402
### xml module

## page405
#### built-in functions and standard library
