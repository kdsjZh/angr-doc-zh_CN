# Program State

* 到目前为止，我们只以最简单的方式使用了angr的模拟程序状态(`SimState`对象)，以演示angr操作的基本概念。在这里，您将了解状态对象的结构，以及如何以各种有用的方式与之交互。

----

## Basic Execution

* 前面，我们展示了如何使用模拟管理器执行一些基本的执行。在下一章中，我们将展示模拟管理器的全部功能，但是现在我们可以使用一个简单得多的接口来演示符号执行的工作原理:`state.step()`。这个方法将执行符号执行的一个步骤，并返回一个名为`SimSuccessors`的对象。与普通模拟不同，符号执行可以生成多个继承状态，这些状态可以用多种方式进行分类。现在，我们关心的是这个对象的`.successors`属性，它是一个包含给定步骤的所有“正常”继承者的列表。

* 为什么是一个列表，而不是一个单一的继承状态?angr的符号执行过程就是执行编译到程序中的各个指令，并对SimState进行修改。当到达像`if (x > 4)`这样的一行代码时，如果x是一个符号位向量会发生什么?在angr的某个深度，将执行比较`x > 4`，结果将是`<Bool x_32_1 > 4>`。

* 这很好，但是下一个问题是，我们是选择“真”分支还是“假”分支?答案是，我们两者都要!我们生成两个完全独立的继承状态——一个模拟条件为真和条件为假的情况。在第一种状态中，我们添加`x > 4`作为约束，在第二种状态中，我们添加`!(x > 4)`作为约束。这样，每当我们使用这些继承状态中的任何一个执行约束解时，状态上的条件都确保我们得到的任何解都是有效的输入，这些输入将导致执行遵循给定状态所遵循的相同路径。

* 为了演示这一点，让我们以[一个假固件映像](https://github.com/angr/angr-doc/tree/842715e048f9b26433739faed75855b7faee5833/examples/fauxware/fauxware/README.md)为例。如果您查看这个二进制文件的[源代码](https://github.com/angr/angr-doc/tree/842715e048f9b26433739faed75855b7faee5833/examples/fauxware/fauxware.c)，您会发现固件的身份验证机制是颠倒的;任何用户名都可以通过密码“SOSNEAKY”作为管理员进行身份验证。此外，与用户输入的第一个比较是与后门的比较，因此，如果我们执行步骤，获得多个继承状态，其中一个状态将包含限制用户输入为后门密码的条件。下面的代码片段实现了这一点:

```python
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> state = proj.factory.entry_state(stdin=angr.SimFile)  # ignore that argument for now - we're disabling a more complicated default setup for the sake of education
>>> while True:
...     succ = state.step()
...     if len(succ.successors) == 2:
...         break
...     state = succ.successors[0]

>>> state1, state2 = succ.successors
>>> state1
<SimState @ 0x400629>
>>> state2
<SimState @ 0x400699
```

* 不要直接查看这些状态上的约束—我们刚刚讨论的分支涉及`strcmp`的结果，这是一个很难用符号模拟的函数，并且产生的约束非常复杂。

* 我们模拟的程序从标准输入中获取数据，默认情况下，angr将标准输入视为无穷无尽的符号数据流。要执行一个约束求解并获得一个可以用来满足约束的输入可能值，我们需要获得对stdin实际内容的引用。稍后，我们将详细讨论文件和输入子系统的工作方式，但是现在，只使用`state.posix.stdin。load(0, state.posix.stdin.size)`来检索一个位向量，该位向量表示到目前为止从stdin读取的所有内容。

```python
>>> input_data = state1.posix.stdin.load(0, state.posix.stdin.size)

>>> state1.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00\x00\x00'

>>> state2.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x00\x80N\x00\x00 \x00\x00\x00\x00'
```

* 正如您所看到的，为了沿着`state1`路径走下去，您必须将后门字符串“SOSNEAKY”作为密码。为了沿着`state2`的道路走下去，你必须给一些除了“SOSNEAKY”以外的东西。z3提供了符合这个标准的数十亿字符串中的一个。 

* Fauxware是angr在2013年成功开发的第一个符号执行程序。通过使用angr找到它的后门，您将参与一个宏大的传说，即对如何使用符号执行从二进制文件中提取信息有一个基本的了解!

----

## State Presets

* 到目前为止，无论何时处理状态，我们都使用`project.factory.entry_state()`创建它。这只是项目工厂中可用的几个状态构造函数之一:
  * `.blank_state()`构造一个“空白石板”的空白状态，其中大部分数据未初始化。当访问未初始化的数据时，将返回一个不受约束的符号值。
  
  * `.entry_state()`构造一个主二进制文件的入口点的状态。
  
  * `.full_init_state()`构造一个准备完成的状态，该状态需要通过在主二进制文件入口点之前运行的初始化器执行，例如，共享库构造器或预初始化器。当它完成这些，它将跳转到入口点。
  
  * `.call_state()`构造准备执行给定函数的状态。
  
 * 您可以通过以下构造函数的几个参数自定义状态:
   
   * 所有这些构造函数都可以使用`addr`参数来指定要开始的确切地址。
   
   * 如果执行的环境可以接受命令行参数或环境，则可以通过`args`将参数列表传递给`entry_state`和`full_init_state`，并通过`env`将环境变量字典传递给`entry_state`和`full_init_state`。这些结构中的值可以是字符串或位向量，并将序列化为状态，作为模拟执行的参数和环境。默认的`args`是一个空列表，所以如果您正在分析的程序希望至少找到一个`argv[0]`，您应该始终提供它!
   
   * 如果希望`argc`是符号的，可以将符号位向量`argc`传递给`entry_state`和`full_init_state`构造函数。但是要小心:如果这样做，还应该为结果状态添加一个约束，即argc的值不能大于传递给`args`的arg的数量。
   
   * 要使用调用状态，应该使用`.call_state(addr, arg1, arg2，…)`调用它，其中`addr`是要调用的函数的地址，`argN`是该函数的第n个参数，可以是python整数、字符串、数组或位向量。如果您希望分配内存并实际传递一个指向对象的指针，您应该将它封装在一个`PointerWrapper`中，即`angr.PointerWrapper(“point to me !”)`。这个API的结果可能有点不可预测，但是我们正在努力。
   
 * 在这些构造函数中可以使用更多的选项!请参阅`project.factory`的[文档](http://angr.io/api-doc/angr.html#angr.factory.AngrObjectFactory)(一个`AngrObjectFactory`)获取更多细节
 
 
 ----
 
 ## Low level interface for memory
 
 * `state.mem`接口可以方便地从内存中加载类型化数据，但是当您希望在某个内存范围内执行原始数据加载和存储时，`state.mem`就显得过于笨重。`state.mem`实际上是一组正确访问底层内存存储的逻辑。而底层内存只是一个平面地址空间，其中充满了位向量数据:`state.memory`。您可以直接通过`.load(addr, size)`和`.store(addr, val)`方法访问`state.memory`:
 
 ```python
>>> s = proj.factory.blank_state()
>>> s.memory.store(0x4000, s.solver.BVV(0x0123456789abcdef0123456789abcdef, 128))
>>> s.memory.load(0x4004, 6) # load-size is in bytes
<BV48 0x89abcdef0123>
 ```
 
 * 正如您所看到的，由于`state.memory`的主要用途是加载没有附加语义的存储段数据，数据是以大端字节序方式加载和存储的。但是，如果希望对加载或存储的数据执行字节交换，可以传递关键字参数endness——如果指定小端字节序，则会发生字节交换。endness应该是`archinfo`包中`Endness`的成员之一，该包用于保存关于angr CPU架构的声明性数据。此外，所分析程序的结束度可以用`arch.memory_endness`表示——例如`state.arch.memory_endness`。
 
 ```python
 >>> import archinfo
>>> s.memory.load(0x4000, 4, endness=archinfo.Endness.LE)
<BV32 0x67453201>
 ```
 
 * 还有一个用于寄存器访问的底层接口`state.registers`，它使用与`state.memory`完全相同的API。但是，解释它的行为需要[深入](https://docs.angr.io/advanced-topics/ir)到angr用于无缝地与多个体系结构协作的抽象中。简而言之，它只是一个寄存器文件，在[archinfo](https://github.com/angr/archinfo)中定义了寄存器和偏移量之间的映射。
 
 ----
 
 ## State Options
 
 * 我们可以对angr的内部进行许多小小的调整，从而优化某些情况下的行为，但也会对其他情况造成损害。这些调整是通过状态选项控制的。 
 
 * 在每个SimState对象上，都有一组(`state.options`)所有启用的选项。每个选项(实际上只是一个字符串)都以某种细微的方式控制angr执行引擎的行为。[附录](https://docs.angr.io/appendix/options)中列出了完整的选项域，以及不同状态类型的默认值。您可以通过`anger.options`访问用于添加状态的单个选项。单独的选项使用大写字母命名，但是也有一些常见的对象分组，您可能希望将它们捆绑在一起使用，使用小写字母命名。
 
 * 当通过任何构造函数创建SimState时，可以传递关键字参数`add_options`和`remove_options`，这两个参数应该是修改默认值的初始选项集的选项集。
 
 ```python
# 示例:启用lazy solver选项，可以尽可能不频繁地检查状态可满足性。
# 对该设置的更改将影响到从该状态创建的后所有继承状态。
>>> s.options.add(angr.options.LAZY_SOLVES)

# 创建一个开启lazy solver选项的状态
>>> s = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})

# 创建一个不开启简化选项的状态
>>> s = proj.factory.entry_state(remove_options=angr.options.simplification)
 ```

----

## State Plugins

* 除了刚才讨论的一组选项之外，SimState中存储的所有内容实际上都存储在附加到该状态的插件中。到目前为止，我们讨论的状态的几乎所有属性都是插件—`memory`、`registers`、`mem`、`regs`、`solvers`等等。这种设计允许代码模块化以及为模拟状态的其他方面轻松实现[新类型的数据存储的能力](https://docs.angr.io/extending-angr/state_plugins)，或者提供插件的替代实现的能力。

* 例如，普通`memory`插件模拟平面内存空间，但是分析可以选择启用“抽象内存”插件，它使用替代数据类型来模拟独立于地址的自由浮动内存映射，从而提供`state.memory`。相反，插件可以降低代码复杂度:`state.memory`和`state.register`实际上是同一个插件的两个不同实例，因为寄存器也是用地址空间模拟的。

### The globals plugin

* `state.globals`是一个非常简单的插件:它实现了标准python dict的接口，允许您在状态上存储任意数据。

### The history plugin

* `state.history`是一个非常重要的插件，它存储关于一个状态在执行过程中所采取的路径的历史数据。它实际上是一个由几个历史节点组成的链表，每个节点代表一轮执行——您可以使用`state.history.parent.parent`遍历这个列表。

* 为了更方便地使用这个结构，history还提供了几个针对特定值的历史的有效迭代器。通常，这些值存储为`history.recent_NAME`，它们上面的迭代器就是`history.NAME`。例如，`for addr in state.history.bbl_addrs: print hex(addr)`将为二进制文件打印一个基本的块地址跟踪，而`state.history.recent_bbl_addrs`是在最近的步骤中执行的基本块的列表，`state.history.parent.recent_bbl_addrs`是在前面的步骤中执行的基本块的列表，等等。如果需要快速获得这些值的平面列表，可以访问`.hardcopy`，例如`state.history.bbl_addr.hardcopy`。但是请记住，基于索引的访问是在interators上实现的。

* 以下是历史中存储的一些值的简短列表:

  * `.callstack.func_addr`是在状态上执行的每轮执行的字符串描述的列表。
  
  * `callstack.call_site_addr`是调用当前函数的基本块的地址
  
  * `callstack.stack_ptr`是从当前函数开始的堆栈指针的值
  
  * `callstack.ret_addr`是当前函数返回时将返回的位置
  
  ----
  
  ## More about I/O:Files, file systems, and network sockets
  
  * 有关如何在angr中建模I/O的更完整和更详细的文档，请参考[使用文件系统、套接字和管道](https://docs.angr.io/advanced-topics/file_system)。
  
  ----
  
  
  ## Copying and Merging
  
  * 状态支持非常快的复制，所以你可以探索不同的可能性:
  
  ```python
  >>> proj = angr.Project('/bin/true')
  >>> s = proj.factory.blank_state()
  >>> s1 = s.copy()
  >>> s2 = s.copy()

  >>> s1.mem[0x1000].uint32_t = 0x41414141
  >>> s2.mem[0x1000].uint32_t = 0x42424242
  ```
  

  