# Top Level Interfaces

* 在开始学习angr之前，您需要对一些基本的angr概念以及如何构造一些基本的angr对象有一个基本的了解。我们将通过检查在您加载了二进制文件之后，您可以直接调用的函数以及属性来研究这个问题!

* 使用angr的第一个操作总是将二进制文件加载到项目中。我们将使用/bin/true作为示例。

```python
>>> import angr
>>> proj=angr.Project('/bin/true')
```

* proj(`angr.Project`类型）是angr中的控制基础。有了它，您将能够在刚刚加载的可执行文件上执行分析和模拟的动作。在angr中,几乎每个对象的使用都依赖于某种形式的proj的存在。

---

## Basic properties

* 首先，我们拥有关于项目的一些基本属性:它的CPU架构、文件名和入口点的地址（OEP）。

```python
>>> import monkeyhex     # 将数字格式的结果转换为16进制
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true'
```

* `arch`，作为`archinfo.Arch`结构的一个实例，是程序编译的架构（Archtecture）。此程序的结构是小端字节序的amd64结构。其中包含了大量CPU运行时的数据。您可以在您空闲时[阅读](https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py)。您所关注的共通的是 `arch.bits`，`arch.bytes`（这是一个 [main](https://github.com/angr/archinfo/blob/master/archinfo/arch.py) 处的一个`@property`声明），`arch.name`以及`arch.memory_endness`等类型。

* `entry`是二进制文件的入口点

* `filename`是二进制文件的绝对路径名

---

## The loader

* 将二进制文件从其在虚拟地址空间中加载获取是一件非常复杂的事!因此我们通过一个叫CLE的模块来完成这件事。而CLE的结果，称之为加载器的对象，可以通过`.loader`获得。我们将很快详细介绍如何使用它，但现在您只需要知道您可以使用它来查看与程序一同被angr加载的共享库，并执行有关被加载的地址空间的基本访问。

```python
>>> proj.loader
<Loaded true, maps [0x400000:0x5004000]>
>>> proj.loader.shared_objects # 可能与您使用的时候的显示结果有所不同（不同的运行环境下加载的libc版本可能有所不同）
{'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
 'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}
>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5004000
>>> proj.loader.main_object  # 我们在这个proj中同时加载了多个二进制文件
Here's the main one!
<ELF Object true, maps [0x400000:0x60721f]>
>>> proj.loader.main_object.execstack  # 查询: 该二进制文件的栈空间是否可执行
False
>>> proj.loader.main_object.pic  # 查询: 该二进制文件是否开启了PIE
True
```

---

## The factory

* angr中有很多类，其中大多数需要实例化一个project。我们提供`project.factory`来避免您到处传递project。它有几个方便的构造函数，用于处理您经常使用的对象。

* 本节还将介绍几个基本的angr概念。未完待续！！

---

### Blocks

* 首先，我们有`project.factory.block()`，它用于从给定地址提取基本代码块。这里有一个非常重要的事实——**angr以基本块为单位分析代码**。你会得到一个Block的返回对象，它将告诉你关于代码块的很多有趣的事情:

```python
>>> block = proj.factory.block(proj.entry) # 从程序的入口点获取一个代码块
<Block for 0x401670, 42 bytes>
>>> block.pp()                          # 将反汇编输出到标准输出
0x401670:       xor     ebp, ebp
0x401672:       mov     r9, rdx
0x401675:       pop     rsi
0x401676:       mov     rdx, rsp
0x401679:       and     rsp, 0xfffffffffffffff0
0x40167d:       push    rax
0x40167e:       push    rsp
0x40167f:       lea     r8, [rip + 0x2e2a]
0x401686:       lea     rcx, [rip + 0x2db3]
0x40168d:       lea     rdi, [rip - 0xd4]
0x401694:       call    qword ptr [rip + 0x205866]
>>> block.instructions                  # 代码块一共有多少指令？
0xb
>>> block.instruction_addrs             # 指令的开始地址？
[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]
```

* 此外，你可以使用Block对象来获得代码块的其他表示形式:

```python
>>> block.capstone                       # capstone的反汇编块（另一款反汇编引擎）
<CapstoneBlock for 0x401670>
>>> block.vex                            # VEX IRSB (此处地址是python运行时的虚拟地址而非被分析程序的虚拟地址)
<pyvex.block.IRSB at 0x7706330>
```

### States

* 这里还有一个关于angr的事实——对象`Projectt`只表示程序的“初始化图像”。当您使用angr执行时，您使用的是表示**模拟程序状态的特定对象**—`SimState`。我们现在就去获取一个吧!

```python
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>
```

* SimState包含程序的内存、寄存器、文件系统数据…任何可以通过执行来更改的“活动数据”都可以在状态中找到。稍后我们将深入讨论如何与状态交互，但是现在，让我们使用`state.regs`以及`state.mem`来访问该状态的寄存器和内存:

```python
>>> state.regs.rip        # 获取当前状态的RIP
<BV64 0x401670>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved  # 将内存中入口点处数据转化为一个C语言的int格式
<BV32 0x8949ed31>
```

* 注意，此处并非python的int，而是**位向量**。python的interger类型与CPU上的数据含义不同。例如CPU上的溢出在python的int类型中并不存在。因此我们在angr中使用位向量。你可以将其理解为一个用一串bit来表示的int。我们以此来模拟CPU中的数据。注意，每个位向量都有一个`.length`属性，以位为单位描述它的宽度。

* 我们将很快学习如何使用它们，但现在，我们先学习一下如何将 python int转换为位向量，然后再转换回来:

```python
>>> bv = state.solver.BVV(0x1234, 32)       # 创建一个32位大小的，数据为0x1234的位向量
<BV32 0x1234>                               # BVV 代表位向量的值
>>> state.solver.eval(bv)                # 转换回python的int类型
0x1234
```

* 你可以把这些位向量存储回寄存器和内存，或者你可以直接存储一个python整数，它会被转换成一个适当大小的位向量:

```python
>>> state.regs.rsi = state.solver.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>
>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
```

* `.mem`接口一开始有点令人困惑，因为它使用了一些非常强大的python magic 。它的使用简介如下:

  * 使用 array[index] 来获取一个特定地址的数据
  * 使用`.<type>`指定内存应该转换为指定格式(`.type`常见值:char、short、int、long、size_t、uint8_t、uint16_t…)
  * 除此之外，您也可以：
    * 存储一个值到指定地址，无论是位向量或者python int都是可行的
    * 使用`.resolve`获取作为位向量的值
    * 使用`.concrete`获取一个python int的值

* 之后我们将介绍更多高级用法!

* 最后，如果您尝试读取更多寄存器，您可能会遇到一个非常奇怪的值:

```python
>>> state.regs.rdi
<BV64 reg_48_11_64{UNINITIALIZED}>
```

* 这仍然是一个64位位向量，但它不包含数值。相反，它有一个名字!这被称为**符号变量**，它是符号执行的基础。别慌!我们将在接下来的两章详细讨论所有这些。

---

### Simulation Managers

* 如果一个状态能够在给定的时间点上代表一个程序，那么一定有一种方法可以让它到达下一个时间点。仿真管理器是angr中执行带状态仿真的主要接口(不管您想叫它什么)。作为一个简短的介绍，让我们展示如何标记前面创建的几个基本块的状态。

* 首先，我们创建将要使用的仿真管理器。构造函数可以接受状态或状态列表作为参数。

```python
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x401670>]
```

* 仿真管理器可以包含多个隐藏的状态。默认的隐藏状态，`active`，是用我们传入的状态初始化的。我们可以看看`simgr.active[0]`来查看我们的状态。

* 现在…准备好，我们要开始执行了。

```python
>>> simgr.step()
```

* 我们刚刚执行了一个基本块的符号执行!我们可以再次查看活动的隐藏状态，注意到它(仿真管理器)已经更新，而且没有修改我们的原始状态。执行无法修改SimState对象——您可以安全地使用单个状态作为多轮执行的“基础”。

```python
>>> simgr.active
[<SimState @ 0x1020300>]
>>> simgr.active[0].regs.rip                 # 全新的状态!
<BV64 0x1020300>
>>> state.regs.rip                           # 仍然相同！
<BV64 0x401670>
```

* `/bin/true`不是一个很好的例子来描述如何用符号执行来做有趣的事情，所以我们现在就到这里。

---

## Analyses

* angr预先包含了几个内置的分析模块，您可以使用这些分析模块从程序中提取一些有趣的信息。如下所示:

```python
>>> proj.analyses.            # 在iPython中输入到此，之后按TAB键列出自动补全结果如下
 proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses       
 proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker          
 proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery      
 proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast  
 proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting           
 proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG                   
 proj.analyses.CFGEmulated          proj.analyses.LoopFinder           proj.analyses.VSA_DDG               
 proj.analyses.CFGFast              proj.analyses.Reassembler
```

* 本书后面将对其中的一些进行说明，但是一般来说，如果您想了解如何使用给定的分析，您应该查看[api文档](http://angr.io/api-doc/angr.html?highlight=cfg#module-angr.analysis)。举一个非常简单的例子:下面是如何构造和使用一个快速的控制流程图:

```python
# 一般情况下，当我们用angr加载二进制文件时，angr也同时加载了该二进制文件的依赖库到同一个虚拟内存空间中
# 对于大部分的分析来说，这个是没有必要的
>>> proj = angr.Project('/bin/true', auto_load_libs=False)
>>> cfg = proj.analyses.CFGFast()
<CFGFast Analysis Result at 0x2d85130>

# cfg.graph i是一个用CFGNode的实例组成的networkx.DiGraph
# 您应该参考networkx的API来学习如何使用它
>>> cfg.graph
<networkx.classes.digraph.DiGraph at 0x2da43a0>
>>> len(cfg.graph.nodes())
951

# 使用cfg.get_any_node来获取指定地址的CFGNode
>>> entry_node = cfg.get_any_node(proj.entry)
>>> len(list(cfg.graph.successors(entry_node)))
2
```

---

## Now What ？

* 阅读了本文之后，您现在应该掌握了几个重要的angr概念:基本块、状态、位向量、模拟管理器和分析。不过，除了使用angr作为一个美化的调试器之外，您实际上不能做任何有趣的事情!继续阅读，你会获得更强大的力量……
