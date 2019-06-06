# Simulation Managers

* angr中最重要的控制接口是SimulationManager，它允许您同时控制状态组的符号执行，并应用搜索策略来探索程序的状态空间。在这里，您将学习如何使用它。

* 仿真管理器允许您以一种灵活的方式选取多个状态。状态被组织成“stashes”，您可以向前运行、筛选、合并和移动。例如，这允许您以不同的速率运行两个不同的状态，然后将它们合并在一起。大多数操作的默认存储是`active`存储，当您初始化一个新的模拟管理器时，您的状态将放在活动存储中。

### Step

* 仿真管理器最基本的功能是将给定存储中的所有状态向前推进一个基本块。使用`.step()`执行此操作。

```python
>>> import angr
>>> proj = angr.Project('examples/fauxware/fauxware', auto_load_libs=False)
>>> state = proj.factory.entry_state()
>>> simgr = proj.factory.simgr(state)
>>> simgr.active
[<SimState @ 0x400580>]

>>> simgr.step()
>>> simgr.active
[<SimState @ 0x400540>]
```

* 当然，隐藏模型的真正强大之处在于，当一个状态遇到符号分支条件时，两个继承状态都会出现在隐藏中，您可以同步执行这两个状态。当您不需要非常小心地控制分析，而只想逐步执行到没有其他步骤可以执行时，您可以使用`.run()`方法。

```python
# 执行到第一个符号分支处
>>> while len(simgr.active) == 1:
...    simgr.step()

>>> simgr
<SimulationManager with 2 active>
>>> simgr.active
[<SimState @ 0x400692>, <SimState @ 0x400699>]

# 执行到所有状态结束
>>> simgr.run()
>>> simgr
<SimulationManager with 3 deadended>
```

* 我们现在有3个结束状态!例如，当一个状态在执行过程中无法产生任何后继，因为它到达了一个`exit`的syscall时，它将从活动存储中删除，并放入`deadended`存储中。

### Stash Management

* 让我们看看如何使用其他隐藏。

* 要在stash之间移动状态，可以使用`.move()`，它接受`from_stash`、`to_stash`和`filter_func`(可选，默认情况下是移动所有内容)。例如，让我们移动输出中有特定字符串的所有东西:

```python
>>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welcome' in s.posix.dumps(1))
>>> simgr
<SimulationManager with 2 authenticated, 1 deadended>
```

* 只需请求将状态移动到它，我们就能够创建一个名为“authenticated”的新存储。这个隐藏中的所有状态的标准输出中都有“Welcome”，这是目前的一个很好的度量标准。

* 每个隐藏都只是一个列表，您可以在列表中建立索引或迭代，以访问每个状态，但是也有一些其他方法可以访问这些状态。如果您在一个stash的名称前面加上一个`one_`，您将得到该`stash`中的第一个状态。如果您在stash的名称前加上`mp_`，您将得到该stash的[多路复用版本](https://github.com/zardus/mulpyplexer)。

```python
>>> for s in simgr.deadended + simgr.authenticated:
...     print(hex(s.addr))
0x1000030
0x1000078
0x1000078

>>> simgr.one_deadended
<SimState @ 0x1000030>
>>> simgr.mp_authenticated
MP([<SimState @ 0x1000078>, <SimState @ 0x1000078>])
>>> simgr.mp_authenticated.posix.dumps(0)
MP(['\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x80\x80\x80\x80@\x80@\x00'])
```

* 当然，`step`、`run`和任何其他操作单个路径隐藏的方法都可以使用一个`stash`参数，指定要操作哪个隐藏。

* 模拟管理器为您管理您的状态提供了很多工具与服务。我们现在不会介绍其中的其余部分,但您可以检查API文档。

---

## Stash types

* 你可以用stashes来做你喜欢的东西,但有一些stashes会被用来对一些特殊的状态进行分类。这些是:

| Stash         | Description                                                                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| active        | 此隐藏包含默认情况下将逐步执行的状态，除非指定了替代隐藏。                                                                                                                           |
| deadended     | 当一个状态由于某种原因不能继续执行时，它将进入死区存储区。这些原因包括没有更多有效的指令、它的所有后继的状态无法满足约束，或者指令指针指向一个非法地址。                                                                            |
| pruned        | 在使用`lazy_solutions`时，除非绝对必要，否则不会检查状态的可满足性。当在`lazy_solutions`存在的情况下发现一个状态无法满足约束条件时，将遍历该状态层次结构，以确定它最初在其历史中何时不满足约束条件。所有继承该点的状态(这些点也将是不满足约束条件)都被修剪并放入这个存储中。 |
| unconstrained | 如果将`save_unrestricted`选项提供给SimulationManager构造函数，则确定为unrestricted的状态(即，指令指针由用户数据或其他符号数据源控制)放在这里。                                                        |
| unsat         | 如果将`save_unsat`选项提供给SimulationManager构造函数，则确定为不可满足的状态(即，它们有相互矛盾的约束，比如输入必须同时为“AAAA”和“BBBB”)。                                                             |



* 还有另一份不属于隐藏的状态的列表:`errored`。如果在执行过程中引发错误，则状态将被包装在`ErrorRecord`对象中，该对象包含状态及其引发的错误，然后将记录插入`errored`。您可以通过`record.state`获得在执行开始时导致错误的状态。同时您也可以使用`state.error`查看发生的错误。此外您还可以使用`record.debug()`在错误的位置启动调试shell。这是一个非常宝贵的调试工具!

### Simple exploration

* 符号执行中一个极其常见的操作是找到到达某个地址的状态，同时在这些状态中丢弃经过另一个地址的所有状态。仿真管理器为这个模式提供了一个快捷方式，`.explore()`方法。

* 当通过`find`参数启动`.explore()`时，将运行直到找到至少一个状态，这些状态匹配设置好的条件。这些条件可以是经过一条指令的地址，可以是经过一个地址列表，或一个函数需要一个返回一个特定状态。当活动隐藏中的任何状态匹配`find`的条件时，这些状态将被放置在`found`的stash中，执行将终止。然后，您可以探索发现的状态，或者决定丢弃它，继续使用其他状态。您还可以使用与`find`相同的格式指定一个`avoid`条件。当一个状态匹配了`avoid`条件，它就会被放入`avoided`的stash存储中，然后继续执行。最后，`num_find`参数控制返回前应该找到的状态数，默认值为1。当然，如果您在找到这么多解决方案之前耗尽了活动存储中的状态，那么无论如何执行都会停止。

* 让我们来看一个简单的crackme[例子](https://docs.angr.io/examples#reverseme-modern-binary-exploitation---csci-4968):

* 首先我们加载二进制文件

```python
>>> proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')

```

* 接下来，我们创建一个仿真模拟器。

```python
>>> simgr = proj.factory.simgr()

```

* 现在，我们进行符号执行，直到找到与我们的条件匹配的状态(即“win”的条件)。

```python
>>> simgr.explore(find=lambda s: b"Congrats" in s.posix.dumps(1))
<SimulationManager with 1 active, 1 found>
```

* 现在，我们可以把flag从那个状态中拿出来了!

```python
>>> s = simgr.found[0]
>>> print(s.posix.dumps(1))
Enter password: Congrats!

>>> flag = s.posix.dumps(0)
>>> print(flag)
g00dJ0B!
```

* 很简单,不是吗?

* 其他示例可以通过浏览[示例](https://docs.angr.io/examples)找到。


## Exploration Techniques

* angr附带了一些固定的功能，可以定制模拟管理器的行为，称为探索技术。为什么需要探索技术？典型例子是修改探索程序状态空间的模式——默认的“一次完成所有事情”策略实际上是广度优先搜索，但是使用探索技术可以实现，例如深度优先搜索。然而，这些技术的检测功能要灵活得多——您可以完全改变angr的步进过程的行为。编写您自己的探索技术将在后面的章节中介绍。

* 要使用探索技术，请调用`simgr.use_technology(tech)`，其中`tech`是`ExplorationTechnique`子类的一个实例。angr内置的探测技术可以在`angr.exploration_techniques`中找到。

* 下面是一些内置功能的快速概述:

  * `DFS`:如前所述，深度优先搜索。一次只保持一个状态为活动状态，将其余状态保存在`deferred`中，直到它死区或错误。
  
  * `Explorer`:此技术实现`.explore()`功能，允许您搜索和避免地址。
  
  * `LengthLimiter`:设置状态经过的路径的最大长度上限。
  
  * `LoopSeer`:使用合理的循环计数近似值来丢弃循环次数过多的状态，将它们放入`spinning`中，如果没有其他可行的状态，则再次将它们取出。
  
  * `ManualMergepoint`:将程序中的一个地址标记为合并点，因此到达该地址的状态将被暂时保存，而在超时内到达同一点的任何其他状态将被合并在一起。
  
  * `MemoryWatcher`:在simgr步骤之间监视系统上空闲/可用的内存，如果内存太低，则停止探索。
  
  * `Oppologist`:“操作辩护者”是一个特别有趣的小工具——如果启用了这项技术并且angr遇到不支持的指令，例如bizzare和外部浮点SIMD指令，它将具体化该指令的所有输入，并使用unicorn引擎模拟单个指令，从而允许继续执行。
  
  * `Spiller`:当有太多状态处于活动状态时，此技术可以将其中一些状态转储到磁盘，以保持低内存消耗。
  
  * `Threading`:为步进过程添加线程级并行性。因为python的全局解释器锁，这没有多大帮助。但如果您有一个程序，它的分析花费了大量时间在angr的本地代码依赖项(unicorn、z3、libvex)中，您可以看到一些好处。
  
  * `Tracer`:一种探测技术，它使执行遵循从其他源记录的动态跟踪。[动态跟踪存储库](https://github.com/angr/tracer)有一些工具来生成这些跟踪。
  
  * `Veritesting`:一篇关于自动识别有用的合并点[CMU论文](https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf)的实现。这非常有用，您可以在SimulationManager构造函数中使用`verititing =True`自动启用它！注意，由于它实现静态符号执行的侵入性方式，它经常不能很好地与其他技术配合使用。
  
* 有关更多信息，请参阅[模拟管理器](http://angr.io/api-doc/angr.html#module-angr.manager)的API文档和[探索技术](http://angr.io/api-doc/angr.html#angr.exploration_techniques.ExplorationTechnique)。