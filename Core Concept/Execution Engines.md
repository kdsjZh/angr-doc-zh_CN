# Execution Engines

* 当您要求在angr中执行某个步骤时，必须实际执行该步骤。angr使用一系列引擎(`SimEngine`类的子类)来模拟给定代码段对输入状态的影响。angr的执行核心只是按顺序尝试所有可用的引擎，使用第一个能够处理该步骤的引擎。以下是默认的引擎列表，顺序如下:

  * 当前面的步骤将我们带到某个不可持续的状态时，故障引擎就会启动

  * 当前面的步骤以syscall结束时，syscall引擎就开始工作了

  * 当钩住当前地址时，hook引擎就会启动

  * 当启用了`UNICORN`状态选项并且状态中没有符号数据时，unicorn引擎就会启动

  * VEX引擎作为最后的后备力量发挥作用。

---

### SimSuccessors

* 实际上依次尝试所有引擎的代码是`project.factory.successors(state， **kwargs)`，它将其参数传递给每个引擎。这个函数是`state.step()`和`simulation_manager.step()`的核心。它返回一个我们之前曾简要讨论过的SimSuccessors对象。SimSuccessors的目的是对继承者状态执行简单的分类，并存储在各种列表属性中。它们是:

| Attribute                  | Guard Condition         | Instruction Pointer                               | Description                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ----------------------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `successors`               | True(可以是符号的，但必须为True)   | 可以是符号的(但解必须小于等于256个;见`unconstrained_successors`)。 | 由引擎处理的状态的正常、可满足的继承状态。该状态的指令指针可以是符号的(即，根据用户输入计算决定跳转)，因此状态实际上可能表示未来执行的几个潜在延续。                                                                                                                                                                                                                                                                                                                                          |
| `unsat_successors`         | False(可以是符号的，但必须为False) | 可以是符号的                                            | 不可满足的继承状态。这些继承状态的约束条件只能是假的(即，不能执行的跳转，或必须执行的跳转的默认分支)                                                                                                                                                                                                                                                                                                                                                                  |
| `flat_successors`          | True(可以是符号的，但必须为True)   | 具体数值                                              | 如上所述，`successors`列表中的状态可以有符号指令指针。这是相当混乱的，因为在代码的其他地方(即当`SimEngineVEX.process`将状态向前推进时)，我们假设一个程序状态只表示代码中一个点的执行。为了缓解这种情况，当我们遇到具有符号指令指针的`successors`时，我们为它们计算所有可能的具体解决方案(最多256个)，并为每个此类解决方案复制状态。我们把这个过程称为“扁平化”。这些`flat_successors`是状态，每个状态都有一个不同的具体指令指针。举个例子,如果一个状态的指令指针在`successors`中是`X + 5`,其中`X`满足`X > 0x800000`和`X < = 0x800010`的约束,扁平成16个不同的`flat_successors`状态,一个的指令指针指向`0x800006`,另一个是`0x800007`,以及`0x800015`等等。 |
| `unconstrained_successors` | True(可以是符号的，但必须为True)   | 符号的(超过256个解决方案)                                   | 在上面描述的平坦化过程中，如果对于指令指针有超过256种可能的解决方案，我们假设指令指针已经被无约束数据覆盖(即，用户数据导致堆栈溢出)。这一假设在一般情况下是站不住脚的。这种状态被放在`unconstrained_successors`而不是`successors`中。                                                                                                                                                                                                                                                                             |
| `all_successors`           | 所有情况                    | 可以是符号                                             | `successors + unsat_successors + unconstrained_successors`                                                                                                                                                                                                                                                                                                                                                           |

---

## Breakpoints

* 待办事项:重写这个来修正叙述

* 与任何像样的执行引擎一样，angr支持断点。这很酷!设置方式如下:

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')

# 获取我们的状态
>>> s = b.factory.entry_state()

# 添加一个断点，即将发生内存写入时将会触发断点并将控制权转交ipdb
>>> s.inspect.b('mem_write')

# 此外，我们还能使断点在内存写入之后触发
# 我们也可以使用一个回调函数来替代ipdb
>>> def debug_func(state):
...     print("State %s is about to do a memory write!")

>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_func)

# 或者我们也可以使用iPython来替代ipdb的触发
>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=angr.BP_IPYTHON)
```

* 除了内存写入之外，还有许多其他地方需要中断。这是列表。对于这些事件，可以在BP_BEFORE或BP_AFTER中断。

| Event type             | Event meaning               |
| ---------------------- | --------------------------- |
| mem_read               | 内存被读取                       |
| mem_write              | 内存被写入                       |
| reg_read               | 寄存器被读取                      |
| reg_write              | 寄存器被写入                      |
| tmp_read               | 临时变量被读取                     |
| tmp_write              | 临时变量被写入                     |
| expr                   | 正在创建一个表达式(即，算术运算的结果或IR中的常数) |
| statement              | 正在翻译IR语句                    |
| instruction            | 正在翻译一条新的(原生的)指令             |
| irsb                   | 一个新的基本块正在被翻译                |
| constraints            | 新的约束被添加到状态中                 |
| exit                   | 从执行中生成一个后继                  |
| symbolic_variable      | 正在创建一个新的符号变量                |
| call                   | 调用指令被触发                     |
| address_concretization | 正在解析符号内存访问                  |

* 这些事件有着不同的属性

| 事件类型                   | 属性名称                                   | 属性可用性                | 属性含义                                                                             |
| ---------------------- | -------------------------------------- | -------------------- | -------------------------------------------------------------------------------- |
| mem_read               | mem_read_address                       | BP_BEFORE / BP_AFTER | 正在读取内存的地址                                                                        |
| mem_read               | mem_read_length                        | BP_BEFORE / BP_AFTER | 读取的内存长度                                                                          |
| mem_read               | mem_read_expr                          | BP_AFTER             | 地址的表达式                                                                           |
| mem_write              | mem_write_address                      | BP_BEFORE / BP_AFTER | 正在写入内存的地址                                                                        |
| mem_write              | mem_write_length                       | BP_BEFORE / BP_AFTER | 内存写入的长度                                                                          |
| mem_write              | mem_write_expr                         | BP_BEFORE / BP_AFTER | 正在写入的表达式                                                                         |
| reg_read               | reg_read_offset                        | BP_BEFORE / BP_AFTER | 正在读取的寄存器的偏移量                                                                     |
| reg_read               | reg_read_length                        | BP_BEFORE / BP_AFTER | 寄存器读取的长度                                                                         |
| reg_read               | reg_read_expr                          | BP_AFTER             | 寄存器中的表达式                                                                         |
| reg_write              | reg_write_offset                       | BP_BEFORE / BP_AFTER | 正在写入的寄存器的偏移量                                                                     |
| reg_write              | reg_write_length                       | BP_BEFORE / BP_AFTER | 寄存器写入的长度                                                                         |
| reg_write              | reg_write_expr                         | BP_BEFORE / BP_AFTER | 正在写的表达式                                                                          |
| tmp_read               | tmp_read_num                           | BP_BEFORE / BP_AFTER | 正在读取的临时变量的数目                                                                     |
| tmp_read               | tmp_read_expr                          | BP_AFTER             | 临时变量的表达式                                                                         |
| tmp_write              | tmp_write_num                          | BP_BEFORE / BP_AFTER | 正在写入的临时变量的数目                                                                     |
| tmp_write              | tmp_write_expr                         | BP_AFTER             | 写入临时变量的表达式                                                                       |
| expr                   | expr                                   | BP_BEFORE / BP_AFTER | IR的表达式                                                                           |
| expr                   | expr_result                            | BP_AFTER             | 计算表达式的值(如AST)                                                                    |
| statement              | statement                              | BP_BEFORE / BP_AFTER | IR语句的索引(在IR基本块中)                                                                 |
| instruction            | instruction                            | BP_BEFORE / BP_AFTER | 原生指令的地址                                                                          |
| irsb                   | address                                | BP_BEFORE / BP_AFTER | 基本块的地址                                                                           |
| constraints            | added_constraints                      | BP_BEFORE / BP_AFTER | 正在添加的约束表达式列表                                                                     |
| call                   | function_address                       | BP_BEFORE / BP_AFTER | 被调用函数的名称                                                                         |
| exit                   | exit_target                            | BP_BEFORE / BP_AFTER | 表示SimExit目标的表达式                                                                  |
| exit                   | exit_guard                             | BP_BEFORE / BP_AFTER | 表示SimExit的守护的表达式                                                                 |
| exit                   | exit_jumpkind                          | BP_BEFORE / BP_AFTER | 表示SimExit类型的表达式                                                                  |
| symbolic_variable      | symbolic_name                          | BP_BEFORE / BP_AFTER | 正在创建的符号变量的名称。求解器引擎可能修改这个名称(通过附加一个惟一的ID和长度)。检查symbolic_expr以获得最终的符号表达式。           |
| symbolic_variable      | symbolic_size                          | BP_BEFORE / BP_AFTER | 正在创建的符号变量的大小                                                                     |
| symbolic_variable      | symbolic_expr                          | BP_AFTER             | 表示新符号变量的表达式                                                                      |
| address_concretization | address_concretization_strategy        | BP_BEFORE / BP_AFTER | 使用SimConcreationStrategy解析地址。这可以由断点处理程序修改，以更改将要应用的策略。如果您的断点处理程序将此设置为None，则跳过此策略。 |
| address_concretization | address_concretization_action          | BP_BEFORE / BP_AFTER | 用于记录内存操作的SimAction对象。                                                            |
| address_concretization | address_concretization_memory          | BP_BEFORE / BP_AFTER | 执行操作的SimMemory对象                                                                 |
| address_concretization | address_concretization_expr            | BP_BEFORE / BP_AFTER | 表示正在解析的内存索引的AST。断点处理程序可以修改它以影响正在解析的地址。                                           |
| address_concretization | address_concretization_add_constraints | BP_BEFORE / BP_AFTER | 是否应该为读取添加约束                                                                      |
| address_concretization | address_concretization_result          | BP_AFTER             | 已解析内存地址(整数)的列表。断点处理程序可以覆盖这些代码以产生不同的解析结果。                                         |

* 这些属性可以作为`state.inspect`访问。在适当的断点回调期间检查，以访问适当的值。您甚至可以修改这些值来进一步修改这些值的用法

```python
>>> def track_reads(state):
...     print('Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address)
...
>>> s.inspect.b('mem_read', when=angr.BP_AFTER, action=track_reads)
```

* 此外，这些属性中的每一个都可以用作要检查的关键字`inspect.b`给断点添加条件:

```python
# 如果在0x1000的地址处的内存被写入，那么在内存写入之前就会中断
>>> s.inspect.b('mem_write', mem_write_address=0x1000)

# 如果0x1000是它的目标表达式的唯一值，那么在内存写之前就会中断expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

# 这将在指令0x8000之后中断，但是只有0x1000可能是从内存中读取的最后一个表达式的值
>>> s.inspect.b('instruction', when=angr.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)
```

* 酷炫的东西!事实上，我们甚至可以将函数指定为一个条件:

```python
# 这是一个复杂的情况，可以做任何事情!在本例中，它确保了RAX是0x41414141，并且
# 从0x8004开始的基本块在此路径历史上的某个时候执行

>>> def cond(state):
...     return state.eval(state.regs.rax, cast_to=str) == 'AAAA' and 0x8004 in state.inspect.backtrace

>>> s.inspect.b('mem_write', condition=cond)
```

### Caution about `mem_read` breakpoint

* `mem_read`断点在执行程序或二进制分析执行内存读取时被触发。如果您在`mem_read`上使用断点，同时也使用`state.mem`从内存地址加载数据，然后知道技术上来讲断点将在读取内存时触发。

* 因此，如果希望从内存加载数据而不触发已经设置的`mem_read`断点，那么使用`state.memory.load`并加上关键字参数`disable_actions=True`和`inspect=False`。

* 对于`state.find`也是如此。您可以使用相同的关键字参数来防止触发`mem_read`断点。
