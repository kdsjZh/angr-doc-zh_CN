# Loading a Binary

---

* 在此之前，您只看到了angr作为加载工具的最简单的功能—您加载了`/bin/true`，然后在没有共享库的情况下再次加载它。您也看到了`proj.loader`和一些它能做的事情。现在，我们将深入研究这些接口的细微差别以及它们可以告诉您的东西。

* 我们先前简要介绍了angr的二进制文件加载器CLE。CLE代表“CLE加载所有东西”，负责获取二进制文件(以及它所依赖的任何库)，并以一种易于使用的方式将其提供给angr的其余部分。

---

## The loader

* 让我们加载`examples/fauxware/fauxware`并深入了解它如何与加载器交互

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> proj.loader
<Loaded fauxware, maps [0x400000:0x5008000]>
```

### Loaded Objects

* CLE加载器(`cle.Loader`)表示所有被加载的二进制对象的组合。它将所有二进制对象加载并映射到单个内存空间。每个二进制对象都由一个后端的加载器加载，加载器后端装载器可以处理该二进制文件的文件类型(`cle.Backend`的一个子类)。例如,`cle.ELF`用于加载ELF二进制文件。

* 内存中也会有与任何加载的二进制文件都对应不上的对象。例如，用于支持本地线程存储的对象和用于提供未解析符号的扩展对象。

* 您可以通过`loader.all_objects`获得CLE已加载对象的完整列表，以及一些更有针对性的分类：

```python
# 已加载对象的完整列表
>>> proj.loader.all_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>,
 <ELFTLSObject Object cle##tls, maps [0x3000000:0x3015010]>,
 <ExternObject Object cle##externs, maps [0x4000000:0x4008000]>,
 <KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>]

# 这是“main”对象，该对象在加载项目时直接指定
>>> proj.loader.main_object
<ELF Object fauxware, maps [0x400000:0x60105f]>

# 这是一个以对象名称为键，对象为键值的字典映射
>>> proj.loader.shared_objects
{ 'fauxware': <ELF Object fauxware, maps [0x400000:0x60105f]>,
  'libc.so.6': <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
  'ld-linux-x86-64.so.2': <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]> }

# 以下是所有的从ELF文件加载的对象
# 如果这是Windows的项目，我们会使用all_pe_objects!
>>> proj.loader.all_elf_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>]

# 以下是我们为无法解析的导入部件以及angr的内部部件提供的地址，我们称之为"扩展对象"
>>> proj.loader.extern_object
<ExternObject Object cle##externs, maps [0x4000000:0x4008000]>

# 这个对象用于为仿真时的系统调用提供地址
>>> proj.loader.kernel_object
<KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>

# 最后，你可以通过给定地址来查找该地址所属的对象
>>> proj.loader.find_object_containing(0x400000)
<ELF Object fauxware, maps [0x400000:0x60105f]>
```

* 您可以直接与这些对象交互，从中提取元数据:

```python
>>> obj = proj.loader.main_object

# 对象的入口点
>>> obj.entry
0x400580

>>> obj.min_addr, obj.max_addr
(0x400000, 0x60105f)

# 搜索这个ELF文件的段以及区块
>>> obj.segments
<Regions: [<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>,
           <ELFSegment memsize=0x238, filesize=0x228, vaddr=0x600e28, flags=0x6, offset=0xe28>]>
>>> obj.sections
<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
           <.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
           <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
            ...etc

# 你可以通过一个地址获取该地址所属的段或区块
>>> obj.find_segment_containing(obj.entry)
<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>
>>> obj.find_section_containing(obj.entry)
<.text | offset 0x580, vaddr 0x400580, size 0x338>

# 通过符号获取其在plt表中的地址
>>> addr = obj.plt['strcmp']
>>> addr
0x400550
>>> obj.reverse_plt[addr]
'strcmp'

# 展示该文件的静态链接的基地址以及CLE实际将其装载到的基地址
>>> obj.linked_base
0x400000
>>> obj.mapped_base
0x400000
```

---

### Symbols and Relocations

* 您还可以使用CLE处理符号。符号是可执行格式世界中的一个基本概念，能够有效地将符号名映射到地址。

* 从CLE获取符号的最简单方法是使用`loader.find_symbol`，它可以接受名称或地址作为参数，并返回一个Symbol对象。

* 符号上最有用的属性是它的名称、所属对象和地址，但是符号的“地址”可能是模糊的。符号对象有三种方式表示其地址:

  * `.rebased_addr`是其在全局地址空间中的地址。这是输出中显示的内容。

  * `.linked_addr`是它相对于二进制预链接基址的地址。例如：`readelf(1)`就是其返回的一个结果

  * `.relative_addr`是它相对于对象基地址的地址。这在文献(尤其是Windows文献)中称为RVA(相对虚拟地址)。

```python
>>> strcmp.name
'strcmp'

>>> strcmp.owner
<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>

>>> strcmp.rebased_addr
0x1089cd0
>>> strcmp.linked_addr
0x89cd0
>>> strcmp.relative_addr
0x89cd0
```

* 除了提供调试信息外，符号还支持动态链接的概念。libc提供strcmp符号作为导出函数，而主二进制文件依赖于它。如果我们要求CLE直接从主对象中给我们一个strcmp符号，它会告诉我们这是一个导入符号。导入符号没有与它们关联的有意义的地址，但是它们提供了一个对符号的引用，用于解析导入符号，如`.resolvedby`。

```python
>>> strcmp.is_export
True
>>> strcmp.is_import
False

# 在Loader上，方法是find_symbol，因为它执行搜索操作来查找符号。
# 对于单个对象，方法是get_symbol，因为一个名称只能有一个符号。
>>> main_strcmp = proj.loader.main_object.get_symbol('strcmp')
>>> main_strcmp
<Symbol "strcmp" in fauxware (import)>
>>> main_strcmp.is_export
False
>>> main_strcmp.is_import
True
>>> main_strcmp.resolvedby
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```

* 导入和导出之间的链接的特定方式应当在内存中注册，并由另一个称为重定位的概念处理。重定位表示，“当您将`[import]`与导出符号匹配时，请将导出地址写入`[location]`，格式为`[format]`。”我们可以通过`obj.relocs`看到一个对象(作为重定位实例)的完整重定位列表，或者只是一个从符号名到重定位的映射（`obj,imports`）。

* 可以通过`.symbol`访问重定位对应的导入符号。而任何可以用作符号的地址标识符，都可用于访问重定位将写入的地址。此外，对于请求重定位的对象，您还可以使用`.owner`获得对该对象的引用。

```python
# 重定位不是很好打印, 因此这些地址是python程序内部的，与我们的程序无关
>>> proj.loader.shared_objects['libc.so.6'].imports
{'__libc_enable_secure': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce780>,
 '__tls_get_addr': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018358>,
 '_dl_argv': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2e48>,
 '_dl_find_dso_for_object': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018588>,
 '_dl_starting_up': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2550>,
 '_rtld_global': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce4e0>,
 '_rtld_global_ro': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fcea20>}
```

* 例如，如果由于找不到共享库的原因，我们不能将导入解析为任何导出。那么在该种情况下CLE将把externs对象(`loader.extern_obj`)自动更新，以声明它，进而将符号作为导出提供。

---

## Loading Options

* 如果在您用angr加载`angr.Project`时希望将一个选项传递给项目隐式创建的`cle.Loader`实例，那么您可以直接将关键字参数传递给项目构造函数，它将被传递给CLE。如果您想查看所有可以传递的选项，您可以查看[CLE API docs](http://angr.io/api-doc/cle.html)，在此处我们只介绍一些重要的或频繁使用的选项

#### Basic Options

* 我们先前已经讨论过`auto_load_libs`选项了——它允许或禁止CLE自动解析共享库依赖关系，并且默认选项为允许。此外，还有一个相反的选项`except_missing_libs`，如果将其设置为true，当二进制文件具有无法解析的共享库依赖关系时，就会引发异常。

* 你可以传递一个字符串列表给`force_load_libs`,其中列出的所有都将被视为无法解析的共享库依赖。或者你可以传递一个字符串列表给`skip_libs`以防止任何库的名称解析为依赖。此外，您可以将字符串列表(或单个字符串)传递给`ld_path`。在搜索默认路径中的共享库前，我们将从`ld_path`中的路径搜索共享库。默认搜索路径有：与加载的程序相同的目录、当前工作目录和系统库。

#### Pre-Binary Options

* 如果您想指定一些只适用于特定二进制对象的选项，CLE也会让您这样做。参数`main_ops`和`lib_opts`通过接受选项字典来实现这一点。`main_opts`是一个从选项名到选项值的映射，而`lib_opts`是一个从库名到字典的映射，将选项名映射到选项值。

* 你可以使用的选项因backend而异，但一些常见的选项是:

  * `backend`-使用哪个后端装载器作为类或名称
  * `base_addr`-使用的基地址
  * `entry_point`-使用的入口点
  * `arch`-使用的架构

* 例：

```python
>>> angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
<Project examples/fauxware/fauxware>
```

### Backends

* CLE目前有用于静态加载ELF、PE、CGC、Mach-O和ELF内核dump文件的后端装载器，以及用IDA加载二进制文件和将文件加载到平面地址空间的后端装载器。CLE将在大多数情况下自动检测到要使用的正确后端装载器，所以您不应该指定使用哪个后端装载器，除非您正在做一些非常奇怪的事情。

* 您可以通过在对象的选项字典中包含一个键来强制CLE为对象使用特定的后端装载器，如上所述。有些后端装载器不能自动检测要使用哪个体系结构，必须指定架构。字典的键不需要匹配任何架构的列表;angr将识别您所表示的体系结构，为任何受支持的arch提供几乎任何通用标识符。

* 若要引用后端装载器，请使用下表中的名称:

| 装载器名字     | 描述                             | 需要指定架构与否 |
| --------- | ------------------------------ | -------- |
| elf       | ELF文件的静态装载器，基于PyElFTools       | 否        |
| pe        | PE文件的静态装载器，基于pefile            | 否        |
| mach-o    | mach-o文件的静态装载器，不支持动态链接或基址重定位   | 否        |
| cgc       | CyperGrandChallenge二进制文件的静态加载器 | 否        |
| backedcgc | CGC二进制文件静态加载器，允许指定内存与寄存器       | 否        |
| elfcore   | elf内核转存文件的静态加载器                | 否        |
| ida       | 运行一个IDA的实例来分析文件                | 是        |
| blob      | 以平面镜像的形式加载文件到内存                | 是        |

---

## Symbolic Function Summary

* 默认情况下，Project试图通过使用称为SimProcedures的符号摘要来替换对库函数的外部调用——实际上就是模仿库函数对状态的影响的python函数。我们实现了一系列[SimProcedure](https://github.com/angr/angr/tree/master/angr/procedures)函数。我们可以在`angr.SIM_PROCEDURES`中使用这些函数。同时，`angr.SIM_PROCEDURES` 的字典是两级的，第一级的键是包名称(libc、posix、win32、存根)，然后每个键值都是一个字典，键值是库函数的名称。执行SimProcedure而不是从系统中加载的实际库函数，可以使分析更加容易处理，但可能会导致[一些错误](https://docs.angr.io/advanced-topics/gotchas)。

* 当某一给定函数没有摘要时:

  * 如果`auto_load_libs`为真(这是默认值)，则执行实际的库函数。这可能是您想要的，也可能不是，这取决于实际的函数。例如，libc的一些函数分析起来非常复杂，并且很可能会导致尝试执行它们的路径的状态数暴增。

  * 如果`auto_load_libs`为假，那么外部函数将无法解析，项目将把它们解析为一个名为`ReturnUnconstrained`的通用“Stub”SimProcedure。该状态，如同其名称所说，每次调用它时，它都返回一个惟一的无约束符号值。

  * 当`use_sim_procedures`（不是`cle.Loader`的成员而是`angr.Project`的成员）被设置为假（默认为真），那么只有扩展对象提供的符号将被SimProcedure替换，它们将被`ReturnUnconstrained`的stub替换，该stub只返回一个符号值。

  * 通过`angr.Project`中的选项`exclude_sim_procedures_list`或者`exclude_sim_procedures_func`，您可以指定特定符号不被SimProcedures替换

  * 您可以查看`angr.Project._register_object`来查看具体的算法

  #### Hooking

  * angr用python摘要替换库代码的机制称为Hook，您也可以这样做！在执行模拟时，在每一步angr都会检查当前地址是否已被Hooked，如果是，则运行钩子而不是该地址的二进制代码。让你这样做的API是`proj.hook(addr, hook)`，其中`hook`是SimProcedure实例。您可以使用`.is_hook`、`.unhook`和`.hooked_by`管理项目的钩子。

  * 还有一个用于Hook指定地址的替代API，通过使用`proj.hook(addr)`作为函数装饰器，您可以指定自己的现成函数作为钩子使用。如果这样做，还可以选择指定length关键字参数，使执行在钩子完成后向前跳转一定数量的字节。

```python
  >>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```

* 此外，您还可以使用`proj.hook_symbol(name, hook)`，提供了一个符号的名称作为第一个参数，用来钩住符号所在的地址。它的一个非常重要的用途是扩展angr的内置库SimProcedure的行为。由于这些库函数只是类，所以可以对它们进行子类化，覆盖它们的行为片段，然后在钩子中使用子类。

---

## So far so good!

* 到目前为止，您应该对如何在CLE加载器和angr项目的级别上控制分析的环境选项有了合理的理解。您还应该了解，angr通过将复杂的库函数与总结函数效果的SimProcedure连接起来，合理地尝试简化其分析。

* 为了了解您可以使用CLE加载器及其后端装载器做的所有事情，请查看[CLE API文档](http://angr.io/api-doc/cle.html)。
