# Solver Engine

---

* angr的强大之处不在于它是一个模拟器，而在于它能够使用我们所称的符号变量运行。与其说变量有一个*具体*的数值，不如说它包含一个*符号*。实际上这只是一个名称。然后，使用该变量执行算术操作将生成操作树(根据编译器理论，称为抽象语法树或AST)。AST可以转换为SMT求解器(如z3)的约束，以便解决诸如“给定这个操作序列的输出，求输入?”的问题。在这里，您将学习如何使用angr来回答这个问题。

---

## Working with Bitvectors

* 让我们获取一个模拟的项目和状态，这样我们就可以开始玩具体的值了。

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```

* 位向量就是一组位的序列，可以将其理解为有界整数。让我们创建几个这样的位向量

```python
# 64位的有着具体值1和100的位向量
>>> one = state.solver.BVV(1, 64)
>>> one
 <BV64 0x1>
>>> one_hundred = state.solver.BVV(100, 64)
>>> one_hundred
 <BV64 0x64>

# 新建一个有着9的具体值的27位的位向量
>>> weird_nine = state.solver.BVV(9, 27)
>>> weird_nine
<BV27 0x9>
```

* 正如您所看到的，您可以创建任何位的序列，并将它们称为位向量。您也可以用它们做数学运算:

```python
>>> one + one_hundred
<BV64 0x65>

# 您可以将python的常规interger用于运算，结果将被转化为合适的数据类型
>>> one_hundred + 0x100
<BV64 0x164>

# 应用普通包装算法的语义
>>> one_hundred - one*200
<BV64 0xffffffffffffff9c>
```

* 不过，你不能使用`one + weird_nine`。将不同长度的位向量一同执行运算是一种类型错误。但是，您可以扩展`weird_nine`使得它拥有合适的比特数:

```python
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> one + weird_nine.zero_extend(64 - 27)
<BV64 0xa>
```

* `zero_extend`将用给定的数值为0的位填充左边的位向量。您还可以使用`sign_extend`填充最高位，使得位向量在保留符号的情况下保持值不变。

* 现在，让我们引入一些符号混合。

```python
# 创建一个名为"x"的64位的符号向量
>>> x = state.solver.BVS("x", 64)
>>> x
<BV64 x_9_64>
>>> y = state.solver.BVS("y", 64)
>>> y
<BV64 y_10_64>
```

* `x`和`y`现在是符号变量，有点像你们在7年级代数里学过的变量。注意，您提供的名称已经被附加的递增计数器所破坏。您可以使用它们执行任意数量的算术操作，但是您不会从结果中得到一个数字，而是得到一个AST。

```python
>>> x + one
<BV64 x_9_64 + 0x1>

>>> (x + one) / 2
<BV64 (x_9_64 + 0x1) / 0x2>

>>> x - y
<BV64 x_9_64 - y_10_64>
```

* 每个AST都有一个`.op`和一个`.args`的属性。op是正在执行的操作的字符串的名字，args是该操作输入的值。除非op是`BVV`或`BVS`(或其他一些…)，否则arg都是AST，AST树最终以BVV或BVS结束。

```python
>>> tree = (x + 1) / (y + 2)
>>> tree
<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
>>> tree.op
'__floordiv__'
>>> tree.args
(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
>>> tree.args[0].op
'__add__'
>>> tree.args[0].args
(<BV64 x_9_64>, <BV64 0x1>)
>>> tree.args[0].args[1].op
'BVV'
>>> tree.args[0].args[1].args
(1, 64)
```

* 从这里开始，我们将使用“位向量”这个词来指代其最顶层操作生成位向量的任何AST。还可以通过AST表示其他数据类型，包括浮点数和我们即将看到的布尔值。

---

## Symbolic Constraints

* 在任意两个类型相似的AST之间执行比较操作将生成另一个AST—-不是位向量，而是符号布尔值。

```python
>>> x == 1
<Bool x_9_64 == 0x1>
>>> x == one
<Bool x_9_64 == 0x1>
>>> x > 2
<Bool x_9_64 > 0x2>
>>> x + y == one_hundred + 5
<Bool (x_9_64 + y_10_64) == 0x69>
>>> one_hundred > 5
<Bool True>
>>> one_hundred > -5
<Bool False>
```

* 从这里可以看出，比较结果在默认情况下是无符号的。最后一个例子中的-5被强制类型转换为`<BV64 0xfffffffffffffb>`，这个值一定不小于100。如果希望对比较结果有符号化，可以使用`one_hundred.SGT(-5)`(即“有符号大于”)。完整的操作列表可以在本章末尾找到。

* 这段代码还说明了使用angr的一个重要问题——永远不要在if- or - while语句的条件下直接使用变量之间的比较，因为答案可能没有一个具体的真值。即使存在一个具体的真值，例如`if one > one_hundred`，也将引发异常。作为替代，您应该使用`solver.is_true`和`solver.is_false`，它在不执行约束解的情况下测试具体的真假。

```python
>>> yes = one == 1
>>> no = one == 2
>>> maybe = x == y
>>> state.solver.is_true(yes)
True
>>> state.solver.is_false(yes)
False
>>> state.solver.is_true(no)
False
>>> state.solver.is_false(no)
True
>>> state.solver.is_true(maybe)
False
>>> state.solver.is_false(maybe)
False
```

---

## Constraints Solving

* 通过将符号布尔值添加为状态的约束，您可以将任何符号布尔值视为关于符号变量有效值的断言（assertions ）。然后，您可以通过对符号表达式求值来查询符号变量的有效值。

* 一个例子可能比这里讲解的更清楚:

```python
>>> state.solver.add(x > y)
>>> state.solver.add(y > 2)
>>> state.solver.add(10 > x)
>>> state.solver.eval(x)
4
```

* 通过向状态添加这些约束，我们迫使约束求解器将它们视为返回值必须满足的断言。如果运行这段代码，可能会得到x的不同值，但是这个值肯定大于3(因为y必须大于2,x必须大于y)，并且小于10。此外，如果您输入`state.solver.eval(y)`，您将得到一个与您得到的x值一致的y值。如果您不在两个查询之间添加任何约束，那么结果将彼此一致。

* 从这里，很容易看到如何完成我们在本章开始时提出的任务——查找产生给定输出的输入。

```python
# 获得一个没有约束的新状态
>>> state = proj.factory.entry_state()
>>> input = state.solver.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.solver.add(operation == output)
>>> state.solver.eval(input)
0x3333333333333381
```

* 注意，同样，这个解决方案只适用于位向量语义。如果我们在整数域上操作，就没有解!

* 如果我们添加冲突或矛盾的约束，这样就没有能够使约束得到满足的值，状态就变得不可满足，对结果的查询将引发异常。您可以通过`state.satisfiable()`来检查状态的可满足性。

```python
>>> state.solver.add(input < 2**32)
>>> state.satisfiable()
False
```

* 您还可以计算更复杂的表达式，而不仅仅是单个变量。

```python
# 新的状态
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```

* 从这里我们可以看出，`eval`是一种通用的方法，它可以将任何位向量转换成python的类型，同时又保证了状态的完整性。这也是为什么我们使用`eval`将具体的位向量转换为python int的原因!

* 同时还请注意，尽管我们使用旧状态创建了x和y变量，但x，y仍然可以在这个新状态中使用。变量不受任何一种状态的约束，可以自由存在。

## Floating point numbers

* z3支持IEEE754浮点数的理论，因此angr也可以使用它们。主要的区别是，浮点数有一个`sort`属性，而不是`width`。您可以使用`FPV`和`FPS`创建浮点符号和值。

```python
# 新的状态
>>> state = proj.factory.entry_state()
>>> a = state.solver.FPV(3.2, state.solver.fp.FSORT_DOUBLE)
>>> a
<FP64 FPV(3.2, DOUBLE)>

>>> b = state.solver.FPS('b', state.solver.fp.FSORT_DOUBLE)
>>> b
<FP64 FPS('FP_b_0_64', DOUBLE)>

>>> a + b
<FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>

>>> a + 4.4
<FP64 FPV(7.6000000000000005, DOUBLE)>

>>> b + 2 < 0
<Bool fpLT(fpAdd('RNE', FPS('FP_b_0_64', DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>
```

* 因此，这里有一些需要解释的地方——对于初学者来说，漂亮的打印对于浮点数不是一个好主意。但除此之外，大多数操作实际上都有第三个参数，这个参数在二进制操作符的使用中隐式添加——舍入模式。IEEE754规范支持多种舍入模式(`round-to-nearest`、`round-to-zero`、`round-to-positive`等)，因此z3必须支持这些模式。如果要为操作指定舍入模式，请显式使用fp操作（例如，`solver.fpAdd`使用舍入模式）并调用舍入模式（`solver.fp.RM_*`中的一个）作为第一个参数。(其中一个solver.fp.RM_*)

* 约束和求解方法是相同的，但是`eval`返回一个浮点数:

```python
>>> state.solver.add(b + 2 < 0)
>>> state.solver.add(b + 2 > -1)
>>> state.solver.eval(b)
-2.4999999999999996
```

* 这很好，但有时我们需要能够直接将浮点数表示为位向量。可以用`raw_to_bv`和`raw_to_fp`方法将位向量解释为浮点数，反之亦然:

```python
>>> a.raw_to_bv()
<BV64 0x400999999999999a>
>>> b.raw_to_bv()
<BV64 fpToIEEEBV(FPS('FP_b_0_64', DOUBLE))>

>>> state.solver.BVV(0, 64).raw_to_fp()
<FP64 FPV(0.0, DOUBLE)>
>>> state.solver.BVS('x', 64).raw_to_fp()
<FP64 fpToFP(x_1_64, DOUBLE)>
```

* 这些转换保留位模式，就像将浮点指针转换为int指针一样，反之亦然。但是，如果希望尽可能地保留值，就像将浮点数转换为int(反之亦然)一样，可以使用另一组方法val_to_fp和val_to_bv。由于浮点数的特性，这些方法必须将目标值的大小或排序作为参数。

```python
>>> a
<FP64 FPV(3.2, DOUBLE)>
>>> a.val_to_bv(12)
<BV12 0x3>
>>> a.val_to_bv(12).val_to_fp(state.solver.fp.FSORT_FLOAT)
<FP32 FPV(3.0, FLOAT)>
```

* 这些方法还可以接受带符号的参数，指定源或目标位向量的符号性。

---

## More Solving Methods

* `eval`将为表达式提供一个可行的解决方案，但是如果您想要多个呢?如果您想确保解决方案是惟一的怎么办?solver为您提供了几种常见的求解的方法:

  * `solver.eval(expression)`：给出给定表达式的一个解

  * `solver.eval_one(expression)`：给出给定表达式的解，如果可能有多个解，则抛出错误。

  * `solver.eval_upto(expression, n)`：给出给定表达式的至多n个解，如果可能小于n，返回的解个数将小于n。

  * `solver.eval_atleast(expression, n)`：给出给定表达式的n个解，如果可能解个数小于n，则抛出一个错误。

  * `solver.eval_exact(expression, n)`：给出给定表达式的n个解，如果可能解的个数小于或大于n，则抛出一个错误。

  * `solver.min(expression)`：给出给定表达式的最小可能解。

  * `solver.max(expression)`：将给出给定表达式的最大可能解。

* 此外，所有这些方法都可以采用以下关键字参数:

  * `extra_constraints`：可以作为约束的元组传递。这些限制将被考虑到这个评估，但不会添加到状态。

  * `cast_to`：可以指定结果转换的数据类型。目前，这只能是`int`和`bytes`，这将导致方法返回底层数据的对应表示。例如，`state.solver.eval(state.solver.BVV(0x41424344, 32), cast_to=bytes)`，返回结果：`b'ABCD'`

---

## Summary

* 真是太多了!!阅读本文之后，您应该能够创建并操作位向量、布尔值和浮点值，以形成操作树，然后查询附加状态的约束求解器，以在一组约束下寻找可能的解决方案。希望至此您已经理解了使用AST表示计算的能力，以及约束求解器的能力。

* 在[附录](https://docs.angr.io/appendix/ops)中，您可以找到适用于AST的所有附加操作的引用，以防您需要一个快速表来查看。
