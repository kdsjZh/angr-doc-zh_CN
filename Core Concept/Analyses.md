# Analyses

---

* angr的目标是使对二进制程序进行的分析变得容易。为此，angr允许您以一种通用格式打包分析代码，这种格式可以很容易地应用于任何项目。稍后我们将介绍如何编写您自己的分析，但是我们的想法是所有的分析都出现在`project.analyses`中(例如`project.analyses.CFGFast()`)。它可以作为函数调用，返回分析结果实例。

---

## Built-in Analyses

| 名称                                                                     | 描述                                                           |
| ---------------------------------------------------------------------- | ------------------------------------------------------------ |
| CFGFast                                                                | 构建一个项目的*控制流程图*                                               |
| [CFGEmulated](https://docs.angr.io/built-in-analyses/cfg)              | 构建一个项目运行时的*控制流程图*                                            |
| VFG                                                                    | 对程序的每个函数执行VSA，创建*数值流程图*并检测堆栈变量                               |
| DDG                                                                    | 计算*数据依赖关系图*，从而确定给定值所依赖的语句                                    |
| [BackwardSlice](https://docs.angr.io/built-in-analyses/backward_slice) | 计算程序相对于某个目标的*后向切片*                                           |
| [Identifier](https://docs.angr.io/built-in-analyses/identifier)        | 标识CGC二进制文件中的公共库函数                                            |
| More!                                                                  | angr有相当多的分析，其中大部分是有效的!如果您想知道如何使用其中的某一个，请提交一个issue来请求获取一个说明文档 |

## Resilience

* 分析可以写得很有弹性，基本上可以捕获并记录任何错误。根据捕获的方式，这些错误将被记录到分析的`errors`或`named_errors`属性中。但是，您可能希望以“fail fast”模式运行分析，这样就不会处理错误。为此，可以将参数`fail_fast=True`传递到分析构造函数中。
