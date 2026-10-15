# 文档导航

文档按职责命名，文件名使用小写英文，不携带项目名、语言后缀或版本号。版本范围在正文说明。

| 文档 | 用途 |
| --- | --- |
| [prd.md](prd.md) | 产品为谁解决什么问题，以及长期方向 |
| [mvp.md](mvp.md) | 首版要交付什么，以及如何判定完成 |
| [architecture.md](architecture.md) | 模块如何分工、依赖和传递数据 |
| [cli.md](cli.md) | 命令、选项、默认值、输出行为和退出码 |
| [validation.md](validation.md) | 查询名称、服务器地址与超时输入的校验边界 |
| [wire-codec.md](wire-codec.md) | 名称和 DNS 报文的编码、解析与错误约定 |
| [network.md](network.md) | 端点模型、套接字所有权、网络错误、查询预算与 UDP/TCP/DoH/DoT 收发 |
| [build.md](build.md) | 准备依赖、本地构建、测试分类与跨平台持续集成 |
| [style.md](style.md) | 中文提示、函数说明与 C++23 代码约定 |
| [todo.md](todo.md) | 已完成工作、下一步与验收记录 |

根目录 [README.md](../README.md) 面向使用者，介绍当前功能与用法；[AGENTS.md](../AGENTS.md) 记录协作、文档和提交约定。

## 阅读顺序

- 使用程序：先看 README，需要自行编译时看 build。
- 了解首版：先看 prd 和 mvp，再看 cli 与 validation。
- 继续开发：先看 todo，再按任务阅读 architecture、wire-codec 或 network。

## 维护规则

同一规则只在负责它的文档中维护，其他文档通过链接引用。长期方向不能覆盖首版范围；已确认的设计不能被写成已实现的功能。实际支持情况以代码、README 和 todo 的验收记录为准。

命令选项集中在 cli，输入边界集中在 validation，报文算法集中在 wire-codec，网络基础接口集中在 network。调整这些规则时同步相关测试与引用，不再在 PRD 和架构文档中复制完整参数表。
