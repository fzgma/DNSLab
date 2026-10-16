# DNS 报文编解码

本文定义名称处理、查询编码和消息解析的接口、边界及错误约定。查询输入规则见 [validation.md](validation.md)，请求关联由应用层的 [响应匹配](architecture.md#响应匹配) 负责。

## 边界与接口

模块只处理内存数据，不创建套接字、不读取系统设置、不打印日志。输入使用 `std::span<const std::byte>`，可恢复错误使用 `std::expected`；禁止将报文字节转换成未对齐整数指针或打包结构体。

名称接口位于 `src/dns/name_codec.hpp`，报文接口位于 `src/dns/wire_codec.hpp`，命名空间均为 `dnslab::dns`：

| 接口 | 结果 |
| --- | --- |
| `parse_ascii_name(input)` | 校验查询名称，返回 `DnsName` 或 `NameInputError` |
| `encode_name(name)` | 生成无压缩名称，返回 `EncodedName` 或 `DnsEncodeError` |
| `decode_name(packet, start)` | 从完整报文的指定位置解码，返回 `DecodedName` 或 `DnsParseError` |
| `format_name(name)` | 生成带尾点、特殊字节已转义的显示文本 |
| `names_equal_case_insensitive(a, b)` | 按标签边界进行 ASCII 大小写无关比较 |

`Packet` 是 `std::vector<std::byte>`。`DnsName` 保存 `std::vector<std::string> labels`，标签是原始字节而非 UTF-8 假设。空标签列表表示根名称；列表中的空字符串不是合法标签。

`EncodedName::bytes` 拥有编码字节。`DecodedName` 包含 `name` 和 `consumed`，后者仅统计原始位置占用的字节，不是展开后名称长度。内部接口不承诺稳定的公共 ABI。

## 整数与普通名称

`src/dns/byte_utils.hpp` 的 `read_u16_be`、`read_u32_be` 从传入偏移读取网络字节序整数，不推进调用方游标；失败返回 `FieldOutOfBounds` 和原请求偏移。`append_u16_be`、`append_u32_be` 追加对应字节。读取先确认 offset 不超过输入大小，再比较剩余长度，最后索引或加法，保证 `SIZE_MAX` 等极端偏移也安全失败。

普通名称按“标签长度、标签字节”连续编码，最后追加一个零字节。单标签最长 63 字节，完整展开编码最长 255 字节，包含全部长度字节和根终止字节。

编码器对任何传入的 `DnsName` 独立检查空标签、标签长度和总长度，再分配输出。它不套用用户输入的字符或纯数字限制，原始标签中的 NUL、控制字节和非 ASCII 字节必须保持不变。

普通解码只在结构位置解释长度字节，标签内容中的指针形状字节仍是数据。解码到根终止符或首个压缩指针对应的名称结束后停止，不能读取原始名称之后的其他字段。

## 压缩名称

压缩指针最高两位为 `11`，其余 14 位为相对于完整 DNS 报文起点的目标偏移。本实现要求目标位于当前指针之前，并检测解析路径循环；`01`、`10` 是不支持的保留标签编码。

### 状态

- `cursor`：当前解析位置，初始为 `start`。
- `jumped`：是否已跟随压缩指针。
- `consumed`：原始位置已占用字节数，初始为 0。
- `expanded_wire_length`：展开长度，初始为 1，为最终根字节预留预算。
- `visited`：已访问的结构起点，只随实际访问增长，不按报文大小预分配。

### 循环顺序

1. 若 `cursor >= packet.size()`，返回 `NameOutOfBounds`。
2. 在读取字节和进入任何分支前检查并记录 `cursor`；重复访问返回 `CompressionLoop`。
3. 指针：确认剩余至少两字节；计算 `target = ((first & 0x3f) << 8) | second`；依次检查目标在报文内且小于当前指针位置。第一次跳转前将 2 加到 `consumed`，设置 `jumped` 后跳到目标。
4. 保留编码：返回 `ReservedLabelEncoding`。
5. 零字节：未跳转时将 1 加到 `consumed`，返回名称。
6. 普通标签：先检查标签字节完整，再检查 `1 + length` 不超过剩余展开预算。复制原始字节并推进位置；仅在尚未跳转时增加 `consumed`。

指针处理使用迭代循环，不使用递归，也不设置任意的小跳转次数上限。严格向后指针仍可能与普通标签形成循环，例如 `01 61 C0 00`，因此不能省略 `visited`。

名称起点可以大于 `0x3fff`，只有指针目标受 14 位限制。`consumed` 与展开长度必须独立：一个两字节指针可以引用完整的 255 字节名称；254 字节普通标签编码（含各标签长度字节）加两字节根指针也可以消耗 256 字节而展开为合法的 255 字节名称。

## 完整消息模型

| 类型 | 内容 |
| --- | --- |
| `DnsHeader` | 事务 ID 与原始 flags；提供 QR、OPCODE、AA、TC、RD、RA、AD、CD 和低 4 位 RCODE 的读取接口 |
| `DnsQuestion` | 名称、原始 16 位类型和 class |
| `ResourceRecord` | owner、原始类型、class、32 位 TTL 和 RDATA |
| `DnsMessage` | Header 及 Question、Answer、Authority、Additional 四个独立集合 |

`RData` 是以下结构的 `std::variant`，未知类型、class 和 flags 位原样保留：

| 结构 | 数据 |
| --- | --- |
| `AData`、`AaaaData` | `address` 保存 4 字节或 16 字节地址 |
| `NameData` | `name` 保存 NS、CNAME、PTR 的目标名称 |
| `MxData` | `preference` 和 `exchange` 保存优先级与交换机名称 |
| `TxtData` | `strings` 保存各段原始字节，不合并、不假设 UTF-8 |
| `SoaData` | `mname`、`rname` 及 `serial`、`refresh`、`retry`、`expire`、`minimum` |
| `OpaqueData` | `bytes` 保存未知类型及非 IN 的 A/AAAA 原始数据；已知类型的畸形数据报错，不转为不透明数据 |

`DnsMessage` 的集合成员为 `questions`、`answers`、`authority`、`additional`，不把附加记录混入应答；问题的 class 字段为 `qclass`，记录的 class 字段为 `rr_class`。

`DnsHeader` 保存 `id`、`flags`，通过 `is_response()`、`opcode()`、`authoritative_answer()`、`truncated()`、`recursion_desired()`、`recursion_available()`、`authenticated_data()`、`checking_disabled()` 和 `rcode()` 读取标志；访问器不修改原始值。

报文接口：

```cpp
std::expected<DnsMessage, DnsParseError>
parse_message(std::span<const std::byte> packet);

std::expected<Packet, DnsEncodeError>
encode_query(const DnsQuestion& question, std::uint16_t transaction_id,
             bool recursion_desired = true);
```

### 消息解析

1. 固定 Header 为 12 字节；更短报 `PacketTooShort`，整包超过 65535 字节报 `PacketTooLarge`。
2. 按 QDCOUNT、ANCOUNT、NSCOUNT、ARCOUNT 顺序读取各集合；不能根据不可信 count 提前大量 `reserve`。
3. 每个字段、名称、记录固定部分和 RDATA 均先检查剩余长度。声明的项目必须全部解析完成；需要开始下一条目但已到包尾时返回 `SectionCountMismatch`，条目已开始但不完整时保留具体的名称或字段错误。
4. 成功后集合长度表达实际数量，无需重复存储 Header 计数。
5. 所有集合处理完成后仍有剩余字节，返回 `TrailingData`。

解析器只保证结构完整，不限制 QR、事务 ID、OPCODE 或问题数量，也不执行请求匹配。

### 资源记录

依次读取 owner 名称、TYPE（2 字节）、CLASS（2 字节）、TTL（4 字节）、RDLENGTH（2 字节），再处理恰好 RDLENGTH 字节的数据。计算结束偏移之前确认声明长度不超过剩余字节。

| 类型与 class | 解析规则 |
| --- | --- |
| A（1），IN（1） | RDLENGTH 必须为 4，否则 `InvalidRdataLength` |
| AAAA（28），IN（1） | RDLENGTH 必须为 16，否则 `InvalidRdataLength` |
| NS（2）、CNAME（5）、PTR（12），任意 class | 在整个报文中解码一个名称，原路径消费长度必须等于 RDLENGTH |
| MX（15），任意 class | 读取大端 16 位优先级，再解码一个交换机名称，必须恰好消费 RDATA；根名称是合法目标 |
| TXT（16），任意 class | 至少一个长度前缀字符串，每段由一字节长度和对应字节组成；空段合法，零 RDLENGTH 或段长度越界非法 |
| SOA（6），任意 class | 依次解码两个名称，再读取五个大端 32 位无符号整数，必须恰好消费 RDATA |
| 其他类型，或不支持的 A/AAAA class | 保存不透明原始字节，不猜测结构 |

名称和字段布局遵循 [RFC 1035 第 3.3 节](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3)。压缩名称的目标始终以整个报文为基准，不能以 RDATA 子视图为基准；原路径消费不得超过所属 RDATA。RDLENGTH 计算压缩后的实际字节数，而非展开后的名称长度。TXT 保留大小写、空段、分段边界与非文本字节，终端转义规则见 [CLI](cli.md#输出与退出码)。

### 查询编码

`encode_query` 仅编码一个 `IN` class 的问题，允许 A、AAAA、CNAME、MX、TXT、NS、SOA、PTR。支持表由 `record_types.hpp` 统一维护，命令行与编码器共用；不接受其他类型或查询类别。事务 ID 由调用方提供；查询编码器不负责随机数。

Header 的 QR、OPCODE、AA、TC、RA、RCODE 及其他扩展位均为 0；RD 按参数设置。QDCOUNT 为 1，其余计数为 0。QNAME 不压缩，后接大端 QTYPE 和 QCLASS；不附加 EDNS 记录。

编码前依次校验名称不变量、查询类型和 class；同一输入有多个错误时按此顺序返回首个错误，不通过截断或默认替换接受无效输入。名称处理沿用 `encode_name` 的原始标签规则，不在此重复用户输入字符校验。

## 错误约定

输入错误的类型和位置由 [validation.md](validation.md#名称错误) 定义。

名称编码错误包含 `code` 和 `label_index`：`EmptyLabel`、`LabelTooLong`、`NameTooLong` 指向首个错误标签或使总长度超限的标签。

查询编码的 `UnsupportedQueryType` 和 `UnsupportedQueryClass` 分别表示查询类型不在支持表内或 class 不是 IN；这两种错误的 `label_index` 固定为 0，不表示名称出错。

解析错误包含稳定 `code` 和相对于整个报文的字节 `offset`，不携带动态说明文本。

| 错误 | 位置 |
| --- | --- |
| `PacketTooShort` | 输入大小，即缺失的首字节位置 |
| `PacketTooLarge` | 65535，即超出报文大小上限的首字节位置 |
| `SectionCountMismatch` | 需要开始下一条目但已经到达的包尾 |
| `FieldOutOfBounds` | 请求的整数读取偏移；RDATA 越界时为 RDATA 起点 |
| `NameOutOfBounds` | 缺失结构字节的位置，或数据截断标签的长度字节 |
| `ReservedLabelEncoding` | 保留编码字节 |
| `CompressionPointerTruncated` | 指针首字节 |
| `CompressionPointerOutOfBounds` | 目标越界的指针首字节 |
| `CompressionPointerNotBackward` | 非向后引用的指针首字节 |
| `CompressionLoop` | 重复访问的位置 |
| `ExpandedNameTooLong` | 使展开长度超限的标签起点 |
| `InvalidRdataLength` | 固定字段缺失、地址长度错误或 TXT 无任何字符串时的 RDLENGTH 字段起点 |
| `RdataLengthMismatch` | 名称或 TXT 段越过自身 RDATA、结构化数据未恰好消费字段时的 RDATA 起点 |
| `TrailingData` | 完成所有集合后第一个多余字节的位置 |

记录先验证 RDATA 是否完整位于报文内，再验证具体类型的长度。名称解码失败时保留名称错误；解码成功但占用长度不符时返回 `RdataLengthMismatch`。网络错误与 DNS RCODE 使用独立模型。

## 验证要求

名称测试覆盖黄金字节、根名称、63/64 与 255/256 边界、每处截断、非零和极大偏移、原始字节保留、安全显示及大小写比较。压缩测试覆盖独立指针、标签加指针、多级引用、向后循环、最大目标、长合法链、实际消耗长度和展开长度。

消息测试覆盖各支持类型的查询黄金样本、RD 开关、结构化 RDATA、TXT 分段、压缩名称、未知类型和 class、各集合数量不符、错误 RDLENGTH、尾随字节以及 flags 保留。

测试使用内存数据，不依赖公共 DNS；单元测试设置运行上限以暴露死循环。运行方式见[构建与测试](build.md)。
