# DNSLab v0.1 — DNS Wire Codec 详细设计

- 状态：普通名称处理已实现；压缩解码与完整消息处理待实现
- 语言：C++23
- 范围：DNS wire message 的构造、结构解析与名称压缩处理
- 不包含：Socket、重试策略、终端输出、JSON 序列化、DoH/DoT、DNSSEC 验证

## 1. 设计目标

DNS Wire Codec 是纯数据处理模块：输入查询参数或报文字节，输出报文字节或类型化 DNS 消息。不得创建 Socket、读取系统 DNS 配置、打印日志或修改全局状态。

首版必须做到：

1. 生成无压缩的标准 DNS 查询，QCLASS 为 IN，支持 A / AAAA。
2. 解析标准 DNS 消息的 Header、Question、Answer、Authority、Additional。
3. 解码名称压缩；处理压缩指针、越界、截断、循环及扩展名称长度限制。
4. 对 IN 类 A/AAAA 和 CNAME 提供类型化 RDATA；未知类型保留为不透明字节。
5. 所有边界检查使用长度与偏移，不进行未对齐指针转换，不读取越界数据。
6. 通过 `std::expected` 返回可诊断错误，不以异常或日志作为常规控制流。

## 2. RFC 基础与约束

- DNS Message Header、Question、RR、RDATA 与名称压缩按 RFC 1035 实现。
- DNS 标签最长 63 octets，解压后的完整 wire-format 名称最长 255 octets。
- 压缩指针是两字节字段，偏移相对于 DNS message 开始处；本实现要求指针目标位于当前指针之前，并检测解析路径循环。
- RR 的 RDLENGTH 是 wire-format RDATA 的字节数；含压缩名称的 RDATA 应以压缩后的实际字节数计算。
- AAAA 是类型码 28，IN 类 AAAA RDATA 必须为 16 字节。

参考：RFC 1035 §§3.2、3.3、4.1；RFC 3596 §2.1–2.3。

## 3. 模块边界与公开接口

建议文件：

```text
src/dns/
  types.hpp       # Name、Header、Question、RR、RDATA、错误类型
  name_codec.hpp  # 名称输入编码、wire 名称解码与格式化接口
  name_codec.cpp
  wire_codec.hpp  # encode_query、parse_message
  wire_codec.cpp
```

内部头文件只供 DNSLab 自身使用，v0.1 不承诺稳定的公共库 ABI/API。

建议接口：

```cpp
using Packet = std::vector<std::byte>;

[[nodiscard]] std::expected<DnsName, NameInputError>
parse_ascii_name(std::string_view input);

[[nodiscard]] std::expected<EncodedName, DnsEncodeError>
encode_name(const DnsName& name);

[[nodiscard]] std::expected<DnsMessage, DnsParseError>
parse_message(std::span<const std::byte> packet);

[[nodiscard]] std::expected<Packet, DnsEncodeError>
encode_query(const DnsQuestion& question, std::uint16_t transaction_id,
             bool recursion_desired = true);

[[nodiscard]] std::string format_name(const DnsName& name);
[[nodiscard]] bool names_equal_case_insensitive(const DnsName& a,
                                                const DnsName& b) noexcept;
```

`EncodedName` 至少包含编码字节；`encode_name` 负责校验不变量。`encode_query` 的调用方提供事务 ID；随机 ID 的生成由 Application 层负责。

所有读取函数接收 `std::span<const std::byte>`；只在需要拥有 RDATA / Packet 的情况下复制数据。

## 4. 数据模型

```cpp
struct DnsName {
    // root name 用空 labels 表示；每个 label 保存原始 octets，允许非文本字节。
    std::vector<std::string> labels;
};

struct DnsHeader {
    std::uint16_t id{};
    std::uint16_t flags{}; // 保留原始 flags word，避免丢失未知/扩展位

    [[nodiscard]] bool is_response() const noexcept;
    [[nodiscard]] std::uint8_t opcode() const noexcept;
    [[nodiscard]] bool authoritative() const noexcept;
    [[nodiscard]] bool truncated() const noexcept;
    [[nodiscard]] bool recursion_desired() const noexcept;
    [[nodiscard]] bool recursion_available() const noexcept;
    [[nodiscard]] bool authenticated_data() const noexcept;
    [[nodiscard]] bool checking_disabled() const noexcept;
    [[nodiscard]] std::uint8_t rcode() const noexcept;
};

struct DnsQuestion {
    DnsName name;
    std::uint16_t type{};
    std::uint16_t qclass{};
};

struct AData    { std::array<std::byte, 4>  address; };
struct AaaaData { std::array<std::byte, 16> address; };
struct NameData { DnsName name; }; // v0.1 用于 CNAME RDATA
struct OpaqueData { std::vector<std::byte> bytes; };
using RData = std::variant<AData, AaaaData, NameData, OpaqueData>;

struct ResourceRecord {
    DnsName owner;
    std::uint16_t type{};
    std::uint16_t rr_class{};
    std::uint32_t ttl{};
    RData rdata;
};

struct DnsMessage {
    DnsHeader header;
    std::vector<DnsQuestion> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authority;
    std::vector<ResourceRecord> additional;
};
```

备注：

- `DnsName::labels` 存储原始字节，不假设所有服务器返回的标签都是 UTF-8。
- `type`、`qclass`、`rr_class` 保留原始 16-bit 值，以便未来支持未知类型和 class。
- `rcode()` 返回 Header 中的低 4 bit。v0.1 不实现 EDNS 扩展 RCODE 的合成。
- Header 的四个计数字段在解析时作为循环次数使用；成功解析后由各 vector 的长度表达。解析器必须确认每个 section 都完整解析。
- A/AAAA 只有在 RR class 为 IN 时进行对应格式解码；未知 class 的数据作为 `OpaqueData` 保存。CNAME 按域名 RDATA 解析。

## 5. Header 与整数读取

DNS 固定 Header 长度为 12 字节。所有多字节整数均以 network byte order（big-endian）读取/写入。

禁止：

- `reinterpret_cast<const std::uint16_t*>(packet.data() + offset)` 等潜在未对齐读取。
- 直接把 packet 字节强转成 packed C++ struct。
- 在加偏移前不检查剩余长度。

建议实现只依赖显式位操作的小型 helper：`read_u16_be`、`read_u32_be`、`append_u16_be`、`append_u32_be`。所有读取通过统一的 checked cursor 或等价的 `remaining()` 检查。

`parse_message` 的基础规则：

1. 小于 12 字节：`PacketTooShort`。
2. 大于 65535 字节：`PacketTooLarge`。
3. 按 Header 中的 QDCOUNT / ANCOUNT / NSCOUNT / ARCOUNT 读取相应项目。
4. 任何字段、名称、RR 固定部分或 RDATA 越过 packet 边界：返回错误。
5. 所有 section 解析完成后若仍有未消费字节：返回 `TrailingData`（v0.1 严格模式）。
6. 不根据不可信的 count 提前 `reserve(count)` 大量内存；依解析进度逐条构造。

`parse_message` 只负责结构完整性，不负责判断该消息是否匹配当前请求。QR、事务 ID、opcode、Question 匹配和 UDP 源端点校验由 Application / Network 边界完成。

## 6. DNS Name 表示与用户输入

### 6.1 Name 模型

- Root name：`labels.empty()`，wire 编码为单个 `0x00`。
- 非 root：每个 label 长度为 1–63 字节；wire 编码为 `length + label bytes`，末尾加 `0x00`。
- 解压后的 wire 长度（所有长度字节、标签字节、终止 root 字节）不得超过 255。
- `format_name` 输出带尾点的绝对名称，例如 `www.example.com.`。
- 输出中的控制字节、非 ASCII 字节、点和反斜线必须转义，避免终端控制注入及标签边界歧义。可采用 DNS presentation 风格的 `\DDD` 转义；label 内的点和反斜线也必须转义。

### 6.2 CLI 输入策略（v0.1）

为避免首版实现完整 master-file escape 与 IDN 处理，CLI 只接受 ASCII、以点分隔的常规 hostname 样式输入；允许可选尾点。每个 label 长度为 1–63，拒绝空中间 label，名称 wire 长度不得超过 255。IDN/IDNA 与 `\DDD` 输入转义延后。

输入策略具体为：空字符串报错，单独的 `.` 表示 root；标签仅接受 ASCII 字母、数字和内部连字符，标签首尾必须为字母或数字。保留输入大小写，允许已转换的 Punycode；拒绝下划线、空白、控制字节、非 ASCII 字节和反斜线转义。末尾最多一个根点，不能用连续点表示空标签。

该输入限制只属于 `parse_ascii_name`，不能套用到网络响应解码器；wire decoder 必须保留合法 label 中任意 octet 的能力。

比较域名时仅将 ASCII `A`–`Z` 折叠成 `a`–`z`，其他 octet 精确比较。输出时保留响应原始大小写。

格式化时，`0x21`–`0x7e` 中除点和反斜线之外的字节原样输出；其余字节统一使用反斜线加三位十进制数字转义，包括空格。格式化结果用于安全展示，不承诺能由受限的 CLI 输入解析函数重新读取。

### 6.3 名称错误位置

- `NameInputError` 保存 `code` 和原始输入中的字节 `offset`。空输入位置为 0；空标签、标签过长或总长度超限指向相应标签起点；非法字符与首尾连字符指向具体字节。
- `DnsEncodeError` 保存 `code` 和 `label_index`，标识首个不合法或使完整名称超长的标签；编码器始终自行校验标签长度和总长度。
- `DnsParseError` 的 `offset` 相对于整个输入报文。非法起点和缺少终止字节指向当前读取位置；截断标签、保留编码和展开名称超限指向相应长度字节。

## 7. 名称压缩解码算法

接口返回解码后的 `DnsName`，以及原始串行位置消耗的字节数：

```cpp
struct DecodedName {
    DnsName name;
    std::size_t consumed; // 仅计 start 位置上原始编码消耗的字节
};

std::expected<DecodedName, DnsParseError>
decode_name(std::span<const std::byte> packet, std::size_t start);
```

`consumed` 与解压后名称长度不是同一个值。例如 RDATA 里只有一个两字节压缩指针，`consumed == 2`，但解压后的名称可能有几十字节。

### 7.1 算法要求

维护：

- `cursor`：当前在 packet 中解码的位置。
- `jumped`：是否已跟随过压缩指针。
- `consumed`：只统计原始 `start` 位置的编码字节；第一次遇到指针时计入 2 字节，跳转后的字节不计入。
- `visited`：标记已访问过的 label/pointer 起始 offset，用于检测解码循环。
- `expanded_wire_length`：按解压后 wire 格式长度计数，初始至少包含 root 终止字节的 1 字节预算。

循环处理当前 octet：

1. `cursor >= packet.size()`：`NameOutOfBounds`。
2. 若最高两位是 `11`，这是 compression pointer：确认有第二字节；计算 `target = ((first & 0x3f) << 8) | second`；确认 target 在 packet 内且 `target < pointer_offset`；首次遇到指针时将 2 加到 `consumed`；设置 `jumped` 并跳到 target。
3. 若最高两位为 `01` 或 `10`：`ReservedLabelEncoding`。
4. 若 octet 为 0：若尚未 jump，`consumed += 1`；完成。
5. 否则 octet 是 1–63 的普通 label 长度；确保标签范围完整在 packet 内；增加 `1 + length` 到 expanded wire 长度且不超过 255；复制 label bytes；若尚未 jump，增加 `1 + length` 到 `consumed`；继续到下一个 label。
6. 若当前 offset 已访问过：`CompressionLoop`。

严格向后指针约束符合 RFC 1035 所描述的 prior occurrence 压缩格式，并限制恶意 forward reference。额外的 visited 检查仍然需要，因为即使每个指针在物理 offset 上都向后，标签数据也可能让解码路径最终回到先前访问过的 pointer。

### 7.2 重要不变量

- 名称解码的所有地址始终以整个 DNS packet 为基准，不能以 RDATA 子 span 为压缩指针基准。
- 名称扩展长度与原始消耗长度分开记录。
- 不允许 `cursor + length` 在无检查时发生越界或整数溢出。推荐先检查 `length <= packet.size() - cursor`。
- Decoder 不做网络 I/O、不输出日志、不修改 packet。

## 8. Resource Record 与 RDATA 解析

每条 RR 依次解析：

1. `owner` 名称（可能压缩）。
2. TYPE：2 字节。
3. CLASS：2 字节。
4. TTL：4 字节。
5. RDLENGTH：2 字节。
6. 恰好 RDLENGTH 字节的 RDATA。

计算 `rdata_end` 前必须验证 `rdlength <= packet.size() - rdata_start`。

### 8.1 类型化 RDATA 规则

- `TYPE=A (1), CLASS=IN (1)`：RDLENGTH 必须等于 4，保存 4 字节地址，否则 `InvalidRdataLength`。
- `TYPE=AAAA (28), CLASS=IN (1)`：RDLENGTH 必须等于 16，保存 16 字节地址，否则 `InvalidRdataLength`。
- `TYPE=CNAME (5)`：从整个 packet 的 `rdata_start` 位置调用 `decode_name`；解码后的 `consumed` 必须严格等于 RDLENGTH，否则 `RdataLengthMismatch`。
- 其他类型 / 不支持的 class：原样保存 `OpaqueData`，不尝试猜测 RDATA 里的结构。

此设计允许解析器识别常用地址记录及 CNAME 链中的名称，同时保留未知类型以避免协议扩展导致数据丢失。

## 9. 查询编码

`encode_query(question, id, recursion_desired)` 输出：

- ID = 调用方提供的 transaction ID。
- QR = 0，OPCODE = 0，AA = 0，TC = 0，RD 按参数，RA = 0，保留/扩展 flags 位为 0，RCODE = 0。
- QDCOUNT = 1；ANCOUNT / NSCOUNT / ARCOUNT = 0。
- QNAME 使用无压缩编码。
- QTYPE 为 A(1) 或 AAAA(28)；QCLASS 为 IN(1)。
- v0.1 不附加 EDNS OPT record；EDNS 与 extended RCODE 延后。

使用无压缩 QNAME 是合法且易于验证的首版选择；接收侧必须支持压缩名称。

## 10. 错误模型

建议 `DnsParseError` 至少包括：

```cpp
enum class DnsParseErrorCode {
    PacketTooShort,
    PacketTooLarge,
    FieldOutOfBounds,
    NameOutOfBounds,
    ReservedLabelEncoding,
    CompressionPointerTruncated,
    CompressionPointerOutOfBounds,
    CompressionPointerNotBackward,
    CompressionLoop,
    ExpandedNameTooLong,
    InvalidRdataLength,
    RdataLengthMismatch,
    SectionCountMismatch,
    TrailingData,
};

struct DnsParseError {
    DnsParseErrorCode code;
    std::size_t offset;
};
```

如有必要，可以在后续增加 section/index 元数据；第一版不要在每个 error 对象中构造动态字符串。由边界层把 enum + offset 转换为用户可读信息。网络错误需使用独立 `NetworkError`，不能和 DNS `RCODE` 混为一谈。

## 11. 响应匹配不属于 Wire Codec

`parse_message` 成功仅表示报文在结构上可解析，不等于它是当前查询的有效响应。Application 收到报文后还必须检查：

1. UDP 报文源 IP/端口与目标服务器匹配（由 Network 层提供可信的来源信息）。
2. `QR=1`。
3. Transaction ID 与发出的查询一致。
4. OPCODE 与查询一致（v0.1 为标准查询 0）。
5. Question 数量为 1，QNAME 大小写不敏感匹配，QTYPE 与 QCLASS 匹配。
6. 仅在完整且匹配的 UDP 响应 `TC=1` 时触发 TCP 回退。

`NXDOMAIN`、`SERVFAIL`、`REFUSED` 等是有效的 DNS 响应状态，不是网络传输错误。

## 12. 单元测试矩阵

### Query Encoder

- 固定黄金样本：`example.com. A IN`，固定 ID `0x1234`，逐字节断言 Header/QNAME/QTYPE/QCLASS。
- A 与 AAAA 的 QTYPE 字节序正确。
- RD 开关正确，所有 count 正确。
- 可选尾点与无尾点产生相同 wire QNAME。
- 空标签、标签超过 63 字节、总 wire 名称超过 255 字节被拒绝。

### Name Decoder

- 普通多标签名称、root name。
- 压缩指针独立名称与“前缀 label + 指针”名称。
- 正确的 `consumed`：压缩名称的消耗长度不等于展开长度。
- 指针缺第二字节、目标越界、forward pointer、pointer loop。
- 保留 label 类型 `01` / `10`。
- label 数据截断、展开名称超过 255 字节。
- label 含 NUL、非 ASCII 与控制字节时安全保存并转义输出。
- 大小写不敏感比较只折叠 ASCII 字母。

### Message / RR Parser

- 完整 Header + Question + A Answer。
- AAAA Answer（16 字节）与错误长度。
- CNAME RDATA 使用压缩指针且 RDLENGTH 只计算压缩后的字节数。
- CNAME RDATA consumed 与 RDLENGTH 不一致。
- 未知 TYPE 原样保留 RDATA。
- QD/AN/NS/AR count 比 packet 内容大、RR 固定字段截断、RDATA 越界、尾随字节。
- flags 中未实现的位不被无声清零。

### 工程质量

- 所有 unit tests 不访问公网。
- 为 parser 增加可选 libFuzzer fuzz target（如果工具链支持）。
- Debug CI 建议启用编译器警告；Linux 可使用 AddressSanitizer / UndefinedBehaviorSanitizer 跑测试。
- 网络集成测试另用本地 fake DNS server，不把公网 DNS 当作单元测试依赖。

## 13. v0.1 明确不做

- EDNS(0) OPT 的语义解析与 extended RCODE 合成。
- DNSSEC 验证；AD/CD 位只保留/展示，不据此宣称本地验证成功。
- IDNA / Unicode 域名转码与 master-file `\\DDD` 输入语法。
- 对 MX、NS、SOA、TXT、SRV 等 RDATA 的类型化解码；这些先作为 opaque bytes 保存。
- DNS 缓存、递归解析、DoH、DoT、并发多服务器比较。
