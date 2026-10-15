这些证书和未加密私钥是**公开的测试数据**，不得用于生产服务，也不得导入系统证书库。
测试仅通过客户端的 `--ca-file` 选项信任 `ca.pem`。

`server.pem` 包含 localhost、127.0.0.1 和 ::1；`wrong-host.pem` 故意不包含这些名称。
`expired.pem` 已于 2021 年过期。正常证书的有效期为 2020 年至 2039 年，不依赖生成日期。

证书指向本地吊销列表 `http://127.0.0.1:18453/dnslab-test-root.crl`。
Python 测试在运行期间通过该端口提供 `root.crl`，使 Windows Schannel 在无需外网的情况下
保留正常的吊销检查。该列表也在 2020 年至 2039 年有效。
端口被其他进程占用时，测试会明确失败，不会终止其他进程。
CTest 必须为这些案例设置 `dnslab_test_crl` 资源锁；HTTPS 和 DoT 服务另用临时回环端口。

`generate_certificates.py` 可重新生成全部文件，仅重新生成时需要可选的 Python
cryptography 包。正常测试只需要 Python 标准库。CA 签名私钥只在生成过程中保存在内存，
不会写入文件。测试不会修改系统信任设置。
