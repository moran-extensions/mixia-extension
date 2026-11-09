# 公开测试备份

这些文件由原秘匣项目未改动的 `BackupService.encrypt` / `VaultFileService.encodePasswordVault` 生成，原生加密 API 使用原项目已有 Node 主机适配器。未读取手机数据，不代表真机导出测试。

- `mixia-pin6.mixia`：3 个虚构 TOTP 账户，密码 `012345`，包括 Unicode、SHA256/8 位、HTML 文本标签及不应导入电脑的备注。
- `mixia-one.mixia`：单个 TOTP 账户，密码 `012345`，验证整体覆盖。
- `mixia-empty.mixia`：空库，密码 `012345`，验证明确清空确认。
- `mixia-hotp.mixia`：HOTP 计次账户，密码 `012345`，验证当前版本拒绝整库导入。
- `mixia-legacy.mixia`：3 个虚构 TOTP 账户，旧版密码 `legacy-test-password`。

测试密钥为公开 RFC 向量或演示密钥，不含真实账户。
