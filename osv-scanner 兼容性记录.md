# MurphySec 与 osv-scanner 兼容性记录

验证内容：MurphySec 生成 SPDX 2.3，osv-scanner 读取 SBOM 并保留包 PURL。集成测试见 `cmd/murphy/internal/scan/osv_scanner_compatibility_test.go`。

## 已覆盖并通过

| 输入 / 布局 | 预期 PURL | 验证 |
|---|---|---|
| Go `go.mod` + `go.sum` | `pkg:golang/github.com/go-chi/chi/v5@v5.0.12` | osv-scanner 保留 |
| npm v3 lockfile | `pkg:npm/lodash@4.17.21` | osv-scanner 保留 |
| npm scoped package | `pkg:npm/%40scope/pkg@1.2.3` | osv-scanner 保留 |
| npm workspaces monorepo | `pkg:npm/lodash@4.17.21` | osv-scanner 保留；根目录和 workspace 成员依赖均纳入 SBOM |
| pnpm v6 | `pkg:npm/lodash@4.17.21` | osv-scanner 保留 |
| Yarn v1 | `pkg:npm/lodash@4.17.21` | osv-scanner 保留 |
| Gradle Groovy | `pkg:maven/com.google.guava/guava@32.1.3-jre` | osv-scanner 保留 |
| NuGet `packages.config` | `pkg:nuget/Newtonsoft.Json@13.0.1` | osv-scanner 保留；另有解析器单测 |
| Ruby / Bundler `Gemfile.lock` | `pkg:gem/rack@2.2.8` | osv-scanner 保留 |
| Python requirements | `pkg:pypi/requests@2.31.0` | osv-scanner 保留 |
| Rust Cargo | `pkg:cargo/serde@1.0.193` | osv-scanner 保留 |
| PHP Composer | `pkg:composer/monolog/monolog@2.9.1` | osv-scanner 保留 |

固定 OSV fixture 使用离线数据库：`lodash@1.0.0` 必须命中 `MAL-TEST-2026-0001`；`lodash@2.0.0` 必须未命中。这样漏洞匹配断言不受线上 OSV 数据变化影响。线上用例只验证 PURL 和扫描器输出结构，漏洞 ID 仅记录日志。

仅有 `package-lock.json`、没有 `package.json` 的输入现已支持，见下方本轮验证记录。

## 运行

在 MurphySec 仓库根目录设置 osv-scanner 可执行文件后运行：

```powershell
$env:OSV_SCANNER = "..\osv-scanner\osv-scanner.exe"
go test ./cmd/murphy/internal/scan -run TestOSVScannerSBOMCompatibility -count=1 -v
```

## package-lock 独立输入修复与在线验证（2026-10-26）

沿用现有扫描入口，无需新增命令行参数。没有 package.json 时，从 package-lock.json 读取项目身份和锁定依赖；支持 lockfileVersion 1、2、3。v2/v3 使用 packages 条目解析实际安装位置，并纳入 workspace importer 及其依赖；workspace 成员也不要求保留 package.json。

本轮修复：
- 保留每个安装位置的节点身份，避免同名同版本包因来源文件相同而合并，确保不同分支的传递依赖版本都输出。
- workspace 从成员目录逐级查找依赖至根 node_modules，支持提升依赖和 workspace link。
- 共用运行时/开发依赖按锁文件的 dev 标记处理，避免被误判为仅开发依赖。
- 校验版本、根条目、空包记录、包版本、link 目标及必需依赖引用。无效锁文件报告解析失败或扫描不完整；有效空项目仍正常返回。

测试见 package_lock_osv_test.go 及 npm/JavaScript 解析器回归测试。在线测试命令（在各自仓库根目录运行）：

~~~powershell
$env:OSV_SCANNER = 'C:\Users\windows\Desktop\localsca\osv-scanner\osv-scanner.exe'
go test . -run '^TestPackageLockSBOMOSV$' -count=1 -v
~~~

| 场景 | 验证 | 本机结果 |
|---|---|---|
| v1 锁文件单独输入 | SBOM 输出 lodash 4.17.21，OSV 保留对应 PURL | 通过 |
| v2/v3 嵌套依赖，无 package.json | 同名同版本 common 位于不同位置，分别保留 lodash 4.17.20、4.17.21 | 通过 |
| v3 成对输入 | 保留上述两个版本，验证原有输入流程 | 通过 |
| v2/v3 workspace，仅一个锁文件 | 无根/成员清单仍输出成员的 lodash 依赖 | 通过 |
| 开发/运行时共享依赖 | shared 保持运行时属性，dev-tool 保持开发属性 | 解析回归通过 |
| 未知版本、缺失根、null 包、未解析必需依赖、损坏 JSON | CLI 非零退出，SBOM 明确标记依赖数据可能不完整 | 通过 |
| 有效空项目 | 无依赖时正常返回，不误报损坏 | 解析回归通过 |

本轮外部扫描使用在线 OSV 服务，不依赖本机数据库缓存。断言 OSV 保留所有预期 PURL，并确认 lodash 4.17.20 有漏洞记录；不将 4.17.21 的线上漏洞数量写死。原有固定数据库测试仍用于可重复的格式验证。

v1 没有现代 packages 根清单信息，独立输入时会以锁内顶层条目作为扫描起点；包名、版本可以输出，但直接/传递关系不能保证与丢失的原始清单完全一致。

本轮全量默认测试通过：274 项 / 78 个包。新增在线测试的 6 个有效输入场景及 5 个错误输入场景全部通过。
