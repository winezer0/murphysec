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

仅有 `package-lock.json`、没有 `package.json` 的输入仍会报告 inspector 失败并以非零状态退出；该支持问题已按当前范围暂缓。

## 运行

在 MurphySec 仓库根目录设置 osv-scanner 可执行文件后运行：

```powershell
$env:OSV_SCANNER = "..\osv-scanner\osv-scanner.exe"
go test ./cmd/murphy/internal/scan -run TestOSVScannerSBOMCompatibility -count=1 -v
```
