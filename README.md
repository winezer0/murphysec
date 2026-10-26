# MurphySec CLI · winezer0 分支

中文 | [English](README_EN.md) | [原项目中文 README](https://github.com/murphysecurity/murphysec/blob/v3/README_ZH.md) | [Original upstream English README](https://github.com/murphysecurity/murphysec/blob/v3/README.md)

本项目基于 [murphysecurity/murphysec](https://github.com/murphysecurity/murphysec)，重点增强本地依赖解析、SPDX 2.3 SBOM 导出及与 osv-scanner 的衔接，保留原有墨菲安全平台扫描入口。

这里的“新版”指 [winezer0/murphysec](https://github.com/winezer0/murphysec) 当前代码，不代表上游官方发布的新版本。下文以本仓库导入原项目的快照 `f1ccb33` 为比较基线，用 **[新增]**、**[修改]**、**[修复]** 标明分支改动；旧版文档仅供查阅原项目用法。

## 文档索引

- [相对原项目的改动](#相对原项目的改动)
- [安装与快速开始](#安装与快速开始)
- [命令与参数](#命令与参数)
- [典型用法](#典型用法)
- [生态与 PURL](#生态与-purl)
- [迁移说明与已知限制](#迁移说明与已知限制)
- [验证与许可证](#验证与许可证)

## 相对原项目的改动

| 类型 | 改动 | 对用户的影响 / 新用法 |
| --- | --- | --- |
| **[新增]** | `dfscan` 支持 `--sbom-format spdx-json`，也接受简写 `spdx` | 可在本地导出带 PURL 的 SPDX 2.3，交给第三方漏洞扫描器；原有 `msdx1.1+json` 格式继续支持 |
| **[修改]** | 原有 `sbom` 命令复用 `dfscan --sbom-format spdx-json` 的处理流程 | 两个入口共享过滤、告警和错误处理；`sbom --out -` 支持标准输出 |
| **[新增]** | `--exclude-dev`、`--direct-only` | 在两种 SBOM 输出格式中按需排除开发依赖、仅保留直接依赖，同时过滤依赖关系 |
| **[修改]** | 扩展多生态 PURL；补充 SPDX 文档元数据、`documentDescribes` 和告警 annotation，稳定关系输出顺序 | 包名不再混入版本；没有 PURL 映射的生态会被明确标记，避免把无法匹配误认为没有漏洞 |
| **[新增]** | `scan` / `dfscan` 支持 `--maven-command` | 可指定 Maven 可执行文件路径；`sbom` 简化入口不提供此参数 |
| **[修复]** | SBOM 路径正确传递 `--no-build`；仅指定 `--sbom-output` 时提前报错 | 跳过受此开关控制的构建；导出时必须明确指定 `--sbom-format`，避免意外进入平台扫描 |
| **[修复]** | inspector 失败不再被忽略，扫描策略按实际值序列化 | 本地扫描失败时输出 stderr 提示、非零退出码，并尽可能保留带告警的部分 SBOM；降级原因也写入输出 |
| **[修复]** | Maven 按 type/classifier 区分依赖，修正 scope 遍历、默认本地仓库与父 POM `relativePath` 解析 | 减少依赖合并错误、库的开发依赖误报和 runtime 传递依赖漏报；未配置 `localRepository` 时使用默认 `~/.m2/repository` |
| **[新增]** | Maven 静态解析支持项目内激活的 profile | 合并 profile 的 properties、dependencyManagement 和 dependencies；支持显式 `-P`、默认、JDK、OS、属性及文件激活条件，无法判定时记告警 |
| **[修复]** | Go 应用 `replace`，优先读取 `vendor/modules.txt`，补充主模块根节点及直接依赖边 | 报告替换后的模块身份/版本；vendor 项目使用 vendored 模块清单；不再生成完全无关系的 Go SBOM |
| **[修复]** | npm 支持独立 `package-lock.json` v1/v2/v3；修正 workspace、嵌套安装位置和开发依赖处理 | 缺少根/成员 `package.json` 时仍可扫描锁文件；保留不同分支的传递版本；损坏或缺少必需引用的锁文件明确报错 |
| **[修复]** | R / renv 的 ecosystem 从误标的 `spm` 改为 `cran` | R 包使用 `pkg:cran/...`，避免按 Swift 包识别 |
| **[修改]** | 调整本分支构建发布流程，移除继承的部分工作流与 issue 模板 | 发布流程面向 Linux / macOS / Windows 的 amd64、arm64 构建，并生成 `SHA256SUMS`；是否已有对应发布请查看本分支 Releases |

实现可查阅 [CLI](cmd/murphy/internal/scan/)、[SPDX 格式化器](inspector/textual_formatter.go)、[Maven](module/maven/)、[Go](module/go_mod/)、[npm](module/npm/) 和 [发布流程](.github/workflows/build.yml)。

## 安装与快速开始

### 安装本分支

从 [winezer0/murphysec Releases](https://github.com/winezer0/murphysec/releases) 选择本分支发布的对应平台产物；若没有所需发布，或要使用当前源码中的改动，请从源码构建。旧 README 中的上游安装脚本和上游 Releases 不保证包含本分支改动。

源码构建需要 Git 和 **Go 1.24.0 或更高版本**（以 [go.mod](go.mod) 为准）。

Linux / macOS：

```bash
git clone https://github.com/winezer0/murphysec.git
cd murphysec
go build -o murphysec .
./murphysec --version
./murphysec --help
```

Windows PowerShell：

```powershell
git clone https://github.com/winezer0/murphysec.git
Set-Location murphysec
go build -o murphysec.exe .
.\murphysec.exe --version
.\murphysec.exe --help
```

下文假设 `murphysec` 已加入 `PATH`；否则使用 `./murphysec` 或 `.\murphysec.exe`。构建扫描按生态需要 Maven/JDK、Go、npm 等工具；静态解析也需要足够的清单、锁文件或本地依赖缓存。

### 第一次本地导出

```bash
murphysec sbom /path/to/project --no-build --out project.spdx.json
```

此命令无需 Token，不调用墨菲安全平台 API，也不上传项目。它生成依赖清单，**不会自行查询漏洞**。需要漏洞结果时，使用下面的 osv-scanner 示例或平台扫描。

本地导出不调用平台 API，与完全断网是两个条件：默认可能执行包管理器；`--no-build` 跳过受支持的构建路径，但依赖解析仍可能读取缓存或访问包仓库。隔离网络使用前应准备好依赖数据并核对告警。

## 命令与参数

| 命令 | 用途 | 墨菲平台 API / Token |
| --- | --- | --- |
| `sbom <DIR>` | 本地导出 SPDX 2.3；默认写当前工作目录的 `spdx.json` | 不调用 / 不需要 |
| `dfscan <DIR> --sbom-format spdx-json` | 本地导出 SPDX，提供更多 Maven 等参数；默认写 stdout | 不调用 / 不需要 |
| `dfscan <DIR> --sbom-format msdx1.1+json` | 本地导出原有私有格式；默认写 stdout | 不调用 / 不需要 |
| `dfscan <DIR>`（未传 `--sbom-format`） | 基于依赖解析进行平台扫描 | 调用 / 需要 |
| `scan <DIR>` | 原有平台综合扫描入口，可上传项目目录文件 | 调用 / 需要 |

以下是与本地导出相关的常用参数，完整列表以各命令 `--help` 为准。

| 参数 | 适用命令 | 含义 |
| --- | --- | --- |
| `--out <FILE>` | `sbom` | 默认 `spdx.json`；`-` 表示 stdout |
| `--sbom-format <FORMAT>` | `dfscan` | `spdx-json` / `spdx` / `msdx1.1+json`；显式开启本地 SBOM 路径 |
| `--sbom-output <FILE>` | `dfscan` | 默认 `-`；必须搭配 `--sbom-format` |
| `--no-build` | `sbom` / `dfscan` / `scan` | 跳过受支持的项目构建，完整性取决于现有依赖数据 |
| `--exclude-dev` **[新增]** | `sbom` / `dfscan` 的 SBOM 输出 | 排除被解析器标为非运行时的依赖，如 Maven test/provided/system、npm dev |
| `--direct-only` **[新增]** | `sbom` / `dfscan` 的 SBOM 输出 | 仅保留直接依赖，可与 `--exclude-dev` 组合 |
| `--maven-command <PATH>` **[新增]** | `dfscan` / `scan` | 指定 Maven 可执行文件 |
| `--maven-settings <FILE>` | `dfscan` | 指定 Maven settings 文件 |
| `--maven-arg=<ARG>` / `--maven-prepend-arg=<ARG>` | `dfscan` / `scan` | 追加 / 前置一个 Maven 参数，可重复；以 `-` 开头的值建议使用 `=` 传入 |
| `--no-log-file` / `--log-level debug` | 全局 | 禁止写日志文件 / 输出排查日志 |

输出目录需预先存在；同名输出文件会被覆盖。两个过滤参数控制导出的依赖树，不是文件目录排除规则。

## 典型用法

### 本地 SPDX 与原格式

```bash
# 简化入口，与下一条共享 SPDX 输出流程
murphysec sbom /path/to/project --no-build --out project.spdx.json

# 完整参数入口
murphysec dfscan /path/to/project --no-build --sbom-format spdx-json --sbom-output project.spdx.json

# 原私有格式：modules、scan_warnings_codes 等字段
murphysec dfscan /path/to/project --no-build --sbom-format msdx1.1+json --sbom-output project.msdx.json

# stdout；也可使用 sbom --out -
murphysec dfscan /path/to/project --no-build --sbom-format spdx-json --sbom-output -

# 只输出运行时直接依赖
murphysec sbom /path/to/project --no-build --exclude-dev --direct-only --out runtime-direct.spdx.json
```

### Maven 专用参数与 profile

```bash
# 构建法：自定义 Maven 路径和 settings，可能下载插件/依赖
murphysec dfscan /path/to/java-project --sbom-format spdx-json --sbom-output java.spdx.json --maven-command /opt/apache-maven/bin/mvn --maven-settings /path/to/settings.xml

# [新增] 静态法：显式选择 prod profile，并提供属性
murphysec dfscan /path/to/java-project --no-build --sbom-format spdx-json --sbom-output java-prod.spdx.json --maven-arg=-Pprod --maven-arg=-Denv=prod
```

上述 Maven 专用参数应使用 `dfscan`；`sbom` 只提供简化的导出参数。**[新增]** 静态法会合并已激活项目 profile 的依赖、依赖管理及属性；无法解析的激活条件会产生告警。构建法的 profile 行为限制见下文。

### npm 独立锁文件、Go vendor

**[修复]** 扫描入口仍接收目录。npm 目录中可以只有 `package-lock.json`，不必补造 `package.json`。

```bash
murphysec sbom /path/to/lockfile-directory --no-build --out npm.spdx.json
murphysec sbom /path/to/vendored-go-project --no-build --out go.spdx.json
```

npm 支持 lockfileVersion 1/2/3；v2/v3 保留 workspace、安装位置和嵌套依赖信息。Go 在存在可读取的 `vendor/modules.txt` 时优先使用其中的模块清单，并结合 `go.mod` 判断直接/间接依赖。

### 衔接 osv-scanner

MurphySec 负责依赖解析与 SBOM 导出，osv-scanner 负责漏洞匹配。安装 OSV-Scanner v2 后，可使用以下流程；文件名保留 `.spdx.json`，便于其识别为 SPDX。参见 [OSV 官方 SBOM 用法](https://google.github.io/osv-scanner/usage/scan-source)。

```bash
murphysec sbom /path/to/project --no-build --out project.spdx.json
osv-scanner scan source --lockfile project.spdx.json --format json --output-file osv-results.json
```

第二步默认查询在线漏洞服务。若需离线匹配，先按 [OSV 官方离线说明](https://google.github.io/osv-scanner/usage/offline-mode/) 准备数据库，再使用其 `--offline` 模式。PURL 可以生成，不代表目标漏洞库覆盖该生态或该版本。

项目内已有解析兼容性与固定离线漏洞 fixture 测试，覆盖范围见 [兼容性记录](OSV_SCANNER_COMPATIBILITY.md)。这不等于所有输入都能生成完整依赖图。

### 原有平台扫描

```bash
murphysec auth login
murphysec dfscan /path/to/project --json
murphysec scan /path/to/project --json
```

登录使用墨菲安全平台访问令牌，也可用 `--token <TOKEN>` 认证。未指定 SBOM 格式的 `dfscan` 会提交依赖数据并查询平台；`scan` 的标准模式会上传目录文件，`dfscan --deep` 等模式也可能上传文件。请按所需模式选择命令；旧文档关于上传内容的描述不能替代当前命令行为。

## 生态与 PURL

当前解析器包含 Maven、Gradle、Ivy、SBT、npm、Yarn、pnpm、Go、Python / Poetry、NuGet、Composer、Cargo、Bundler、Pub、CocoaPods、Conan、LuaRocks、Perl、rebar3、R / renv 和 ArkTS / ohpm。具体支持范围取决于输入格式及工具环境，不能将“存在解析器”视为所有项目均已验证。

**[修改]** SPDX 导出的 ecosystem → PURL type 映射如下：

| ecosystem | PURL type |
| --- | --- |
| `maven` / `npm` / `pypi` / `nuget` | 同名类型 |
| `go` / `bundler` / `pubspec` / `composer` | `golang` / `gem` / `pub` / `composer` |
| `cargo` / `conan` / `cocoapods` / `luarocks` | 同名类型 |
| `cran` / `hex` / `rebar` / `perl` / `spm` | `cran` / `hex` / `hex` / `cpan` / `swift` |

映射表中的 `spm → swift` 只是输出映射，不代表新增 Swift 项目解析器；R / renv 实际输出已修正为 `cran`。没有映射的生态（如 `ohpm`）仍可保留组件信息，但不编造 PURL，SPDX annotation 会提示匹配缺口。

## 迁移说明与已知限制

| 旧用法 / 场景 | 当前行为与建议 |
| --- | --- |
| `dfscan DIR --sbom-output out.json` | **[修改]** 缺少 `--sbom-format` 会报错；改为 `--sbom-format spdx-json --sbom-output out.spdx.json`，或显式选择原 msdx 格式 |
| `sbom DIR --out out.json` | 命令保留；**[修改]** 复用统一导出流程，可增加过滤参数；交给 OSV 时建议改用 `.spdx.json` 后缀 |
| `sbom --type ...` | 旧命令隐藏的 `--type` 参数已移除；格式固定为 SPDX JSON，无需传入 |
| 用 `--json` 请求本地 SBOM | `--json` 是平台结果展示选项；本地导出使用 `sbom` 或 `dfscan --sbom-format ...` |
| 本地扫描退出非零但仍有 SBOM 文件 | **[修改]** inspector 失败时可能保留部分结果；检查 stderr、SPDX `annotations` 或 msdx `scan_warnings_codes`，勿将文件存在视为成功 |
| 降级扫描退出 0 | 仍可能包含 `mvn_not_found`、`mvn_failed`、`mvn_profile_activation_unknown` 等告警；自动化流程需同时检查输出中的告警 |
| Maven 构建法 profile | 当前仍把收集到的全部 profile ID 传给 Maven `-P`，可能激活本不应生效的 profile；需按激活条件分析时可使用 `--no-build` 静态法，并检查结果 |
| Go 静态 / vendor 图 | 可识别直接/间接类别，但不能还原全部传递边；本地目录 `replace` 保留原 require 身份/版本，不能推断本地改动内容；静态法命中 `exclude` 会告警，不重算 MVS |
| npm v1 仅锁文件输入 | 缺少原清单时，以锁内顶层项为起点，直接/传递关系不能保证完全还原 |
| 开发依赖过滤 | 依赖解析器的标记；未标记的依赖不会自动当作开发依赖，不能据此证明最终部署包组成 |

## 验证与许可证

本分支包含 Maven profile、Go replace/vendor、npm 锁文件/依赖图、SPDX 格式和告警等回归测试。常规测试：

```bash
go test ./...
```

OSV 集成测试需要额外设置 `OSV_SCANNER`；未设置时跳过。运行方法、已验证输入和在线/离线测试区别见 [OSV_SCANNER_COMPATIBILITY.md](OSV_SCANNER_COMPATIBILITY.md)。

遵循 [Apache License 2.0](LICENSE)，保留原项目的版权与许可证声明。贡献说明见 [CONTRIBUTING.md](CONTRIBUTING.md)。
