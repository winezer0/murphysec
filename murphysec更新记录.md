# murphysec 更新记录（相对原版）

> **基线**：`f1ccb33`（import-snapshot，与上游 `v3` 分支代码完全一致）
> **当前**：`main` 分支
> **规模**：26 个 commit，47 个文件，+2589 / −485
> **目的**：让 murphysec 解析出的依赖清单可直接交给 `osv-scanner --offline` 做离线漏洞扫描，
> 不引入任何中间转换程序。
> **记录时间**：2026-10-26

---

## 一、总览

| 类别 | 条数 | 涉及模块 |
|---|---|---|
| Bug 修复 | 16 | maven（4）、golang（3）、npm（2）、renv（1）、SBOM 输出（5）、CLI/模型（1） |
| 新增功能 | 5 | SBOM 输出、purl 生成、输出过滤、CLI 参数 |
| 重构 | 1 | `sbom` 子命令改为 `dfscan` 的薄别名 |
| 测试 / 文档 / 清理 | 4 | OSV 兼容性测试、NuGet 测试、`.github` 清理 |

> 另有一批改动已在工作区实现并验证、尚未提交（Maven profile 支持），见 §七。

修复效果（以 `mvn dependency:tree` 为真值，4 个夹具）：

| 夹具 | 原版 | 现在 |
|---|---|---|
| BOM import + exclusions + optional | 63 报 / **精确率 12.7%** | 8 报 / 100% |
| 三层继承，变量在祖父 | 2 报 / 召回 25% | 8 报 / 100% |
| `runtime` 作用域 | 1 报 / 召回 33.3% | 3 报 / 100% |
| 父 pom 只在本地工作树 | 无法解析 | 1 报 / 100% |
| Go（inott-epg-go） | 71 包 / 34 漏洞（漏 1 条 CVE） | 67 包 / **35 漏洞** |

---

## 二、Bug 修复

### 2.1 Maven 解析

#### M-1 · 依赖去重 key 缺 type/classifier，真实 compile 依赖被标成 test

**原版行为**：去重只按 `groupId:artifactId` 做键。同一个坐标的 `test-jar` 和 `jar` 会被合并成一条，
后遍历到的 test-jar 覆盖了 jar 的 scope，于是 `logback-core`、`log4j-api` 这类真实 compile 依赖
在输出里变成 `test`。下游若按 `scope=compile` 过滤，这两个包直接消失——**精度问题变成了漏报**。

**修复**：去重键带上 `type` 和 `classifier`。

**commit**：`7b561de`

#### M-2 · 库自身的 dev 依赖被当成本项目依赖 + `runtime` 作用域不递归

**原版行为**：两处方向相反的错。

- `BackupResolve` 把每个 pom 都当独立项目全量解析，没有 scope 剪枝。log4j-core 自己声明的
  29 个 test 依赖（junit、mockito、hsqldb、wiremock、activemq…）全部被当成本项目的依赖报出来。
  最小用例（只有 log4j-core 2.14.1，真值 2 包）报了 37 包。
- 剪枝条件写成 `dep.Scope != "compile"`，把 `runtime` 也一起裁掉了，而 runtime 是**需要传递**的，
  导致 runtime 依赖的下游传递依赖全部丢失。

**修复**：dev-only 边不继续下探（`test`/`provided`），`runtime` 保留传递；
判断条件改成显式 scope 列表而不是 `!= "compile"`。

**commit**：`d442674`

#### M-3 · `settings.xml` 没有 `<localRepository>` 时完全忽略 `~/.m2`

**原版行为**：解析 `settings.xml` 时，只有当文件里写了 `<localRepository>` 才设置本地仓库路径。
文件存在但没写这一项时路径保持空字符串——**一个本地 pom 也读不到**，全部依赖去远程拉。
隔离网环境直接失效。

**修复**：解析前先把 `~/.m2/repository` 作为默认值填进去，文件里显式配置时再覆盖。

**commit**：`016da03`

#### M-4 · 父 pom 不走 `relativePath`

**原版行为**：父 pom 只能通过 `MavenRegistryAPI` 从远程仓库拉。工程内 `../parent/pom.xml`
这种本地父子结构（`<relativePath>` 声明）完全不被考虑，私有父 pom 在公网 404 时解析失败。

**修复**：`fetchParent` 优先按 `Parent.RelativePath` 去文件系统找。

**commit**：`fd9a508`

### 2.2 Go 解析

#### G-1 · `go.mod` 的 `replace` 被忽略

**原版行为**：静态解析只读 `file.Require`，报的版本是写在 require 里的那个。
但 `replace` 才决定实际编译的是哪份代码。inott-epg-go 里 `golang.org/x/sys` 写的是 `v0.6.0`，
`replace` 指向 `v0.0.0-20210112080510-...`，报 `v0.6.0` 就漏掉了 `CVE-2022-29526`
（34 条漏洞，实际 35 条）。

**修复**：新增 `replaceTable`，通配（`replace A => B vN`）与精确（`replace A vX => B vY`）
两种写法都支持，精确优先于通配，与 go 命令一致；本地目录替换（`replace A => ./local`）保持原模块身份。
`exclude` 命中记为 scan warning，不删除组件（删了会让它的漏洞一起消失）。

**commit**：`1cfaca5`

#### G-2 · 遍历进 `vendor/`，把依赖自带的清单当独立项目

**原版行为**：目录遍历没有排除 `vendor`。vendor 里是每个依赖的**完整源码副本**，
其中还带着它们自己的 `Gopkg.lock`。`json-iterator/go` 和 `modern-go/reflect2` 各有一个，
于是 `modern-go/concurrent` 出现两次：`v0.0.0-20180306012644`（正确）和 `1.0.0`（dep 时代版本号）。

**修复**：`inspector/auto_scan_ignore` 加入 `vendor`（对所有生态生效，PHP/Rust 的 vendor 同理）；
`vendor/modules.txt` 存在时优先用它建图——它是 go 命令的解析结果，`replace`/MVS/exclude 都已生效。

**commit**：`4f39134`

#### G-3 · SPDX 里 `relationships` 是空数组

**原版行为**：静态解析产出的是平铺列表，`DependencyItem.Dependencies` 永远为空，
而 `DependencyGraph` 只在有子项时才画边。结果 71 个包、0 条关系，
`documentDescribes` 还指向了恰好排在第一个的依赖包。

**修复**：主模块作为根节点，直接依赖挂在它下面 → 30 条 `DEPENDS_ON`。
间接依赖保持平铺（静态解析确实不知道它们的父节点，硬挂到根上是假数据）。

**commit**：`63d3b82`

### 2.3 npm 解析

#### N-1 · monorepo 根目录扫描时，workspace 成员的依赖全部丢失

**原版行为**：只走 lockfile 的根 importer。但 monorepo 把每个 workspace 成员的依赖记在
**各自的 importer 条目**下，于是扫根目录得到的 SBOM 里没有任何成员依赖——看起来干净，实际全漏。

顺带一个相关缺陷：`checkWorkspace` 从被扫描目录自己开始 glob，导致声明了 `"packages/*"`
的 monorepo 根**把自己判成 workspace 成员**，转而跳过根扫描。

**修复**：根 importer 之后遍历所有非 `node_modules` 的 importer（排序保证输出稳定）；
workspace glob 改从父目录开始——只有祖先才能声明某目录是成员。

**commit**：`08b8728`

#### N-2 · 只有 `package-lock.json`、没有 `package.json` 时扫不出依赖

**原版行为**：npm inspector 依赖 `package.json` 判断项目和读取包信息，只有锁文件时直接空结果。
实际场景里（容器镜像、只提交锁文件的仓库）这种情况并不少见。

**修复**：新增独立锁文件的支持路径，从 lockfile 自身推导项目信息与依赖图；
补了锁文件回归测试和在线 OSV 兼容性用例。

**commit**：`8a0bbd6`

### 2.4 生态标识

#### R-1 · R 包被标成 Swift 生态，导致 R 项目永远 0 漏洞

**原版行为**：renv inspector 解析的是 `renv.lock`（CRAN 上的 R 库），生态却声明为 `spm`
（Swift Package Manager）。两个后果：spm 在 purl 表里没有映射 → 不生成 purl →
osv-scanner 打出 `Filtered N local/unscannable` 后以退出码 0 结束；即使有 purl，
也会去查 Swift 的漏洞库。

**修复**：生态改为 `cran`，输出 `pkg:cran/<name>@<version>`。

**commit**：`dcb5938`

### 2.5 SBOM 输出

| # | 原版行为 | 修复 | commit |
|---|---|---|---|
| S-1 | SPDX 包名直接用 `CompName`，Maven 包名成了 `com.fasterxml.jackson.core:jackson-databind` | 包名只取 artifact，group 交给 purl 的 namespace | `ccd53e3` |
| S-2 | SPDX 文档字段不全（缺 `documentNamespace` 等必需项），scan 告警没进文档 | 补齐 SPDX 2.3 必需字段，scan warning 写进 document annotations | `dd4b168` |
| S-3 | 只传 `--sbom-output` 不传 `--sbom-format` 时静默按默认格式输出 | 参数组合非法时立即报错退出 | `2438ac5` |
| S-4 | `--no-build` 在 SBOM 输出路径上不生效，仍然尝试构建 | 尊重 `--no-build`，跳过构建 | `bf4dae7` |
| S-5 | `relationships` 顺序随机（遍历 map），同一项目两次导出会 diff 出噪声 | 按 `(from, to)` 排序，保证输出稳定 | `c35670a` |

### 2.6 模型 / CLI

| # | 原版行为 | 修复 | commit |
|---|---|---|---|
| C-1 | `ScanStrategy.MarshalText` 用值接收者，`backup` 被序列化成 `normal`，无法从结果判断是否降级 | 改用指针接收者 | `337d87a` |
| C-2 | `inspector.ManagedInspect` 的返回值被丢弃，inspector 失败仍产出短 SBOM 且退出码 0 | 失败写 stderr、置退出码 1、记 scan warning（进 SPDX annotation） | `a7063b8` |

---

## 三、新增功能

### 3.1 SBOM 输出（`--sbom-format spdx-json`）

`dfscan` 现在可以直接输出 SPDX 2.3，之前只有私有 msdx 格式（无 purl，无法对接 osv-scanner）。

```bash
murphysec sbom <dir> --out x.spdx.json            # 独立子命令（推荐）
murphysec dfscan <dir> --sbom-format spdx-json --sbom-output x.spdx.json
```

`sbom` 子命令本身不联服务端，可离线使用。

**commit**：`91c0bdc`、`10dd3a8`

### 3.2 多生态 purl 生成

SPDX 的每个 package 带 `externalRefs`（`referenceType: purl`）。**17 个生态映射到 16 种 purl 类型**：

```
maven → maven      npm → npm         pypi → pypi       go → golang
nuget → nuget      composer → composer  cargo → cargo  bundler → gem
pubspec → pub      conan → conan     cocoapods → cocoapods
luarocks → luarocks  cran → cran     hex/rebar → hex   perl → cpan
spm → swift
```

没有对应 purl 类型的生态不硬造 type，而是写一条 document annotation 说明
「这些包无法被消费者识别，其漏洞不会被报告」。

**commit**：`6459a03`、`9962967`、`dcb5938`

### 3.3 输出过滤

| 参数 | 作用 |
|---|---|
| `--exclude-dev` | 从 SBOM 里去掉 dev/test/provided 依赖 |
| `--direct-only` | 只保留直接依赖 |

**commit**：`76ee650`

### 3.4 CLI 参数

| 参数 | 作用 |
|---|---|
| `--maven-command` | 指定 Maven 可执行文件（不在 PATH、或要用特定 JDK 时） |

**commit**：`a7063b8`

### 3.5 扫描可见性

- inspector 失败不再静默：stderr + 退出码 1 + SPDX annotation
- 无 purl 的生态写 annotation 告警
- Maven 回退到静态解析时记 scan warning

**commit**：`a7063b8`、`9962967`、`d442674`

---

## 四、行为变更（可能影响现有用法）

| 变化 | 影响 |
|---|---|
| 输出里的 scope 标注变准了 | 依赖 `scope=test` 过滤的人会发现包数变多（多出来的是之前被误标的真实依赖） |
| 库自身的 dev 依赖不再出现 | 结果是变**少**，但更准确（真值对齐） |
| SBOM 里多了一个根节点包 | 依赖图需要它；纯依赖清单（如 CSV）应把它过滤掉 |
| `relationships` 从空数组变成 30 条边 | 只看 `packages` 的消费者不受影响 |
| `refs/heads/main` 的默认输出仍是 msdx | `dfscan` 不加 `--sbom-format` 时行为不变 |

---

## 五、验证

```bash
# Maven 4 夹具回归
sh sca-compare/regress.sh <murphysec 路径>
# fixture  truth  reported  hit  missed
# bom      8      8         8    0     P=100.0% R=100.0%
# runtime  3      3         3    0     P=100.0% R=100.0%
# inherit  8      8         8    0     P=100.0% R=100.0%
# relpath  1      1         1    0     P=100.0% R=100.0%

# Go 端到端
murphysec sbom <go-project> --no-build --out bom.spdx.json
osv-scanner scan source --offline --offline-vulnerabilities --all-packages --lockfile bom.spdx.json
# 67 packages / 35 advisories，与 osv-scanner 直读 go.mod 的结果逐行一致
```

单测：`go test ./module/go_mod/ ./module/npm/ ./module/nuget/ ./inspector/ ./cmd/...` 全绿。

---

## 六、commit 索引

| commit | 类型 | 主题 |
|---|---|---|
| `7b561de` | fix | Maven 去重 key 缺 type/classifier |
| `d442674` | fix | Maven dev 依赖泄漏 + runtime 不传递 |
| `016da03` | fix | 本地仓库默认值 |
| `fd9a508` | fix | `relativePath` 父 pom |
| `337d87a` | fix | `ScanStrategy.MarshalText` |
| `dcb5938` | fix | renv → cran |
| `ccd53e3` | fix | SPDX 包名取 artifact |
| `dd4b168` | fix | 补全 SPDX 文档 + 携带告警 |
| `2438ac5` | fix | 参数组合校验 |
| `bf4dae7` | fix | `--no-build` 在 SBOM 路径生效 |
| `c35670a` | fix | `relationships` 稳定排序 |
| `1cfaca5` | fix | Go `replace` |
| `4f39134` | fix | vendor 递归 + `modules.txt` 优先 |
| `63d3b82` | fix | Go 依赖边 |
| `08b8728` | fix | npm workspace 成员 |
| `8a0bbd6` | fix | npm 独立锁文件 |
| `91c0bdc` | feat | `dfscan` 输出 SPDX |
| `6459a03` | feat | 全生态 purl |
| `76ee650` | feat | `--exclude-dev` / `--direct-only` |
| `9962967` | feat | rebar/perl/swift purl |
| `a7063b8` | feat | `--maven-command` + 失败可见 |
| `10dd3a8` | refactor | `sbom` 成为 `dfscan` 别名 |
| `86e6f34` | test | 无 purl 生态的告警断言 |
| `1d3530f` | test | NuGet `developmentDependency` |
| `666cde2` | docs+test | OSV 兼容性记录与集成测试 |
| `69a329d` | chore | 移除继承的 `.github` |
| `32b5091` | feat | Maven profile 静态解析与激活条件识别 |
| `7e3a08e` | fix | 修复 GitHub Actions 发布流程 |

---

## 七、Maven profile 支持（已提交）

本节功能已于 `32b5091` 提交，并纳入上方 commit 索引。静态解析实现及 profile 列表处理现已成为当前分支代码；构建扫描的激活行为仍有下方已知限制。

### 7.1 Maven profile 支持（静态解析）

新增 `module/maven/profiles.go`（约 380 行）+ `profiles_test.go`，把 Maven 的
`<profiles>` 语义补进静态解析路径。

**之前**：`gopom` 能解析 `<profiles>`，但代码只用了 `profile.Modules`；
`profile.Dependencies` / `DependencyManagement` / `Properties` 从未被读取。
profile 内声明的依赖全部漏掉——实测 0 包。

**现在**：`resolve_context.go` 在解析每个 POM 时先算出激活的 profile，依次合并：

```go
profiles := activeMavenProfiles(ctx, project, pom.Path)
for _, profile := range profiles { builder.properties.PutMap(profile.Properties.Entries) }
for _, profile := range profiles { builder.depms.mergeAll(profile.DependencyManagement.Dependencies, true, false) }
for _, profile := range profiles { builder.deps.mergeAll(profile.Dependencies, true, false) }
```

激活判定覆盖 Maven 的六种条件：

| 条件 | 实现 |
|---|---|
| `<activeByDefault>` | 无其它 profile 被激活时生效 |
| `<jdk>` | 精确版本与区间（如 `[17,)`），版本比较自行实现 |
| `<os>` | name / family / arch（含 Windows 与 Unix 家族归一） |
| `<property>` | 支持 `${...}` 求值、取反 `!value`、读系统属性与环境变量 |
| `<file>` | exists / missing，相对 POM 目录解析 |
| 显式指定 | 从 `--maven-arg` / `--maven-prepend-arg` 透传的参数里解析 `-P a,!b`、`--activate-profiles` 与 `-D key=value` |

判不了的条件不猜：`reportUnsupportedProfileActivation` 会往 scan warning 里写一条
（新增 `scanerr.KindMavenProfileResolution`），最终进 SPDX annotation。

**实测**（fixture：`old-jdk` 由 `<jdk>1.8</jdk>` 激活并引入 commons-io，
`default-on` 为 `activeByDefault` 并引入 commons-lang3，本机 JDK 21）：

| | 结果 |
|---|---|
| 修复前 | `[]`（空） |
| 修复后 | `['commons-lang3']` ✅ 与 Maven 语义一致 |

单测：`TestMavenProfileActivationConditions` 覆盖 jdk range / jdk mismatch / property /
negated property / environment property / OS family / OS arch / file exists / file missing
九个场景，全绿。

### 7.2 构建法的 profile 列表

`findPomProfiles` 重写到 `profiles.go`：遍历整个 reactor（含 profile 里声明的 module），
带路径去重（Windows 下大小写归一）。任何 POM 读不动都直接返回错误，
避免拿一个不完整的 profile 列表去跑 `mvn` —— 那样构建出的树会缺依赖。

`mvn_graph_cmd.go` 把参数拼装抽成 `appendMavenProfileArgs`，行为不变。

> ⚠️ 这一半**没有**按 activation 筛选：实测仍然下发 `-P old-jdk,default-on`
> （JDK 21 下 `old-jdk` 本不该激活）。见「已知未修复」第一条。

---

## 附：已知未修复

| 项 | 说明 |
|---|---|
| 构建法把全部 profile 塞进 `mvn -P` | `findPomProfiles` 仍收集所有 profile id 并拼成 `-P`，实测下发 `-P old-jdk,default-on`。`-P` 是手动激活，会覆盖 `<jdk>`/`<os>` 判定，导致不该激活的 profile 也被打开（多报）。静态解析这一半是对的，构建法这一半还没同步 |
| Go 项目混入无版本 PyPI 组件 | 项目里有裸 `.py` 脚本时会被 Python inspector 拾取，产生 4 条无版本噪声（osv-scanner 会过滤） |
| 漏洞检测依赖 SaaS | `sbom`/`dfscan` 子命令本身不联服务端，但漏洞查询仍需平台 |
