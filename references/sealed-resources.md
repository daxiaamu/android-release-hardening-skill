# 通用认证加密资源

适用于单体 APK 中需要由业务代码按逻辑 ID 读取的普通资源：JSON、文本、模型、模板、离线页面、二进制数据和独立程序。组件不依赖目标包名、账号体系或具体文件名；OPLUSBox 只是[项目适配案例](sealed-resources-project-cases.md)。

标准接入只需：配置资源清单、切换选定资源的读取接口、运行原有加固命令。不需要修改 protect.py 或 native 源码。该功能默认关闭。

## 输入与配置

通过 `--sealed-resources-manifest resources.json` 或主配置的 `"sealed_resources_manifest": "resources.json"` 启用。清单路径相对于执行命令的工作目录解析；entry 始终是输入 APK ZIP 条目名，不是电脑文件路径或 APKtool 的 unknown/ 路径。

```json
{"schema":1,"resources":[
  {"id":"configuration","entry":"assets/config/rules.json"},
  {"id":"model/weights","entry":"assets/models/weights.dat"},
  {"id":"page/index","entry":"assets/pages/index.html"},
  {"id":"root/template","entry":"templates/root.txt"}
]}
```

完整示例见 scripts/dxprotect/sealed-resources.example.json。id 与 entry 可完全不同，不要求包名前缀。只选择业务准备切换读取方式的条目；未选择的资源、业务 JNI 库和业务 DEX 不由资源组件修改。

- schema 必须为整数 1；只接受 schema/resources 字段，每项只接受 id/entry。
- 最多 256 项；单项不超过 16 MiB，总计不超过 64 MiB；允许空文件。
- id 为 1–128 个 ASCII 字符，首字符为字母或数字，后续允许字母、数字、点、下划线、斜杠、横线。
- entry 是规范相对路径，可含空格和 Unicode 文件名；禁止反斜杠、冒号、路径逃逸、重复源文件、符号链接及结构性条目（Manifest、DEX、资源表、META-INF 等）。
- 根目录普通资源按 APKtool 的 unknown/ 布局解析；assets/lib 等直接布局也支持。多处同名映射时拒绝，不猜测来源。
- 不传参数，或清单为 `{"schema":1,"resources":[]}`，均不创建资源索引、不调用资源加密、不删除任何输入文件。

## 稳定读取接口

`com.daxiaamu.shellbinding.OuterShare.resource(String id): byte[]`

该命名空间是壳的固定 ABI，不是目标 App 的 applicationId；目标项目可以使用任意包名。需在壳完成初始化后的主 App 进程调用，例如 Activity 或业务入口，不在原 Application.attachBaseContext 中调用。

```kotlin
val facade = Class.forName("com.daxiaamu.shellbinding.OuterShare")
val read = facade.getMethod("resource", String::class.java)
val bytes = read.invoke(null, "model/weights") as ByteArray
try {
    // 将 bytes 交给业务解析器，不长期缓存明文。
} finally {
    bytes.fill(0)
}
```

使用反射无需编译期壳依赖，不要把另一个 OuterShare 实现打进业务 APK。壳自身的 R8 保留规则已包含 resource(String)。缺失资源、资源互换、认证失败和未初始化均拒绝；反射调用的 SecurityException 会包装在 InvocationTargetException 中，由项目按自身错误处理流程展示。

这个接口只证明密文及应用完整性，不提供会员、许可证或用户授权。如果项目有这些要求，由业务在读取、创建明文文件或安装载荷之前完成；无此要求的离线 App 不需要引入账号或联网流程。返回缓冲区归调用方所有，用完清理；转成不可变 String 后无法保证立即擦除。

## 支持边界

| 场景 | 行为与要求 |
|---|---|
| 普通 Java/Kotlin 单体 APK | 使用标准 CLI、资源清单和稳定读取接口 |
| 自带真实 JNI/SO | 默认保留库及其导出，继续参与原生完整性清单；不要把 System.loadLibrary 依赖的库选成普通资源 |
| 独立可执行 helper | 建议先以 assets 普通二进制输入；如显式选中 lib/ 下的独立程序，会在原生清单生成前移走，不能再依赖 nativeLibraryDir |
| Android res/raw 或编译资源 | 不是透明替换；所有消费者必须改用稳定接口。仍被 Resources、XML 或框架自动读取的条目不应选择 |
| 定制 LSP/插件壳 | 资源组件可复用；入口 DEX 分离、额外配置、测量图仍由已有适配层负责。不要覆盖定制副本或盲目加密独立启动 DEX |
| split APK/AAB | 此接口不扩展基础工具的支持范围；先生成受支持的 standalone APK |

这里只变更选定资源的读取方式；普通加固壳原有 Application/Provider/ABI/API 兼容边界仍然有效。资源读取成功不等于业务整体功能已验收。

## 存储与最终包验收

随机 assets 子目录下的 resources.idx 是认证加密索引，资源为随机 *.res（不会被当作业务 DEX 的 *.bin 加载）。每个资源在加密前绑定逻辑 ID：
`DXRSRC01 + uint16be(id字节长度) + idUTF8 + 原始字节`。
复用既有 native DXPROT01 格式及每构建密钥，不在业务配置中增加解密密钥；运行时逐次取得独立完整性 ticket。

标准工具在输出最终签名 APK 前自动调用 verify_sealed_resources，检查密文/索引摘要、原始路径删除和改名的同字节明文副本。空文件无秘密内容，故只检查路径删除及认证密文，不因为其他未选择的空文件而误拒绝。

若在已有定制流水线接入模块：
1. 将 seal_resources(decoded, manifest, key, asset_dir, seal) 放在原生清单枚举前；沿用本次壳的 key，不生成第二套。
2. 保留 OuterShare.resource 与 StubApplication 的 readResourceBytes/readSealedBytes；不能丢失已有 facade、配置和入口扩展。
3. 报告写入 resource_plan；最终 APK 调用 verify_sealed_resources(apk, asset_dir_name, resource_plan)。
4. 在项目自身完成原始条目提取检查、真实进程读取、未知/篡改拒绝及业务回归。示例应用不能代替项目验收。

## 可复现通用性测试

`python -m unittest discover -s scripts/dxprotect/tests -v`

`tests/run_resource_matrix.py` 是显式集成测试：自建测试证书与三个无关包名的 APK，不读取任何项目源码或发布密钥。分别覆盖纯 Java、自定义 Application + 原 JNI、资源保护关闭；启用场景验证文本/JSON/模型/HTML/空文件/Unicode路径/根资源，未知资源必须拒绝。纯Java场景使用CLI开关，JNI场景使用JSON主配置，分别验证两种入口。运行参数 --android-sdk、--ndk、--java-home、--apktool、--out；JDK需能运行所选build-tools的R8/D8。可选 --serial 指定获准设备，--package-suffix 用于独立重跑。默认只本地构建，带 serial 才安装独立测试 App；拒绝覆盖已存在包，不卸载其他应用。

本地与设备结果写入测试输出目录，不进入技能仓库。一般性验收标准是：切换目标包名、资源 ID 与目录，只改清单和业务读取代码，工具源码不变。

2026-11-17：25项本地回归通过。8T（API37、arm64）上的纯Java、原JNI和关闭资源保护三个场景均构建/启动通过；启用场景中六类资源SHA-256匹配且未知ID被拒绝，关闭场景原始资源保持字节一致。证据在工作区 apk-analysis/generic-resource-matrix/ 的各轮 results.json、build.log 和 ui.xml。此记录不代表旧Android/API或所有项目结构均已覆盖。

## 安全边界

本功能解决 APK 的静态明文资源暴露，不保证 ROOT 所有者无法从运行进程或已安装文件提取内容。没有通用会员判断、没有静默执行 helper、没有自动安装模块或更改设备启动行为。基础签名验证、进程完整性和项目授权必须独立验收。
