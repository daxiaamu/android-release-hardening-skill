# DXProtect V8 通用 APK 加固壳

DXProtect 的输入是已经构建完成的单体 APK，输出是重新签名的加固 APK。它不要求目标项目源码，也不会修改业务源码；`fixture/` 仅用于本工具自身回归，不会被复制进目标 APP。

处理链路：

`项目源码 → 官方 release APK → DXProtect → 正式签名的加固 APK + JSON 验收报告`

## V8 加固结构

- 原 `classes*.dex` 从 APK 顶层移除，分别加密并认证后放入每构建随机的 assets 路径；API 27+ 使用带原 APK native 搜索路径的 `InMemoryDexClassLoader`。
- 壳由随机包名、随机类名、随机 JNI 方法名、随机 SO 名、随机元数据键和随机资产路径组成；同一输入连续构建不会产生固定补丁位置。
- 两个独立 native 库分别持有信任材料并做 SHA-256 自封印/交叉封印；只有两者一致时才签发进程绑定、带随机 nonce 和 HMAC 的短期 capability。
- 反剥壳份额采用双 SO 拆分：anchor SO 只持有 B 份秘密并根据 challenge/phase/domain 与交叉封印摘要生成片段；engine SO 只持有 A 份秘密，并结合片段、壳 DEX、正式签名和业务 SO 清单生成最终份额。两个秘密不得同时出现在任一 SO。
- 完整性图生成 32 字节 graph state，而不是只给出通过/失败。实际 signer、双壳 SO、壳 DEX、全部业务 SO、capability 和运行时状态共同进入该 state，并继续进入份额密钥和多轮输出。只把检查函数改成返回成功而不生成正确 state 时，业务输出必须失配。
- 集成了 `com.daxiaamu.shellbinding.OuterShare` 窄接口的业务引擎，应在初态、迭代轮、最终 Proof、Scene/View Seal 与 watchdog 中消费至少三组不同 domain 的份额。固定值、空实现或删除整个壳均不得保留正式输出。
- 签名通过 `PackageManager/SigningInfo` 与 native 直接解析已安装 APK v2/v3 Signing Block 两条路径交叉校验。
- JNI 仅导出 `JNI_OnLoad`，通过 `RegisterNatives` 绑定每构建随机方法；类名、方法名、JNI 签名和运行时探针字符串以 volatile 异或数组保存，避免编译器常量折叠重新泄露明文。
- native 从已安装 APK 中直接定位、解压并校验壳 `classes.dex`，将 Java 壳修改纳入交叉校验图。
- 构建时枚举输入 APK 的全部原始业务 SO，为每个 `lib/<abi>/*.so` 生成 SHA-256 清单；entry 名以每构建随机异或数组保存。启动、解密与 watchdog 从已安装 APK 重新解压测量全部业务 SO，避免只修改内层 native 后重新计算内层 self-seal。
- `strict` 运行时策略检查 `TracerPid` 和已知注入映射；`tracer` 仅检查调试附加，`off` 关闭该层。它是附加信号，不替代签名和文件校验。
- 启动、Activity resume 和每构建随机 watchdog 周期都会刷新 capability；失败进入不可取消、禁止 Back/外部点击且只有“退出”按钮的失败界面。
- 输出先在临时位置签名并完成结构/签名验收，再原子替换目标文件，失败不会留下半成品覆盖原输出。
- native 自封印定位标记必须按构建随机生成且不可自描述；不得保留 `ENGINEHASH`/`ANCHORHASH` 一类稳定字符串。
- 在旧 Android build-tools 的 D8 对合法 Java 8 启动类图发生内部崩溃时，工具会回退到同目录 `dx` 只编译小型启动 DEX；该回退不改变 native 加密、测量和份额图。

## 使用

复制 `dxprotect.config.example.json` 到源码仓库之外，填写目标 APK、输出、正式签名和工具链路径。签名密码只通过环境变量传入：

```powershell
$env:DXP_STORE_PASS = "<正式 keystore 密码>"
$env:DXP_KEY_PASS = "<正式 key 密码>"
./dxprotect.ps1 -Config D:\secure\ikan-release-protection.json
```

也可以直接调用：

```powershell
python ./tools/protect.py `
  --input app-release.apk `
  --output app-protected.apk `
  --keystore D:\secure\release.jks --alias release `
  --ks-pass-env DXP_STORE_PASS --key-pass-env DXP_KEY_PASS `
  --apktool D:\APKDB\apktool\apktool_3.0.2.jar `
  --android-sdk D:\AndroidSDK `
  --java-home "C:\Program Files\Java\jdk-17" `
  --abis auto --min-api 23 --runtime-guard strict
```

`auto` 会跟随原 APK 已有 ABI；纯 Java/Kotlin APK 默认生成 arm64-v8a 与 armeabi-v7a。当前壳支持 arm64-v8a、armeabi-v7a、x86、x86_64，最低 API 23。工具只会抬高、不降低原 APK 的 `minSdkVersion`。

## 兼容性与预检

已覆盖的本地回归包括：多 DEX、自定义 Application 身份恢复、壳 BootstrapProvider、普通 Activity、NativeActivity、自带 JNI/SO、API 27+ 内存加载和原 nativeLibraryDir 继承。

构建会拒绝：

- Split APK、功能 Split、已加固 APK；
- 自定义 `android:appComponentFactory`（它可能早于壳 DEX 加载）；
- `sharedUserId` APK、预览版代号 minSdk、未知 ABI；
- 重复 ZIP 条目、缺失/外露 DEX、壳 DEX 哈希变化、缺失 native 库或 payload 数量不一致。

多进程、isolatedProcess、Direct Boot 和 largeHeap 会写入 JSON 兼容性警告，必须在目标设备上逐项回归。AAB 需先生成 universal/standalone APK；本工具当前不直接处理 split 集合。

## 产物与验收

每次成功构建输出：

- `*.apk`：最终对齐并签名的 APK；
- `*.apk.dxprotect.json`：输入/输出 SHA-256、签名证书摘要、ABI、原 Application/Launcher、兼容性预检、随机化档案、壳 DEX 摘要及业务 SO entry/digest 清单。

发布前至少验证冷启动、升级安装、前后台切换、15 秒停留、自定义 Application、全部 ABI/JNI 功能，以及以下篡改结果：重新签名、壳 DEX 修改、payload 修改、壳 SO 修改、每个原始业务 SO 独立修改、Manifest 入口修改。必须包含一个“只修改业务 SO 并重算其内部 self-seal”的样本。防御成功必须显示规定的不可取消失败弹窗；崩溃、黑屏或静默退出均属于兼容性失败。

还必须执行剥壳重建回归：运行时提取业务 DEX，恢复原 Application/launcher，删除壳 provider、metadata、assets 和壳 SO，只保留业务资源与业务 SO 后用测试证书重签。若该裸包只需把业务签名/自校验分支改为成功，就能继续计算新 challenge 的正确业务输出，则外壳仍是可删除的启动门，不能作为发布通过条件。

对使用 V7 份额接口的项目，再增加两项验收：一是给剥壳 APK 注入返回固定 32 字节的假 `OuterShare`，确认其全部新 challenge 输出均与官方不同；二是逐 ABI 检查最终两个壳 SO，确认 A/B 份秘密没有同时出现在同一文件。

## 安全边界

这是一套提高静态分析、动态调试、脱壳和重打包维护成本的离线客户端防御，不是不可破解的信任边界。拥有 root、任意代码执行和足够时间的攻击者最终可以控制本地进程。高价值授权、可变策略和秘密应放在服务器；keystore、密码、mapping 和 native symbols 不得进入本仓库。
