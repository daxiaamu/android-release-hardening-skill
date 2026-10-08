# DXProtect 代码保护增强（2026-10-08）

本阶段修改通用 APK 壳和发布工具，不修改输入 APK 的业务源码，也不把回归示例当成用户业务应用。

## 已落地
1. 壳编译默认采用 R8 release 优化/混淆。Manifest 入口、动态注册 JNI 类/方法及固定 OuterShare 接口显式保留；其他辅助实现允许内联、合并、重命名。R8 失败会终止构建，不静默降级。可明确指定 --shell-optimizer d8 使用旧兼容路径，报告会记录降级模式。
2. Java 临时解密数组用 finally 清理；非法 DEX 清理后拒绝；多 DEX 加载中途失败时清理已分配 direct buffer；旧版本文件加载的写入、关闭和发布失败路径删除未发布临时文件。
3. 两个 native 库使用 volatile 写入的 secure_zero，避免普通 memset 清零被优化删除；增加 HMAC ipad/opad、SHA 上下文及解密 key/nonce 临时块清理，并检查 JNI 输出数组分配失败。
4. 最终签名 APK 发布前增加 release_surface 门禁：拒绝打包源码、常见签名密钥容器、mapping、私钥 PEM 标记、壳以外的明文 DEX；从最终包提取 ELF 检查。壳必须仅导出 JNI_OnLoad、不得带调试/完整符号段，不得重新泄露生成的 JNI lookup 文本或稳定自描述锚点。
5. 业务 SO 不被机械重写或剥离 JNI 导出；其中调试/符号段会作为警告写入报告。调用方应在业务原始构建中处理这些警告。
6. 映射文件通过 --shell-mapping-output <私有路径> 单独保存，不写入 APK。不得提交到公开仓库。正式构建不建议 --keep-work，它会保留原始 DEX、构建秘密和映射。

示例补充参数：
--shell-optimizer r8 --shell-mapping-output D:/secure/build-mappings/release-shell.txt

## 实测
- 本机 16 项 unittest 通过（包括六项新增代码保护测试）。
- 发布扫描采用 1 MiB 流式读取和跨块重叠，不将整个 ZIP 条目读入内存；覆盖跨分块私钥标记测试。
- 用真实 NDK ELF 验证额外导出和调试段会被门禁拒绝；优化后的 native 清零行为通过宿主 -O2 程序测试。
- R8 映射显示辅助验签方法被重命名/内联；不是只把名称改为随机串后声称完成混淆。
- 回归包四 ABI（arm64-v8a/armeabi-v7a/x86/x86_64）编译及最终 ELF 检查通过；所有壳库仅导出 JNI_OnLoad、无调试/完整符号段。
- 经用户许可，在 OnePlus 8T d4d771ab（API 37）安装独立测试证书的回归包，验证多 DEX、自定义 Application 和原 JNI/SO 加载。不是正式业务 APK 的全量兼容性验证。
- Android 23–29 等旧版本实机矩阵及故障注入仍未完成；源码路径断言不能替代实机异常测试。

## 仍然不能承诺
成功加载的 direct DEX 缓冲区不能随意擦掉：ART/ClassLoader 可能继续使用它们。API 23–28 兼容路径仍需私有目录明文 DEX。不得把清理临时副本说成运行时没有明文，或保证 root 无法 dump。

R8 本次作用于壳，不作用于任意输入业务 DEX。若要让业务代码提取后也更难读，必须在业务项目 release 构建开启 R8，按反射、序列化、JNI 和动态组件补精确 keep 规则，然后全量回归。不能对成品 APK 盲目重命名业务类。

未加入 OLLVM 控制流平坦化、指令虚拟机或自动业务 native 化。它们需要选择具体关键算法和可维护工具链，不能用不兼容或崩溃冒充安全。发布泄漏门禁是启发式检查，不是完整密钥扫描器；它可能拒绝合法源码资源，应在原项目明确调整打包，不能静默删除。

本地校验与混淆均可在完全受控环境被修改/模拟；本阶段提高的是静态理解成本、临时提取成本及发布卫生，不能称不可逆向。没有加入提示词注入载荷。

R8 规则依据：[Android 官方 keep rules](https://developer.android.com/topic/performance/app-optimization/keep-rules-overview)；实现与产物证据以本工具回归为准。
