# DXProtect：APK v2 密码学验签（2026-10-08）

## 已实现
- 在业务 DEX 解密、原 Application 恢复之前验证 APK v2；缺少 v2 不回退到 v1。
- 解析 EOCD、中央目录和 APK Signing Block，检查长度边界、结构一致性、重复签名块和单签名者策略。
- 校验 signed-data 数字签名、证书公钥与 signer 公钥的一致性。
- 用构建时注入的证书 SHA-256 指纹固定身份，并与 PackageManager 的安装身份交叉检查。证书本身是公开信息，不被当作秘密密钥。
- 按 Android v2 的 1 MiB 分块规则重算 APK 内容摘要，覆盖签名块之前的数据、中央目录、调整偏移后的 EOCD；不是仅查证书或比较可重算的自定义哈希。
- 校验 digests/signatures 的算法 ID 顺序一致性；已声明 v3 的 stripping-protection 属性要求 v3 块仍存在。
- 启动强制同步验签；周期验签在单后台线程执行，完成后在主线程继续原 native watchdog。失败沿现有失败界面路由，不继续周期链。

## 算法与策略边界
解析支持 RSA PKCS#1、RSA-PSS、ECDSA、DSA 的 v2 SHA-256/SHA-512 算法 ID（DSA 仅 SHA-256）；未知算法不参与选择，无可用算法则拒绝。实际运行还取决于设备的 Java 加密 provider。当前真实签名测试覆盖 RSA PKCS#1/SHA-256 和 ECDSA/SHA-256，不代表其他算法已完成 Android 版本矩阵验证。

独立实现的是 **v2** 验签，不是独立的 v3/v3.1/v4 验签器；DXProtect 构建仍启用 v1/v2/v3，系统安装验证及原 native 签名身份检查继续保留。多签名者、密钥轮换、ZIP64、split APK 不在本次支持承诺内。签名块最大 16 MiB，异常结构拒绝。

v2 规范不覆盖未知 Signing Block 条目；增加未知条目不一定破坏签名。不能称所有文件字节都被签名保护，更不能承诺 root 下校验逻辑无法被修改。Java 验签器本身由已有壳 DEX/native 完整性链保护，仍需后续独立审计及篡改演训。

大 APK 冷启动仍需顺序读取签名覆盖区；周期验证虽已移出 UI 线程，仍有 I/O、电量成本。尚未完成大包性能基准。验证后文件替换的竞争及内存级攻击，不由文件签名验证单独解决。

## 验证记录
全部本机 unittest：10 项通过，其中新增密码学验签测试 5 项，内含多个子样本：
- 正确 RSA、ECDSA 签名，2.2 MB 随机资产，覆盖多分块；
- 修改 APK 内容、中央目录、EOCD、signed-data、真实 signature 字节：拒绝；
- 未签名、截断、错误固定指纹：拒绝；
- 缺少 v2、签名声明的 v3 被剥离：拒绝；
- 攻击者签名包加入复制的官方证书自定义 pair：以真实攻击者指纹验证仍通过；以官方固定指纹验证拒绝。

构建工具编译完整壳成功；apksigner 验证生成包的 v1/v2/v3 均通过。
连接设备 PLK110（Android API 37）使用独立回归证书安装；冷启动界面显示 multi-DEX、自定义 Application 和原 JNI/SO 加载成功。
API 26/27/28/29 真机启动与失败界面矩阵、后台恢复、App Link/快捷方式尚未完成。本次成功启动记录不能代替上述验收。

## 代码入口
- scripts/dxprotect/stub/src/com/daxiaamu/protector/ApkSignatureVerifier.java
- scripts/dxprotect/stub/src/com/daxiaamu/protector/StubApplication.java
- scripts/dxprotect/stub/src/com/daxiaamu/protector/BuildProfile.java
- scripts/dxprotect/tools/protect.py
- scripts/dxprotect/tests/test_apk_signature_verifier.py

测试可设置 JAVA_HOME、ANDROID_HOME 和 DXP_TEST_FIXTURE 指向独立工具链及未加固 fixture。
运行：python -m unittest discover -s scripts/dxprotect/tests -v

规范依据：[AOSP APK v2](https://source.android.com/docs/security/features/apksigning/v2)，[AOSP V2SchemeSigner](https://android.googlesource.com/platform/tools/apksig/+/master/src/main/java/com/android/apksig/internal/apk/v2/V2SchemeSigner.java)。
