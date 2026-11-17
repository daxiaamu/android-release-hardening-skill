# 签名与资源认证：隔离负测试

本参考用于核查具体假设，不将静态发现证书、函数或字符串当作绕过证据。OuterShare.resource(String)、资源清单和DXPROT01/DXRSRC01保持兼容。

## 信任边界

证书DER、公钥和指纹是公开身份信息，不等于泄漏签名私钥；不能据此强制换证书或黑名单旧证书。DER比较也不是密码学验签：后者必须检查APK签名字节及覆盖区摘要。

上游使用ApkSignatureVerifier.verify(apkPath, BuildProfile.SIGNER_SHA256)，在启动时与PackageManager结果交叉检查，并在后台周期复验。native直接解析APK证书是另一证据路径，但不能冒充签名字节验证。定制副本必须核对是否实际集成完整验证器、固定pin生成及启动/后台调用，不能将上游能力直接算作项目已有。

## 实验设计

tests/run_security_regression.py 自生成测试密钥、独立包名与临时工作区，不接受生产APK或正式私钥作为输入。当前驱动使用Windows SDK/JDK/NDK，只在明确的--serial设备执行；没有ROOT模块安装、重启或真实Frida注入。

资源负例经同一测试证书合法重签，业务DEX/SO不变，从而排除安装器/整体APK验签抢先拦截。

| 用例 | 裁决 |
|---|---|
| 两个正常的独立构建 | 真正App进程读取成功 |
| IDX位翻转后同证书重签 | resource API抛SecurityException |
| 换另一构建IDX | 不同每构建密钥，认证拒绝 |
| 同构建合法RES冒充IDX | 类型/JSON解析拒绝 |
| 同构建RES互换 | envelope逻辑ID不匹配，拒绝 |
| 恢复原测试APK | 再次读取成功 |
| 临时源码副本仅让PM getter返回固定pin，再用另一测试证书重签 | 独立APK密码学路径拒绝；弹窗仅退出，Back/外部点击不能关闭 |

PM用例是源码级返回值模拟，不是实测Frida，也不覆盖同时替换文件读取、验证器、JNI或全部进程状态。临时修改不进入生产源码或安装技能。

参数：--android-sdk、--ndk、--java-home、--apktool、--out、--serial；成功后清理本次创建的三个测试App，保留APK/XML/日志/results.json。失败保留现场。不会卸载其他应用。

## IDX认证

索引原本经过native DXPROT01 HMAC。只看Java解密后的size/schema/path检查，不能断言无认证。隔离实验确认受损/跨构建索引拒绝，同密钥的其他类型容器不能冒充索引，资源内容还绑定逻辑ID。损坏后fail-closed是预期行为，不应回退到未认证明文。

这不是ROOT所有者无法提取密钥或控制进程的证明；项目账号/许可证授权仍需先于资源读取。

## 固定段名

旧 .dxpseal/.dxppeer/.dxaseal/.dxapeer 是可确认的定位指纹。本轮将四个seal槽放入普通只读 .rodata。
继续采用随机marker、交叉摘要与volatile读取；未改密码协议、JNI契约或原始业务SO。inspect_elf新增legacy_seal_sections，通用门禁只拒绝壳库的旧段名，不改业务库。

定制LSP流水线只复用inspect_elf检查壳SO，不能套用通用“仅classes.dex”限制来误拒绝合法独立入口DEX。

NDK zlib.h的ZLIB_VERSION作为inflateInit2_的ABI参数，且按Android API条件重定义。1.3.0.1-motley来自该依赖，不是秘密或授权因素；本轮保留ABI参数。段名移除仅降低定位便利度，不代表无法逆向。

## 2026-11-17 证据

26项主机回归通过，含“只有旧段名、无多余导出/调试信息”的真实ELF反例。四ABI构建/签名验证通过，8个壳SO仅JNI_OnLoad、无调试/旧seal段。

8T d4d771ab（API37）上7项正负用例通过，基线恢复成功；单退出按钮及Back/外部点击持久性也核验通过。通用证据位于工作区apk-analysis/second-audit/security-negative-odmim8sx/，四ABI报告为apk-analysis/second-audit/all-abi-protected.apk.dxprotect.json，不随技能发布。

项目联合候选SHA-256：12952A0ECF27C9A2080C4252CC5AD708538DBE365C35BEBB2756E8F8213597C9，与实际文件及verification.json一致。项目补齐定制副本遗漏的完整验签器，独立验证LSP、配置、原生图、签名负例、UI、12资源和内存ZIP。没有发布盒子APP、安装模块或重测救援；旧API和真实动态注入不能据此宣称通过。

BLA字符串需与class_def区分，不依据报告推测加密独立LSP入口或修改第三方流水线。
