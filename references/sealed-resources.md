# SealedResources 本地联合验证接口（未发布）

工具源码：D:/myproject/poweramp/skills/android-release-hardening/scripts/dxprotect/
本接口补充资源保护，不替换 OPLUSBox 的 LSP 分离、binding-config 或 BLA 流程。不要覆盖盒子现有 protect.py；在现有分支按下述挂接点合并。

## 业务接口
`com.daxiaamu.shellbinding.OuterShare.resource(String id)` 返回 byte[]，失败抛 SecurityException；调用方用完后清零。沿用现有反射桥，不需要 Context 参数。仅主 App 壳完成恢复且完整性有效时可读，LSP 独立进程不应调用。
该接口验证壳/签名/密文完整性，不代替在线会员授权。盒子必须先完成在线授权，再调用 read、创建明文ZIP或写出helper；状态/卸载/既有离线救援不依赖该接口。

## 构建配置
`--sealed-resources-manifest D:/private/shield-resources.json`
JSON:
```json
{"schema":1,"resources":[
 {"id":"shield/core-apps","entry":"core-apps.sh"},
 {"id":"shield/webui-status","entry":"shield-webui-status.sh"},
 {"id":"shield/webui/index.html","entry":"shield-webui/index.html"},
 {"id":"shield/helper/arm64-v8a","entry":"lib/arm64-v8a/libshieldcore.so"}
]}
```
entry 是输入 APK ZIP 条目名，不是外部文件路径；需列举所有 WebUI 文件及四 ABI helper。工具只处理明确选择的普通文件，严格拒绝 Manifest、DEX、路径逃逸、重复id/entry和缺失文件。

## 现有 LSP 工具挂接点
1. 将 tools/sealed_resources.py 放到现有 tools/；从其导入 seal_resources。
2. argparse 增加 --sealed-resources-manifest（Path）。
3. apktool decode 后，在枚举 business_native_manifest **之前**执行：
   `resource_plan = seal_resources(decoded, manifest, key, asset_dir, seal)`
   其中 key 是本次壳加密密钥、asset_dir 是随机 assets 子目录；原资源/helper 经认证加密后从 decoded 移除。因此原 helper 不再进入需要在 lib/ 重测的业务 SO 清单。业务 JNI SO 保持原样。注意将本次 key/profile/asset_dir 的生成提前，不能重新生成第二份 key。
4. 合并 stub/src/com/daxiaamu/protector/StubApplication.java 中 readResourceBytes/readSealedBytes 方法，以及 stub/src/com/daxiaamu/shellbinding/OuterShare.java 的 resource(String)。复用既有 NativeBridge 解密方法和运行时 capability。
5. R8 显式保留 OuterShare.resource(String)；业务源码通过反射读取，不打包与壳重复的实现。BLA 不得改稳定接口名。
6. 构建结束在原 report 添加 resource_plan（只包含id、密文条目、大小、哈希，不包含密钥）。
   发布前调用 `verify_sealed_resources(final_apk, profile["asset_dir"], resource_plan)`，确认索引/密文摘要一致、原路径已移除且没有改名明文副本。盒子专用 audit_shield_payload.py 仍必须独立通过。
7. 发布前要求联合验证与用户发布授权；不得用通用技能全目录覆盖项目定制壳。盒子定制副本由主开发局部合并，保留LSP/value/runtime.cfg扩展。

## 存储约定
随机 asset_dir 下 resources.idx 为认证加密索引，资源为随机 *.res（不是 *.bin，避免误作业务DEX加载）。每个明文包为 DXRSRC01 + uint16be(idUTF8字节长度) + idUTF8 + 内容；运行时解密后比对id，防止资源替换/互换。沿用既有 DXPROT01 认证加密格式，不另加 APK 内可见资源解密密钥。

限制：运行时授权ROOT可读取解密结果；此方案解决 APK 静态明文载荷，不保证安装后的脚本/WebUI/helper 无法提取。联合验证结果未确认前不得称正式修复通过。

## 2026-11-17 本地证据
- 原始正式2.6.1 APK：audit_shield_payload.py 检出12项明文暴露。
- 用原包12项真实载荷作为独立回归输入，完成四ABI/R8壳构建及v1/v2/v3签名验证；新包通过通用资源门禁及盒子专用提取审计。
- 产物：D:/myproject/poweramp/apk-analysis/oplusbox-2.6.1/local-sealed-fixture/protected.apk；静态证据为同目录plaintext-after.json及*.dxprotect.json。
- 五项资源行为测试覆盖认证回读、错key/篡改拒绝、输入校验、路径映射、随机化及最终APK改名明文副本/密文修改。
- 最终全量本地回归21项通过（58.258秒），git diff --check通过；这些不替代盒子最终UI/会员/LSP联合验收。
- 不将回归包当成真实盒子最终APK验证；实际会员、LSP、UI及授权后安装由主开发对话继续联合验证。未提交、未推送GitHub，未更新已安装技能或盒子定制副本。

## 2026-11-17 联合验证通过
- 主开发候选APK SHA-256：BBC0E6E0B83A82D5B64F1B2B25C34B7B0D5CD23B6457BB2254A9631E0901168C，与plaintext-gate.json记录一致，提取审计通过。
- 8T d4d771ab：冷启动、信息/功能/设置/用户中心界面通过；真实App进程探针记录 SHIELD_RESOURCE_PROBE_PASS count=12 unknown_rejected=true。
- 主开发报告原生探针通过LSP、签名、配置/DEX解密、完整性图和SO/DEX/配置篡改拒绝；保留R8、BLA、classes2及binding-config扩展。
- 证据位于盒子项目 artifacts/shield-audit-work/ 下的plaintext-gate.json、ui/verification.json、resource-probe/result.log及保护报告。通用技能仓库不包含候选APK、密钥、账户或私有构建配置。
- 仅确认静态载荷保护及上述运行时读取/兼容性检查；未安装ROOT护盾、未重启或重测开机救援，不能推断ROOT运行时不可dump。
