# 项目适配案例：OPLUSBox

本案例只记录项目专用约束与首次联合证据，不是通用接口的前置要求。通用配置、API 和限制见 [通用认证加密资源](sealed-resources.md)。

## 项目特例

- 盒子使用 R8 → LSP 入口/业务 DEX 分离 → BLA 双 DEX → 定制壳 → 正式签名流程。
- 定制副本需要保留 OuterShare.value、runtime.cfg、classes2 测量与 --binding-config/--lsp-entry-dex；不能被通用工具全目录覆盖。
- 资源 ID 与原始脚本/WebUI条目一致；四 ABI helper 改为 assets/shield-native/<abi>/core.bin 输入，再通过对应逻辑 ID 读取。
- 在线会员鉴权属于盒子业务：必须在读取、创建明文ZIP前完成。状态、卸载及已经安装的离线救援无需调用资源读取API。此要求不强加给其他项目。
- 盒子的 audit_shield_payload.py 是项目提取门禁，保留在项目中，不作为所有 App 的通用规则。

## 首次联合验证（2026-11-17）

原始正式 2.6.1 有12项明文载荷；通用修复后，真实候选APK的提取门禁、资源认证读取及未知资源拒绝通过。候选 SHA-256：BBC0E6E0B83A82D5B64F1B2B25C34B7B0D5CD23B6457BB2254A9631E0901168C。

8T d4d771ab 的冷启动、信息/功能/设置/用户中心通过，真实 App 进程探针记录 SHIELD_RESOURCE_PROBE_PASS count=12 unknown_rejected=true。主开发验证了原生图、LSP、签名、配置/DEX解密与 SO/DEX/配置篡改拒绝。证据在项目 artifacts/shield-audit-work/ 下；不把私有候选APK、账户、密钥或配置提交到技能仓库。

这些证据没有覆盖护盾模块安装、设备重启或开机救援；也不代表 ROOT 运行时不可 dump。后续通用性测试使用独立合成项目，不依赖盒子源码或此案例产物。
