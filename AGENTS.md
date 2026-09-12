# HUKS 组件指引

## 项目定位

本仓库对应 OpenHarmony `base/security/huks`。HUKS（Universal KeyStore）为应用提供密钥管理与密码学运算能力，包括密钥生成、导入、导出、加密/解密、签名/验签、密钥协商、MAC、密钥证明等。HUKS 分三层：

- `interfaces/`：对外 API 层。包含 NDK C API（`kits/c`）、NAPI JS API（`kits/napi`）、CJ FFI API（`kits/cj`）、内部 SDK（`inner_api/huks_standard`）、加密扩展能力（`js/crypto_extension_module`）。
- `frameworks/`：框架层，被 interfaces 和 services 共用。标准系统实现在 `huks_standard/main`，小/mini 系统在 `huks_lite`。
- `services/`：服务层与引擎层。`huks_service/main` 是密钥管理服务（SA），`huks_engine/main/core` 是密码学运算引擎核心（商用版本须运行在 TEE 或安全芯片内；开源默认软件实现）。
- `utils/`：共享工具（crypto_adapter、file_operator、list、mutex、condition、compatibility_bin）。
- `etc/`、`hisysevent.yaml`、`huks_service.cfg`、`huks_service.rc`：运行配置。
- `test/`、`test/fuzz_test/`：单元测试与 fuzz 目标。

系统适配：`standard`（标准系统）、`small`（小系统）、`mini`（mini 系统），由 `os_level` 控制，构建分支见根 `BUILD.gn`。

### 按任务类型定位代码

| 任务类型 | 首选目录 | 关键文件 |
| --- | --- | --- |
| 修改 NDK C API | `interfaces/kits/c/` | `include/native_huks_api.h`, `native_huks_param.h`, `native_huks_type.h`, `src/*.c` |
| 修改 NAPI JS API | `interfaces/kits/napi/` | `include/huks_napi.h`, `src/*.cpp`, 版本目录 `include/v8`/`v9`/`v12`/`v24`/`ukey` |
| 修改 CJ FFI API | `interfaces/kits/cj/` | `include/cj_huks_ffi.h`, `src/*.cpp` |
| 修改内部 SDK 接口 | `interfaces/inner_api/huks_standard/main/` | `include/hks_api.h`, `hks_param.h`, `hks_type.h`, `hks_tag.h`, `hks_type_enum.h`, `huks_hdi.h` |
| 修改 SDK 框架逻辑 | `frameworks/huks_standard/main/core/` | `core/include/*.h`, `core/src/*.c` |
| 修改密钥管理服务核心 | `services/huks_standard/huks_service/main/core/` | `hks_client_service.h`, `hks_session_manager.h`, `hks_se_session_manager.h` |
| 修改三段式会话（init/update/finish） | `services/.../huks_service/main/core/` | `hks_session_manager.h`；引擎侧 `huks_engine/main/core/include/hks_core_service_three_stage.h` |
| 修改密钥存储/持久化 | `services/.../huks_service/main/hks_storage/` | `hks_storage.h`, `hks_storage_manager.h`, `hks_storage_adapter.h`, `hks_storage_file_lock.h` |
| 修改密码学运算引擎核心 | `services/huks_standard/huks_engine/main/core/` | `hks_core_interfaces.h`, `hks_core_service_key_generate.h`, `hks_core_service_key_operate_one_stage.h`, `hks_core_service_key_operate_three_stage.h`, `hks_core_service_three_stage.h`, `hks_core_service_key_other.h` |
| 修改密钥证明/Attestation | `services/.../huks_engine/main/core/` | `hks_core_service_key_attest.h` |
| 修改密钥 Blob 加密结构 | `services/.../huks_engine/main/core/` | `hks_keyblob.h` |
| 修改 KeyNode（内存密钥表示） | `services/.../huks_engine/main/core/` | `hks_keynode.h` |
| 修改安全访问控制 | `services/.../huks_engine/main/core/` | `hks_secure_access.h`, `hks_auth.h` |
| 修改权限校验 | `services/.../huks_service/main/os_dependency/idl/ipc/` | `hks_permission_check.cpp`, `hks_permission_check.h` |
| 修改 IPC 服务/序列化 | `services/.../huks_service/main/os_dependency/idl/ipc/` | `hks_ipc_service.c/.h`, `hks_service_ipc_serialization.c/.h` |
| 修改 IPC 接口码（需 CODEOWNERS 评审） | `frameworks/huks_standard/main/common/include/` | `huks_service_ipc_interface_code.h`（见项目约束） |
| 修改 SA/System Ability | `services/.../huks_service/main/os_dependency/sa/` | `hks_sa.cpp/.h`, `hks_sa_interface.cpp/.h`, `sa_profile/` |
| 修改多用户/OS 账户校验 | `services/.../huks_service/main/os_dependency/sa/` | `hks_osaccount_check.cpp/.h` |
| 修改用户认证集成 | `services/.../huks_service/main/systemapi_wrap/useridm/` | useridm 包装 |
| 修改 Access Token 集成 | `services/.../huks_service/main/systemapi_wrap/at_wrapper/` | at_wrapper |
| 修改 Bundle/包名集成 | `services/.../huks_service/main/systemapi_wrap/bms/` | bms |
| 修改安全元素（SE）集成 | `services/.../huks_service/main/systemapi_wrap/se/` | se |
| 修改密钥升级逻辑 | `services/.../huks_service/main/upgrade/`，`core/include/hks_upgrade_helper.h`, `hks_upgrade_key_accesser.h`；引擎侧 `huks_engine/main/core/include/hks_upgrade_key.h` |
| 修改芯片平台解密 | `services/.../huks_engine/main/core/` | `hks_chipset_platform_decrypt.h` |
| 修改 SM 导入包装密钥 | `services/.../huks_engine/main/core/` | `hks_sm_import_wrap_key.h` |
| 修改设备证书管理 | `services/.../huks_engine/main/device_cert_manager/`，`os_dependency/sa/hks_dcm_callback_handler.*` | — |
| 修改加密扩展能力（ukey） | `services/.../huks_service/extension/`，`interfaces/js/crypto_extension_module/` | — |
| 修改轻量/小系统实现 | `frameworks/huks_lite/`, `interfaces/inner_api/huks_lite/`, `interfaces/kits/liteapi/` | — |
| 修改构建开关 | `build/config.gni`，`huks.gni` | 见"构建开关"表 |
| 修改运行参数 | `etc/huks.para`, `etc/huks.para.dac` | — |
| 修改测试 | `test/unittest/huks_standard_test/`，`test/fuzz_test/` | 见"构建和验证" |

### 嵌套指引

本仓库无目录级别的嵌套 AGENTS.md。所有任务级指导以本文件为准；领域背景知识见下方"知识索引"，直接路由到对应源码头文件与配置文件。

## 构建和验证

构建基于 GN，从 OpenHarmony 源码根目录执行，**不在本子目录执行**。`os_level` 决定构建分支（standard/small/mini，对应 L2 标准系统 / L1 小系统 / L0 mini 系统）。产品与系统级别对应：`rk3568`=L2 standard、`ipcamera_hispark_taurus_linux`=L1 small、`wifiiot_hispark_pegasus`=L0 mini。

```sh
# ===== 标准系统（rk3568）=====
# 构建整个 HUKS 组件（fwk + service）
./build.sh --product-name=rk3568 --build-target out/rk3568/build_configs/security/huks:huks --no-prebuilt-sdk

# 构建并运行 TDD/FUZZ 测试用例
./build.sh --product-name=rk3568 --build-target out/rk3568/build_configs/security/huks:huks_test --no-prebuilt-sdk

# ===== mini 系统 =====
./build.sh --no-prebuilt-sdk --product-name wifiiot_hispark_pegasus

# ===== small 系统 =====
./build.sh --no-prebuilt-sdk --product-name ipcamera_hispark_taurus_linux
```

### 关键测试目标（test/BUILD.gn）

| 测试目标 | 路径 | 覆盖 |
| --- | --- | --- |
| `huks_module_test` | `unittest/huks_standard_test/module_test/` | 模块级接口测试 |
| `huks_mock_test` | `unittest/huks_standard_test/module_test/mock/` | Mock 环境测试 |
| `hukssdk_test` | `unittest/huks_standard_test/interface_inner_test/sdk_test/` | SDK 接口测试 |
| `huks_mt_test` | `unittest/huks_standard_test/interface_inner_test/alg_module_test/` | 算法模块多线程测试 |
| `crypto_engine_unit_test` | `unittest/huks_standard_test/crypto_engine_test/` | 引擎核心算法测试 |
| `huks_storage_test` | `unittest/.../service_test/huks_service/storage/` | 存储层测试 |
| `service_ipc_test` | `unittest/.../service_test/huks_service/os_dependency/idl/ipc/` | IPC 测试 |
| `huks_useridm_wrap_test` | `unittest/.../service_test/huks_service/systemapi_wrap/useridm_test/` | 用户认证包装测试 |
| `huks_file_transfer_config_parser_test` | `unittest/.../upgrade/file_transfer/config_parser/` | 升级配置解析测试 |
| `huks_multithread_test` | `unittest/huks_standard_test/storage_multithread_test/` | 存储多线程测试 |
| `huks_UT_test` | `unittest/huks_standard_test/three_stage_test/` | 三段式会话测试 |
| `fuzztest` | `test/fuzz_test/`（`hksserviceonremoterequest_fuzzer`, `innerapi_fuzzer`） | Fuzz |
| `huks_stability_test` | `test/reliability/` | 可靠性测试 |

### 构建开关（build/config.gni、huks.gni）

| 开关 | 默认 | 说明 |
| --- | --- | --- |
| `huks_security_level` | `"software"` | `software` 时编译 `huks_engine_core_standard`；商用须改为 TEE/安全芯片实现 |
| `os_level` | — | `standard`/`small`/`mini`，决定构建分支 |
| `hks_enable_test` | `false` | 上传代码必须为 false |
| `enable_hks_coverage` | `false` | 覆盖率 |
| `enable_hks_mock` | `false` | Mock 模式 |
| `huks_enable_ukey_config` | `false` | PC ukey 配置 |
| `huks_use_rkc_in_standard` | `false` | 标准系统是否使用 RKC |
| `huks_key_version` | `"3"` | 密钥版本 |
| `huks_key_store_standard_path` | `/data/service/el1/public/huks_service` | 标准系统密钥存储路径 |
| `huks_enable_upgrade_key` | `true` | 密钥文件自动升级 |
| `huks_enable_upgrade_rkc_v1tov2` | `true` | RKC v1→v2 升级 |
| `huks_uid_trust_list_define` | `"{}"` | 改密钥 owner 的 uid 白名单 |
| `huks_change_storage_level_config` | `"{ 0, 3333, 5520 }"` | 改存储级别的信任列表 |
| `use_crypto_lib` | `"openssl"` | 底层密码库 |

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已提交** - 使用 `git commit -s`，多代理协作时添加 `Co-Authored-By: Agent`
2. **本地构建通过** - 执行上述构建命令，至少 `huks_components` 构建通过
3. **相关测试通过** - 按改动区域选择对应测试目标（改引擎跑 `crypto_engine_unit_test`；改存储跑 `huks_storage_test`/`huks_multithread_test`；改 IPC 跑 `service_ipc_test`；改三段式跑 `huks_UT_test`；改 SDK 跑 `hukssdk_test`/`huks_module_test`；改算法跑 `huks_mt_test`）
4. **公共 API 兼容性确认（如适用）** - 涉及 API/序列化/密钥格式改动需确认不破坏兼容性（见项目约束）
5. **板侧/真机验证（如适用）** - 涉及 TEE、安全芯片、密钥存储、用户认证的改动需提供板侧证据
6. **文档更新（如适用）** - 公共 API 修改需更新注释

### 如果无法运行验证

明确说明无法运行的原因，列出推荐的验证步骤供人工执行，标记需要人工验证的部分。若本地无 OpenHarmony 源码树，至少保证改动文件可独立编译（`gn gen` + `ninja` 单文件目标）。

### 完成报告格式

报告应包含：改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（API 兼容性、密钥格式兼容性、安全边界、性能风险）、未完成事项。

## 知识索引

本仓库无独立 `docs/` 目录。改动前按场景读取对应源码头文件与配置文件，理解接口契约与不变量。

### 场景与路径路由

| 场景 | 修改目录 | 先读 |
| --- | --- | --- |
| 三段式会话（init/update/finish）、密钥运算流程、KeyNode 生命周期 | `huks_service/main/core/`、`huks_engine/main/core/` | `hks_session_manager.h`、`hks_core_service_three_stage.h`、`hks_core_service_key_operate_three_stage.h`、`hks_keynode.h` |
| 密钥 Blob 加密结构、持久化密钥格式、密钥版本兼容 | `huks_engine/main/core/` | `hks_keyblob.h`、`hks_upgrade_key.h`；`huks.gni` 中 `huks_key_version` |
| 密钥存储、文件锁、多线程存储 | `huks_service/main/hks_storage/` | `hks_storage.h`、`hks_storage_manager.h`、`hks_storage_file_lock.h`；`build/config.gni` 中 `huks_key_store_standard_path` |
| 权限校验、Access Token、访问控制 | `huks_service/main/os_dependency/idl/ipc/`、`systemapi_wrap/at_wrapper/`、`huks_engine/main/core/` | `hks_permission_check.h`、`hks_secure_access.h`、`hks_auth.h`；`config.gni` 中 `huks_uid_trust_list_define`、`huks_change_storage_level_config` |
| IPC 接口、序列化、接口码 | `os_dependency/idl/ipc/`、`frameworks/huks_standard/main/common/include/` | `hks_ipc_service.h`、`hks_service_ipc_serialization.h`、`huks_service_ipc_interface_code.h`（CODEOWNERS 评审） |
| 密钥升级、版本迁移、RKC v1→v2 | `huks_service/main/upgrade/`、`huks_engine/main/core/` | `hks_upgrade_helper.h`、`hks_upgrade_key.h`、`hks_upgrade_key_accesser.h`；`config.gni` 中 `huks_enable_upgrade_*` |
| 用户认证、多用户 | `systemapi_wrap/useridm/`、`screen_lock_wrapper/`、`os_dependency/sa/hks_osaccount_check.*` | 对应 wrapper；`huks.gni` 中 `enable_user_auth_framework` |
| 密钥证明（Attestation） | `huks_engine/main/core/`、`device_cert_manager/` | `hks_core_service_key_attest.h`、`hks_dcm_callback_handler.*` |
| 芯片平台解密、安全环境（TEE）集成 | `huks_engine/main/core/` | `hks_chipset_platform_decrypt.h`；`config.gni` 中 `huks_security_level` |
| NDK/NAPI/CJ 公共 API 行为 | `interfaces/kits/*` | 对应 `*.h` 头文件、`.map` 版本符号文件 |
| 构建、板侧测试、SA 配置 | 任意构建/测试改动 | `BUILD.gn`、`build/config.gni`、`huks.gni`、`huks_service.cfg`、`huks_service.rc`、`etc/huks.para` |
| 应用 API 行为、算法规格、密钥材料格式、参数集 | `interfaces/kits/*`、`huks_engine/main/core/` | 官方开发指南对应页（见“官方开发指南路由”）；`hks_tag.h`/`hks_type.h` 中的 Tag 与枚举 |

### 词汇路由

任务描述、日志、issue、API 或文件中出现以下术语时，先理解其指向的源码与配置：

| 术语 | 含义与去向 |
| --- | --- |
| KeyBlob | 密钥的加密持久化容器。读 `huks_engine/main/core/include/hks_keyblob.h` |
| KeyNode | 密钥在内存中的运行时表示。读 `hks_keynode.h` |
| RKC（Root Key Component） | 根密钥组件。读 `hks_upgrade_key.h`；`config.gni` 中 `huks_use_rkc_in_standard`、`huks_enable_upgrade_rkc_v1tov2` |
| 三段式 / three-stage | init→update→finish 异步密钥运算。读 `hks_core_service_three_stage.h`、`hks_session_manager.h` |
| Secure Access | 密钥访问控制（基于访问控制标签）。读 `hks_secure_access.h`、`hks_auth.h` |
| Attestation | 密钥证明。读 `hks_core_service_key_attest.h` |
| HDI | Hardware Device Interface。读 `interfaces/inner_api/huks_standard/main/include/huks_hdi.h`；`config.gni` 中 `huks_enable_hdi_in_standard` |
| ukey | PC 环境外部密钥。读 `services/huks_standard/huks_service/extension/`；`config.gni` 中 `huks_enable_ukey_config` |
| DCM | Device Cert Manager。读 `huks_engine/main/device_cert_manager/`、`hks_dcm_callback_handler.*` |
| uid trust list | 改密钥 owner 的白名单。`config.gni` 中 `huks_uid_trust_list_define` |
| storage level trust list | 改存储级别信任列表。`config.gni` 中 `huks_change_storage_level_config` |
| `.map` 文件 | 版本符号导出映射，API 兼容性。各 `lib*.map` 文件 |
| 密钥材料格式 | 导入/导出密钥的二进制布局：密钥对=Header+原文（RSA/ECC/Curve25519 等各异），公钥用 X.509 DER 封装。读 `huks-concepts.md` |
| 数字信封导入（envelop key） | 经数字信封安全导入密钥的机制。读 `huks-key-import-overview.md`（数字信封页 `huks-import-envelop-key-arkts.md` / `-ndk.md`） |
| 群组密钥（group key） | API 23+ 跨应用共享密钥特性。读 `huks-group-key-overview.md` |
| Provider / 资源管理 | ukey 外部密钥扩展能力：Provider 注册/注销、资源管理（获取资源 ID、打开/关闭资源）。读 `huks-external-hardware-key-management-overview.md`；实现见 `services/.../extension/` |
| CryptoExtensionAbility | 驱动 HAP 继承以实现外部密钥管理扩展的 ExtensionAbility（Stage 模型派生类）。读 `huks-extension-ability-support-overview.md`；实现见 `interfaces/js/crypto_extension_module/` |
| 匿名/离线匿名/非匿名证明 | 密钥证明模式（匿名/离线匿名/非匿名；非匿名仅系统应用，需 `ohos.permission.ATTEST_KEY`）。读 `huks-key-attestation-overview.md`；实现见 `hks_core_service_key_attest.h` |
| 必选规格/可选规格 | 算法规格分级：必选规格为所有厂商均支持的规格（建议使用以保证全平台兼容），可选规格由厂商决定是否实现。读各 `huks-*-overview.md` |
| initSession/updateSession/finishSession/abortSession | 三段式会话应用层 API 名。读 `huks-key-use-overview.md`；服务侧 `hks_session_manager.h`、引擎侧 `hks_core_service_three_stage.h` |

### 官方开发指南路由

应用层 API 行为、算法规格、参数集、密钥材料格式以官方《Universal Keystore Kit 开发指南》为准，改动 `interfaces/kits/*` 或引擎算法规格前必先对照对应页。

基线目录：`https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/`（目录下各 `huks-*.md`，索引见 `Readme-CN.md`）

| 改动主题 | 先读页（相对基线目录） |
| --- | --- |
| 整体架构 / 三层职责 / API 范围 | `huks-overview.md` |
| 基础概念（TEE、密钥材料格式、X.509 DER 公钥封装） | `huks-concepts.md` |
| 密钥使用通用流程（initSession/updateSession/finishSession/abortSession、会话超时） | `huks-key-use-overview.md` |
| 密钥生成算法规格 | `huks-key-generation-overview.md` |
| 密钥导入（明文 / 安全导入 wrapped key / 数字信封 envelop key） | `huks-key-import-overview.md` |
| 加解密算法规格（AES/RSA/SM4/SM2/DES/3DES、必选/可选规格、API 级别） | `huks-encryption-decryption-overview.md` |
| 签名/验签算法规格 | `huks-signing-signature-verification-overview.md` |
| 密钥协商算法规格 | `huks-key-agreement-overview.md` |
| 密钥派生算法规格 | `huks-key-derivation-overview.md` |
| HMAC 算法规格 | `huks-hmac-overview.md` |
| 访问控制（用户身份认证 / 细粒度） | `huks-identity-authentication-overview.md` |
| 密钥证明（匿名 / 离线匿名 / 非匿名仅系统应用） | `huks-key-attestation-overview.md` |
| 群组密钥（API 23+） | `huks-group-key-overview.md` |
| 外部密钥管理扩展（ukey / Provider / 资源 / CryptoExtensionAbility） | `huks-external-hardware-key-management-overview.md` |

> 算法规格分“必选规格”与“可选规格”：改动引擎算法不得移除已支持的“必选规格”，否则破坏全平台兼容（见各 `huks-*-overview.md` 算法规格表）。涉及新 API 须确认 API 级别标注。

### 开始编辑前

按以下顺序确认：
1. 确认任务类别（API / 框架 / 服务 / 引擎 / 存储 / IPC / 测试 / 构建）
2. 根据上表确定需要阅读的源码头文件与配置
3. 根据"项目约束"确认不违反任何约束
4. 声明："我将修改 X，已阅读 Y 文件，遵循 Z 约束"

## 项目约束

### 性能约束

- 密钥运算（init/update/finish）和加解密是高频/热路径，不要在每次运算中增加全量扫描、字符串格式化或 INFO 日志。
- 三段式会话的 update 可被多次调用，避免在 update 路径中分配可避免内存或做重计算。
- 密钥存储加锁路径（`hks_storage_file_lock`）避免长耗时操作阻塞并发密钥访问。

### 架构约束

- 三层归属保持显式：API 契约在 `interfaces/`，框架逻辑在 `frameworks/huks_standard/main/core`，服务管理在 `huks_service/main/core`，密码学运算在 `huks_engine/main/core`。不要把引擎运算逻辑塞进服务层，也不要把服务管理逻辑塞进引擎层。
- 安全环境边界不可模糊：`huks_security_level=software` 时引擎核心编译为 `huks_engine_core_standard`；商用须在 TEE/安全芯片实现。不要为软件实现而绕过安全访问控制（`hks_secure_access`）。
- KeyNode 与 KeyBlob 的职责分离：KeyBlob 是持久化加密容器，KeyNode 是运行时内存表示。不要把运行时状态写回 KeyBlob 持久化层。
- 密钥升级路径独立：`huks_service/main/upgrade/` 与引擎侧 `hks_upgrade_key.h` 处理版本迁移，不要在主密钥管理路径内联升级逻辑。

### 编码约定

- C/C++ 改动优先复用项目内已有的返回约定与宏（如 `HKS_SUCCESS`/`HKS_FAILURE`、`HKS_IF_NOT_SUCC_LOGE` 等），不要引入风格不一致的错误处理。
- 优先使用项目已有的日志宏（`HUKS_LOG*` / `hilog` 包装），不要混用 `printf`。
- 错误码使用 `hks_error_code.h` 中已定义值，不要新增冗余错误码除非确认现有无法覆盖。

### 公共 API 约束

**Do not（禁止）：**
- 修改已发布的 NDK C API（`interfaces/kits/c/include/native_huks_*.h`）、NAPI JS API（`interfaces/kits/napi/`）、CJ FFI API（`interfaces/kits/cj/include/cj_huks_ffi.h`）、内部 SDK（`inner_api/huks_standard/main/include/hks_api.h`/`hks_param.h`/`hks_type.h`）的签名、参数类型、返回值类型
- 修改已有 API 的错误码（`hks_error_code.h`）除非明确标注为废弃
- 删除或重命名已有公共 API 符号（`.map` 文件定义导出符号）
- 修改已有 API 的行为语义（如异步变同步、阻塞变非阻塞、默认安全级别变化）
- 修改 `hks_type.h`/`hks_type_enum.h`/`hks_tag.h` 中已发布的枚举值与 Tag 值（破坏二进制兼容）

**Ask before（修改前必须确认）：**
- 新增公共 API：确认是否需要权限检查、DFX 日志、HiSysEvent 上报
- 修改内部 SDK 接口（`inner_api`）：评估是否影响跨组件兼容性
- 修改错误处理逻辑：确认是否影响应用层的错误码兼容性

### 安全与权限边界

**Do not（禁止）：**
- 绕过 `hks_permission_check`（`os_dependency/idl/ipc/hks_permission_check.cpp`）中的权限校验逻辑
- 绕过 `hks_secure_access.h` / `hks_auth.h` 中的密钥访问控制
- 在未验证的情况下直接使用跨进程传递的文件描述符、共享内存或 Parcel 数据
- 将密钥明文、密钥材料、口令等敏感信息写入非安全日志或 HiSysEvent
- 修改 `huks_uid_trust_list_define`、`huks_change_storage_level_config` 等信任列表配置而不经安全评审
- 修改涉及多用户/多账户访问控制的逻辑（`hks_osaccount_check`）除非经过安全评审
- 关闭或弱化 `huks.gni` 中 `enable_user_auth_framework` 相关校验

**Ask before（修改前必须确认）：**
- 涉及 Access Token（`systemapi_wrap/at_wrapper/`）相关代码的改动
- 涉及用户认证（`systemapi_wrap/useridm/`）改动
- 涉及安全元素（SE，`systemapi_wrap/se/`）改动
- 涉及密钥证明、设备证书管理（DCM）改动
- 涉及 TEE / 安全芯片集成（`huks_security_level` 非 software）的改动
- 修改权限校验白名单或 uid 信任列表

### 协议与数据格式兼容性

**Do not（禁止）：**
- 修改 IPC 序列化顺序或 Parcel 数据布局（`hks_service_ipc_serialization.c`）
- 修改 `huks_service_ipc_interface_code.h` 中的接口码值/顺序——此文件受 `CODEOWNERS` 保护，任何改动需 `@leonchan5` 评审
- 修改 KeyBlob 持久化数据结构布局（`hks_keyblob.h`）而不处理密钥版本兼容（`huks_key_version`、`hks_upgrade_key.h`）
- 修改密钥存储文件格式/路径（`huks_key_store_standard_path`）而不提供升级迁移
- 修改 `.map` 版本符号映射文件以删除已有导出符号

**Ask before（修改前必须确认）：**
- 新增 IPC 接口码：需在 `huks_service_ipc_interface_code.h` 新增（需 CODEOWNERS 评审），并确认跨版本兼容
- 修改密钥版本：确认 `huks_enable_upgrade_*` 升级路径覆盖迁移
- 修改底层密码库切换（`use_crypto_lib` openssl/mbedtls）：确认算法输出一致

### 生成代码边界

**Do not（禁止）：**
- 手动编辑 IDL 编译器生成的 IPC Proxy/Stub 代码（`os_dependency/idl/ipc` 中生成部分）
- 直接修改由构建系统生成的 `.map` 符号导出

**正确做法：**
- 修改 IDL 定义文件后重新运行 IDL 编译器生成代码
- 新增导出符号通过源码声明，构建系统生成 `.map`

### 设备与安全环境约束

**涉及真实设备/安全环境时：**
- 不执行可能影响设备密钥、密钥存储区或安全环境的破坏性操作（如批量删密钥、改 RKC）
- 商用版本（`huks_security_level` 非 software）改动必须在 TEE/安全芯片环境验证，提供板侧证据（日志、HiSysEvent 输出）
- 密钥存储路径（`/data/service/el1/public/huks_service`）的访问需权限检查，不要直接读写
- 涉及密钥证明/DCM 的改动需在支持证明的设备上验证

## 关键风险总结

改动前自检是否触及以下高风险项之一，若触及则升级评审：

1. **公共 API 签名/枚举/Tag/错误码** → 二进制兼容破坏
2. **IPC 接口码 / 序列化顺序 / `huks_service_ipc_interface_code.h`** → 跨进程兼容破坏（需 CODEOWNERS 评审）
3. **KeyBlob 格式 / 密钥版本 / 存储路径** → 已有密钥无法解密或迁移失败
4. **权限校验 / Secure Access / 信任列表** → 安全边界被绕过
5. **引擎核心算法输出** → 密码学正确性/安全性问题
6. **用户认证 / 多用户** → 访问控制越权
7. **安全环境（TEE/安全芯片）集成** → 商用密钥保护失效
