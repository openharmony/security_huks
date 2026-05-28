# HUKS Fuzzer 修改执行记录

## 一、基础信息

| 项目 | 值 |
|------|-----|
| 基础分支 | `pr_2102`（来自 gitcode.com/openharmony/security_huks MR 2102） |
| 工作分支 | `fix_fuzz_on_pr2102` |
| PR 2102 commits | `94805f54 refactor fuzz 1` + `fdcd58e7 refactor fuzz 2` |
| PR 2102 修改范围 | 100个文件，+1888/-1246行 |

## 二、PR 2102 已完成的改造（确认可用部分）

PR 2102 的改造质量较好，主要完成了：

1. **新增 `hks_fuzz_util.h/cpp` 基础设施**：
   - `ConstructParamSetFromFdp(FuzzedDataProvider &fdp)` — 使用 `HKS_VALID_TAGS[]` 随机选择合法 tag，生成语义更有效的 ParamSet
   - `ConstructGenKeyParamSetFromFdp(FuzzedDataProvider &fdp)` — 生成包含算法/密钥大小/用途等核心参数的密钥生成 ParamSet
   - `ConstructParamSetAddFuzzData(const WrapParamSet&, FuzzedDataProvider &)` — 在已有 ParamSet 上追加 fuzz 参数
   - `HksFuzzGenerateKey(FuzzedDataProvider&, HksBlob&)` — 辅助密钥生成
   - `HksFuzzInitWithGoldenPath()` — 初始化黄金路径（RSA/ECC/AES/HMAC 完整生命周期）

2. **新增 `hks_fuzz_stats.h`**：`FuzzStatsRecord(int32_t result)` 统计 API 返回码分布

3. **新增 `hks_valid_tags.h` + `hks_param.c` 扩展**：`HKS_VALID_TAGS[]` 数组包含所有合法 HKS tag 值

4. **所有 fuzzer 统一模式**：
   - `LLVMFuzzerTestOneInput` 在全局作用域（namespace 外）
   - `DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)` 在 `namespace OHOS::Security::Hks` 内
   - `LLVMFuzzerInitialize` 调用 `HksFuzzInitWithGoldenPath()`
   - 调用 `FuzzStatsRecord(ret)` 记录统计

5. **BUILD.gn 修改**：将 `hks_fuzz_util` 提取为 `ohos_static_library`，各 fuzzer 通过 `deps` 引用

## 三、发现的问题清单

### P0：编译/链接问题（必须修复）

无。PR 2102 的 namespace 结构是正确的，编译应该能通过。

### P1：功能/逻辑问题（应修复）

| # | 文件 | 行号 | 问题描述 | 修复方案 |
|---|------|------|---------|---------|
| P1-1 | `hksconcurrent_fuzzer.cpp` | 943 | `FuzzHash` 被错误映射到 `HKS_MSG_MAC`，与 `FuzzMac`(942行) 重复使用同一消息码，导致统计混淆 | 将 `HKS_MSG_MAC` 改为独立负数 code（如 `-5`），与 `FuzzMac` 区分 |
| P1-2 | `hksencrypt_fuzzer.cpp` | 25-30 | 密钥 blob 大小仅 1-32 字节，AES-256 密钥需 32 字节、RSA 密钥需 128-512 字节，大部分密钥生成会因别名太小或格式不对失败 | 增大 blob 大小范围，密钥别名建议 1-64 字节 |
| P1-3 | 多个 fuzzer | - | 密钥别名（keyAlias）blob 仅 1-32 字节，而 HksGenerateKey 要求别名长度 > 0 且有合理长度 | 统一别名大小为 1-64 字节 |
| P1-4 | `hksagreekey_fuzzer.cpp` | - | 使用密钥别名作为 privateKey（协商私钥），但 HksAgreeKey 的 privateKey 参数应是密钥别名而非原始数据 | 改为使用密钥别名 + HksFuzzGenerateKey |

### P2：健壮性问题（建议修复）

| # | 文件 | 行号 | 问题描述 | 修复方案 |
|---|------|------|---------|---------|
| P2-1 | `hks_fuzz_util.cpp` | 505 | 文件末尾 `}}}` 后缺少换行符 | 添加末尾换行符 |
| P2-2 | 所有 50 个 `*_fuzzer.cpp` | - | 没有任何 .cpp 文件直接 `#include <fuzzer/FuzzedDataProvider.h>`，全部依赖 `hks_fuzz_util.h` 的传递 include | 在各 .cpp 中添加显式 include（优先级低，当前可编译） |
| P2-3 | `hks_fuzz_stats.h` | 28-35 | `FuzzStatsRecord` 使用非原子的 `static` 局部变量，在多线程 fuzzer 中存在数据竞争 | 改用 `std::atomic<size_t>` 或在注释中说明仅限单线程 fuzzer |
| P2-4 | `hksrkc_fuzzer/BUILD.gn` | 53,55 | `hilog:libhilog` 重复添加了两次 | 删除重复项 |
| P2-5 | `hksfiletransfer_fuzzer/BUILD.gn` | 47,49 | `hilog:libhilog` 重复添加了两次 | 删除重复项 |
| P2-6 | `hksstorage_fuzzer.cpp` | - | 依赖被 `#include .c` 文件传递的 `securec.h`，自身未显式 include | 添加显式 `#include <securec.h>` |
| P2-7 | `hksfiletransfer_fuzzer.cpp` | - | 同 P2-6 | 添加显式 `#include <securec.h>` |

### P3：改进建议（优先级最低）

| # | 描述 | 备注 |
|---|------|------|
| P3-1 | 删除 `DoSomethingInterestingWithMyAPI` 包装函数，直接在 `LLVMFuzzerTestOneInput` 中写逻辑 | 用户明确要求此为最低优先级 |
| P3-2 | 各 fuzzer 的密钥 blob 大小范围可根据不同 API 调优 | 需逐个分析 |
| P3-3 | `FuzzGoldenPathIpc()` 中 `HksAnonAttestKey` 映射到 `HKS_MSG_ATTEST_KEY_ASYNC_REPLY` 不准确 | 查找正确的 IPC 消息码 |

## 四、修改记录

### Batch 1：修复 P1/P2 问题（已完成 ✅）

**修改原因**：修复功能/逻辑错误、构建配置冗余、健壮性问题

**修改内容**：

| 文件 | 修改 | 状态 |
|------|------|------|
| `hksconcurrent_fuzzer.cpp` L943 | `HKS_MSG_MAC` → `-5`（FuzzHash 统计码与 FuzzMac 区分） | ✅ 已修改 |
| `hks_fuzz_util.cpp` L505 | 添加文件末尾换行符 | ✅ 已修改 |
| `hksrkc_fuzzer/BUILD.gn` L55 | 删除重复 `external_deps += [ "hilog:libhilog" ]` | ✅ 已修改 |
| `hksfiletransfer_fuzzer/BUILD.gn` L49 | 删除重复 `external_deps += [ "hilog:libhilog" ]` | ✅ 已修改 |
| `hksstorage_fuzzer.cpp` L30 | 添加 `#include <securec.h>` 显式 include | ✅ 已修改 |
| `hksfiletransfer_fuzzer.cpp` L18 | 添加 `#include <securec.h>` 显式 include | ✅ 已修改 |

### Batch 3：改造 hksstorage_fuzzer（已完成 ✅）

**修改原因**：原始 fuzzer 的26个测试函数全部硬编码参数（固定 processName/userId/keyAlias），`(void)data; (void)size;` 丢弃 fuzz 输入。且使用 `#include .c` 编译方式。

**改造内容**：
- 保留全部26个原始硬编码函数，新增7个 FDP 驱动的 fuzz 函数
- 新增函数列表：
  1. `FuzzStoreKeyBlob` — fuzz 控制 processInfo/keyAlias/keyBlob/storageType/paramSet
  2. `FuzzGetKeyBlob` — fuzz 控制 processInfo/keyAlias/outputBuf/storageType/paramSet
  3. `FuzzDeleteKeyBlob` — fuzz 控制 processInfo/keyAlias/storageType/paramSet
  4. `FuzzStorageFileLock` — fuzz 控制 path 字符串 + lock/unlock 序列
  5. `FuzzResumeInvalidCharacter` — fuzz 控制 input char（覆盖所有 ASCII 值）
  6. `FuzzInitStorageMaterial` — fuzz 控制 processInfo/authStorageLevel/storageType
  7. `FuzzGetFileInfo` — fuzz 控制 pathType/uidPath/userIdPath/keyAliasPath
- 安全措施：
  - `BuildProcessInfoFromFdp()` 保证 processInfo 所有字段非空合法（防止 `HksManageStore*` 空指针崩溃）
  - `HksStorageFileLockCreate` 内部有 NULL 检查，返回 NULL 时跳过后续操作
  - `HksGetFileInfo` 的 material 字段指向 `std::string::c_str()`，保证 null-terminated
  - 保留 `#include .c` 编译方式不变
- 每次 DoSomethingInterestingWithMyAPI 执行：1-3个硬编码函数（保留覆盖率）+ 1个 FDP 函数（探索新路径）

| 文件 | 修改 | 状态 |
|------|------|------|
| `hksstorage_fuzzer.cpp` | 保留26个硬编码 + 新增7个 FDP 函数 | ✅ 已修改 |

### Batch 3.1：修复 hksstorage_fuzzer 编译错误（已完成 ✅）

**修改原因**：Batch 3 改造后存在2个编译错误

**修改内容**：
1. `HKS_STORAGE_TYPE_CERTCHAIN` 不存在 → 改为 `HKS_STORAGE_TYPE_BAK_KEY`（实际枚举值：KEY=0, ROOT_KEY=1, BAK_KEY=2）
2. `PickValueInArray` 无法推导未指定大小的数组 → 为所有传给 `PickValueInArray` 的 static const 数组添加显式大小：
   - `g_fuzzStorageTypes[3]`、`g_fuzzAuthStorageLevels[4]`、`g_fuzzPathTypes[6]`、`g_fuzzFuncs[7]`、`g_hardcodedFuncs[26]`

| 文件 | 修改 | 状态 |
|------|------|------|
| `hksstorage_fuzzer.cpp` | 修复2个编译错误 | ✅ 已修改 |

### Batch 4：改造 hksfiletransfer_fuzzer（已完成 ✅）

**修改原因**：原始 fuzzer 的14个测试函数全部硬编码参数（固定 g_accessTokenType/g_hapName/userId/uid），`(void)data; (void)size;` 丢弃 fuzz 输入。且使用 `#include .c` 编译方式。

**改造内容**：
- 保留全部14个原始硬编码函数，新增2个 FDP 驱动的 fuzz 函数：
  1. `FuzzParseConfig` — fuzz 控制 accessTokenType(HAP/NATIVE/SHELL)、hapName、uid、userId、accessTokenId、alias
  2. `FuzzFileTransferOnUserUnlock` — fuzz 控制 userId
- 每次 DoSomethingInterestingWithMyAPI 执行：1-3个硬编码函数 + 1个 FDP 函数
- 安全措施：
  - `FuzzParseConfig` 中 `g_hapName` 使用 `static thread_local std::string` 保持生命周期
  - `HksInitParamSet` 失败时提前返回，防止 nullptr 解引用
  - `HksParseConfig` 的 alias 参数使用 `std::string::c_str()`，保证 null-terminated
  - 保留 `#include .c` 编译方式不变
- 使用 PR 2102 统一模式：`LLVMFuzzerInitialize` + `FuzzStatsRecord`

| 文件 | 修改 | 状态 |
|------|------|------|
| `hksfiletransfer_fuzzer.cpp` | 保留14个硬编码 + 新增2个 FDP 函数 + PR 2102 模式 | ✅ 已修改 |

---

## 五、关键设计决策记录

| 决策 | 原因 | 日期 |
|------|------|------|
| 在 PR 2102 分支上工作而非 cherry-pick | 当前分支与 PR 2102 基础不同，cherry-pick 冲突过多 | 2026-05-27 |
| 保留 `DoSomethingInterestingWithMyAPI` 函数 | 用户明确要求此为最低优先级，先不动 | 2026-05-27 |
| 最小化修改原则 | 每步修改需可编译验证，逐步推进 | 2026-05-27 |
| "保留+补充"改造策略 | 保留硬编码函数保证已有覆盖率不下降，新增 FDP 函数探索新路径 | 2026-05-28 |
| `PickValueInArray` 数组需显式大小 | 模板无法从 `const T[]` 推导数组大小，必须用 `const T[N]` | 2026-05-28 |
| `HKS_STORAGE_TYPE_CERTCHAIN` → `HKS_STORAGE_TYPE_BAK_KEY` | `HKS_STORAGE_TYPE_CERTCHAIN` 不存在，实际枚举仅有 KEY/ROOT_KEY/BAK_KEY | 2026-05-28 |
