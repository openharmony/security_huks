# HUKS Inner API Fuzzer 覆盖率改进计划

## 一、当前现状

### 1.1 整体覆盖率数据（2026-05-26）

| 指标 | 命中 | 总计 | 覆盖率 |
|------|------|------|--------|
| 行覆盖 | 5538 | 9271 | **59.7%** |
| 函数覆盖 | 574 | 853 | **67.3%** |
| 分支覆盖 | 1999 | 5590 | **35.8%** |

### 1.2 各模块覆盖率（按升序排列，重点关注低覆盖模块）

| 模块路径 | 行覆盖率 | 函数覆盖率 | 分支覆盖率 | 关注优先级 |
|---------|---------|-----------|-----------|-----------|
| huks_service/main/ha | 20.6% | 25.7% | 5.8% | P0 |
| huks_service/main/upgrade/lock | 15.4% | 42.9% | 8.3% | P0 |
| huks_service/main/plugin_proxy | 38.6% | 33.3% | 25.6% | P1 |
| huks_service/main/upgrade/file_transfer | 38.8% | 54.2% | 17.1% | P1 |
| huks_service/main/core | 43.9% | 51.8% | 24.0% | P1 |
| huks_service/main/os_dependency/sa | 28.3% | 51.8% | 11.1% | P1 |
| huks/utils/file_operator | 47.5% | 77.8% | 31.0% | P1 |
| huks_service/main/common | 48.3% | 53.7% | 35.8% | P1 |
| huks_service/main/hks_storage | 56.1% | 73.4% | 33.4% | P1 (storage fuzzer相关) |
| huks_service/main/systemapi_wrap/at_wrapper | 56.1% | 75.0% | 36.4% | P2 |
| huks_service/main/os_dependency/posix | 62.9% | 80.0% | 43.8% | P2 |
| huks_service/main/crypto_engine/rkc | 63.9% | 60.9% | 37.4% | P1 (rkc fuzzer相关) |
| huks_service/main/os_dependency/idl/ipc | 63.5% | 62.6% | 35.8% | P2 |
| huks/utils/mutex | 66.0% | 100% | 45.8% | P2 |
| huks_service/main/os_dependency/ipc | 83.0% | 93.0% | 53.6% | 已较好 |
| huks_service/main/systemapi_wrap/hisysevent_wrapper | 84.3% | 100% | 58.5% | 已较好 |
| interfaces/inner_api/huks_standard/source | 88.8% | 100% | 56.9% | 已较好 |
| huks_service/main/crypto_engine/openssl | 95.0% | 100% | 61.5% | 已达标 |
| huks_service/main/systemapi_wrap/hitrace_meter_wrapper | 100% | 100% | - | 已达标 |

### 1.3 Fuzzer 问题全景分类

#### 类别A：完全无效 Fuzzer（丢弃全部 fuzz 输入，0% fuzz 覆盖率）

以下 6 个 fuzzer 完全使用 `(void)data; (void)size;` 丢弃 fuzz 输入，等价于固定单测循环执行，libFuzzer 的变异引擎无法驱动任何新路径：

| Fuzzer | 问题描述 | 影响的模块 | 测试函数数 |
|--------|---------|-----------|-----------|
| `hksclientipcserialization_fuzzer` | 9个函数全部硬编码参数 | `os_dependency/ipc`(~83%), `common/src` | 9 |
| `hksfiletransfer_fuzzer` | 14个函数全部硬编码，含`#include .c`直接编译 | `upgrade/file_transfer`(38.8%) | 14 |
| `hksipc_fuzzer` | 34个函数全部硬编码(11个序列化+23个IPC服务) | `os_dependency/ipc`(83%), `os_dependency/idl/ipc`(63.5%), `core`(43.9%) | 34 |
| `hksrkc_fuzzer` | 1个函数硬编码，含`#include .c`直接编译 | `crypto_engine/rkc`(63.9%) | 1 |
| `hksstorage_fuzzer` | 26个函数全部硬编码，含`#include .c`直接编译 | `hks_storage`(56.1%), `file_operator`(47.5%), `mutex`(66%), `common`(48.3%) | 26 |
| `hksreportwrapper_fuzzer` | 2个函数全部硬编码 | `ha`(20.6%) | 2 |

#### 类别B：近乎无效 Fuzzer（调用无参数API或仅1条路径，~0% fuzz 覆盖率）

| Fuzzer | 问题描述 | 影响的模块 |
|--------|---------|-----------|
| `hksinitialize_fuzzer` | `(void)size;` 调用 `HksInitialize()` 无参数API，仅1条路径 | core(初始化逻辑) |
| `hksrefreshkeyinfo_fuzzer` | `(void)size;` 调用 `HksRefreshKeyInfo()` 无参数API，仅1条路径 | core(刷新逻辑) |
| `hksgeterrormsg_fuzzer` | 调用 `HksGetErrorMsg()` 无参数API，仅1条路径 | common/src |
| `hksgetsdkversion_fuzzer` | 仅测试输出buffer大小，内容被覆盖无意义 | interfaces/inner_api |
| `hksprocessattestkeyasyncreply_fuzzer` | 仅测试1种IPC消息类型(HKS_MSG_ATTEST_KEY_ASYNC_REPLY)，无参数变异 | os_dependency/ipc |

#### 类别C：弱 Fuzzer（结构性问题，低覆盖率，44个）

**子类C1：Tiny-Blob 问题（sizeof(uint32_t)=4字节，21个）**

所有 HksBlob 参数仅为 4 字节，crypto 操作需要 16-4096+ 字节，几乎所有调用在参数校验阶段失败：

| Fuzzer | Tiny blob | 深层路径缺失 |
|--------|----------|-------------|
| `hksencrypt_fuzzer` | key/plainText/cipherText=4B | AES/RSA/SM4加密路径 |
| `hksdecrypt_fuzzer` | key/cipherText/plainText=4B | AES/RSA/SM4解密路径 |
| `hkssign_fuzzer` | key/srcData/signature=4B | RSA/ECC/DSA/SM2签名路径 |
| `hksverify_fuzzer` | key/srcData/signature=4B | RSA/ECC/DSA/SM2验签路径 |
| `hksmac_fuzzer` | key/srcData/mac=4B | HMAC/SM3 MAC路径 |
| `hksagreekey_fuzzer` | privateKey/peerPublicKey/agreedKey=4B | ECDH/X25519/DH协商路径 |
| `hksderivekey_fuzzer` | mainKey/derivedKey=4B | HKDF/PBKDF2派生路径 |
| `hksclearukeypinauthstate_fuzzer` | resourceId=4B | Ukey资源ID探索 |
| `hkscloseremotehandle_fuzzer` | resourceId=4B | 远程资源探索 |
| `hksopenremotehandle_fuzzer` | resourceId=4B | 远程资源探索 |
| `hksgetukeypinauthstate_fuzzer` | resourceId=4B | Ukey状态探索 |
| `hksauthukeypin_fuzzer` | resourceId=4B | Ukey PIN认证探索 |
| `hksregisterprovider_fuzzer` | providerName=4B | provider注册探索 |
| `hksunregisterprovider_fuzzer` | providerName=4B | provider注销探索 |
| `hksexportprovidercertificates_fuzzer` | providerName=4B | provider证书探索 |
| `hksexportcertificate_fuzzer` | resourceId=4B | 证书导出探索 |
| `hksgetresourceid_fuzzer` | providerName/resourceId=4B | 资源ID解析 |
| `hksgetremoteproperty_fuzzer` | operation/resourceId/propertyId=4B | 属性查询(仅mod 2) |
| `hksrename_fuzzer` | oldKey/newKey=4B | key alias变更 |
| `hksgeneraterandom_fuzzer` | random=4B | 随机数生成(需更大buffer) |
| `hkswrapkey_fuzzer` | key/srcData/mac=4B | wrap/unwrap/Mac路径 |

**子类C2：无效 ParamSet 问题（44个 fuzzer 全部受影响）**

所有弱 fuzzer 使用 `ConstructHksParamSetFromFuzz()` 读取原始垃圾字节作为 HksParam tags，产生几乎100%无效的 paramSet。应使用 `ConstructGenKeyParamSetFromFdp()` 和 `ConstructParamSetFromFdp()` 生成语义有效的参数组合：

| 受影响 Fuzzer | ParamSet 问题 | 应使用的方法 |
|--------------|--------------|-------------|
| hksgeneratekey, hksdeletekey, hkskeyexist, hksgetkeyparamset, hksexportpublickey, hksimportkey, hksimportwrappedkey, hksinit, hksupdate, hksfinish, hksabort, hkshash, hksattestkey, hksanonattestkey, hksanonattestkeyoffline, hksgetcertificatechain, hksvalidatecertchain, hkslistaliases, hkschangestoragelevel, hksgetkeyinfolist 等44个 | `ConstructHksParamSetFromFuzz` 产生随机tag值，几乎不可能形成有效的算法+密钥大小+用途组合 | `ConstructGenKeyParamSetFromFdp`(密钥生成) + `ConstructParamSetFromFdp`(操作参数) |

**子类C3：无密钥生命周期设置（30+个）**

加密/签名/验签/协商/派生/导出/删除/认证等操作都需要密钥先存在，但没有任何 fuzzer 在操作前生成密钥：

| 受影响 Fuzzer | 缺失的密钥设置 |
|--------------|--------------|
| hksencrypt, hksdecrypt, hkssign, hksverify, hksmac, hksagreekey, hksderivekey, hksinit, hksupdate, hksfinish, hksabort, hksexportpublickey, hksdeletekey, hkskeyexist, hksgetkeyparamset, hksattestkey, hksanonattestkey, hksanonattestkeyoffline, hksgetcertificatechain, hksvalidatecertchain, hkslistaliases, hksrename, hkschangestoragelevel, hksgetkeyinfolist, hksimportwrappedkey, hkswrapkey | 需要先 `HksGenerateKey` 创建密钥，再执行操作 |

**子类C4：无多步骤操作链（4个）**

Init/Update/Finish/Abort 各自独立测试，从未链接成完整操作流程：

| Fuzzer | 缺失的操作链 |
|--------|-------------|
| `hksinit_fuzzer` | Init -> Update(s) -> Finish/Abort |
| `hksupdate_fuzzer` | 需先 Init 再 Update |
| `hksfinish_fuzzer` | 需先 Init+Update 再 Finish |
| `hksabort_fuzzer` | 需先 Init 再 Abort |

**子类C5：硬编码输出 buffer（6个）**

CertChain buffer 预分配 4096 字节但零初始化，实际证书内容从未被 fuzz 变异：

| Fuzzer | 问题 |
|--------|------|
| hksattestkey, hksanonattestkey, hksanonattestkeyoffline, hksgetcertificatechain, hksvalidatecertchain, hksexportpublickey | 证书/公钥buffer为空，验证/导出始终失败 |

**子类C6：其他结构性问题**

| Fuzzer | 问题 |
|--------|------|
| `hksbnexpmod_fuzzer` | BN_SIZE=10字节太小，大数运算需至少64+字节 |
| `hksimportcertificate_fuzzer` | 使用 `reinterpret_cast<uint32_t*>(data)` 未对齐指针，UB；手动字节解析脆弱 |
| `hksabort_fuzzer` | 第49行有死代码（return 0 after return 0） |
| `hksqueryabilityinfo_fuzzer` | 仅测试单一API，无ability type变异 |

#### 类别D：优质 Fuzzer（1个）

| Fuzzer | 质量 |
|--------|------|
| `hksconcurrent_fuzzer` | **优秀** - 使用 FuzzedDataProvider，覆盖 40+ API，生成合理大小的 blob，使用 `ConstructGenKeyParamSetFromFdp` 生成有效密钥参数，创建密钥后再操作，链接 init+update+finish/abort，有统计追踪。**唯一弱点：** 每次仅执行1个API(`fdp.PickValueInArray`)，跨API交互模式（如 generate->delete->keyexist）较少被探索 |

#### 1.4 问题根因总结

| 问题类型 | 影响的 Fuzzer 数量 | 覆盖率影响 |
|---------|-------------------|-----------|
| A: 完全丢弃 fuzz 输入 | 6 | 0% fuzz 覆盖率 |
| B: 无参数API/单路径 | 5 | ~0% fuzz 覆盖率 |
| C1: Tiny-Blob(4字节) | 21 | 仅校验失败路径 |
| C2: 无效 ParamSet | 44 | 深层算法路径几乎不可达 |
| C3: 无密钥生命周期 | 30+ | 操作始终失败 |
| C4: 无操作链 | 4 | Init/Update/Finish/Abort 独立失败 |
| C5: 空输出 buffer | 6 | 证书/公钥验证始终失败 |
| C6: 其他结构问题 | 4 | 特定路径不可达 |
| D: 优质 | 1 | 高覆盖率基准 |

**结论：58个 fuzzer 中仅 1 个(1.7%)提供有意义覆盖率。57个 fuzzer 主要执行早期错误返回路径，深层算法路径(RSA/ECC/AES操作、密钥生命周期、IPC序列化、存储管理、RKC管理)几乎从未被 fuzz 到。**

#### 1.5 改造完成状态（2026-05-27）

**所有 57 个问题 fuzzer 已完成改造！** 验证结果：

| 验证指标 | 结果 |
|---------|------|
| 使用 `FuzzedDataProvider` 的 fuzzer | **57/58** (hksconcurrent_fuzzer 也已使用) |
| 仍有 `(void)data; (void)size;` 的 fuzzer | **0** |
| 仍有 `ConstructHksParamSetFromFuzz` 的调用方 | **0** (仅 hks_fuzz_util.cpp 中保留定义) |
| 仍有 `reinterpret_cast<uint32_t*>` UB 的 fuzzer | **0** |
| 仍有 Tiny-Blob (4字节) 的 fuzzer | **0** |

改造详情：
- **44 个弱 Fuzzer (C1-C6)**: 全部改造为 FDP 模式，使用 `ConstructGenKeyParamSetFromFdp` / `ConstructParamSetFromFdp`，密钥操作前99%概率先生成密钥，Init/Update/Finish/Abort 链接为完整操作链
- **5 个近乎无效 Fuzzer (B)**: 全部改造，hksinitialize 增加 HksRefreshKeyInfo 组合，hksgeterrormsg 增加错误码循环，hksprocessattestkeyasyncreply 扩展 IPC 消息类型
- **6 个完全无效 Fuzzer (A)**: 全部改造，hksipc/hksclientipcserialization 用 fuzz 数据驱动 IPC 序列化/反序列化，hksstorage/hksfiletransfer/hksrkc 用 FDP 控制参数变异，hksreportwrapper 用 fuzz 数据填充 processName/userId/errorCode
- **hksabort 死代码**: 已删除
---

## 二、分支目标

### 2.1 总体目标

| 指标 | 当前值 | Phase1-4完成后 | Phase5-7完成后 | 最终目标 |
|------|--------|--------------|--------------|---------|
| 行覆盖率 | 59.7% | ≥65% | ≥68% | **≥70%** |
| 函数覆盖率 | 67.3% | ≥71% | ≥73% | **≥75%** |
| 分支覆盖率 | 35.8% | ≥40% | ≥43% | **≥45%** |

注：当前 59.7% 行覆盖率主要来自 `hksconcurrent_fuzzer` 和已较好的模块(ipc 83%, openssl 95%)。剩余57个fuzzer几乎不贡献新覆盖率，改造后预计行覆盖率可提升10个百分点。

### 2.2 各模块改进目标（按优先级）

| 模块 | 当前行覆盖 | 目标行覆盖 | 负责 Fuzzer |
|------|-----------|-----------|-------------|
| upgrade/file_transfer | 38.8% | ≥55% | hksfiletransfer_fuzzer |
| upgrade/lock | 15.4% | ≥40% | hksfiletransfer_fuzzer |
| hks_storage | 56.1% | ≥70% | hksstorage_fuzzer |
| crypto_engine/rkc | 63.9% | ≥75% | hksrkc_fuzzer |
| core | 43.9% | ≥55% | hksipc_fuzzer | **已完成** ✅ |
| os_dependency/idl/ipc | 63.5% | ≥75% | hksipc_fuzzer, hksclientipcserialization_fuzzer | **已完成** |
| os_dependency/sa | 28.3% | ≥40% | hksipc_fuzzer | **已完成** |
| common/src | 48.3% | ≥60% | hksstorage_fuzzer, hksipc_fuzzer | **已完成** |
| file_operator | 47.5% | ≥60% | hksstorage_fuzzer | **已完成** |
| ha | 20.6% | ≥35% | hksreportwrapper_fuzzer | **已完成** |
| plugin_proxy | 38.6% | ≥50% | hksipc_fuzzer | **已完成** |

### 2.3 各 Fuzzer 改造状态

---

## 三、改进计划

### 3.1 改造原则

1. **安全优先**：fuzz 输入不得导致 fuzzer 崩溃或无限循环；对 fuzz 数据做边界限制
2. **最小改动**：保持现有测试逻辑不变，在关键参数处注入 fuzz 变异
3. **FuzzedDataProvider 驱动**：统一使用 FDP 消费 fuzz 输入，通过 `ConsumeIntegralInRange`、`ConsumeBool`、`PickValueInArray`、`ConsumeBytes` 等方法控制参数
5. **面向覆盖率**：针对各模块未覆盖分支，设计 fuzz 输入变异策略

### 3.2 分步实施

#### Phase 1：基础设施改造（优先级 P0）

**1.1 扩展 hks_fuzz_util 通用工具**

当前 `hks_fuzz_util.h/cpp` 中 `ConstructGenKeyParamSetFromFdp` 和 `ConstructParamSetFromFdp` 仅被 `hksconcurrent_fuzzer` 使用。需要：

- 新增 `ConstructOperationParamSetFromFdp(FuzzedDataProvider &fdp, uint32_t alg, uint32_t keySize)` — 根据已有算法+密钥大小，生成语义有效的操作参数（加密模式、填充、digest 等）
- 新增 `ConsumeRandomBlob(FuzzedDataProvider &fdp, size_t minSize, size_t maxSize)` — 生成大小在 [minSize, maxSize] 范围内的 blob，而非固定4字节
- 新增 `ConsumeHksBlobAlias(FuzzedDataProvider &fdp)` — 生成密钥别名 blob（长度 1-64 字节，内容随机）
- 新增 `ConsumeHksBlobData(FuzzedDataProvider &fdp, size_t minSize)` — 生成数据 blob（长度 minSize~2048 字节）
- 新增 `GenerateKeyThenOperate(FuzzedDataProvider &fdp, uint32_t operation)` — 封装"生成密钥 → 执行操作 → 删除密钥"的完整生命周期
- 新增 `ChainInitUpdateFinish(FuzzedDataProvider &fdp, uint32_t alg, uint32_t keySize)` — 封装"Init → Update(s) → Finish/Abort"的完整操作链
- 确保所有新增工具可被任何 fuzzer 复用

**1.2 修复 FDP 未对齐问题**

- `hksimportcertificate_fuzzer` 的 `reinterpret_cast<uint32_t*>(data)` 需改为使用 `FuzzedDataProvider::ConsumeIntegral<uint32_t>()` 避免UB

#### Phase 2：类别A改造 — 完全无效 Fuzzer（6个） 

**2.1 hksclientipcserialization_fuzzer** 

```
改造方式：用 FuzzedDataProvider 选择执行哪个测试函数，用 fuzz 数据填充 blob/paramSet
- fdp.PickValueInArray 选择测试函数编号 (0-8)
- 用 fdp.ConsumeBytesWithTerminator 生成 blob 数据
- 用 ConstructParamSetFromFdp 生成 paramSet
- 序列化测试：用 fuzz 数据作为 srcData 内容
- 反序列化测试：用 fuzz 数据构造合法 IPC buffer（先序列化再反序列化）
预期：覆盖 os_dependency/ipc、common/src 的更多 Pack/Unpack 分支
```

**2.2 hksfiletransfer_fuzzer** 

```
改造方式：用 fuzz 数据控制 config 内容和变量
- 用 fdp.ConsumeBytes 生成 config 文件内容（替代硬编码宏）
- 用 fdp.ConsumeIntegralInRange 生成 userId/uid/tokenType
- 用 fdp.ConsumeBytesWithTerminator 生成 hapName
- 保留 #include .c 编译方式，但在参数注入处使用 fuzz 数据
预期：覆盖 upgrade/file_transfer(38.8%→≥55%), lock(15.4%→≥40%) 更多分支
```

**2.3 hksipc_fuzzer** 

```
改造方式：用 fuzz 数据选择 IPC 消息类型并注入数据
- fdp.PickValueInArray 选择 IPC 消息类型 (0-15+)
- 将 fuzz 字节注入 srcData blob（替代硬编码的二进制数组）
- 用 fdp.ConsumeBool 决定是否添加特定参数到 paramSet
- 对反序列化函数：构造合法序列化数据后注入 fuzz 变异
预期：覆盖 IPC 反序列化更多错误路径，core(43.9%→≥55%), idl/ipc(63.5%→≥75%)
```

**2.4 hksrkc_fuzzer** 

```
改造方式：用 fuzz 数据变异 KSF 文件内容
- 用 fdp.ConsumeBytes 生成变异的 oldKsfFile 内容（替代硬编码二进制）
- 用 fdp.ConsumeBool 决定是否变异各字段（version、rkIndex、mkEncrypt等）
- 保留 #include .c 编译方式
预期：覆盖 rkc(63.9%→≥75%) 解析更多分支和错误路径
```

**2.5 hksstorage_fuzzer** 

```
改造方式：用 fuzz 数据控制 userId/uid/alias/storageType
- fdp.PickValueInArray 选择存储操作类型
- fdp.ConsumeBytesWithTerminator 生成 processName/keyAlias
- fdp.ConsumeIntegralInRange 生成 userId/uid/storageType
- fdp.ConsumeBool 选择是否使用 InvalidCharacter 路径
- 保留 #include .c 编译方式
预期：覆盖 storage(56.1%→≥70%), file_operator(47.5%→≥60%), common(48.3%→≥60%) 更多路径
```

**2.6 hksreportwrapper_fuzzer**

```
改造方式：用 fuzz 数据变异 processName/userId/errorCode
- fdp.ConsumeBytesWithTerminator 生成 processName
- fdp.ConsumeIntegralInRange 生成 userId
- fdp.ConsumeIntegralInRange 生成 errorCode (0 ~ HKS_ERROR_MAX)
预期：覆盖 ha(20.6%→≥35%) 更多事件上报分支
```

#### Phase 3：类别B改造 — 近乎无效 Fuzzer（5个）

**3.1 hksinitialize_fuzzer**

```
改造方式：组合 HksInitialize + 其他初始化相关API
- 在 HksInitialize 后，用 fuzz 数据决定是否调用 HksRefreshKeyInfo/HksGetSdkVersion 等
- 通过多次初始化（正常+重复初始化）覆盖不同初始化状态分支
预期：覆盖 core 初始化的更多状态分支
```

**3.2 hksrefreshkeyinfo_fuzzer / hksgeterrormsg_fuzzer / hksgetsdkversion_fuzzer**

```
改造方式：这些API本身无参数，改为组合测试
- 将它们合并到一个"基础服务 fuzzer"中，或嵌入其他 fuzzer作为辅助步骤
- hksgeterrormsg: 用 fdp.ConsumeIntegralInRange 选择不同 HksErrorCode，测试错误消息映射
预期：覆盖基础服务的更多分支（但这些API本身分支有限，收益较低）
```

**3.3 hksprocessattestkeyasyncreply_fuzzer**

```
改造方式：扩展IPC消息类型覆盖
- fdp.PickValueInArray 选择多种 IPC 消息类型（不仅仅是 ATTEST_KEY_ASYNC_REPLY）
- 用 fuzz 数据填充 MessageParcel 的不同字段
预期：覆盖更多 IPC 服务处理分支
```

#### Phase 4：类别C1改造 — Tiny-Blob Fuzzer（21个）

**核心改造：用 FuzzedDataProvider 替代 ReadData，生成合理大小的 blob**

```
改造模式（适用于所有21个 Tiny-Blob fuzzer）：

原来：
  uint8_t *keyData = ReadData<uint8_t *>(data, size, sizeof(uint32_t));
  key.data = keyData; key.size = sizeof(uint32_t);  // 仅4字节

改为：
  FuzzedDataProvider fdp(data, size);
  size_t keySize = fdp.ConsumeIntegralInRange<size_t>(16, 2048);
  auto keyData = fdp.ConsumeBytes<uint8_t>(keySize);
  key.data = keyData.data(); key.size = keyData.size();

各 fuzzer 的具体大小范围：
- 密钥 blob: fdp.ConsumeIntegralInRange(16, 2048)  // RSA-1024=128B, RSA-2048=256B
- 数据 blob: fdp.ConsumeIntegralInRange(1, 4096)
- 签名 blob: fdp.ConsumeIntegralInRange(32, 512)
- 别名 blob: fdp.ConsumeIntegralInRange(1, 64)
- resourceId: fdp.ConsumeBytesWithTerminator(1, 64, '\0')
```

#### Phase 5：类别C2改造 — 无效 ParamSet（44个）

**核心改造：全面替换 ConstructHksParamSetFromFuzz 为 FDP 驱动的语义有效 ParamSet**

```
改造模式：

原来：
  struct HksParamSet *paramSet = ConstructHksParamSetFromFuzz(data, size);
  // tag 值为随机垃圾，几乎不可能形成有效组合

改为：
  FuzzedDataProvider fdp(data, size);
  // 密钥生成操作：使用 ConstructGenKeyParamSetFromFdp(fdp) 生成有效算法+密钥大小
  struct HksParamSet *genParamSet = ConstructGenKeyParamSetFromFdp(fdp);
  // 其他操作：使用 ConstructParamSetFromFdp(fdp) 或 ConstructOperationParamSetFromFdp(fdp, alg, keySize)
  struct HksParamSet *opParamSet = ConstructOperationParamSetFromFdp(fdp, alg, keySize);
```

#### Phase 6：类别C3改造 — 无密钥生命周期（30+个）

**核心改造：操作前先生成密钥，操作后删除密钥**

```
改造模式（适用于所有30+个无密钥设置的 fuzzer）：

原来：
  HksEncrypt(keyAlias, paramSet, plainText, cipherText);  // keyAlias对应的密钥不存在，始终失败

改为：
  FuzzedDataProvider fdp(data, size);
  struct HksParamSet *genParamSet = ConstructGenKeyParamSetFromFdp(fdp);
  HksGenerateKey(keyAlias, genParamSet, nullptr);  // 先创建密钥
  // 从 genParamSet 提取算法信息，生成对应的操作参数
  struct HksParamSet *opParamSet = ConstructOperationParamSetFromFdp(fdp, alg, keySize);
  HksEncrypt(keyAlias, opParamSet, plainText, cipherText);  // 密钥存在，操作可能成功
  HksDeleteKey(keyAlias, nullptr);  // 清理密钥

封装为工具函数 GenerateKeyThenOperate(fdp, operation)
```

#### Phase 7：类别C4改造 — 操作链（4个）

**核心改造：合并 init+update+finish/abort 为完整操作链**

```
改造方式：将 hksinit/hksupdate/hksfinish/hksabort 合并改造

原来：4个独立 fuzzer 各测1步，由于缺少前置步骤始终失败
改为：单 fuzzer 或 hksconcurrent_fuzzer 内增加完整操作链

FuzzedDataProvider fdp(data, size);
// 1. 生成密钥
struct HksParamSet *genParamSet = ConstructGenKeyParamSetFromFdp(fdp);
HksGenerateKey(keyAlias, genParamSet, nullptr);
// 2. Init
struct HksParamSet *initParamSet = ConstructOperationParamSetFromFdp(fdp, alg, keySize);
HksInit(keyAlias, initParamSet, &handle, &token);
// 3. Update(s) - 循环次数由 fdp.ConsumeIntegralInRange(1, 5) 控制
for (int i = 0; i < updateCount; i++) {
    HksUpdate(handle, updateParamSet, inData, outData);
}
// 4. Finish 或 Abort - 由 fdp.ConsumeBool 决定
if (fdp.ConsumeBool()) {
    HksFinish(handle, finishParamSet, inData, outData);
} else {
    HksAbort(handle, abortParamSet);
}
// 5. 清理
HksDeleteKey(keyAlias, nullptr);

封装为工具函数 ChainInitUpdateFinish(fdp, alg, keySize)
```

#### Phase 8：类别C5改造 — 空输出 buffer（6个）

```
改造方式：用 fuzz 数据填充证书/公钥 buffer

原来：certChain data 全为0，验证始终失败
改为：
  FuzzedDataProvider fdp(data, size);
  // 1. 先生成密钥 + 设置attest参数
  // 2. certChain outData 用合理大小的空 buffer（libFuzzer环境下attest可能受限）
  // 3. hksvalidatecertchain: 用 fuzz 数据作为证书内容而非空 buffer
  auto certData = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange(64, 4096));
```

#### Phase 9：类别C6改造 — 其他结构性问题（4个）

```
- hksbnexpmod_fuzzer: 将 BN_SIZE 从 10 改为 fdp.ConsumeIntegralInRange(16, 512)
- hksimportcertificate_fuzzer: 替换 reinterpret_cast<uint32_t*> 为 FDP 的 ConsumeIntegral
- hksabort_fuzzer: 删除第49行死代码
- hksqueryabilityinfo_fuzzer: 增加 ability type 变异
```

#### Phase 10：hksconcurrent_fuzzer 增强

```
当前弱点：每次仅执行1个API，跨API交互模式较少
改进：
- 增加"组合操作模式"：fdp.ConsumeBool 决定是否执行组合操作
  - 模式1: GenerateKey → Encrypt → Decrypt → DeleteKey
  - 模式2: GenerateKey → Sign → Verify → DeleteKey
  - 模式3: GenerateKey → AgreeKey → DeleteKey
  - 模式4: GenerateKey → Init → Update(s) → Finish → DeleteKey
  - 模式5: GenerateKey → Export → Import → DeleteKey
- 增加"负向测试模式"：用 fuzz 数据构造非法参数，测试错误处理分支
  - 无效算法组合、无效密钥大小、缺失必要参数
```

### 3.3 改造优先级排序

| 优先级 | Phase | 预期覆盖率提升 | 工作量 |
|--------|-------|---------------|--------|
| P0 | Phase 1: 基础设施(扩展hks_fuzz_util) | 所有后续Phase的基础 | 中 |
| P0 | Phase 6+5: 密钥生命周期+有效ParamSet | 行覆盖率+5~10%，函数+3~5% | 大(30+个fuzzer) |
| P0 | Phase 4: Tiny-Blob改造 | 行覆盖率+3~5% | 中(21个fuzzer) |
| P1 | Phase 2: 类别A无效Fuzzer改造 | 行覆盖率+3~5%，分支+3~5% | 大(6个fuzzer) |
| P1 | Phase 7: 操作链 | 分支覆盖率+2~3% | 小(合并4个fuzzer) |
| P1 | Phase 10: concurrent增强 | 行覆盖率+2~3% | 小 |
| P2 | Phase 3: 类别B近乎无效 | 行覆盖率+1~2% | 小(5个fuzzer) |
| P2 | Phase 8: 空buffer | 分支覆盖率+1~2% | 小(6个fuzzer) |
| P2 | Phase 9: 其他结构问题 | 微量提升 | 极小(4个fuzzer) |

---

## 四、风险与注意事项

1. **`#include .c` 文件问题**：hksstorage、hksrkc、hksfiletransfer 三个 fuzzer 直接 include 了 .c 源文件，改动时需注意编译依赖
2. **内存安全**：fuzz 注入 blob/alias 时需确保 buffer 生命周期正确，避免 use-after-free。FDP 的 `ConsumeBytes` 返回 `std::vector`，需注意 `data()` 指针在 vector 生命周期内的有效性
3. **文件操作副作用**：storage fuzzer 的 HksManageStoreKeyBlob 会写实际文件，fuzz 运行时需确保临时目录可用
4. **性能**：避免单次 LLVMFuzzerTestOneInput 执行过多测试函数导致超时（建议 fuzz 选择执行 1-3 个测试而非全部）
5. **不需要的 fuzzer 不关注**：部分模块如 `openssl`(95%)、`hitrace_meter_wrapper`(100%) 已达标无需额外关注
6. **密钥生成可能失败**：Phase 6 的密钥生命周期改造中，某些算法+密钥大小组合可能在 fuzzer 环境下不支持，需加入失败检测和回退逻辑
7. **ParamSet 有效性**：`ConstructGenKeyParamSetFromFdp` 生成的参数组合需覆盖实际支持的算法枚举值，避免产生无效组合导致 API 始终返回 HKS_ERROR_NOT_SUPPORTED
8. **FDP 数据耗尽**：FuzzedDataProvider 消耗完 fuzz 数据后返回默认值(0/空)，需确保耗尽后的操作不会导致崩溃或无限循环
9. **并发安全**：hksconcurrent_fuzzer 增强组合操作时需注意密钥操作的线程安全，避免并发删除正在使用的密钥
10. **未对齐访问 UB**：`reinterpret_cast<uint32_t*>(data)` 在 ARM 等严格对齐平台上会触发 UB，必须全部改为 FDP 的 ConsumeIntegral
