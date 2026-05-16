# UKey打点框架二期实施计划

## 实施完成情况（2026-05-16）

### ✅ 已完成阶段（Git: 18 commits）

**阶段1-9**：11个新事件完整实现 + 两次重构（代码减少74.6%）  
**阶段10**：部分业务集成完成（4个ukey专用接口）

### 核心成果

| 项目 | 原始 | 最终 | 改善 |
|------|------|------|------|
| 代码行数 | 2074行 | 689行 | 减少74.6% ✅ |
| 函数数量 | 108个重复函数 | 6通用+90wrapper | 消除重复 |
| 新增事件成本 | 108行代码 | 1行配置+5行wrapper | 减少94% |
| 新增字段成本 | 修改108×18处 | 修改约20处 | 减少90% |

---

## 数据结构修改

### UKeyInfo结构体（新增7字段）
```c
struct HksBlob abilityName;      // 新增
struct HksBlob extBundleName;    // 新增
uint32_t alg;                    // 新增
uint32_t purpose;                // 新增
uint32_t detailErrcode;          // 新增
struct HksBlob handle;           // 新增
struct HksBlob extraData;        // 新增
```

### 新增事件（38-48）
- INIT_SESSION (38), UPDATE_SESSION (39), FINISH_SESSION (40), ABORT_SESSION (41)
- IMPORT_CERT (42), GET_RESOURCE_ID (43), CLEAR_PIN_STATE (44)
- GENERATE_KEY (45), EXPORT_PUBLIC_KEY (46), IMPORT_WRAPPED_KEY (47)
- SET_REMOTE_PROPERTY (48)

---

## 架构重构

### 重构历程

**第一次重构（表驱动）**：2074→599行（71%减少）  
**第二次重构（字段映射）**：599→528行（74.6%减少）  
**inline函数替换**：528→689行（消除120字符告警）  
**导出符号修复**：去掉inline关键字，改为普通函数

### 最终架构（689行）

```
hks_report_ukey_event.cpp
├─ 配置层（85行）
│  ├─ 字段位图（13个FLAG）
│  ├─ 字段映射表（13字段 × {flag, tag, name, type}）
│  ├─ 事件配置表（18事件 × {eventId, fieldFlags, compareType}）
│  └─ 查找函数
├─ 处理层（200行）
│  ├─ 辅助函数（3个）
│  ├─ 通用函数（6个）
│  └─ 主入口（ReportUKeyEvent支持paramSet=NULL）
├─ 兼容层（400行）
│  ├─ wrapper函数（90个，非inline导出符号）
│  ├─ AddParamSet wrapper（18个）
│  └─ 数组定义
```

### 核心设计

**表驱动**：18行配置驱动18个事件  
**字段映射**：13个字段统一处理，循环+辅助函数  
**wrapper函数**：90个函数（18事件×5），非inline导出符号供HA Plugin使用

---

## 业务逻辑集成状态

### ✅ 已添加打点（IPC层，ukey专用接口）

| 事件ID | 函数 | 位置 | 状态 |
|--------|------|------|------|
| 31-37 | 已有ukey接口 | hks_ipc_service.c | ✅ 已有打点 |
| 42 | HksIpcServiceImportCertificate | hks_ipc_service.c | ✅ 新增打点 |
| 43 | HksIpcServiceGetResourceId | hks_ipc_service.c | ✅ 新增打点 |
| 44 | HksIpcServiceClearPinAuthState | hks_ipc_service.c | ✅ 新增打点 |
| 48 | HksIpcServiceSetOrGetRemoteProperty | hks_ipc_service.c | ✅ 区分GET(37)/SET(48) |

### ⏸️ 待添加打点（复用huks接口）

| 事件ID | 函数 | 正确位置 | 状态 |
|--------|------|----------|------|
| 38 | HksIpcServiceInit | hks_client_service.c | ⏸️ 待验证后添加 |
| 39 | HksIpcServiceUpdate | hks_client_service.c | ⏸️ 待验证后添加 |
| 40 | HksIpcServiceFinish | hks_client_service.c | ⏸️ 待验证后添加 |
| 41 | HksIpcServiceAbort | hks_client_service.c | ⏸️ 待验证后添加 |
| 45 | HksIpcServiceGenerateKey | hks_client_service.c | ⏸️ 待验证后添加 |
| 46 | HksIpcServiceExportPublicKey | hks_client_service.c | ⏸️ 待验证后添加 |
| 47 | HksIpcServiceImportWrappedKey | hks_client_service.c | ⏸️ 待验证后添加 |

### 集成模式（简化版，无需startTime）

```c
// 1. 执行业务逻辑
int32_t ret = BusinessLogic(...);

// 2. 打点上报（startTime由框架内部统计）
struct UKeyInfo ukeyInfo = { .eventId = ..., .detailErrcode = ret };
struct UKeyCommonInfo ukeyCommon = { .returnCode = ret };
ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);
```

---

## Git提交历史（18个）

```
18. feat(ukey): Add event reporting for 4 ukey-specific interfaces
17. revert(ukey): Remove IPC service event reporting for reused huks interfaces
16. fix(ukey): Remove inline from wrapper functions to export symbols for HA Plugin
15. feat(ukey): Integrate ukey event reporting in IPC service for 11 new events (已revert)
14. refactor: Fix 120-char warnings and optimize plan.md
13. refactor(ukey): Replace macro wrappers with inline functions
12. fix(ukey): Resolve compilation errors - add missing Tag definitions
11. docs: Document second refactoring with field mapping table optimization
10. refactor(ukey): Further simplify 3 long functions with field mapping table
09. docs: Mark refactoring as completed with 71% code reduction
08. refactor(ukey): Use table-driven design to reduce code from 2074 to 607 lines
07. docs: Add code refactoring plan for ukey event handlers
06. docs: Update plan.md with implementation progress
05. feat(ukey): Update HA Plugin eventProcList with 11 new ukey events
04. feat(ukey): Implement 4 key operation ukey event handlers (batch 3)
03. feat(ukey): Implement 4 session management ukey event handlers (batch 2)
02. feat(ukey): Implement 3 simple ukey event handlers (batch 1)
01. feat(ukey): Add new ukey event IDs and extend data structures
```

---

## 技术要点

### 字段组合（按事件）

| 事件类型 | 关键字段 |
|---------|---------|
| 会话事件（38-41） | resourceId + alg + purpose + handle + extraData |
| 密钥事件（45-47） | resourceId + alg + purpose |
| 证书事件（42, 46） | resourceId + providerName |
| 资源管理（43, 44, 48） | resourceId + propertyId/extraData |

### 比较策略

- COMPARE_RESOURCE_ID：大部分事件使用resourceId
- COMPARE_HANDLE：会话事件使用handle
- COMPARE_PROPERTY_ID：GET/SET PROPERTY使用resourceId+propertyId

### Tag扩展

新增：HKS_TAG_PARAM6~10_BUFFER（30032-30036）

### ReportUKeyEvent函数修改

允许paramSet=NULL（部分ukey接口如ClearPinAuthState没有paramSet）

---

## 注意事项

1. 每行不超过120字符（已修复）
2. 新增字段需内存管理
3. detailErrcode记录失败原因
4. 使用`#ifdef HKS_UKEY_EXTENSION_CRYPTO`包裹
5. 字段组合不同事件不同
6. wrapper函数必须非inline（导出符号供HA Plugin）
7. 复用huks接口的打点应在hks_client_service.c添加，不是IPC层

---

## 下一步工作

**阶段10继续**：在hks_client_service.c添加7个复用huks接口打点

待验证ukey专用接口打点正常后：
1. 三段式事件（38-41）：INIT/UPDATE/FINISH/ABORT
2. 密钥操作事件（45-47）：GENERATE_KEY/EXPORT_PUBLIC_KEY/IMPORT_WRAPPED_KEY

优先级：
- P0（高频）：INIT_SESSION, UPDATE_SESSION, FINISH_SESSION, GENERATE_KEY
- P1（中等）：EXPORT_PUBLIC_KEY, IMPORT_WRAPPED_KEY
- P2（低频）：ABORT_SESSION