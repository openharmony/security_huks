/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#include "hks_client_service.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "hks_type.h"
#include "hks_client_service_common.h"
#include "hks_client_service_util.h"
#include "hks_common_check.h"
#include "hks_error_code.h"
#include "hks_event_info.h"
#include "hks_hitrace.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_permission_check.h"
#include "hks_report.h"
#include "hks_report_three_stage_get.h"
#include "hks_se_session_manager.h"
#include "hks_session_manager.h"
#include "hks_storage.h"
#include "hks_storage_manager.h"
#include "hks_template.h"
#include "hks_util.h"
#include "huks_access.h"
#ifdef HKS_UKEY_EXTENSION_CRYPTO
#include "hks_ukey_check.h"
#include "hks_ukey_service_adapter.h"
#endif
#include "hks_client_check.h"
#include "securec.h"

#ifndef _CUT_AUTHENTICATE_

static int32_t AppendKeyAliasToNewParamSet(const struct HksBlob *keyAlias, struct HksParamSet **paramSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    do {
        // Business may pass HKS_TAG_KEY_ALIAS during init; check first and remove the existing one if present
        struct HksParam *existingKeyAliasParam = NULL;
        if (HksGetParam(*paramSet, HKS_TAG_KEY_ALIAS, &existingKeyAliasParam) == HKS_SUCCESS) {
            const uint32_t tagsToDelete[] = { HKS_TAG_KEY_ALIAS };
            struct HksParamSet *cleanedParamSet = NULL;
            ret = HksDeleteTagsFromParamSet(tagsToDelete, HKS_ARRAY_SIZE(tagsToDelete),
                *paramSet, &cleanedParamSet);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "delete existing key alias failed, ret = %" LOG_PUBLIC "d", ret)
            ret = AppendToNewParamSet(cleanedParamSet, &newParamSet);
            HksFreeParamSet(&cleanedParamSet);
        } else {
            ret = AppendToNewParamSet(*paramSet, &newParamSet);
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init new param set failed, ret = %" LOG_PUBLIC "d", ret)
        struct HksParam paramArray[] = {
            { .tag = HKS_TAG_KEY_ALIAS, .blob = {.size = keyAlias->size, .data = keyAlias->data} },
        };
        ret = HksAddParams(newParamSet, paramArray, HKS_ARRAY_SIZE(paramArray));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add key alias, ret = %" LOG_PUBLIC "d", ret)

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build new param set failed, ret = %" LOG_PUBLIC "d", ret)

        HksFreeParamSet(paramSet);
        *paramSet = newParamSet;
        return ret;
    } while (0);
    HksFreeParamSet(&newParamSet);
    return ret;
}

static int32_t GetKeyAndNewParamSetForServiceInit(const struct HksProcessInfo *processInfo,
    const struct HksBlob *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *key,
    struct HksParamSet **outParamSet)
{
    int32_t ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, key, outParamSet);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    ret = AppendKeyAliasToNewParamSet(keyAlias, outParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "append key alias failed, ret = %" LOG_PUBLIC "d", ret)
    return ret;
}

static int32_t CreateOperation(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *handle, bool abortable)
{
    if (IsSeHandle(handle)) {
        return HksCreateSeOperation(processInfo, paramSet, handle);
    }

    return HksCreateOperation(processInfo, paramSet, handle, abortable);
}

static int32_t QueryOperationWrapper(const struct HksProcessInfo *processInfo,
    const struct HksBlob *handle, HksOperationUnion *unionOp)
{
    unionOp->isSe = IsSeHandle(handle);
    if (unionOp->isSe) {
        unionOp->op.seOperation = HksQuerySeOperationAndMarkInUse(processInfo, handle);
    } else {
        unionOp->op.operation = QueryOperationAndMarkInUse(processInfo, handle);
    }
    if ((unionOp->isSe ? (void *)unionOp->op.seOperation : (void *)unionOp->op.operation) == NULL) {
        HKS_LOG_E("operationHandle is not exist or being busy");
        return HKS_ERROR_NOT_EXIST;
    }
    return HKS_SUCCESS;
}

static bool IsOperationExist(const struct HksProcessInfo *processInfo,
    const struct HksBlob *handle, HksOperationUnion *unionOp)
{
    if (unionOp->isSe) {
        unionOp->op.seOperation = HksQuerySeOperationAndMarkInUse(processInfo, handle);
    } else {
        unionOp->op.operation = QueryOperationAndMarkInUse(processInfo, handle);
    }
    if ((unionOp->isSe ? (void *)unionOp->op.seOperation : (void *)unionOp->op.operation) == NULL) {
        HKS_LOG_I("operationHandle is not exist or being busy");
        return false;
    }
    return true;
}

static int32_t CheckAccessTokenWrapper(const HksOperationUnion *unionOp,
    const struct HksProcessInfo *processInfo)
{
    (void)unionOp;
    (void)processInfo;
#ifdef HKS_SUPPORT_ACCESS_TOKEN
    uint64_t accessTokenId = unionOp->isSe ? unionOp->op.seOperation->processInfo.accessTokenId
                                           : unionOp->op.operation->accessTokenId;
    if (accessTokenId != processInfo->accessTokenId) {
        HKS_LOG_E("compare access token id failed, unauthorized calling");
        return HKS_ERROR_BAD_STATE;
    }
#endif
    return HKS_SUCCESS;
}

static int32_t QueryAndCheckAccessToken(const struct HksProcessInfo *processInfo,
    const struct HksBlob *handle, HksOperationUnion *unionOp)
{
    int32_t ret = QueryOperationWrapper(processInfo, handle, unionOp);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "QueryOperationWrapper fail")
    return CheckAccessTokenWrapper(unionOp, processInfo);
}

static void MarkOperationUnUseWrapper(HksOperationUnion *unionOp)
{
    if (unionOp == NULL) {
        return;
    }
    if (unionOp->isSe) {
        HksMarkSeOperationUnUse(unionOp->op.seOperation);
    } else {
        MarkOperationUnUse(unionOp->op.operation);
    }
}

static void MarkAndDeleteOperationByUnion(HksOperationUnion *unionOp, const struct HksBlob *handle)
{
    if (unionOp == NULL) {
        return;
    }
    MarkOperationUnUseWrapper(unionOp);
    if (unionOp->isSe) {
        /* Skip delete if SE operation is NULL to prevent cross-process DoS */
        HKS_IF_NULL_RETURN_VOID(unionOp->op.seOperation);
        HksDeleteSeOperation(handle);
        unionOp->op.seOperation = NULL;
    } else {
        /* Skip delete if operation is NULL to prevent cross-process DoS via handle forgery */
        HKS_IF_NULL_RETURN_VOID(unionOp->op.operation);
        DeleteOperation(handle);
        unionOp->op.operation = NULL;
    }
}

struct HksServiceInitCtx {
    const struct HksProcessInfo *processInfo;
    const struct HksBlob *keyAlias;
    const struct HksParamSet *paramSet;
    struct HksBlob *handle;
    struct HksBlob *token;
    struct HksBlob keyFromFile;
    struct HksParamSet *newParamSet;
    struct HksHitraceId traceId;
    uint64_t startTime;
    bool isSeCalling;
    int32_t ret;
};

static void ServiceInitCore(struct HksServiceInitCtx *ctx)
{
    do {
#ifdef HKS_UKEY_EXTENSION_CRYPTO
        if (HksCheckIsUkeyOperation(ctx->paramSet, &ctx->ret) == HKS_SUCCESS) {
            ctx->ret = HksServiceOnUkeyInitSession(ctx->processInfo, ctx->keyAlias, ctx->paramSet, ctx->handle);
            break;
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "HksCheckIsUkeyOperation failed, ret = %" LOG_PUBLIC "d", ctx->ret)
#endif
        ctx->ret = HksCheckServiceInitParams(&ctx->processInfo->processName, ctx->keyAlias, ctx->paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "check ServiceInit params failed, ret = %" LOG_PUBLIC "d", ctx->ret)
        ctx->ret = RejectSeSecurityLevel(ctx->paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "reject se security level, ret = %" LOG_PUBLIC "d", ctx->ret)
        ctx->ret = GetKeyAndNewParamSetForServiceInit(ctx->processInfo, ctx->keyAlias, ctx->paramSet,
            &ctx->keyFromFile, &ctx->newParamSet);
        if (ctx->ret == HKS_SUCCESS) {
            ctx->ret = CheckKeySecuritySeFromKeyFile(&ctx->keyFromFile, &ctx->isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckKeySecuritySeFromKeyFile fail, ret = %" LOG_PUBLIC "d", ctx->ret)
            ctx->ret = HuksAccessInit(&ctx->keyFromFile, ctx->newParamSet, ctx->handle, ctx->token);
            IfNotSuccAppendHdiErrorInfo(ctx->ret);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ctx->ret == HKS_ERROR_CORRUPT_FILE || ctx->ret == HKS_ERROR_FILE_SIZE_FAIL ||
            ctx->ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(ctx->keyFromFile);
            ctx->ret = GetKeyData(ctx->processInfo, ctx->keyAlias, ctx->newParamSet,
                &ctx->keyFromFile, HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "get bak key and new param failed, ret = %" LOG_PUBLIC "d", ctx->ret)
            ctx->ret = CheckKeySecuritySeFromKeyFile(&ctx->keyFromFile, &ctx->isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckKeySecuritySeFromKeyFile fail, ret = %" LOG_PUBLIC "d", ctx->ret)
            ctx->ret = HuksAccessInit(&ctx->keyFromFile, ctx->newParamSet, ctx->handle, ctx->token);
            IfNotSuccAppendHdiErrorInfo(ctx->ret);
        }
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "Huks Init failed, ret = %" LOG_PUBLIC "d", ctx->ret)
        ctx->ret = CreateOperation(ctx->processInfo, ctx->paramSet, ctx->handle, true);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "create operation failed, ret = %" LOG_PUBLIC "d", ctx->ret)
    } while (0);
}

static void ServiceInitCleanup(struct HksServiceInitCtx *ctx)
{
    HKS_FREE_BLOB(ctx->keyFromFile);
    HksFreeParamSet(&ctx->newParamSet);
    DecrementSeCountByService(ctx->isSeCalling);
    HksHitraceEnd(&ctx->traceId);
}

int32_t HksServiceInit(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *handle, struct HksBlob *token)
{
    struct HksServiceInitCtx ctx = {
        .processInfo = processInfo, .keyAlias = keyAlias,
        .paramSet = paramSet, .handle = handle, .token = token,
        .keyFromFile = { 0, NULL }, .newParamSet = NULL,
        .traceId = {0}, .startTime = 0, .isSeCalling = false, .ret = 0
    };
    (void)HksElapsedRealTime(&ctx.startTime);
#ifdef L2_STANDARD
    ctx.traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif
    ServiceInitCore(&ctx);
#ifdef L2_STANDARD
    HksEventInfo eventInfo = { };
    (void)HksGetInitEventInfo(ctx.keyAlias, &ctx.keyFromFile, ctx.paramSet, ctx.processInfo, &eventInfo);
    HksThreeStageReportInfo info = { ctx.ret, 0, HKS_INIT, ctx.startTime, ctx.traceId.traceId.chainId, ctx.handle,
        {ctx.isSeCalling, {NULL}} };
    (void)HksServiceInitReport(__func__, ctx.processInfo, ctx.newParamSet, &info, &eventInfo);
#endif
    ServiceInitCleanup(&ctx);
    return ctx.ret;
}

static int32_t HksServiceCheckBatchUpdateTime(struct HksOperation *operation)
{
    uint64_t curTime = 0;
    int32_t ret = HksElapsedRealTime(&curTime);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksElapsedRealTime failed");
    if (operation->batchOperationTimestamp < curTime) {
        HKS_LOG_E("Batch operation timeout");
        return HKS_ERROR_INVALID_TIME_OUT;
    }
    return ret;
}

static void MarkAndDeleteOperation(struct HksOperation **operation, const struct HksBlob *handle)
{
    HKS_IF_NULL_LOGE_RETURN_VOID(operation, "operation is null")
    MarkOperationUnUse(*operation);
    DeleteOperation(handle);
    *operation = NULL;
}

static void UpdateEnd(HksOperationUnion *unionOp, struct HksHitraceId *traceId)
{
    MarkOperationUnUseWrapper(unionOp);
    HksHitraceEnd(traceId);
}

struct HksServiceUpdateCtx {
    const struct HksBlob *handle;
    const struct HksProcessInfo *processInfo;
    const struct HksParamSet *paramSet;
    const struct HksBlob *inData;
    struct HksBlob *outData;
    struct HksParamSet *newParamSet;
    HksOperationUnion unionOp;
    bool isSeCalling;
    int32_t ret;
};

static int32_t CheckBatchOperation(HksOperationUnion *unionOp, const struct HksBlob *handle)
{
    if (unionOp->isSe) {
        return HKS_SUCCESS;
    }
    int32_t ret = HKS_SUCCESS;
    if (unionOp->op.operation->isBatchOperation) {
        ret = HksServiceCheckBatchUpdateTime(unionOp->op.operation);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksServiceCheckBatchUpdateTime fail, ret = %" LOG_PUBLIC "d", ret);
            MarkOperationUnUse(unionOp->op.operation);
            DeleteOperation(handle);
        }
    }
    return ret;
}

static void ServiceUpdateCore(struct HksServiceUpdateCtx *ctx)
{
    do {
#ifdef HKS_UKEY_EXTENSION_CRYPTO
        if (HksCheckIsUkeyOperation(ctx->paramSet, &ctx->ret) == HKS_SUCCESS) {
            ctx->ret = HksServiceOnUkeyUpdateSession(ctx->processInfo, ctx->handle, ctx->paramSet, ctx->inData,
                ctx->outData);
            break;
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "HksCheckIsUkeyOperation failed, ret = %" LOG_PUBLIC "d", ctx->ret)
#endif
        ctx->ret = QueryOperationWrapper(ctx->processInfo, ctx->handle, &ctx->unionOp);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "QueryOperationWrapper fail")

        ctx->ret = RejectSeSecurityLevel(ctx->paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "reject se security level, ret = %" LOG_PUBLIC "d", ctx->ret)

        ctx->ret = CheckAccessTokenWrapper(&ctx->unionOp, ctx->processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckAccessTokenWrapper fail")

        ctx->ret = CheckBatchOperation(&ctx->unionOp, ctx->handle);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckBatchOperation fail, ret = %" LOG_PUBLIC "d", ctx->ret)

        if (IsSeHandle(ctx->handle)) {
            ctx->ret = CheckSeSessionCallInService(&ctx->isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckSeSessionCallInService fail, ret = %" LOG_PUBLIC "d", ctx->ret)
        }

        ctx->ret = AppendProcessInfoAndDefault(ctx->paramSet, ctx->processInfo,
            ctx->unionOp.isSe ? NULL : ctx->unionOp.op.operation, &ctx->newParamSet, false);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "append process info failed, ret = %" LOG_PUBLIC "d", ctx->ret)

        ctx->ret = HksCheckAcrossAccountsPermission(ctx->newParamSet, ctx->processInfo->userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ctx->ret)

        ctx->ret = HuksAccessUpdate(ctx->handle, ctx->newParamSet, ctx->inData, ctx->outData);
        IfNotSuccAppendHdiErrorInfo(ctx->ret);
        if (ctx->ret != HKS_SUCCESS) {
            HKS_LOG_E("HuksAccessUpdate fail, ret = %" LOG_PUBLIC "d", ctx->ret);
            MarkAndDeleteOperationByUnion(&ctx->unionOp, ctx->handle);
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "update execution failed, ret = %" LOG_PUBLIC "d", ctx->ret);
    } while (0);
}

int32_t HksServiceUpdate(const struct HksBlob *handle, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData)
{
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksHitraceId traceId = {0};
#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif
    struct HksServiceUpdateCtx ctx = {
        .handle = handle, .processInfo = processInfo,
        .paramSet = paramSet, .inData = inData, .outData = outData,
        .newParamSet = NULL, .unionOp = {false, {NULL}},
        .isSeCalling = false, .ret = 0
    };
    ServiceUpdateCore(&ctx);
#ifdef L2_STANDARD
    HksThreeStageReportInfo info = { ctx.ret, inData->size, HKS_UPDATE, startTime,
        traceId.traceId.chainId, handle, ctx.unionOp };
    (void)HksThreeStageReport(__func__, processInfo, ctx.newParamSet, &info);
#endif
    UpdateEnd(&ctx.unionOp, &traceId);
    HksFreeParamSet(&ctx.newParamSet);
    DecrementSeCountByService(ctx.isSeCalling);
    return ctx.ret;
}

static int32_t InitOutputDataForFinish(struct HksBlob *output, const struct HksBlob *outData, bool isStorage)
{
    output->data = (uint8_t *)HksMalloc(output->size);
    HKS_IF_NULL_RETURN(output->data, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(output->data, output->size, 0, output->size);
    if (!isStorage) {
        if ((memcpy_s(output->data, output->size, outData->data, outData->size) != EOK)) {
            HKS_FREE(output->data);
            return HKS_ERROR_INSUFFICIENT_MEMORY;
        }
    }
    return HKS_SUCCESS;
}

struct HksServiceFinishCtx {
    const struct HksBlob *handle;
    const struct HksProcessInfo *processInfo;
    const struct HksParamSet *paramSet;
    const struct HksBlob *inData;
    struct HksBlob *outData;
    struct HksBlob output;
    struct HksParamSet *newParamSet;
    bool isNeedStorage;
    bool isSeCalling;
    uint32_t outSize;
    HksOperationUnion unionOp;
    int32_t ret;
};

static void ServiceFinishCore(struct HksServiceFinishCtx *ctx)
{
    do {
        if (ctx->outSize != 0) {
            ctx->ret = InitOutputDataForFinish(&ctx->output, ctx->outData, ctx->isNeedStorage);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "init output data failed")
        }
#ifdef HKS_UKEY_EXTENSION_CRYPTO
        if (HksCheckIsUkeyOperation(ctx->paramSet, &ctx->ret) == HKS_SUCCESS) {
            ctx->ret = HksServiceOnUkeyFinishSession(ctx->processInfo, ctx->handle, ctx->paramSet, ctx->inData,
                ctx->outData);
            break;
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "HksCheckIsUkeyOperation failed, ret = %" LOG_PUBLIC "d", ctx->ret)
#endif
        ctx->ret = QueryAndCheckAccessToken(ctx->processInfo, ctx->handle, &ctx->unionOp);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "QueryAndCheckAccessToken fail")

        ctx->ret = RejectSeSecurityLevel(ctx->paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "reject se security level, ret = %" LOG_PUBLIC "d", ctx->ret)

        if (IsSeHandle(ctx->handle)) {
            ctx->ret = CheckSeSessionCallInService(&ctx->isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckSeSessionCallInService fail, ret = %" LOG_PUBLIC "d", ctx->ret)
        }

        ctx->ret = AppendProcessInfoAndDefault(ctx->paramSet, ctx->processInfo,
            ctx->unionOp.isSe ? NULL : ctx->unionOp.op.operation, &ctx->newParamSet, true);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "append process info failed, ret = %" LOG_PUBLIC "d", ctx->ret)

        ctx->ret = HksCheckAcrossAccountsPermission(ctx->newParamSet, ctx->processInfo->userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ctx->ret)

        ctx->ret = HuksAccessFinish(ctx->handle, ctx->newParamSet, ctx->inData, &ctx->output);
        IfNotSuccAppendHdiErrorInfo(ctx->ret);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "HuksAccessFinish fail, ret = %" LOG_PUBLIC "d", ctx->ret)

        ctx->ret = StoreOrCopyKeyBlob(ctx->newParamSet, ctx->processInfo, &ctx->output, ctx->outData,
            ctx->isNeedStorage);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "StoreOrCopyKeyBlob fail, ret = %" LOG_PUBLIC "d", ctx->ret)
    } while (0);
}

int32_t HksServiceFinish(const struct HksBlob *handle, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData)
{
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksHitraceId traceId = {0};
#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif
    struct HksServiceFinishCtx ctx = {
        .handle = handle, .processInfo = processInfo,
        .paramSet = paramSet, .inData = inData, .outData = outData,
        .output = { 0, NULL }, .newParamSet = NULL,
        .isNeedStorage = false, .isSeCalling = false,
        .outSize = outData->size, .unionOp = {false, {NULL}}, .ret = 0
    };
    if (HksCheckKeyNeedStored(paramSet, &ctx.isNeedStorage) == HKS_SUCCESS && ctx.isNeedStorage) {
        ctx.outSize = MAX_KEY_SIZE;
    }
    ctx.output = (struct HksBlob){ ctx.outSize, NULL };
    ServiceFinishCore(&ctx);
    if (ctx.output.data != NULL) {
        (void)memset_s(ctx.output.data, ctx.output.size, 0, ctx.output.size);
    }
    HKS_FREE_BLOB(ctx.output);
#ifdef L2_STANDARD
    HksThreeStageReportInfo info = { ctx.ret, inData->size, HKS_FINISH, startTime,
        traceId.traceId.chainId, handle, ctx.unionOp };
    (void)HksThreeStageReport(__func__, processInfo, ctx.newParamSet, &info);
#endif
    MarkAndDeleteOperationByUnion(&ctx.unionOp, handle);
    HksFreeParamSet(&ctx.newParamSet);
    DecrementSeCountByService(ctx.isSeCalling);
    HksHitraceEnd(&traceId);
    return ctx.ret;
}

struct HksServiceAbortCtx {
    const struct HksBlob *handle;
    const struct HksProcessInfo *processInfo;
    const struct HksParamSet *paramSet;
    struct HksParamSet *newParamSet;
    HksOperationUnion unionOp;
    bool isSeCalling;
    uint64_t startTime;
    struct HksHitraceId traceId;
    const char *funcName;
    int32_t ret;
};

static void ServiceAbortCore(struct HksServiceAbortCtx *ctx)
{
    do {
#ifdef HKS_UKEY_EXTENSION_CRYPTO
        if (HksCheckIsUkeyOperation(ctx->paramSet, &ctx->ret) == HKS_SUCCESS) {
            ctx->ret = HksServiceOnUkeyAbortSession(ctx->processInfo, ctx->handle, ctx->paramSet);
            break;
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "HksCheckIsUkeyOperation failed, ret = %" LOG_PUBLIC "d", ctx->ret)
#endif
        ctx->ret = RejectSeSecurityLevel(ctx->paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "reject se security level, ret = %" LOG_PUBLIC "d", ctx->ret)
        if (!IsOperationExist(ctx->processInfo, ctx->handle, &ctx->unionOp)) {
            ctx->ret = HKS_SUCCESS;
            break;
        }
        if (ctx->unionOp.isSe) {
            ctx->ret = CheckSeSessionCallInService(&ctx->isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckSeSessionCallInService fail, ret = %" LOG_PUBLIC "d", ctx->ret)
        }
        ctx->ret = AppendProcessInfoAndDefault(ctx->paramSet, ctx->processInfo,
            ctx->unionOp.isSe ? NULL : ctx->unionOp.op.operation, &ctx->newParamSet, false);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "append process info failed, ret = %" LOG_PUBLIC "d", ctx->ret)

        ctx->ret = HksCheckAcrossAccountsPermission(ctx->newParamSet, ctx->processInfo->userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d",
            ctx->ret)

        ctx->ret = HuksAccessAbort(ctx->handle, ctx->newParamSet);
        IfNotSuccAppendHdiErrorInfo(ctx->ret);
        HKS_IF_NOT_SUCC_LOGE(ctx->ret, "HuksAccessAbort fail, ret = %" LOG_PUBLIC "d", ctx->ret)
#ifdef L2_STANDARD
        HksThreeStageReportInfo info = { ctx->ret, 0, HKS_ABORT, ctx->startTime,
            ctx->traceId.traceId.chainId, ctx->handle, ctx->unionOp };
        (void)HksThreeStageReport(ctx->funcName, ctx->processInfo, ctx->newParamSet, &info);
#endif
        MarkAndDeleteOperationByUnion(&ctx->unionOp, ctx->handle);
    } while (0);
}

int32_t HksServiceAbort(const struct HksBlob *handle, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet)
{
    struct HksServiceAbortCtx ctx = {
        .handle = handle, .processInfo = processInfo,
        .paramSet = paramSet, .newParamSet = NULL,
        .unionOp = {IsSeHandle(handle), {NULL}},
        .isSeCalling = false, .startTime = 0, .traceId = {0},
        .funcName = __func__, .ret = 0
    };
    (void)HksElapsedRealTime(&ctx.startTime);
#ifdef L2_STANDARD
    ctx.traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif
    ServiceAbortCore(&ctx);
    MarkOperationUnUseWrapper(&ctx.unionOp);
    HksFreeParamSet(&ctx.newParamSet);
    DecrementSeCountByService(ctx.isSeCalling);
    HksHitraceEnd(&ctx.traceId);
    return ctx.ret;
}

static int32_t BuildAbortParamSet(struct HksParamSet **newParamSet)
{
    int32_t ret = HksInitParamSet(newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksInitParamSet fail!");
    do {
        // This param exists solely to pass the paramSet validation check
        struct HksParam Param = { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_TEMP};
        ret = HksAddParams(*newParamSet, &Param, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAddParams  fail!");

        ret = HksBuildParamSet(newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksBuildParamSet  fail!");
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(newParamSet);
    }
    return ret;
}

int32_t HksServiceAbortByPid(int32_t pid)
{
    struct HksParamSet *newParamSet = NULL;
    struct HksOperation *operation;
    int32_t ret;
    do {
        operation = QueryOperationByPidAndMarkInUse(pid);
        if (operation == NULL) {
            HKS_LOG_E("operationHandle by pid failed! not exist or being busy");
            ret = HKS_ERROR_NOT_EXIST; /* return success if the handle is not found */
            break;
        }

        ret = BuildAbortParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "BuildAbortParamSet failed, ret = %" LOG_PUBLIC "d", ret)

        struct HksBlob handleBlob = { .data = (uint8_t *)(&(operation->handle)), .size = sizeof(operation->handle) };
        ret = HuksAccessAbort(&handleBlob, newParamSet);
        IfNotSuccAppendHdiErrorInfo(ret);
        HKS_IF_NOT_SUCC_LOGE(ret, "HuksAccessAbort for dead process fail, ret = %" LOG_PUBLIC "d", ret)

        MarkAndDeleteOperation(&operation, &handleBlob);
    } while (0);
    MarkOperationUnUse(operation);
    HksFreeParamSet(&newParamSet);
    return ret;
}

#endif /* _CUT_AUTHENTICATE_ */
