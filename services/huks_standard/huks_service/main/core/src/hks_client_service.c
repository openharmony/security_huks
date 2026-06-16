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
#include <unistd.h>
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#include "hks_error_code.h"
#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_client_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include "hks_type.h"
#include "hks_base_check.h"
#include "hks_client_check.h"
#ifdef HKS_SUPPORT_API_ATTEST_KEY
#include "hks_client_service_dcm.h"
#include "parameter.h"
#endif
#include "hks_client_service_common.h"
#include "hks_client_service_util.h"
#include "hks_common_check.h"
#include "hks_event_info.h"
#include "hks_hitrace.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_permission_check.h"
#include "hks_plugin_adapter.h"
#include "hks_report.h"
#include "hks_session_manager.h"
#include "hks_se_session_manager.h"
#include "hks_storage.h"
#include "hks_storage_manager.h"
#include "hks_template.h"
#include "huks_access.h"
#include "hks_util.h"
#ifdef HKS_UKEY_EXTENSION_CRYPTO
#include "hks_ukey_check.h"
#endif

#include "hks_upgrade_key_accesser.h"
#include "hks_upgrade_helper.h"
#include "hks_report_generate_key.h"
#include "hks_report_delete_key.h"
#include "hks_report_import_key.h"
#include "hks_report_list_aliases.h"
#include "hks_report_check_key_exited.h"
#include "hks_report_rename_key.h"
#include "hks_report_data_size.h"
#include "hks_report_common.h"
#include "hks_report_three_stage_get.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"

#ifdef L2_STANDARD
#include "hks_ha_event_report.h"
#include "hks_ukey_three_stage_adapter.h"
#include "hks_report_ukey_event.h"
#include "hks_se_api_wrap.h"
#endif

#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#include "hks_upgrade_lock.h"
#endif

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
#include "hks_get_process_info.h"

#include <string.h>
#endif

#include "securec.h"

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
#include "hks_useridm_api_wrap.h"
#endif

#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
#include "hks_bms_api_wrap.h"
#endif
#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#include "hks_config_parser.h"
#endif

#ifdef HKS_UKEY_EXTENSION_CRYPTO
static int32_t HksCheckMultiSetTag(const struct HksParamSet *paramSet)
{
    for (uint32_t i = 0; i < paramSet->paramsCnt; ++i) {
        uint32_t curTag = paramSet->params[i].tag;
        for (uint32_t j = i + 1; j < paramSet->paramsCnt; ++j) {
            if (curTag == paramSet->params[j].tag) {
                HKS_LOG_E("paramSet contains multi-tags! 0x%" LOG_PUBLIC "x", curTag);
                return HKS_ERROR_INVALID_ARGUMENT;
            }
        }
    }
    return HKS_SUCCESS;
}
#endif

#ifndef _CUT_AUTHENTICATE_
#ifdef _STORAGE_LITE_
int32_t HksServiceGetKeyInfoList(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount)
{
    (void)paramSet;
    int32_t ret = HksCheckGetKeyInfoListParams(&(processInfo->processName), keyInfoList, listCount);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = HksStoreGetKeyInfoList(keyInfoList, listCount);

#ifdef L2_STANDARD
    HksReport(__func__, processInfo, NULL, ret);
#endif

    return ret;
}

#else /* _STORAGE_LITE_ */

int32_t HksServiceGetKeyInfoList(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount)
{
    int32_t ret;
#ifdef L2_STANDARD
    struct HksParamSet *newParamSet = NULL;
#endif

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    uint32_t listMaxCnt = *listCount;
#endif
    do {
        ret = HksCheckGetKeyInfoListParams(&processInfo->processName, keyInfoList, listCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check params failed, ret = %" LOG_PUBLIC "d", ret)

#ifdef L2_STANDARD
        ret = AppendStorageLevelIfNotExistInner(processInfo, paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append storage level failed")
#else
        const struct HksParamSet *newParamSet = paramSet;
#endif
        ret = HksManageGetKeyAliasByProcessName(processInfo, newParamSet, keyInfoList, listCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get key alias list from storage failed, ret = %" LOG_PUBLIC "d", ret)
        for (uint32_t i = 0; i < *listCount; ++i) {
            struct HksBlob keyFromFile = { 0, NULL };
            ret = GetKeyFileData(processInfo, newParamSet, &(keyInfoList[i].alias), &keyFromFile, HKS_STORAGE_TYPE_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get key data failed, ret = %" LOG_PUBLIC "d", ret)
            ret = GetKeyParamSet(&keyFromFile, keyInfoList[i].paramSet);
            HKS_FREE_BLOB(keyFromFile);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get key paramSet failed, ret = %" LOG_PUBLIC "d", ret)
        }
    } while (0);
#ifdef L2_STANDARD
    HksFreeParamSet(&newParamSet);
#endif

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
    if (ret == HKS_SUCCESS && HksCheckNeedUpgradeForSmallToService(processInfo) == HKS_SUCCESS) {
        ret = HksGetOldKeyInfoListForSmallToService(processInfo, keyInfoList, listMaxCnt, listCount);
    }
#endif

#ifdef L2_STANDARD
    HksReport(__func__, processInfo, NULL, ret);
#endif

    return ret;
}
#endif /* _STORAGE_LITE_ */
#endif /* _CUT_AUTHENTICATE_ */

#ifndef _CUT_AUTHENTICATE_

static int32_t DksAppendKeyAliasAndNewParamSet(struct HksParamSet *paramSet, const struct HksBlob *keyAlias,
    struct HksParamSet **outParamSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    do {
        if (paramSet != NULL) {
            ret = AppendToNewParamSet(paramSet, &newParamSet);
        } else {
            ret = HksInitParamSet(&newParamSet);
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init new param set failed, ret = %" LOG_PUBLIC "d", ret)
        struct HksParam paramArray[] = {
            { .tag = HKS_TAG_KEY_ALIAS, .blob = {.size = keyAlias->size, .data = keyAlias->data} },
        };
        ret = HksAddParams(newParamSet, paramArray, HKS_ARRAY_SIZE(paramArray));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add key alias, ret = %" LOG_PUBLIC "d", ret)

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build new param set failed, ret = %" LOG_PUBLIC "d", ret)

        HksFreeParamSet(&paramSet);
        *outParamSet = newParamSet;
        return ret;
    } while (false);
    HksFreeParamSet(&newParamSet);
    return ret;
}

static int32_t GetKeyAndNewParamSet(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key, struct HksParamSet **outParamSet)
{
    int32_t ret = AppendProcessInfoAndDefault(paramSet, processInfo, NULL, outParamSet, true);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
        "append process info and default strategy failed, ret = %" LOG_PUBLIC "d", ret)

    struct HksParam* dksParam = NULL;
    ret = HksGetParam(paramSet, DKS_TAG_IS_USE_DISTRIBUTED_KEY, &dksParam);
    if (ret == HKS_SUCCESS && dksParam->boolParam) {
        HKS_LOG_D("dks recover after use, has the DKS_TAG_IS_USE_DISTRIBUTED_KEY tag, read keyfile from Ta cache!");
        ret = DksAppendKeyAliasAndNewParamSet(*outParamSet, keyAlias, outParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "dks append key alias and new param set failed, ret = %" LOG_PUBLIC "d.", ret)
    } else if (ret == HKS_ERROR_PARAM_NOT_EXIST || (ret == HKS_SUCCESS && !dksParam->boolParam)) {
        ret = GetKeyData(processInfo, keyAlias, *outParamSet, key, HKS_STORAGE_TYPE_KEY);
        HKS_IF_NOT_SUCC_LOGE(ret, "get key data failed, ret = %" LOG_PUBLIC "d.", ret)
    } else {
        HKS_IF_NOT_SUCC_LOGE(ret, "get DKS_TAG_IS_USE_DISTRIBUTED_KEY failed, ret = %" LOG_PUBLIC "d.", ret)
    }
    // free outParamSet together after do-while
    return ret;
}

#ifdef HKS_SUPPORT_ED25519_TO_X25519
static int32_t GetAgreeStoreKey(uint32_t keyAliasTag, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    struct HksParam *keyAliasParam = NULL;
    int32_t ret = HksGetParam(paramSet, keyAliasTag, &keyAliasParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get agree key alias tag failed")

    HKS_IF_TRUE_LOGE_RETURN(keyAliasParam->blob.size > HKS_MAX_KEY_ALIAS_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "invalid main key size: %" LOG_PUBLIC "u", keyAliasParam->blob.size)

    return GetKeyData(processInfo, &(keyAliasParam->blob), paramSet, key, HKS_STORAGE_TYPE_KEY);
}

static int32_t TranslateToInnerCurve25519Format(const uint32_t alg, const struct HksBlob *key,
    struct HksBlob *publicKey)
{
    HKS_IF_TRUE_LOGE_RETURN(key->size != HKS_KEY_BYTES(HKS_CURVE25519_KEY_SIZE_256), HKS_ERROR_INVALID_KEY_INFO,
        "Invalid curve25519 public key size! key size = 0x%" LOG_PUBLIC "X", key->size)

    uint32_t totalSize = sizeof(struct HksPubKeyInfo) + key->size;
    uint8_t *buffer = (uint8_t *)HksMalloc(totalSize);
    HKS_IF_NULL_LOGE_RETURN(buffer, HKS_ERROR_MALLOC_FAIL, "malloc failed! %" LOG_PUBLIC "u", totalSize)

    (void)memset_s(buffer, totalSize, 0, totalSize);

    struct HksPubKeyInfo *curve25519Key = (struct HksPubKeyInfo *)buffer;
    curve25519Key->keyAlg = (enum HksKeyAlg)alg;
    curve25519Key->keySize = HKS_CURVE25519_KEY_SIZE_256;
    curve25519Key->nOrXSize = key->size; /* curve25519 public key */

    uint32_t offset = sizeof(struct HksPubKeyInfo);
    (void)memcpy_s(buffer + offset, totalSize - offset, key->data, key->size);
    publicKey->data = buffer;
    publicKey->size = totalSize;
    return HKS_SUCCESS;
}

static int32_t GetAgreePublicKey(const uint32_t alg, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    struct HksParam *isKeyAliasParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS, &isKeyAliasParam);
    if ((ret == HKS_SUCCESS) && (!(isKeyAliasParam->boolParam))) {
        struct HksParam *keyParam = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_AGREE_PUBLIC_KEY, &keyParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get agree public key tag fail")

        return TranslateToInnerCurve25519Format(alg, &(keyParam->blob), key);
    }

    return GetAgreeStoreKey(HKS_TAG_AGREE_PUBLIC_KEY, processInfo, paramSet, key);
}

static int32_t GetAgreePrivateKey(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    return GetAgreeStoreKey(HKS_TAG_AGREE_PRIVATE_KEY_ALIAS, processInfo, paramSet, key);
}

static int32_t ConbineIntoKeyPair(const struct HksBlob *privateKey,
    const struct HksBlob *publicKey, struct HksBlob *keyPair)
{
    uint32_t size = sizeof(struct Hks25519KeyPair) + privateKey->size + publicKey->size; /* size has been checked */
    uint8_t *buffer = (uint8_t *)HksMalloc(size);
    HKS_IF_NULL_RETURN(buffer, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(buffer, size, 0, size);

    struct Hks25519KeyPair keyPairStruct = { publicKey->size, privateKey->size };
    uint32_t offset = 0;

    (void)memcpy_s(buffer + offset, size, &keyPairStruct, sizeof(keyPairStruct));
    offset += sizeof(keyPairStruct);

    (void)memcpy_s(buffer + offset, size - offset, publicKey->data, publicKey->size);
    offset += publicKey->size;

    (void)memcpy_s(buffer + offset, size - offset, privateKey->data, privateKey->size) ;

    keyPair->data = buffer;
    keyPair->size = size;
    return HKS_SUCCESS;
}

static int32_t GetAgreeKeyPair(const uint32_t alg, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    int32_t ret;
    struct HksBlob privateKey = { 0, NULL };
    struct HksBlob publicKey = { 0, NULL };
    do {
        ret = GetAgreePublicKey(alg, processInfo, paramSet, &publicKey);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = GetAgreePrivateKey(processInfo, paramSet, &privateKey);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = ConbineIntoKeyPair(&privateKey, &publicKey, key);
    } while (0);

    HKS_FREE_BLOB(privateKey);
    HKS_FREE_BLOB(publicKey);
    return ret;
}
#endif

static int32_t GetAgreeBaseKey(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksBlob *key)
{
    (void)key;
    struct HksParam *keyAlgParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &keyAlgParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_ALG_FAIL, "get alg tag fail")

    HKS_IF_TRUE_LOGI_RETURN(keyAlgParam->uint32Param != HKS_ALG_AES, HKS_SUCCESS,
        "not an aes key, no need check main key and derive factor")

#ifdef HKS_SUPPORT_ED25519_TO_X25519
    struct HksParam *agreeAlgParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_AGREE_ALG, &agreeAlgParam);
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_CHECK_GET_ALG_FAIL)

    HKS_IF_TRUE_RETURN(agreeAlgParam->uint32Param != HKS_ALG_X25519 && agreeAlgParam->uint32Param != HKS_ALG_ED25519,
        HKS_ERROR_INVALID_ALGORITHM)

    return GetAgreeKeyPair(agreeAlgParam->uint32Param, processInfo, paramSet, key);
#else
    (void)processInfo;
    return HKS_ERROR_INVALID_ARGUMENT; /* if aes generated by agree but x25519/ed25519 is ot support, return error */
#endif
}

static int32_t GetDeriveMainKey(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksBlob *key)
{
    struct HksParam *keyGenTypeParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_GENERATE_TYPE, &keyGenTypeParam);
    /* not set tag KEY_GENERATE_TYPE, gen key by default type */
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_SUCCESS)

    if (keyGenTypeParam->uint32Param == HKS_KEY_GENERATE_TYPE_AGREE) {
        return GetAgreeBaseKey(processInfo, paramSet, key);
    } else if (keyGenTypeParam->uint32Param == HKS_KEY_GENERATE_TYPE_DEFAULT) {
        return HKS_SUCCESS;
    }
    return HKS_ERROR_INVALID_ARGUMENT;
}

static int32_t GetKeyIn(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksBlob *key)
{
    int32_t ret = GetDeriveMainKey(processInfo, paramSet, key);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* if not generate by derive, init keyIn by default value(ca to ta not accept null pointer) */
    if (key->data == NULL) {
        key->size = 1; /* malloc least buffer as keyIn buffer */
        key->data = (uint8_t *)HksMalloc(key->size);
        HKS_IF_NULL_LOGE_RETURN(key->data, HKS_ERROR_MALLOC_FAIL, "malloc failed")

        key->data[0] = 0;
    }
    return HKS_SUCCESS;
}

static int32_t StoreOrCopyKeyBlob(const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo,
    struct HksBlob *output, struct HksBlob *outData, bool isNeedStorage)
{
    if (!isNeedStorage) {
        HKS_IF_TRUE_LOGE_RETURN(outData->size != 0 &&
            memcpy_s(outData->data, outData->size, output->data, output->size) != EOK, HKS_ERROR_INSUFFICIENT_MEMORY,
            "copy keyblob data fail")
        outData->size = output->size;
        return HKS_SUCCESS;
    }

    struct HksParam *keyAliasParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_ALIAS, &keyAliasParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get key alias fail, ret = %" LOG_PUBLIC "d", ret)

    HKS_IF_TRUE_LOGE_RETURN(keyAliasParam->blob.size > HKS_MAX_KEY_ALIAS_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "key alias size is too long, size is %" LOG_PUBLIC "u", keyAliasParam->blob.size)

    ret = CheckKeyCondition(processInfo, &keyAliasParam->blob, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "CheckKeyCondition fail, ret = %" LOG_PUBLIC "d", ret)

    ret = HksManageStoreKeyBlob(processInfo, paramSet, &keyAliasParam->blob, output, HKS_STORAGE_TYPE_KEY);
    HKS_IF_NOT_SUCC_LOGE(ret, "store keyblob to storage failed, ret = %" LOG_PUBLIC "d", ret)

    return ret;
}

static void HksReportEvent(const char *funcName, const struct HksHitraceId *traceId,
    const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet, int32_t ret)
{
#ifdef L2_STANDARD
    HksHitraceEnd(traceId);
    HksReport(funcName, processInfo, paramSet, ret);
#else
    (void)funcName;
    (void)traceId;
    (void)processInfo;
    (void)paramSet;
    (void)ret;
#endif
}
#if defined(L2_STANDARD) && defined(HKS_SUPPORT_GET_BUNDLE_INFO)
static int32_t CheckExistingDeveloperId(const struct HksParamSet *paramSet, const struct HksBlob *developerId,
    bool *needAdd)
{
    *needAdd = true;
    struct HksParam *existingDevIdParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_DEVELOPER_ID, &existingDevIdParam);
    if (ret != HKS_SUCCESS) {
        return HKS_SUCCESS;
    }
    *needAdd = false;
    if (existingDevIdParam->blob.size == developerId->size &&
        HksMemCmp(existingDevIdParam->blob.data, developerId->data, developerId->size) == 0) {
        return HKS_SUCCESS;
    }
    HKS_LOG_E("developer id is not allowed to be passed in from external!");
    return HKS_ERROR_INVALID_ARGUMENT;
}

static int32_t AppendGroupKeyInfo(const struct HksProcessInfo *processInfo, struct HksParamSet **outParamSet)
{
    int32_t ret = HksCheckAssetAccessGroup(processInfo, *outParamSet);
    HKS_IF_TRUE_RETURN(ret == HKS_ERROR_PARAM_NOT_EXIST, HKS_SUCCESS)
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "groupid is invalid")

    struct HksParamSet *paramSet = *outParamSet;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob developerId = { 0, NULL };
    do {
        if (paramSet != NULL) {
            ret = AppendToNewParamSet(paramSet, &newParamSet);
        } else {
            ret = HksInitParamSet(&newParamSet);
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append tag to new paramset failed")

        ret = HksGetDeveloperId(processInfo, &developerId);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get developerId failed")

        bool needAdd = true;
        ret = CheckExistingDeveloperId(*outParamSet, &developerId, &needAdd);
        HKS_IF_NOT_SUCC_BREAK(ret)

        if (needAdd) {
            struct HksParam paramArr[] = {
                { .tag = HKS_TAG_DEVELOPER_ID, .blob = developerId },
            };
            ret = HksAddParams(newParamSet, paramArr, HKS_ARRAY_SIZE(paramArr));
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add developerInfo failed")
        }

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramset failed")

        HksFreeParamSet(outParamSet);
        *outParamSet = newParamSet;
        HKS_FREE_BLOB(developerId);
        return HKS_SUCCESS;
    } while (0);

    HKS_FREE_BLOB(developerId);
    HksFreeParamSet(&newParamSet);
    return ret;
}
#endif

static int32_t GenerateKeyOperation(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    struct HksParamSet *newParamSet, struct HksBlob *keyIn, struct HksBlob *output)
{
    int32_t ret;

    ret = CheckKeyCondition(processInfo, keyAlias, newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check key condition failed, ret = %" LOG_PUBLIC "d", ret)

    ret = GetKeyIn(processInfo, newParamSet, keyIn);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyIn failed, ret = %" LOG_PUBLIC "d", ret)

    ret = HuksAccessGenerateKey(keyAlias, newParamSet, keyIn, output);
    IfNotSuccAppendHdiErrorInfo(ret);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "access level generate key failed, ret = %" LOG_PUBLIC "d", ret)

    ret = HksManageStoreKeyBlob(processInfo, newParamSet, keyAlias, output, HKS_STORAGE_TYPE_KEY);
    HKS_IF_NOT_SUCC_LOGE(ret, "store keyblob to storage failed, ret = %" LOG_PUBLIC "d", ret)

    return ret;
}

#ifdef HKS_UKEY_EXTENSION_CRYPTO
static int32_t GenerateKeyUkeyOperation(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn)
{
    int32_t ret = HksCheckMultiSetTag(paramSetIn);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckMultiSetTag failed, ret = %" LOG_PUBLIC "d", ret)
    ret = HksServiceOnUkeyGenerateKey(processInfo, keyAlias, paramSetIn);
    HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceOnUkeyGenerateKey failed, ret = %" LOG_PUBLIC "d", ret)
    ReportUKeyKeyEvent(HKS_EVENT_UKEY_GENERATE_KEY, ret, processInfo, paramSetIn);
    return ret;
}
#endif

struct HksServiceGenKeyCtx {
    const struct HksProcessInfo *processInfo;
    const struct HksBlob *keyAlias;
    const struct HksParamSet *paramSetIn;
    struct HksBlob *keyOut;
    struct HksParamSet *newParamSet;
    uint8_t *keyOutBuffer;
    struct HksBlob output;
    struct HksBlob keyIn;
    bool isSeCalling;
    int32_t ret;
};

static void ServiceGenerateKeyCore(struct HksServiceGenKeyCtx *ctx)
{
    ctx->output = (struct HksBlob){ ML_DSA_MAX_KEY_SIZE, ctx->keyOutBuffer };
    ctx->keyIn = (struct HksBlob){ 0, NULL };
    do {
        if ((ctx->keyOut != NULL) && (ctx->keyOut->data != NULL) && (ctx->keyOut->size != 0)) {
            ctx->output = *ctx->keyOut;
        }
        ctx->ret = HksCheckGenAndImportKeyParams(&ctx->processInfo->processName, ctx->keyAlias, ctx->paramSetIn,
            &ctx->output);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "check generate key params failed, ret = %" LOG_PUBLIC "d", ctx->ret)

        ctx->ret = AppendNewInfoForGenKeyInService(ctx->processInfo, ctx->paramSetIn, &ctx->newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "append processName tag failed, ret = %" LOG_PUBLIC "d", ctx->ret)

        ctx->ret = CheckKeySecuritySeFromParamSet(ctx->processInfo, ctx->newParamSet, &ctx->isSeCalling);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckKeySecuritySeFromParamSet fail, ret = %" LOG_PUBLIC "d", ctx->ret)

        ctx->ret = GenerateKeyOperation(ctx->processInfo, ctx->keyAlias, ctx->newParamSet, &ctx->keyIn, &ctx->output);
        HKS_IF_NOT_SUCC_LOGE(ctx->ret, "GenerateKeyOperation failed, ret = %" LOG_PUBLIC "d", ctx->ret)
    } while (0);
}

int32_t HksServiceGenerateKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksBlob *keyOut)
{
    uint64_t enterTime = 0;
    (void)HksElapsedRealTime(&enterTime);
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    int32_t ret = 0;
    if (HksCheckIsUkeyOperation(paramSetIn, &ret) == HKS_SUCCESS) {
        return GenerateKeyUkeyOperation(processInfo, keyAlias, paramSetIn);
    }
#endif
    struct HksServiceGenKeyCtx ctx = {
        .processInfo = processInfo, .keyAlias = keyAlias,
        .paramSetIn = paramSetIn, .keyOut = keyOut,
        .newParamSet = NULL, .keyOutBuffer = NULL,
        .output = { 0, NULL }, .keyIn = { 0, NULL },
        .isSeCalling = false, .ret = 0
    };
    ctx.keyOutBuffer = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE);
    HKS_IF_NULL_RETURN(ctx.keyOutBuffer, HKS_ERROR_MALLOC_FAIL)
    struct HksHitraceId traceId = {0};
#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif
    ServiceGenerateKeyCore(&ctx);
#ifdef L2_STANDARD
    struct HksParamSet *reportParamSet = NULL;
    struct InfoPair infoPair = { .startTime = enterTime, .traceId = traceId.traceId.chainId };
    (void)PreConstructGenKeyReportParamSet(ctx.keyAlias, ctx.paramSetIn, infoPair, &ctx.output, &reportParamSet);
    (void)ConstructReportParamSet(__func__, ctx.processInfo, ctx.newParamSet, ctx.ret, &reportParamSet);
    HksEventReport(__func__, ctx.processInfo, ctx.paramSetIn, reportParamSet, ctx.ret);
    DeConstructReportParamSet(&reportParamSet);
#endif
    DecrementSeCountByService(ctx.isSeCalling);
    HKS_FREE(ctx.keyOutBuffer);
    if (ctx.keyIn.data != NULL) {
        (void)memset_s(ctx.keyIn.data, ctx.keyIn.size, 0, ctx.keyIn.size);
    }
    HKS_FREE(ctx.keyIn.data);
    HksFreeParamSet(&ctx.newParamSet);
    HksHitraceEnd(&traceId);
    return ctx.ret;
}

int32_t HksServiceSign(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *srcData, struct HksBlob *signature)
{
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = {0};

#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif

    do {
        ret = HksCheckAllParams(&processInfo->processName, keyAlias, paramSet, srcData, signature);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check sign params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "sign: get main key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        if (ret == HKS_SUCCESS) {
            ret = HuksAccessSign(&keyFromFile, newParamSet, srcData, signature);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ret == HKS_ERROR_CORRUPT_FILE || ret == HKS_ERROR_FILE_SIZE_FAIL || ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(keyFromFile);
            ret = GetKeyData(processInfo, keyAlias, newParamSet, &keyFromFile, HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "sign: get bak key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

            ret = HuksAccessSign(&keyFromFile, newParamSet, srcData, signature);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#endif
    } while (0);

#ifdef L2_STANDARD
    HksOneStageReportInfo info = {ret, startTime, traceId.traceId.chainId, __func__, HKS_ONE_STAGE_SIGN_VERIFY};
    (void)HksOneStageEventReport(keyAlias, &keyFromFile, newParamSet, processInfo, &info);
#endif
    HksHitraceEnd(&traceId);
    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksServiceVerify(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *srcData, const struct HksBlob *signature)
{
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = {0};

#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif

    do {
        ret = HksCheckAllParams(&processInfo->processName, keyAlias, paramSet, srcData, signature);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check verify params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "verify: get main key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        if (ret == HKS_SUCCESS) {
            ret = HuksAccessVerify(&keyFromFile, newParamSet, srcData, signature);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ret == HKS_ERROR_CORRUPT_FILE || ret == HKS_ERROR_FILE_SIZE_FAIL || ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(keyFromFile);
            ret = GetKeyData(processInfo, keyAlias, newParamSet, &keyFromFile, HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "verify: get bak key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

            ret = HuksAccessVerify(&keyFromFile, newParamSet, srcData, signature);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#endif
    } while (0);

#ifdef L2_STANDARD
    HksOneStageReportInfo info = {ret, startTime, traceId.traceId.chainId, __func__, HKS_ONE_STAGE_SIGN_VERIFY};
    (void)HksOneStageEventReport(keyAlias, &keyFromFile, newParamSet, processInfo, &info);
#endif
    HksHitraceEnd(&traceId);
    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksServiceEncrypt(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };

    do {
        ret = HksCheckAllParams(&processInfo->processName, keyAlias, paramSet, plainText, cipherText);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check encrypt failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "encrypt: get main key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        if (ret == HKS_SUCCESS) {
            ret = HuksAccessEncrypt(&keyFromFile, newParamSet, plainText, cipherText);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ret == HKS_ERROR_CORRUPT_FILE || ret == HKS_ERROR_FILE_SIZE_FAIL || ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(keyFromFile);
            ret = GetKeyData(processInfo, keyAlias, newParamSet, &keyFromFile, HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret,
                "encrypt: get bak key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)
            ret = HuksAccessEncrypt(&keyFromFile, newParamSet, plainText, cipherText);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#endif
    } while (0);

#ifdef L2_STANDARD
    HksOneStageReportInfo info = {ret, startTime, 0, __func__, HKS_ONE_STAGE_CRYPTO};
    (void)HksOneStageEventReport(keyAlias, &keyFromFile, newParamSet, processInfo, &info);
#endif
    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksServiceDecrypt(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *cipherText, struct HksBlob *plainText)
{
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = {0};

#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif

    do {
        ret = HksCheckAllParams(&processInfo->processName, keyAlias, paramSet, cipherText, plainText);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check decrypt failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "decrypt: get main key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        if (ret == HKS_SUCCESS) {
            ret = HuksAccessDecrypt(&keyFromFile, newParamSet, cipherText, plainText);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ret == HKS_ERROR_CORRUPT_FILE || ret == HKS_ERROR_FILE_SIZE_FAIL || ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(keyFromFile);
            ret = GetKeyData(processInfo, keyAlias, newParamSet, &keyFromFile, HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret,
                "decrypt: get bak key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)
            ret = HuksAccessDecrypt(&keyFromFile, newParamSet, cipherText, plainText);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#endif
    } while (0);
#ifdef L2_STANDARD
    HksOneStageReportInfo info = {ret, startTime, traceId.traceId.chainId, __func__, HKS_ONE_STAGE_CRYPTO};
    (void)HksOneStageEventReport(keyAlias, &keyFromFile, newParamSet, processInfo, &info);
#endif
    HksHitraceEnd(&traceId);
    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksServiceDeleteKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HKS_SUCCESS;
#ifdef L2_STANDARD
    uint64_t enterTime = 0;
    (void)HksElapsedRealTime(&enterTime);
    struct HksParamSet *newParamSet = NULL;
#else
    const struct HksParamSet *newParamSet = paramSet;
#endif
    do {
        ret = HksCheckProcessNameAndKeyAlias(&processInfo->processName, keyAlias);
        HKS_IF_NOT_SUCC_BREAK(ret)

#ifdef L2_STANDARD
        ret = AppendStorageLevelIfNotExistInner(processInfo, paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append storage level failed")
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
        ret = AppendGroupKeyInfo(processInfo, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append group key info failed, ret = %" LOG_PUBLIC "d", ret)
#endif
#endif
        /*
        * Detele key first, record log if failed; then delete cert chain, return error if failed;
        * Return error code of deleteKey in the end.
        */
        ret = HksManageStoreDeleteKeyBlob(processInfo, newParamSet, keyAlias, HKS_STORAGE_TYPE_KEY);
        if ((ret != HKS_SUCCESS) && (ret != HKS_ERROR_NOT_EXIST)) {
            HKS_LOG_E("service delete main key failed, ret = %" LOG_PUBLIC "d", ret);
        }
#ifdef HKS_ENABLE_SMALL_TO_SERVICE
        int32_t oldRet = HKS_FAILURE;
        if (HksCheckNeedUpgradeForSmallToService(processInfo) == HKS_SUCCESS) {
            oldRet = HksDeleteOldKeyForSmallToService(keyAlias);
            ret = (oldRet == HKS_SUCCESS) ? HKS_SUCCESS : ret;
        }
#endif
    } while (0);
#ifdef L2_STANDARD
    struct HksParamSet *reportParamSet = NULL;
    (void)PreConstructDeleteKeyReportParamSet(keyAlias, paramSet, enterTime, &reportParamSet);
    (void)ConstructReportParamSet(__func__, processInfo, newParamSet, ret, &reportParamSet);
    HksEventReport(__func__, processInfo, NULL, reportParamSet, ret);
    DeConstructReportParamSet(&reportParamSet);
    HksFreeParamSet(&newParamSet);
#endif
    return ret;
}

int32_t HksServiceKeyExist(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet)
{
    uint64_t enterTime = 0;
    (void)HksElapsedRealTime(&enterTime);
    int32_t ret = HksCheckProcessNameAndKeyAlias(&processInfo->processName, keyAlias);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

#ifdef L2_STANDARD
    struct HksParamSet *newParamSet = NULL;
#else
    const struct HksParamSet *newParamSet = paramSet;
#endif
    do {
#ifdef L2_STANDARD
        ret = AppendStorageLevelIfNotExistInner(processInfo, paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append storage level failed")
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
        ret = AppendGroupKeyInfo(processInfo, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append group key info failed, ret = %" LOG_PUBLIC "d", ret)
#endif
#endif
        ret = HksManageStoreIsKeyBlobExist(processInfo, newParamSet, keyAlias, HKS_STORAGE_TYPE_KEY);
#ifdef HKS_ENABLE_SMALL_TO_SERVICE
        if (HksCheckNeedUpgradeForSmallToService(processInfo) == HKS_SUCCESS) {
            if (ret == HKS_ERROR_NOT_EXIST) {
                // if change key owner success, the key should exist; otherwise the key not exist
                int32_t oldRet = HksChangeKeyOwnerForSmallToService(processInfo, NULL, keyAlias, HKS_STORAGE_TYPE_KEY);
                ret = (oldRet == HKS_SUCCESS) ? HKS_SUCCESS : ret;
            }
        }
#endif
    } while (0);
#ifdef L2_STANDARD
    struct HksParamSet *reportParamSet = NULL;
    (void)PreConstructCheckKeyExitedReportParamSet(keyAlias, paramSet, enterTime, &reportParamSet);
    (void)ConstructReportParamSet(__func__, processInfo, newParamSet, ret, &reportParamSet);
    HksEventReport(__func__, processInfo, NULL, reportParamSet, ret);
    DeConstructReportParamSet(&reportParamSet);
    HksFreeParamSet(&newParamSet);
#endif
    return ret;
}

int32_t HksServiceGetKeyParamSet(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };

    do {
        ret = HksCheckGetKeyParamSetParams(&processInfo->processName, keyAlias, paramSetOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check get key paramSet params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSetIn, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret,
            "get key paramSet: get key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        if (ret == HKS_SUCCESS) {
            ret = HuksAccessGetKeyProperties(newParamSet, &keyFromFile);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ret == HKS_ERROR_CORRUPT_FILE || ret == HKS_ERROR_FILE_SIZE_FAIL || ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(keyFromFile);
            ret = GetKeyData(processInfo, keyAlias, newParamSet, &keyFromFile, HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret,
                "get key paramSet: get bak key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)
            ret = HuksAccessGetKeyProperties(newParamSet, &keyFromFile);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret,
            "get key paramset or access level check key validity failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyParamSet(&keyFromFile, paramSetOut);
        HKS_IF_NOT_SUCC_LOGE(ret, "get Key paramSet failed, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);

#ifdef L2_STANDARD
    HksReport(__func__, processInfo, paramSetOut, ret);
#endif

    return ret;
}

int32_t HksServiceImportKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *key)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    uint8_t *keyOutBuffer = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE);
    HKS_IF_NULL_LOGE_RETURN(keyOutBuffer, HKS_ERROR_MALLOC_FAIL, "malloc keyOutBuffer failed.")
    struct HksBlob keyOut = { ML_DSA_MAX_KEY_SIZE, keyOutBuffer };
#ifdef L2_STANDARD
    struct HksParamSet *reportParamSet = NULL;
    uint64_t enterTime = 0;
    (void)HksElapsedRealTime(&enterTime);
#endif
    do {
        ret = HksCheckGenAndImportKeyParams(&processInfo->processName, keyAlias, paramSet, key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check import key params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = RejectSeSecurityLevel(paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "reject se security level for import key failed, ret = %" LOG_PUBLIC "d", ret)

        ret = AppendNewInfoForGenKeyInService(processInfo, paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append processName tag failed, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckKeyCondition(processInfo, keyAlias, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "import: check key condition failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HuksAccessImportKey(keyAlias, key, newParamSet, &keyOut);
        IfNotSuccAppendHdiErrorInfo(ret);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "access level import public key failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksManageStoreKeyBlob(processInfo, newParamSet, keyAlias, &keyOut, HKS_STORAGE_TYPE_KEY);
        HKS_IF_NOT_SUCC_LOGE(ret, "store keyblob to storage failed, ret = %" LOG_PUBLIC "d", ret)
    } while (0);
#ifdef L2_STANDARD
    (void)PreConstructImportKeyReportParamSet(keyAlias, paramSet, enterTime, &keyOut, &reportParamSet);
    (void)ConstructReportParamSet(__func__, processInfo, newParamSet, ret, &reportParamSet);
    HksEventReport(__func__, processInfo, paramSet, reportParamSet, ret);
    DeConstructReportParamSet(&reportParamSet);
#endif
    HKS_FREE(keyOutBuffer);
    HksFreeParamSet(&newParamSet);
    return ret;
}

static int32_t GetKeyAndNewParamSetInForGenKeyInService(const struct HksProcessInfo *processInfo,
    const struct HksBlob *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *key,
    struct HksParamSet **outParamSet)
{
    int32_t ret = AppendNewInfoForGenKeyInService(processInfo, paramSet, outParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "append new info failed, ret = %" LOG_PUBLIC "d", ret)

    ret = GetKeyData(processInfo, keyAlias, *outParamSet, key, HKS_STORAGE_TYPE_KEY);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get key data failed, ret = %" LOG_PUBLIC "d.", ret);
        HksFreeParamSet(outParamSet);
    }

    return ret;
}

struct HksImportWrappedInnerArgs {
    const struct HksProcessInfo *processInfo;
    const struct HksBlob *keyAlias;
    const struct HksBlob *wrappingKeyAlias;
    const struct HksParamSet *paramSet;
    const struct HksBlob *wrappedKeyData;
    bool *isSeCalling;
};

static int32_t GetAndImportKeystoreKey(const struct HksImportWrappedInnerArgs *args,
    struct HksParamSet **newParamSet, struct HksBlob *keyOut)
{
    struct HksBlob cipherKey = { 0, NULL };
    struct HksImportKeyStoreArgs data = { .keyAlias = *args->wrappingKeyAlias, .uidInt = args->processInfo->uidInt };
    int32_t ret = HksPluginImportWrappedKey(&data, &cipherKey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
        "HksPluginImportWrappedKey failed, ret = %" LOG_PUBLIC "d", ret)
    do {
        ret = AppendProcessInfoAndDefault(args->paramSet, args->processInfo, NULL, newParamSet, true);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append new info failed, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckKeySecuritySeFromParamSet(args->processInfo, *newParamSet, args->isSeCalling);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckKeySecuritySeFromParamSet fail, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckKeyCondition(args->processInfo, args->keyAlias, *newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check key condition failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HuksAccessImportWrappedKey(args->keyAlias, &cipherKey, &cipherKey, *newParamSet, keyOut);
        IfNotSuccAppendHdiErrorInfo(ret);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "access import wrappedKey failed, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HKS_FREE_BLOB(cipherKey);
    return ret;
}

#ifdef L2_STANDARD
static bool IsSeFromKeyBlob(const struct HksBlob *keyFromFile)
{
    const struct HksParamSet *keyParamSet = (const struct HksParamSet *)keyFromFile->data;
    if (HksCheckParamSet(keyParamSet, keyFromFile->size) != HKS_SUCCESS) {
        return false;
    }
    return IsSeSecurityLevel(keyParamSet);
}

static int32_t CheckImportWrappedKeySeMatch(const struct HksBlob *wrappingKeyFromFile,
    const struct HksParamSet *paramSet)
{
    if (IsSeFromKeyBlob(wrappingKeyFromFile) != IsSeSecurityLevel(paramSet)) {
        HKS_LOG_E("ImportWrappedKey: wrapping key and paramSet SE level mismatch");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}
#endif

static int32_t GetAndImportWrappedKey(const struct HksImportWrappedInnerArgs *args,
    struct HksParamSet **newParamSet, struct HksBlob *keyOut)
{
    struct HksParam *suite = NULL;
    if (HksGetParam(args->paramSet, HKS_TAG_UNWRAP_ALGORITHM_SUITE, &suite) == HKS_SUCCESS &&
        suite->uint32Param == HKS_UNWRAP_SUITE_KEYSTORE) {
        return GetAndImportKeystoreKey(args, newParamSet, keyOut);
    }

    struct HksBlob wrappingKeyFromFile = { 0, NULL };
    int32_t ret = HksServiceKeyExist(args->processInfo, args->wrappingKeyAlias, args->paramSet);
    do {
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "wrapping key is not exist, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSetInForGenKeyInService(args->processInfo, args->wrappingKeyAlias, args->paramSet,
            &wrappingKeyFromFile, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get wrapping key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckKeySecuritySeFromParamSet(args->processInfo, *newParamSet, args->isSeCalling);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckKeySecuritySeFromParamSet fail, ret = %" LOG_PUBLIC "d", ret)

#ifdef L2_STANDARD
        ret = CheckImportWrappedKeySeMatch(&wrappingKeyFromFile, args->paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ImportWrappedKey SE level mismatch, ret = %" LOG_PUBLIC "d", ret)
#endif

        ret = CheckKeyCondition(args->processInfo, args->keyAlias, *newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check condition failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HuksAccessImportWrappedKey(args->wrappingKeyAlias, &wrappingKeyFromFile, args->wrappedKeyData,
            *newParamSet, keyOut);
        IfNotSuccAppendHdiErrorInfo(ret);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "access import wrappedKey failed, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HKS_FREE_BLOB(wrappingKeyFromFile);
    return ret;
}

int32_t HksServiceImportWrappedKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksBlob *wrappingKeyAlias, const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    bool isSeCalling = false;
    struct HksBlob wrappingKeyFromFile = { 0, NULL };
    struct HksHitraceId traceId = {0};

#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif
    struct HksBlob keyOut = { MAX_KEY_SIZE, (uint8_t *)HksMalloc(MAX_KEY_SIZE) };
    HKS_IF_NULL_LOGE_RETURN(keyOut.data, HKS_ERROR_MALLOC_FAIL, "malloc keyout fail")
    do {
#ifdef HKS_UKEY_EXTENSION_CRYPTO
        if (HksCheckIsUkeyOperation(paramSet, &ret) == HKS_SUCCESS) {
            ret = HksCheckMultiSetTag(paramSet);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckMultiSetTag failed, ret = %" LOG_PUBLIC "d", ret)
            ret = HksServiceOnUkeyImportWrappedKey(processInfo, keyAlias, wrappingKeyAlias, paramSet, wrappedKeyData);
            HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceOnUkeyImportWrappedKey failed, ret = %" LOG_PUBLIC "d", ret)
            ReportUKeyKeyEvent(HKS_EVENT_UKEY_IMPORT_WRAPPED_KEY, ret, processInfo, paramSet);
            break;
        }
#endif

        ret = HksCheckImportWrappedKeyParams(&processInfo->processName, keyAlias,
            wrappingKeyAlias, paramSet, wrappedKeyData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check import params failed, ret = %" LOG_PUBLIC "d", ret)

        struct HksImportWrappedInnerArgs constArgs = { .processInfo = processInfo, .keyAlias = keyAlias,
            .wrappingKeyAlias = wrappingKeyAlias, .paramSet = paramSet, .wrappedKeyData = wrappedKeyData,
            .isSeCalling = &isSeCalling };
        ret = GetAndImportWrappedKey(&constArgs, &newParamSet, &keyOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get and import wrappedKey failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksManageStoreKeyBlob(processInfo, newParamSet, keyAlias, &keyOut, HKS_STORAGE_TYPE_KEY);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "store keyblob to storage failed, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    DecrementSeCountByService(isSeCalling);
    HKS_FREE_BLOB(keyOut);
    HKS_FREE_BLOB(wrappingKeyFromFile);
    HksFreeParamSet(&newParamSet);
    HksReportEvent(__func__, &traceId, processInfo, paramSet, ret);
    return ret;
}

#ifdef SUPPORT_STORAGE_BACKUP
static int32_t CheckBakKeySecuritySeIfNeeded(const struct HksProcessInfo *processInfo,
    const struct HksBlob *keyFromFile, bool *isSeCalling)
{
    if (*isSeCalling) {
        return HKS_SUCCESS;
    }
    return CheckKeySecuritySeFromKeyFile(processInfo, keyFromFile, isSeCalling);
}
#endif

int32_t HksServiceExportPublicKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    bool isSeCalling = false;

    do {
#ifdef HKS_UKEY_EXTENSION_CRYPTO
        if (HksCheckIsUkeyOperation(paramSet, &ret) == HKS_SUCCESS) {
            ret = HksCheckMultiSetTag(paramSet);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckMultiSetTag failed, ret = %" LOG_PUBLIC "d", ret)
            ret = HksServiceOnUkeyExportPublicKey(processInfo, keyAlias, paramSet, key);
            HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceOnUkeyExportPublicKey failed, ret = %" LOG_PUBLIC "d", ret)
            ReportUKeyKeyEvent(HKS_EVENT_UKEY_EXPORT_PUBLIC_KEY, ret, processInfo, paramSet);
            break;
        }
#endif

        ret = HksCheckExportPublicKeyParams(&processInfo->processName, keyAlias, key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check export public key params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        if (ret == HKS_SUCCESS) {
            ret = CheckKeySecuritySeFromKeyFile(processInfo, &keyFromFile, &isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckKeySecuritySeFromKeyFile fail, ret = %" LOG_PUBLIC "d", ret)
            ret = HuksAccessExportPublicKey(&keyFromFile, newParamSet, key);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ret == HKS_ERROR_CORRUPT_FILE || ret == HKS_ERROR_FILE_SIZE_FAIL || ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(keyFromFile);
            ret = GetKeyData(processInfo, keyAlias, newParamSet, &keyFromFile, HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret,
                "export public: get bak key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)
            ret = CheckBakKeySecuritySeIfNeeded(processInfo, &keyFromFile, &isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckBakKeySeIfNeeded fail, ret = %" LOG_PUBLIC "d", ret)
            ret = HuksAccessExportPublicKey(&keyFromFile, newParamSet, key);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#endif
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    DecrementSeCountByService(isSeCalling);

#ifdef L2_STANDARD
    HksReport(__func__, processInfo, NULL, ret);
#endif

    return ret;
}

int32_t HksServiceAgreeKey(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *privateKey, const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = {0};

#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif

    do {
        ret = HksCheckAllParams(&processInfo->processName, privateKey, paramSet, peerPublicKey, agreedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check agree key params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, privateKey, paramSet, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "agree: get main key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        if (ret == HKS_SUCCESS) {
            ret = HuksAccessAgreeKey(newParamSet, &keyFromFile, peerPublicKey, agreedKey);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ret == HKS_ERROR_CORRUPT_FILE || ret == HKS_ERROR_FILE_SIZE_FAIL || ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(keyFromFile);
            ret = GetKeyData(processInfo, privateKey, newParamSet, &keyFromFile, HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "agree: get bak key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)
            ret = HuksAccessAgreeKey(newParamSet, &keyFromFile, peerPublicKey, agreedKey);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#endif
    } while (0);

#ifdef L2_STANDARD
    HksOneStageReportInfo info = {ret, startTime, traceId.traceId.chainId, __func__, HKS_ONE_STAGE_AGREE};
    (void)HksOneStageEventReport(agreedKey, &keyFromFile, newParamSet, processInfo, &info);
#endif
    HksHitraceEnd(&traceId);
    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksServiceDeriveKey(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *mainKey, struct HksBlob *derivedKey)
{
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = {0};

#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif

    do {
        ret = HksCheckDeriveKeyParams(&processInfo->processName, paramSet, mainKey, derivedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check derive key params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, mainKey, paramSet, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "derive: get main key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        if (ret == HKS_SUCCESS) {
            ret = HuksAccessDeriveKey(newParamSet, &keyFromFile, derivedKey);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ret == HKS_ERROR_CORRUPT_FILE || ret == HKS_ERROR_FILE_SIZE_FAIL || ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(keyFromFile);
            ret = GetKeyData(processInfo, mainKey, newParamSet, &keyFromFile, HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "derive: get bak key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)
            ret = HuksAccessDeriveKey(newParamSet, &keyFromFile, derivedKey);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#endif
    } while (0);

#ifdef L2_STANDARD
    HksOneStageReportInfo info = {ret, startTime, traceId.traceId.chainId, __func__, HKS_ONE_STAGE_DERIVE};
    (void)HksOneStageEventReport(derivedKey, &keyFromFile, newParamSet, processInfo, &info);
#endif
    HksHitraceEnd(&traceId);
    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksServiceMac(const struct HksProcessInfo *processInfo, const struct HksBlob *key,
    const struct HksParamSet *paramSet, const struct HksBlob *srcData, struct HksBlob *mac)
{
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = {0};

#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif

    do {
        ret = HksCheckAllParams(&processInfo->processName, key, paramSet, srcData, mac);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check mac params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, key, paramSet, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "mac: get main key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        if (ret == HKS_SUCCESS) {
            ret = HuksAccessMac(&keyFromFile, newParamSet, srcData, mac);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ret == HKS_ERROR_CORRUPT_FILE || ret == HKS_ERROR_FILE_SIZE_FAIL || ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(keyFromFile);
            ret = GetKeyData(processInfo, key, newParamSet, &keyFromFile, HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "mac: get bak key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)
            ret = HuksAccessMac(&keyFromFile, newParamSet, srcData, mac);
            IfNotSuccAppendHdiErrorInfo(ret);
        }
#endif
    } while (0);

#ifdef L2_STANDARD
    HksOneStageReportInfo info = {ret, startTime, traceId.traceId.chainId, __func__, HKS_ONE_STAGE_MAC};
    (void)HksOneStageEventReport(key, &keyFromFile, newParamSet, processInfo, &info);
#endif
    HksHitraceEnd(&traceId);
    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksServiceInitialize(void)
{
    int32_t ret;
    do {
        ret = HuksAccessModuleInit();
        IfNotSuccAppendHdiErrorInfo(ret);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks core service initialize failed! ret = %" LOG_PUBLIC "d", ret)

        ret = HksInitPluginProxy();
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init plugin failed, ret=%" LOG_PUBLIC "d", ret);

#ifdef _STORAGE_LITE_
        ret = HksLoadFileToBuffer();
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "load file to buffer failed, ret = %" LOG_PUBLIC "d", ret)
#endif

#ifdef HKS_ENABLE_MARK_CLEARED_FOR_SMALL_TO_SERVICE
        (void)HksMarkOldKeyClearedIfEmpty();
#endif
    } while (0);

#ifdef L2_STANDARD
    HksReport(__func__, NULL, NULL, ret);
#endif

    return ret;
}

int32_t HksServiceRefreshKeyInfo(const struct HksBlob *processName)
{
    int32_t ret;

    do {
        ret = HksStoreDestroy(processName);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "destroy storage files ret = 0x%" LOG_PUBLIC "X", ret)

#ifndef _HARDWARE_ROOT_KEY_
        ret = HuksAccessRefresh();
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Hks core service refresh info failed! ret = 0x%" LOG_PUBLIC "X", ret)
#endif

#ifdef _STORAGE_LITE_
        ret = HksFileBufferRefresh();
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "load file to buffer failed, ret = %" LOG_PUBLIC "d", ret)
#endif
    } while (0);

#ifdef L2_STANDARD
    int userId = 0;
    struct HksBlob userIdBlob = { sizeof(int), (uint8_t *)&userId };
    struct HksProcessInfo processInfo = {userIdBlob, *processName};
    HksReport(__func__, &processInfo, NULL, ret);
#endif

    return ret;
}

#ifdef HKS_SUPPORT_API_ATTEST_KEY
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
static int32_t AddAppInfoToParamSet(const struct HksProcessInfo *processInfo, struct HksBlob *appInfo,
    struct HksParamSet *paramSet)
{
    int32_t ret;
    do {
        enum HksCallerType appidType = HksGetCallerType();
        if (appidType == HKS_HAP_TYPE) {
            ret = HksGetHapInfo(processInfo, appInfo);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetHapInfo failed")
        } else if (appidType == HKS_SA_TYPE) {
            ret = HksGetSaInfo(appInfo);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetSaInfo failed")
        }

        ret = CheckBlob(appInfo);
        if (ret == HKS_SUCCESS) {
            struct HksParam params[] = {
                { .tag = HKS_TAG_ATTESTATION_APPLICATION_ID, .blob = *appInfo },
                { .tag = HKS_TAG_ATTESTATION_APPLICATION_ID_TYPE, .uint32Param = appidType }
            };
            ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(params[0]));
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add appInfo failed")
        } else {
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Check appInfo Blob failed!")
        }
    } while (0);
    return ret;
}
#endif

static int32_t AddModelToParamSet(struct HksParamSet *paramSet)
{
    const char *modelPtr = GetProductModel();
    HKS_IF_NULL_LOGE_RETURN(modelPtr, HKS_ERROR_NULL_POINTER, "GetProductModel failed")

    struct HksParam modelParam = {
        .tag = HKS_TAG_ATTESTATION_ID_MODEL,
        .blob = { .size = strlen(modelPtr), .data = (uint8_t *)modelPtr }
    };
    int32_t ret = HksAddParams(paramSet, &modelParam, 1);
    HKS_IF_NOT_SUCC_LOGE(ret, "add model failed")
    return HKS_SUCCESS;
}

static int32_t AddAppInfoAndModelToParamSet(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    int32_t ret;
    struct HksBlob appInfo = { 0, NULL };
    struct HksParamSet *newParamSet = NULL;

    do {
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
        ret = AppendToNewParamSet(paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy paramSet failed")

        ret = AddAppInfoToParamSet(processInfo, &appInfo, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add appInfo to paramset failed")
#else
        ret = AppendToNewParamSet(*outParamSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy outParamSet failed")
#endif

        ret = AddModelToParamSet(newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add model to paramset failed")

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramset failed")

#ifndef HKS_SUPPORT_GET_BUNDLE_INFO
        HksFreeParamSet(outParamSet);
#endif
        *outParamSet = newParamSet;
        HKS_FREE_BLOB(appInfo);
        return ret;
    } while (0);

    HKS_FREE_BLOB(appInfo);
    HksFreeParamSet(&newParamSet);
    return ret;
}

struct HksCertChainInfo {
    struct HksBlob *certChain;
    uint32_t certChainCapacity;
};

static int32_t DcmGenerateCertChainInAttestKey(
    const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const uint8_t *remoteObject, struct HksCertChainInfo *certChainInfo, bool isSeKey)
{
    (void)processInfo;
    (void)paramSet;
    (void)remoteObject;
    (void)certChainInfo;
    (void)isSeKey;
    int32_t ret = HKS_SUCCESS;
#ifndef HKS_UNTRUSTED_RUNNING_ENV
    HKS_IF_NOT_TRUE_LOGI_RETURN(HksAttestIsAnonymous(paramSet), HKS_SUCCESS, "non anonymous attest key.")
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    HksUpgradeOrRequestUnlockRead();
#endif
    struct HksParam *anonyModeParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_ANONYMOUS_ATTESTATION_MODE, &anonyModeParam);
    if (ret == HKS_SUCCESS && anonyModeParam->uint32Param == HKS_ANONYMOUS_ATTEST_OFFLINE) {
        ret = DcmLocalGenerateCertChain(processInfo, certChainInfo->certChain, remoteObject);
    } else {
        if (isSeKey) {
            ret = DcmSeGenerateCertChain(certChainInfo->certChain, remoteObject);
        } else {
            ret = DcmGenerateCertChain(certChainInfo->certChain, remoteObject);
        }
    }
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    HksUpgradeOrRequestLockRead();
#endif
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "DcmGenerateCertChain fail, ret = %" LOG_PUBLIC "d.", ret)

    (void)memset_s(certChainInfo->certChain->data, certChainInfo->certChainCapacity, 0,
        certChainInfo->certChainCapacity);
    certChainInfo->certChain->size = certChainInfo->certChainCapacity;
#endif
    return ret;
}

static void AttestFree(struct HksBlob *keyFromFile, struct HksParamSet **newParamSet,
    struct HksParamSet **processInfoParamSet, struct HksHitraceId *traceId)
{
    HksFreeParamSet(newParamSet);
    HksFreeParamSet(processInfoParamSet);
    HksHitraceEnd(traceId);
    HKS_IF_NULL_LOGE_RETURN_VOID(keyFromFile, "keyFromFile is null")
    HKS_FREE_BLOB(*keyFromFile);
}

static int32_t AccessAttestKey(struct HksBlob *keyFromFile, struct HksParamSet *newParamSet, struct HksBlob *certChain)
{
    int32_t ret = HuksAccessAttestKey(keyFromFile, newParamSet, certChain);
    IfNotSuccAppendHdiErrorInfo(ret);
    return ret;
}

struct HksAttestKeyCtx {
    const struct HksProcessInfo *processInfo;
    const struct HksBlob *keyAlias;
    const struct HksParamSet *paramSet;
    struct HksBlob *certChain;
    const uint8_t *remoteObject;
    struct HksBlob keyFromFile;
    struct HksParamSet *newParamSet;
    struct HksParamSet *processInfoParamSet;
    bool isSeCalling;
    uint32_t certChainCapacity;
    int32_t ret;
};

static void AttestKeyCoreOp(struct HksAttestKeyCtx *ctx)
{
    ctx->ret = HksCheckAttestKeyParams(&ctx->processInfo->processName, ctx->keyAlias, ctx->paramSet, ctx->certChain);
    do {
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "check attest key param fail");
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
        ctx->ret = GetKeyAndNewParamSet(ctx->processInfo, ctx->keyAlias, ctx->paramSet,
            &ctx->keyFromFile, &ctx->processInfoParamSet);
        HKS_IF_NOT_SUCC_LOGE(ctx->ret, "GetKeyAndNewParamSet failed, ret = %" LOG_PUBLIC "d.", ctx->ret)
#else
        ctx->ret = GetKeyAndNewParamSet(ctx->processInfo, ctx->keyAlias, ctx->paramSet,
            &ctx->keyFromFile, &ctx->newParamSet);
        HKS_IF_NOT_SUCC_LOGE(ctx->ret, "GetKeyAndNewParamSet failed, ret = %" LOG_PUBLIC "d.", ctx->ret)
#endif
        if (ctx->ret == HKS_SUCCESS) {
            ctx->ret = CheckKeySecuritySeFromKeyFile(ctx->processInfo, &ctx->keyFromFile, &ctx->isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckKeySecuritySeFromKeyFile fail, ret = %" LOG_PUBLIC "d", ctx->ret)
        }
        ctx->certChainCapacity = ctx->certChain->size;
        if (ctx->ret == HKS_SUCCESS) {
            ctx->ret = AddAppInfoAndModelToParamSet(ctx->processInfo, ctx->processInfoParamSet, &ctx->newParamSet);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "AddAppInfoAndModelToParam failed, ret = %" LOG_PUBLIC "d.", ctx->ret)
            ctx->ret = AccessAttestKey(&ctx->keyFromFile, ctx->newParamSet, ctx->certChain);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        if (ctx->ret == HKS_ERROR_CORRUPT_FILE || ctx->ret == HKS_ERROR_FILE_SIZE_FAIL ||
            ctx->ret == HKS_ERROR_NOT_EXIST) {
            HKS_FREE_BLOB(ctx->keyFromFile);
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
            HksFreeParamSet(&ctx->newParamSet);
#endif
            ctx->ret = AddAppInfoAndModelToParamSet(ctx->processInfo, ctx->processInfoParamSet, &ctx->newParamSet);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "AddAppInfoAndModelToParam failed, ret = %" LOG_PUBLIC "d.", ctx->ret)
            ctx->ret = GetKeyData(ctx->processInfo, ctx->keyAlias, ctx->newParamSet, &ctx->keyFromFile,
                HKS_STORAGE_TYPE_BAK_KEY);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "get bak key and new param failed, ret = %" LOG_PUBLIC "d", ctx->ret)
            ctx->ret = CheckBakKeySecuritySeIfNeeded(ctx->processInfo, &ctx->keyFromFile, &ctx->isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckBakKeySeIfNeeded fail, ret = %" LOG_PUBLIC "d", ctx->ret)
            ctx->ret = AccessAttestKey(&ctx->keyFromFile, ctx->newParamSet, ctx->certChain);
        }
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "HuksAttestKey fail, ret = %" LOG_PUBLIC "d.", ctx->ret)
        struct HksCertChainInfo certChainInfo = { ctx->certChain, ctx->certChainCapacity };
        ctx->ret = DcmGenerateCertChainInAttestKey(ctx->processInfo, ctx->paramSet,
            ctx->remoteObject, &certChainInfo, ctx->isSeCalling);
    } while (0);
}

int32_t HksServiceAttestKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *certChain, const uint8_t *remoteObject)
{
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksHitraceId traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
    struct HksAttestKeyCtx ctx = {
        .processInfo = processInfo, .keyAlias = keyAlias,
        .paramSet = paramSet, .certChain = certChain, .remoteObject = remoteObject,
        .keyFromFile = { 0, NULL }, .newParamSet = NULL,
        .processInfoParamSet = NULL, .isSeCalling = false,
        .certChainCapacity = 0, .ret = 0
    };
    AttestKeyCoreOp(&ctx);
#ifdef L2_STANDARD
    HksOneStageReportInfo info = {ctx.ret, startTime, traceId.traceId.chainId, __func__, HKS_ONE_STAGE_ATTEST};
    (void)HksOneStageEventReport(keyAlias, &ctx.keyFromFile, ctx.newParamSet, processInfo, &info);
#endif

    AttestFree(&ctx.keyFromFile, &ctx.newParamSet, &ctx.processInfoParamSet, &traceId);
    DecrementSeCountByService(ctx.isSeCalling);
    return ctx.ret;
}
#else // HKS_SUPPORT_API_ATTEST_KEY
int32_t HksServiceAttestKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *certChain, const uint8_t *remoteObject)
{
    (void)processInfo;
    (void)keyAlias;
    (void)paramSet;
    (void)certChain;
    (void)remoteObject;
    return HKS_ERROR_NOT_SUPPORTED;
}
#endif // HKS_SUPPORT_API_ATTEST_KEY

static int32_t CreateOperation(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *handle, bool abortable)
{
    if (IsSeHandle(handle)) {
        return HksCreateSeOperation(processInfo, paramSet, handle);
    }

    return HksCreateOperation(processInfo, paramSet, handle, abortable);
}

typedef struct {
    bool isSe;
    union {
        struct HksOperation *operation;
        struct HksSeOperation *seOperation;
    } op;
} HksOperationUnion;

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
        HksDeleteSeOperation(handle);
        unionOp->op.seOperation = NULL;
    } else {
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
        ctx->ret = GetKeyAndNewParamSet(ctx->processInfo, ctx->keyAlias, ctx->paramSet,
            &ctx->keyFromFile, &ctx->newParamSet);
        if (ctx->ret == HKS_SUCCESS) {
            ctx->ret = CheckKeySecuritySeFromKeyFile(ctx->processInfo, &ctx->keyFromFile, &ctx->isSeCalling);
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
            ctx->ret = CheckBakKeySecuritySeIfNeeded(ctx->processInfo, &ctx->keyFromFile, &ctx->isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckBakKeySeIfNeeded fail, ret = %" LOG_PUBLIC "d", ctx->ret)
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
    HksThreeStageReportInfo info = { ctx.ret, 0, HKS_INIT, ctx.startTime, ctx.traceId.traceId.chainId, ctx.handle };
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

        ctx->ret = CheckAccessTokenWrapper(&ctx->unionOp, ctx->processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckAccessTokenWrapper fail")

        ctx->ret = CheckBatchOperation(&ctx->unionOp, ctx->handle);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ctx->ret, "CheckBatchOperation fail, ret = %" LOG_PUBLIC "d", ctx->ret)

        if (IsSeHandle(ctx->handle)) {
            ctx->ret = CheckSeSessionCallInService(ctx->processInfo, &ctx->isSeCalling);
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
        traceId.traceId.chainId, handle,
        ctx.unionOp.isSe ? NULL : ctx.unionOp.op.operation };
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

        if (IsSeHandle(ctx->handle)) {
            ctx->ret = CheckSeSessionCallInService(ctx->processInfo, &ctx->isSeCalling);
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
        traceId.traceId.chainId, handle,
        ctx.unionOp.isSe ? NULL : ctx.unionOp.op.operation };
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
        if (!IsOperationExist(ctx->processInfo, ctx->handle, &ctx->unionOp)) {
            ctx->ret = HKS_SUCCESS;
            break;
        }
        if (ctx->unionOp.isSe) {
            ctx->ret = CheckSeSessionCallInService(ctx->processInfo, &ctx->isSeCalling);
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
            ctx->traceId.traceId.chainId, ctx->handle,
            ctx->unionOp.isSe ? NULL : ctx->unionOp.op.operation };
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

void HksServiceDeleteProcessInfo(const struct HksProcessInfo *processInfo, bool anco)
{
#ifndef __LITEOS_M__
    HKS_LOG_I("remove session");
    DeleteSessionByProcessInfo(processInfo);

    if (processInfo->processName.size == 0) {
        HksServiceDeleteUserIDKeyAliasFile(&processInfo->userId);
    } else {
        if (anco) {
#ifdef L2_STANDARD
            HksServiceDeleteAncoUIDKeyFile(processInfo);
#else
            HKS_LOG_E("only L2 device supported anco");
#endif
        } else {
            HksServiceDeleteUIDKeyAliasFile(processInfo);
        }
    }
#else
    (void)anco;
    (void)processInfo;
#endif
}

#endif

int32_t HksServiceGenerateRandom(const struct HksProcessInfo *processInfo, struct HksBlob *random)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;

    do {
        ret = HksCheckGenerateRandomParams(&processInfo->processName, random);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check generate random params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = AppendProcessInfoAndDefault(NULL, processInfo, NULL, &newParamSet, false);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append process info failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HuksAccessGenerateRandom(newParamSet, random);
        IfNotSuccAppendHdiErrorInfo(ret);
    } while (0);

    HksFreeParamSet(&newParamSet);

#ifdef L2_STANDARD
    HksReport(__func__, processInfo, NULL, ret);
#endif

    return ret;
}

int32_t HksServiceListAliases(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksKeyAliasSet **outData)
{
#ifdef L2_STANDARD
    struct HksParamSet *newParamSet = NULL;
    uint64_t enterTime = 0;
    (void)HksElapsedRealTime(&enterTime);
    int32_t ret = HKS_SUCCESS;
    do {
        ret = AppendStorageLevelIfNotExistInner(processInfo, paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append storage level failed")
#ifdef HKS_SUPPORT_GET_BUNDLE_INFO
        ret = AppendGroupKeyInfo(processInfo, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append group key info failed, ret = %" LOG_PUBLIC "d", ret)
#endif
        ret = HksCheckListAliasesParam(&(processInfo->processName));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check list aliases param failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksManageListAliasesByProcessName(processInfo, newParamSet, outData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "list aliases by process name failed, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

#ifdef L2_STANDARD
    struct HksParamSet *reportParamSet = NULL;
    (void)PreConstructListAliasesReportParamSet(paramSet, enterTime, &reportParamSet);
    (void)ConstructReportParamSet(__func__, processInfo, newParamSet, ret, &reportParamSet);
    HksEventReport(__func__, processInfo, NULL, reportParamSet, ret);
    DeConstructReportParamSet(&reportParamSet);
#endif
    HksFreeParamSet(&newParamSet);
    return ret;
#else
    (void)processInfo;
    (void)paramSet;
    (void)outData;
    return HKS_SUCCESS;
#endif
}

int32_t HksServiceRenameKeyAlias(const struct HksProcessInfo *processInfo, const struct HksBlob *oldKeyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *newKeyAlias)
{
    uint64_t enterTime = 0;
    (void)HksElapsedRealTime(&enterTime);
    int32_t ret = HKS_SUCCESS;
    do {
        ret = HksCheckProcessNameAndKeyAlias(&processInfo->processName, oldKeyAlias);
        HKS_IF_NOT_SUCC_BREAK(ret, "HksCheckProcessNameAndKeyAlias failed!");

        ret = HKsCheckOldKeyAliasDiffNewKeyAlias(oldKeyAlias, newKeyAlias);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("the new key alias same as old key alias !, ret = %" LOG_PUBLIC "d", ret);
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }

        ret = HksCheckOldKeyExist(processInfo, oldKeyAlias, paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret, "HksCheckOldKeyExist failed!, ret = %" LOG_PUBLIC "d", ret);

        ret = HksCheckNewKeyNotExist(processInfo, newKeyAlias, paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret, "HksCheckNewKeyNotExist failed!, ret = %" LOG_PUBLIC "d", ret);

        ret = HksManageStoreRenameKeyAlias(processInfo, oldKeyAlias, paramSet, newKeyAlias,
            HKS_STORAGE_TYPE_KEY);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("bad state, rename faild !, ret = %" LOG_PUBLIC "d", ret);
            ret = HKS_ERROR_BAD_STATE;
        }
    } while (0);
#ifdef L2_STANDARD
    struct HksParamSet *reportParamSet = NULL;
    (void)PreConstructRenameReportParamSet(oldKeyAlias, newKeyAlias, paramSet,
        enterTime, &reportParamSet);
    (void)ConstructReportParamSet(__func__, processInfo, NULL, ret, &reportParamSet);
    HksEventReport(__func__, processInfo, paramSet, reportParamSet, ret);
    DeConstructReportParamSet(&reportParamSet);
#endif
    return ret;
}

#ifdef L2_STANDARD
static int32_t AppendChangeStorageLevelInfoInService(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    do {
        ret = (paramSet != NULL) ? AppendToNewParamSet(paramSet, &newParamSet) : HksInitParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append client service tag failed")

        // process name only can be inserted by service
        ret = HKS_ERROR_INVALID_ARGUMENT;
        HKS_IF_TRUE_BREAK(CheckProcessNameTagExist(newParamSet))

        struct HksParam paramArr[] = {
            { .tag = HKS_TAG_PROCESS_NAME, .blob = processInfo->processName },
            { .tag = HKS_TAG_USER_ID, .uint32Param = processInfo->userIdInt },
            { .tag = HKS_TAG_IS_CHANGE_STORAGE_LEVEL, .boolParam = true },
            { .tag = HKS_TAG_SCREEN_STATE, .boolParam = HksGetScreenState()},
#ifdef HKS_SUPPORT_ACCESS_TOKEN
            { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = processInfo->accessTokenId },
#endif
        };

        ret = HksAddParams(newParamSet, paramArr, HKS_ARRAY_SIZE(paramArr));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add processInfo failed")

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramset failed")

        *outParamSet = newParamSet;
        return ret;
    } while (0);
    HksFreeParamSet(&newParamSet);
    return ret;
}

/*
 * dest key exist and src key exist, which means HKS_ERROR_KEY_CONFLICT
 * dest key exist and src key not exist, which means HKS_SUCCESS(not need update)
 * dest key not exist and src key exist, which means need update
 * dest key not exist and src key not exist, which means HKS_ERROR_NOT_EXIST
 */
static int32_t HksCheckSrcKeyAndDestKeyCondition(const struct HksProcessInfo *processInfo,
    const struct HksBlob *keyAlias, const struct HksParamSet *srcParamSet, const struct HksParamSet *destParamSet,
    bool *isSkipUpdate)
{
    int32_t ret = HksManageStoreIsKeyBlobExist(processInfo, destParamSet, keyAlias, HKS_STORAGE_TYPE_KEY);
    if (ret == HKS_SUCCESS) {
        ret = HksManageStoreIsKeyBlobExist(processInfo, srcParamSet, keyAlias, HKS_STORAGE_TYPE_KEY);
        if (ret == HKS_SUCCESS) {
            HKS_LOG_E("source and destination both have key, key conflict");
            ret = HKS_ERROR_KEY_CONFLICT;
        } else if (ret == HKS_ERROR_NOT_EXIST) {
            HKS_LOG_I("destination already has key, source doesn't have key, no need to transfer key ");
            // no need to update key, actually return success
            *isSkipUpdate = true;
        } else {
            HKS_LOG_E("hks get key blob is exist failed");
        }
    } else if (ret == HKS_ERROR_NOT_EXIST) {
        ret = HksManageStoreIsKeyBlobExist(processInfo, srcParamSet, keyAlias, HKS_STORAGE_TYPE_KEY);
        HKS_IF_TRUE_LOGE(ret == HKS_ERROR_NOT_EXIST, "source and destination both don't have key");
    } else {
        HKS_LOG_E("hks get key blob is exist failed");
    }
    return ret;
}

static int32_t HksMallocNewKey(struct HksBlob *newKey)
{
    newKey->data = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
    HKS_IF_NULL_RETURN(newKey->data, HKS_ERROR_MALLOC_FAIL)

    newKey->size = MAX_KEY_SIZE;
    return HKS_SUCCESS;
}
#endif

int32_t HksServiceChangeStorageLevel(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *srcParamSet, const struct HksParamSet *destParamSet)
{
#ifdef L2_STANDARD
    int32_t ret;
    bool isSkipUpdate = false;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob oldKey = { 0, NULL };
    struct HksBlob newKey = { 0, NULL };
    do {
        ret = HksCheckProcessInConfigList(&processInfo->processName);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check process in config list failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckChangeStorageLevelParams(&processInfo->processName, keyAlias, srcParamSet, destParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check change storage level params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckSrcKeyAndDestKeyCondition(processInfo, keyAlias, srcParamSet, destParamSet, &isSkipUpdate);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check src key and dest key condition failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyFileData(processInfo, srcParamSet, keyAlias, &oldKey, HKS_STORAGE_TYPE_KEY);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get key data failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = AppendChangeStorageLevelInfoInService(processInfo, destParamSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append change storage level info failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksMallocNewKey(&newKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "new key malloc failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HuksAccessUpgradeKey(&oldKey, newParamSet, &newKey);
        IfNotSuccAppendHdiErrorInfo(ret);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "access upgrade key failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksManageStoreKeyBlob(processInfo, newParamSet, keyAlias, &newKey, HKS_STORAGE_TYPE_KEY);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "store keyblob to storage failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksManageStoreDeleteKeyBlob(processInfo, srcParamSet, keyAlias, HKS_STORAGE_TYPE_KEY);
        HKS_IF_TRUE_BREAK(ret == HKS_SUCCESS || ret == HKS_ERROR_NOT_EXIST)

        ret = HksManageStoreDeleteKeyBlob(processInfo, srcParamSet, keyAlias, HKS_STORAGE_TYPE_KEY);
        HKS_IF_TRUE_BREAK(ret == HKS_SUCCESS || ret == HKS_ERROR_NOT_EXIST)

        ret = HKS_ERROR_KEY_CLEAR_FAILED;
        HKS_LOG_E("delete src key failed");
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(oldKey);
    HKS_FREE_BLOB(newKey);
    HksReport(__func__, processInfo, newParamSet, ret);
    HKS_IF_TRUE_RETURN(isSkipUpdate, HKS_SUCCESS)
    return ret;
#else
    (void)processInfo;
    (void)keyAlias;
    (void)srcParamSet;
    (void)destParamSet;
    return HKS_SUCCESS;
#endif
}

static int32_t CheckWrapKeyType(const struct HksParamSet *paramSetIn)
{
    struct HksParam *wrapTypeParam = NULL;
    int32_t ret = HksGetParam(paramSetIn, HKS_TAG_KEY_WRAP_TYPE, &wrapTypeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get wrapTypeParam failed")
 
    switch (wrapTypeParam->uint32Param) {
        case HKS_KEY_WRAP_TYPE_HUK:
            return HKS_SUCCESS;
        default:
            HKS_LOG_E("invalid wrap type, type = %" LOG_PUBLIC "d", wrapTypeParam->uint32Param);
            return HKS_ERROR_INVALID_KEY_WRAP_TYPE;
    }
}

struct HksAccessWrapKeyArgs {
    const struct HksBlob *inData;
    const struct HksParamSet *paramSet;
    struct HksBlob *outData;
};

static int32_t AccessWrapKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *wrappedKey)
{
    struct HksAccessWrapKeyArgs args = {
        .inData = key,
        .paramSet = paramSet,
        .outData = wrappedKey
    };
    uint32_t size = sizeof(args);
    return HksPluginOnAccessWrapKey(CODE_SA_WRAP_KEY, &args, &size);
}

static int32_t AccessUnwrapKey(const struct HksParamSet *paramSet, const struct HksBlob *wrappedKey,
    struct HksBlob *keyOut)
{
    struct HksAccessWrapKeyArgs args = {
        .inData = wrappedKey,
        .paramSet = paramSet,
        .outData = keyOut
    };
    uint32_t size = sizeof(args);
    return HksPluginOnAccessWrapKey(CODE_SA_UNWRAP_KEY, &args, &size);
}

int32_t HksServiceWrapKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *wrappedKey)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    bool isSeCalling = false;

    do {
        ret = HksCheckWrapAndUnwrapKeyParams(&processInfo->processName, keyAlias, paramSet, wrappedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check wrap params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "GetKeyAndNewParamSet failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = CheckKeySecuritySeFromKeyFile(processInfo, &keyFromFile, &isSeCalling);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckKeySecuritySeFromKeyFile fail, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckWrapKeyType(newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check wrap type failed, ret = %" LOG_PUBLIC "d", ret)

        ret = AccessWrapKey(&keyFromFile, newParamSet, wrappedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HuksAccessWrapKey failed, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HKS_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    DecrementSeCountByService(isSeCalling);
    return ret;
}

int32_t HksServiceUnwrapKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *wrappedKey)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    uint8_t *keyOutBuffer = NULL;
    bool isSeCalling = false;

    do {
        ret = HksCheckWrapAndUnwrapKeyParams(&processInfo->processName, keyAlias, paramSet, wrappedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check wrap params failed, ret = %" LOG_PUBLIC "d", ret)

        ret = AppendNewInfoForGenKeyInService(processInfo, paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append processName tag failed, ret = %" LOG_PUBLIC "d", ret)

        bool isSeWrappedKey = false;
        ret = CheckWrappedKeySeVersionInService(wrappedKey, &isSeWrappedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckWrappedKeySeVersionInService fail, ret = %" LOG_PUBLIC "d", ret)

        if (isSeWrappedKey) {
            ret = CheckSeSessionCallInService(processInfo, &isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckSeSessionCallInService fail, ret = %" LOG_PUBLIC "d", ret)
        }

        ret = CheckKeyCondition(processInfo, keyAlias, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check key condition failed, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckWrapKeyType(newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check wrap type failed, ret = %" LOG_PUBLIC "d.", ret)

        keyOutBuffer = (uint8_t *)HksMalloc(MAX_KEY_SIZE);
        if (keyOutBuffer == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        struct HksBlob keyOut = { MAX_KEY_SIZE, keyOutBuffer };
        ret = AccessUnwrapKey(newParamSet, wrappedKey, &keyOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HuksAccessUnwrapKey failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksManageStoreKeyBlob(processInfo, newParamSet, keyAlias,
            &keyOut, HKS_STORAGE_TYPE_KEY);
        HKS_IF_NOT_SUCC_LOGE(ret, "store keyblob to storage failed, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    DecrementSeCountByService(isSeCalling);
    HKS_FREE(keyOutBuffer);
    HksFreeParamSet(&newParamSet);
    return ret;
}

static int32_t HksCheckAndBuildShareParam(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksParamSet **newParamSet)
{
    int32_t ret = HksCheckParamSetValidity(paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check sharedKeyParamSet failed, ret = %" LOG_PUBLIC "d", ret)

    struct HksParam *sharedKeyAlias = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_KEY_ALIAS, &sharedKeyAlias);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckAndBuildShareParam get shared key alias fail")

    ret = AppendNewInfoForGenKeyInService(processInfo, paramSet, newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Encaps AppendNewInfoForGenKeyInService fail")

    ret = CheckKeyCondition(processInfo, &sharedKeyAlias->blob, *newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "encaps check key condition fail")

    return ret;
}

int32_t HksServiceEncapsulate(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksParamSet *sharedKeyParamSet,
    struct HksEncapsulationResult *encapResult)
{
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksParamSet *newParamSet = NULL;
    struct HksParamSet *newShareParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = {0};

#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif

    do {
        ret = HksCheckAndBuildShareParam(processInfo, sharedKeyParamSet, &newShareParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check sharedKeyParamSet failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "encapsulate: get key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        struct HksParam *sharedKeyAlias = NULL;
        ret = HksGetParam(newShareParamSet, HKS_TAG_KEY_ALIAS, &sharedKeyAlias);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceEncapsulate get shared key alias fail")
        ret = HuksAccessEncapsulate(&keyFromFile, newParamSet, &sharedKeyAlias->blob,
            newShareParamSet, encapResult);
        IfNotSuccAppendHdiErrorInfo(ret);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HuksAccessEncapsulate fail")

        struct HksParam *keySize = NULL;
        ret = HksGetParam(newShareParamSet, HKS_TAG_KEY_SIZE, &keySize);
        if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
            ret = HKS_SUCCESS;
            break;
        }

        ret = HksManageStoreKeyBlob(processInfo, newShareParamSet, &sharedKeyAlias->blob, &encapResult->sharedSecret,
            HKS_STORAGE_TYPE_KEY);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "store keyblob to storage failed, ret = %" LOG_PUBLIC "d", ret)
        (void)memset_s(encapResult->sharedSecret.data, encapResult->sharedSecret.size, 0,
            encapResult->sharedSecret.size);
        encapResult->sharedSecret.size = 0;
    } while (0);

#ifdef L2_STANDARD
    HksOneStageReportInfo info = {ret, startTime, traceId.traceId.chainId, __func__, HKS_ONE_STAGE_ENCAPSULATE};
    (void)HksOneStageEventReport(keyAlias, &keyFromFile, newParamSet, processInfo, &info);
#endif
    HksHitraceEnd(&traceId);
    HKS_MEMSET_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&newShareParamSet);
    return ret;
}

int32_t HksServiceDecapsulate(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksParamSet *sharedKeyParamSet,
    struct HksBlob *encapOrsharedSecret)
{
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    struct HksParamSet *newParamSet = NULL;
    struct HksParamSet *newSharedKeyParamSet = NULL;
    struct HksBlob keyFromFile = { 0, NULL };
    struct HksHitraceId traceId = {0};
    struct HksBlob outData = { 0, NULL };

#ifdef L2_STANDARD
    traceId = HksHitraceBegin(__func__, HKS_HITRACE_FLAG_DEFAULT | HKS_HITRACE_FLAG_NO_BE_INFO);
#endif

    do {
        ret = HksCheckBlobAndParamSet(keyAlias, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check keyAlias and paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAndBuildShareParam(processInfo, sharedKeyParamSet, &newSharedKeyParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check sharedKeyParamSet failed, ret = %" LOG_PUBLIC "d", ret)

        ret = GetKeyAndNewParamSet(processInfo, keyAlias, paramSet, &keyFromFile, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "decapsulate: get key and new paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HuksAccessDecapsulate(&keyFromFile, newParamSet, newSharedKeyParamSet, encapOrsharedSecret, &outData);
        IfNotSuccAppendHdiErrorInfo(ret);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HuksAccessEncapsulate fail")

        struct HksParam *keySize = NULL;
        ret = HksGetParam(newSharedKeyParamSet, HKS_TAG_KEY_SIZE, &keySize);
        if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
            ret = HKS_SUCCESS;
            break;
        }

        struct HksParam *keyalias = NULL;
        ret = HksGetParam(newSharedKeyParamSet, HKS_TAG_KEY_ALIAS, &keyalias);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCoreDecapsulate get key alias fail")

        ret = HksManageStoreKeyBlob(processInfo, newSharedKeyParamSet, &keyalias->blob, &outData,
            HKS_STORAGE_TYPE_KEY);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "store keyblob to storage failed, ret = %" LOG_PUBLIC "d", ret)
        (void)memset_s(outData.data, outData.size, 0, outData.size);
        outData.size = 0;
    } while (0);

#ifdef L2_STANDARD
    *encapOrsharedSecret = outData;
    HksOneStageReportInfo info = {ret, startTime, traceId.traceId.chainId, __func__, HKS_ONE_STAGE_DECAPSULATE};
    (void)HksOneStageEventReport(encapOrsharedSecret, &keyFromFile, newParamSet, processInfo, &info);
#endif
    HksHitraceEnd(&traceId);
    HKS_MEMSET_FREE_BLOB(keyFromFile);
    HksFreeParamSet(&newParamSet);
    HksFreeParamSet(&newSharedKeyParamSet);
    return ret;
}
