/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_report_wrapper.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_inner.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
 
#define EXTRA_DATA_SIZE 512

#define STRING_TAG_KEY_SIZE "keySize"
#define STRING_TAG_DIGEST "digest"
#define STRING_TAG_BLOCK_MODE "blockMode"
#define STRING_TAG_UNWRAP_ALGORITHM_SUITE "unwrapAlgorithmSuit"
#define STRING_TAG_ITERATION "iteration"
#define STRING_TAG_PURPOSE "purpose"
#define STRING_TAG_ATTESTATION_MODE "attestationMode"
#define STRING_TAG_PACKAGE_NAME "packageName"
#define STRING_TAG_KEY_ALIAS "keyAlias"

static const struct HksBlob g_tagKeySize = {sizeof(STRING_TAG_KEY_SIZE) - 1, (uint8_t *)STRING_TAG_KEY_SIZE};
static const struct HksBlob g_tagDigest = {sizeof(STRING_TAG_DIGEST) - 1, (uint8_t *)STRING_TAG_DIGEST};
static const struct HksBlob g_tagBlockMode = {sizeof(STRING_TAG_BLOCK_MODE) - 1, (uint8_t *)STRING_TAG_BLOCK_MODE};
static const struct HksBlob g_tagUnwrapAlgorithmSuit = {sizeof(STRING_TAG_UNWRAP_ALGORITHM_SUITE) - 1,
    (uint8_t *)STRING_TAG_UNWRAP_ALGORITHM_SUITE};
static const struct HksBlob g_tagIteration = {sizeof(STRING_TAG_ITERATION) - 1, (uint8_t *)STRING_TAG_ITERATION};
static const struct HksBlob g_tagPurpose = {sizeof(STRING_TAG_PURPOSE) - 1, (uint8_t *)STRING_TAG_PURPOSE};
static const struct HksBlob g_tagAttestationMode = {
    sizeof(STRING_TAG_ATTESTATION_MODE) - 1, (uint8_t *)STRING_TAG_ATTESTATION_MODE};
static const struct HksBlob g_tagPackageName = {
    sizeof(STRING_TAG_PACKAGE_NAME) - 1, (uint8_t *)STRING_TAG_PACKAGE_NAME};
static const struct HksBlob g_tagKeyAlias = {
    sizeof(STRING_TAG_KEY_ALIAS) - 1, (uint8_t *)STRING_TAG_KEY_ALIAS};

// You need to BIO_free_all the return value after usage.
static BIO *ConstructOpensslBase64BioChain(void)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    HKS_IF_NULL_LOGE_RETURN(b64, NULL, "BIO_new(BIO_f_base64()) fail")
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        HKS_LOG_E("BIO_new(BIO_s_mem()) fail");
        BIO_free_all(b64);
        return NULL;
    }
    BIO *chain = BIO_push(b64, bio);
    if (bio == NULL) {
        HKS_LOG_E("BIO_push(b64, bio) fail");
        BIO_free_all(b64);
        BIO_free_all(bio);
        return NULL;
    }
    return chain;
}

// You need to free out->data after usage.
static int OpensslBase64Encode(const struct HksBlob *in, struct HksBlob *out)
{
    if (CheckBlob(in) != HKS_SUCCESS || out == NULL) {
        HKS_LOG_E("invalid in blob or out blob");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    BIO *chain = ConstructOpensslBase64BioChain();
    HKS_IF_NULL_LOGE_RETURN(chain, HKS_ERROR_INSUFFICIENT_MEMORY, "ConstructOpensslBase64BioChain fail")
    int ret = HKS_ERROR_INVALID_ARGUMENT;
    do {
        int writeLength = BIO_write(chain, in->data, in->size);
        if (writeLength <= 0) {
            HKS_LOG_E("BIO_write fail %" LOG_PUBLIC "d %" LOG_PUBLIC "s",
                writeLength, ERR_reason_error_string(ERR_get_error()));
            break;
        }
        enum {
            HKS_OPENSSL_SUCCESS = 1,
        };
        int osslRet = BIO_flush(chain);
        if (osslRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("BIO_flush fail %" LOG_PUBLIC "d %" LOG_PUBLIC "s",
                osslRet, ERR_reason_error_string(ERR_get_error()));
            break;
        }
        BUF_MEM *bptr = NULL;
        osslRet = BIO_get_mem_ptr(chain, &bptr);
        if (osslRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("BIO_get_mem_ptr fail %" LOG_PUBLIC "d %" LOG_PUBLIC "s",
                osslRet, ERR_reason_error_string(ERR_get_error()));
            break;
        }
        if (bptr->length >= EXTRA_DATA_SIZE) {
            HKS_LOG_E("too long key alias base64 data %" LOG_PUBLIC "zu", bptr->length);
            break;
        }
        out->size = bptr->length + 1;
        out->data = HksMalloc(out->size);
        HKS_IF_NULL_LOGE_BREAK(out->data, "HksMalloc alias base64 data fail")
        errno_t memRet = memcpy_s(out->data, out->size, bptr->data, bptr->length);
        if (memRet != EOK) {
            HKS_LOG_E("memcpy_s key alias base64 fail %" LOG_PUBLIC "d", memRet);
            break;
        }
        out->data[bptr->length] = '\0';
        ret = HKS_SUCCESS;
    } while (false);
    BIO_free_all(chain);
    return ret;
}

static int32_t AppendParamToExtra(const struct HksParam *paramIn, char *extraOut, uint32_t *index)
{
    if (paramIn->tag == HKS_TAG_PACKAGE_NAME || paramIn->tag == HKS_TAG_KEY_ALIAS) {
        int32_t num = snprintf_s(extraOut + *index, EXTRA_DATA_SIZE - *index, EXTRA_DATA_SIZE - *index - 1, "%s",
            paramIn->blob.data);
        if (num < 0) {
            HKS_LOG_E("snprintf_s failed!");
            return HKS_ERROR_BAD_STATE;
        }
        *index = *index + num;
        return HKS_SUCCESS;
    }
    switch (GetTagType(paramIn->tag)) {
        case HKS_TAG_TYPE_UINT: {
            int32_t num = snprintf_s(extraOut + *index, EXTRA_DATA_SIZE - *index, EXTRA_DATA_SIZE - *index - 1, "%u",
                paramIn->uint32Param);
            if (num < 0) {
                HKS_LOG_E("snprintf_s failed!");
                return HKS_ERROR_BAD_STATE;
            }
            *index = *index + num;
            break;
        }
        default:
            break;
    }
    return HKS_SUCCESS;
}

static bool ISExceedTheLimitSize(const uint32_t val)
{
    if (val > EXTRA_DATA_SIZE) {
        HKS_LOG_E("no enough space!");
        return true;
    }

    return false;
}

static int32_t AppendToExtra(const struct HksBlob *tag, const struct HksParam *paramIn, char *extraOut,
    uint32_t *index)
{
    if (ISExceedTheLimitSize(*index)) {
        return HKS_ERROR_BAD_STATE;
    }
    if (memcpy_s(extraOut + *index, EXTRA_DATA_SIZE - *index, tag->data, tag->size) != EOK) {
        HKS_LOG_E("copy extra tag failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *index += tag->size;

    char split = ':';
    if (ISExceedTheLimitSize(*index)) {
        return HKS_ERROR_BAD_STATE;
    }
    if (memcpy_s(extraOut + *index, EXTRA_DATA_SIZE - *index, &split, sizeof(char)) != EOK) {
        HKS_LOG_E("copy split failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *index += sizeof(char);

    if (ISExceedTheLimitSize(*index)) {
        return HKS_ERROR_BAD_STATE;
    }
    int32_t ret = AppendParamToExtra(paramIn, extraOut, index);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "append param to extra failed!")

    split = ';';
    if (ISExceedTheLimitSize(*index)) {
        return HKS_ERROR_BAD_STATE;
    }
    if (memcpy_s(extraOut + *index, EXTRA_DATA_SIZE - *index, &split, sizeof(char)) != EOK) {
        HKS_LOG_E("copy split failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *index += sizeof(char);
    return HKS_SUCCESS;
}

static void AppendIfExist(uint32_t tag, const struct HksParamSet *paramSetIn, const struct HksBlob *tagString,
    char *extraOut, uint32_t *index)
{
    struct HksParam *temp = NULL;
    int32_t ret = HksGetParam(paramSetIn, tag, &temp);
    if (ret == HKS_SUCCESS) {
        ret = AppendToExtra(tagString, temp, extraOut, index);
        HKS_IF_NOT_SUCC_LOGE(ret, "Append extra data failed!")
    } else {
        HKS_LOG_D("Tag not exist.");
    }
}

static void AppendKeyAliasBase64IfExist(const struct HksParamSet *paramSetIn, const struct HksBlob *tagString,
    char *extraOut, uint32_t *index)
{
    struct HksParam *temp = NULL;
    int32_t ret = HksGetParam(paramSetIn, HKS_TAG_KEY_ALIAS, &temp);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_D("Tag not exist.");
        return;
    }
    struct HksParam aliasBase64 = {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = { .size = 0, .data = NULL },
    };
    ret = OpensslBase64Encode(&temp->blob, &aliasBase64.blob);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("OpensslBase64Encode fail %" LOG_PUBLIC "d", ret);
        return;
    }
    ret = AppendToExtra(tagString, &aliasBase64, extraOut, index);
    HKS_IF_NOT_SUCC_LOGE(ret, "Append extra data failed!")
    HKS_FREE_BLOB(aliasBase64.blob);
}

static void GetAlgorithmTag(const struct HksParamSet *paramSetIn, uint32_t *algorithm)
{
    struct HksParam *algorithmParam = NULL;
    int32_t ret = HksGetParam(paramSetIn, HKS_TAG_ALGORITHM, &algorithmParam);
    if (ret == HKS_SUCCESS) {
        *algorithm = algorithmParam->uint32Param;
    } else {
        HKS_LOG_E("Get key type failed!");
    }
}

static void PackExtra(const struct HksParamSet *paramSetIn, char *extraOut)
{
    uint32_t index = 0;
    AppendIfExist(HKS_TAG_PURPOSE, paramSetIn, &g_tagPurpose, extraOut, &index);
    AppendIfExist(HKS_TAG_KEY_SIZE, paramSetIn, &g_tagKeySize, extraOut, &index);
    AppendIfExist(HKS_TAG_DIGEST, paramSetIn, &g_tagDigest, extraOut, &index);
    AppendIfExist(HKS_TAG_BLOCK_MODE, paramSetIn, &g_tagBlockMode, extraOut, &index);
    AppendIfExist(HKS_TAG_UNWRAP_ALGORITHM_SUITE, paramSetIn, &g_tagUnwrapAlgorithmSuit, extraOut, &index);
    AppendIfExist(HKS_TAG_ITERATION, paramSetIn, &g_tagIteration, extraOut, &index);
    AppendIfExist(HKS_TAG_ATTESTATION_MODE, paramSetIn, &g_tagAttestationMode, extraOut, &index);
    AppendIfExist(HKS_TAG_PACKAGE_NAME, paramSetIn, &g_tagPackageName, extraOut, &index);
    AppendKeyAliasBase64IfExist(paramSetIn, &g_tagKeyAlias, extraOut, &index);
}

int32_t ReportFaultEvent(const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSetIn, int32_t errorCode)
{
    if (errorCode == HKS_SUCCESS) {
        return HKS_SUCCESS;
    }
    char *extra = NULL;
    int32_t ret;
    do {
        extra = (char *)HksMalloc(EXTRA_DATA_SIZE);
        if (extra == NULL) {
            HKS_LOG_E("Malloc extra data failed!");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        (void)memset_s(extra, EXTRA_DATA_SIZE, 0, EXTRA_DATA_SIZE);

        // algorithmTag is 0 if no algorithm designed in paramset
        uint32_t algorithmTag = 0;
        if (paramSetIn != NULL) {
            if (HksCheckParamSet(paramSetIn, paramSetIn->paramSetSize) == HKS_SUCCESS) {
                GetAlgorithmTag(paramSetIn, &algorithmTag);
                PackExtra(paramSetIn, extra);
            }
        }

        // userId is 0 if no userId
        uint32_t userId = 0;

        // processName is 0 if no processName
        int processName = 0;
        if (processInfo != NULL) {
            userId = processInfo->userIdInt;
            if (memcpy_s(&processName, sizeof(processName), processInfo->processName.data,
                processInfo->processName.size) != EOK) {
                HKS_LOG_E("process name is no int, default as 0");
                processName = 0;
            }
        }
        struct EventValues eventValues = { userId, processName, algorithmTag, errorCode };
        ret = WriteEvent(FAULT, funcName, &eventValues, extra);
    } while (0);
    HKS_FREE(extra);
    return ret;
}
