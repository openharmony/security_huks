/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "hks_client_check.h"

#include <stddef.h>

#include "hks_log.h"
#include "hks_param.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_storage_manager.h"

#ifdef _STORAGE_LITE_
#include "hks_storage_adapter.h"
#endif

#ifndef _CUT_AUTHENTICATE_
#ifdef _STORAGE_LITE_

int32_t GetKeyParamSet(const struct HksBlob *key, struct HksParamSet *paramSet)
{
    struct HksParamSet *tmpParamSet = NULL;
    int32_t ret = TranslateKeyInfoBlobToParamSet(NULL, key, &tmpParamSet);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    if (paramSet->paramSetSize < tmpParamSet->paramSetSize) {
        HksFreeParamSet(&tmpParamSet);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    if (memcpy_s(paramSet, paramSet->paramSetSize, tmpParamSet, tmpParamSet->paramSetSize) != EOK) {
        HKS_LOG_E("memcpy paramSet failed");
        ret = HKS_ERROR_INSUFFICIENT_MEMORY;
    } else {
        ret = HksFreshParamSet(paramSet, false);
    }

    HksFreeParamSet(&tmpParamSet);
    return ret;
}

#else /* _STORAGE_LITE_ */

static const uint32_t SENSITIVE_DELETE_TAG[] = { HKS_TAG_KEY, HKS_TAG_ACCESS_TOKEN_ID };

int32_t GetKeyParamSet(const struct HksBlob *key, struct HksParamSet *paramSet)
{
    if (key->size < sizeof(struct HksParamSet)) {
        HKS_LOG_E("get key paramset: invalid key size: %" LOG_PUBLIC "u", key->size);
        return HKS_ERROR_INVALID_KEY_INFO;
    }

    const struct HksParamSet *tmpParamSet = (const struct HksParamSet *)key->data;
    struct HksParamSet *outParamSet = NULL;
    int32_t ret = HksDeleteTagsFromParamSet(SENSITIVE_DELETE_TAG,
        sizeof(SENSITIVE_DELETE_TAG) / sizeof(SENSITIVE_DELETE_TAG[0]), tmpParamSet, &outParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "delete tag from paramSet failed, ret = %" LOG_PUBLIC "d.", ret)

    if (paramSet->paramSetSize < outParamSet->paramSetSize) {
        HksFreeParamSet(&outParamSet);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    (void)memcpy_s(paramSet, paramSet->paramSetSize, outParamSet, outParamSet->paramSetSize);

    ret = HksFreshParamSet(paramSet, false);

    HksFreeParamSet(&outParamSet);
    return ret;
}

int32_t GetKeyFileData(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, struct HksBlob *key, enum HksStorageType mode)
{
    uint32_t size;
    int32_t ret = HksManageStoreGetKeyBlobSize(processInfo, paramSet, keyAlias, &size, mode);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyblob size from storage failed, ret = %" LOG_PUBLIC "d.", ret)

    if (size > MAX_KEY_SIZE) {
        HKS_LOG_E("invalid key size, size = %" LOG_PUBLIC "u", size);
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    key->data = (uint8_t *)HksMalloc(size);
    HKS_IF_NULL_LOGE_RETURN(key->data, HKS_ERROR_MALLOC_FAIL, "get key data: malloc failed")

    key->size = size;
    ret = HksManageStoreGetKeyBlob(processInfo, paramSet, keyAlias, key, mode);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get keyblob from storage failed, ret = %" LOG_PUBLIC "d", ret);
        HKS_FREE_BLOB(*key);
    }
    return ret;
}

#ifdef HKS_ENABLE_UPGRADE_KEY
int32_t ConstructUpgradeKeyParamSet(const struct HksProcessInfo *processInfo, const struct HksParamSet *srcParamSet,
     struct HksParamSet **outParamSet)
{
    (void)srcParamSet;
    struct HksParamSet *paramSet = NULL;
    int32_t ret;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init param set failed!")

        struct HksParam processNameParam;
        processNameParam.tag = HKS_TAG_PROCESS_NAME;
        processNameParam.blob = processInfo->processName;

        ret = HksAddParams(paramSet, &processNameParam, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add param processNameParam failed!")

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build param set failed!")

        *outParamSet = paramSet;
        return HKS_SUCCESS;
    } while (0);
    HksFreeParamSet(&paramSet);
    return ret;
}
#endif

#endif /* _STORAGE_LITE_ */
#endif /* _CUT_AUTHENTICATE_ */