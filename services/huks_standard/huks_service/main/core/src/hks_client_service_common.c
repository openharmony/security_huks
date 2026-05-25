/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "hks_client_service_common.h"

#include <stdatomic.h>
#include <stddef.h>
#include <securec.h>

#include "hks_log.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_event_info.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"

#ifdef L2_STANDARD
#include "hks_se_api_wrap.h"
#endif

static volatile atomic_bool g_isScreenOn = false;

int32_t AppendToNewParamSet(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    HKS_IF_NULL_LOGI_RETURN(outParamSet, HKS_ERROR_NULL_POINTER, "outParamSet is null")
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;

    do {
        ret = HksCheckParamSet(paramSet, paramSet->paramSetSize);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check paramSet failed")

        ret = HksFreshParamSet((struct HksParamSet *)paramSet, false);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append fresh paramset failed")

        ret = HksInitParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append init operation param set failed")

        ret = HksAddParams(newParamSet, paramSet->params, paramSet->paramsCnt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append params failed")

        *outParamSet = newParamSet;
        return ret;
    } while (0);

    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t BuildFrontUserIdParamSet(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet, int frontUserId)
{
    HKS_IF_NULL_LOGE_RETURN(outParamSet, HKS_ERROR_NULL_POINTER, "outParamSet is null ptr")
    struct HksParamSet *newParamSet = NULL;
    int32_t ret;
    do {
        ret = (paramSet != NULL) ? AppendToNewParamSet(paramSet, &newParamSet) : HksInitParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init param set failed")

        struct HksParam frontUserIdParam;
        frontUserIdParam.tag = HKS_TAG_FRONT_USER_ID;
        frontUserIdParam.int32Param = frontUserId;
        ret = HksAddParams(newParamSet, &frontUserIdParam, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add frontUserIdParam fail!");

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build append info failed")
        *outParamSet = newParamSet;

        return HKS_SUCCESS;
    } while (0);

    HksFreeParamSet(&newParamSet);
    *outParamSet = NULL;
    return ret;
}

void HksSetScreenState(bool state)
{
    atomic_store(&g_isScreenOn, state);
}

bool HksGetScreenState(void)
{
    return atomic_load(&g_isScreenOn);
}

bool IsSeSecurityLevel(const struct HksParamSet *paramSet)
{
    struct HksParam *securityLevelParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_SECURITY_LEVEL, &securityLevelParam);
    HKS_IF_TRUE_RETURN(ret != HKS_SUCCESS, false)

    HKS_LOG_I("security level is %" LOG_PUBLIC "u", securityLevelParam->uint32Param);
    return securityLevelParam->uint32Param == HKS_KEY_SECURITY_LEVEL_SE ||
           securityLevelParam->uint32Param == HKS_KEY_SECURITY_LEVEL_INDEPENDENT_SE;
}

bool IsSeHandle(const struct HksBlob *handle)
{
    HKS_IF_TRUE_RETURN(handle == NULL || handle->size != sizeof(uint64_t), false)

    uint64_t handleVal = 0;
    HKS_IF_TRUE_RETURN(memcpy_s(&handleVal, sizeof(handleVal), handle->data, sizeof(handleVal)) != EOK, false)

    if ((handleVal >> HKS_SE_HANDLE_MASK_BIT) != 0) {
        HKS_LOG_I("is se handle");
        return true;
    }

    return false;
}

int32_t CheckKeySecuritySeFromKeyFile(const struct HksProcessInfo *processInfo,
    const struct HksBlob *keyFromFile, bool *isSeCalling)
{
#ifdef L2_STANDARD
    if (keyFromFile == NULL || keyFromFile->data == NULL || keyFromFile->size < sizeof(struct HksParamSet)) {
        return HKS_SUCCESS;
    }
    const struct HksParamSet *keyParamSet = (const struct HksParamSet *)keyFromFile->data;
    struct HksParam *securityLevelParam = NULL;
    int32_t ret = HksGetParam(keyParamSet, HKS_TAG_KEY_SECURITY_LEVEL, &securityLevelParam);
    HKS_IF_TRUE_RETURN(ret != HKS_SUCCESS, HKS_SUCCESS)

    if (securityLevelParam->uint32Param == HKS_KEY_SECURITY_LEVEL_SE ||
        securityLevelParam->uint32Param == HKS_KEY_SECURITY_LEVEL_INDEPENDENT_SE) {
        ret = HksSePermissionCheck(processInfo);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Se permission check failed.")

        ret = HksSeIncrementSeCount();
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Failed to increment SE call count.")

        *isSeCalling = true;
    }
    return HKS_SUCCESS;
#else
    (void)processInfo;
    (void)keyFromFile;
    (void)isSeCalling;
    return HKS_SUCCESS;
#endif
}

void DecrementSeCountByService(bool isSeCalling)
{
#ifdef L2_STANDARD
    if (isSeCalling) {
        (void)HksSeDecrementSeCount();
        return;
    }
#else
    (void)isSeCalling;
#endif
}
