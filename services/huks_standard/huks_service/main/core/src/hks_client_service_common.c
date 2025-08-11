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

#include "hks_log.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type_enum.h"

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
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newParamSet);
        *outParamSet = NULL;
    }
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
