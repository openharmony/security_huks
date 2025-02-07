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

#include "hks_client_service_common.h"

#include <stddef.h>

#include "hks_log.h"
#include "hks_param.h"
#include "hks_template.h"

int32_t AppendToNewParamSet(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
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
    struct HksParamSet *newParamSet = NULL;
    int32_t ret;
    do {
        if (paramSet != NULL) {
            ret = AppendToNewParamSet(paramSet, &newParamSet);
        } else {
            ret = HksInitParamSet(&newParamSet);
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init param set failed")

        struct HksParam frontUserIdParam;
        frontUserIdParam.tag = HKS_TAG_FRONT_USER_ID;
        frontUserIdParam.int32Param = frontUserId;
        ret = HksAddParams(newParamSet, &frontUserIdParam, 1);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add frontUserIdParam fail!");

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
