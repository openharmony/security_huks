/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "huks_test_param_util.h"

#include <vector>

#include "hks_log.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hks_template.h"

namespace HuksTest {

int32_t TestBuildParamSet(const struct HksParam *params, const uint32_t paramCnt, struct HksParamSet **paramSetOut)
{
    int32_t ret;
    struct HksParamSet *paramSet = nullptr;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksAddParams(paramSet, params, paramCnt);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)
    } while (0);

    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        return ret;
    }
    *paramSetOut = paramSet;
    return HKS_SUCCESS;
}

int32_t TestBuildInitParamSet(const struct HksParam *param, const std::vector<HksParam> &tagParam,
    uint32_t paramCnt, struct HksParamSet **paramSetOut)
{
    int32_t ret;
    struct HksParamSet *paramSet = nullptr;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        if (param != nullptr && paramCnt > 0) {
            ret = HksAddParams(paramSet, param, paramCnt);
            HKS_IF_NOT_SUCC_BREAK(ret)
        }

        for (std::size_t i = 0; i < tagParam.size(); i++) {
            ret = HksAddParams(paramSet, &tagParam[i], 1);
            HKS_IF_NOT_SUCC_BREAK(ret)
        }
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
    }
    *paramSetOut = paramSet;
    return HKS_SUCCESS;
}
}  // namespace HuksTest
