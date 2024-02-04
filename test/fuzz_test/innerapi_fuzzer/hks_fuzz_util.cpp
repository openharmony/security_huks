/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {
std::vector<HksParam> ConstructHksParams(uint8_t *&data, size_t &size)
{
    std::vector<HksParam> params {};
    while (size >= sizeof(HksParam)) {
        HksParam *p = ReadData<HksParam *>(data, size, sizeof(HksParam));
        if (GetTagType(static_cast<HksTag>(p->tag)) != HKS_TAG_TYPE_BYTES) {
            params.emplace_back(*p);
            continue;
        }
        if (size < p->blob.size) {
            continue;
        }
        p->blob.data = ReadData<uint8_t *>(data, size, p->blob.size);
        params.emplace_back(*p);
    }
    return params;
}

WrapParamSet ConstructHksParamSetFromFuzz(uint8_t *&data, size_t &size)
{
    auto params = ConstructHksParams(data, size);
    WrapParamSet ps {};
    int32_t ret = HksInitParamSet(&ps.s);
    if (ret != HKS_SUCCESS) {
        return {};
    }
    if (!params.empty()) {
        ret = HksAddParams(ps.s, params.data(), params.size());
        if (ret != HKS_SUCCESS) {
            return {};
        }
    }
    ret = HksBuildParamSet(&ps.s);
    if (ret != HKS_SUCCESS) {
        return {};
    }
    return ps;
}
}}}