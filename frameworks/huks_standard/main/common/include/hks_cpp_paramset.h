/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef HKS_CPP_PARAMSET_H
#define HKS_CPP_PARAMSET_H

#include <vector>
#include "hks_error_code.h"
#include "hks_param.h"
#include "hks_tag.h"
#include "hks_type.h"
#include "hks_type_enum.h"

class CppParamSet {
public:
    explicit CppParamSet() = default;
    explicit CppParamSet(const HksParamSet *paramSetIn);
    explicit CppParamSet(const std::vector<HksParam> &params);
    CppParamSet(HksParamSet *paramSetIn, bool takeOwnership);
    CppParamSet(const HksBlob &inBlob);
    CppParamSet(const HksParamSet *inPs, const std::vector<HksParam> &params);
    CppParamSet(const CppParamSet &inCppPs, const std::vector<HksParam> &params);
    ~CppParamSet();

    bool AddParams(const std::vector<HksParam> &params);
    CppParamSet(const CppParamSet &inCppPs);
    CppParamSet &operator=(const CppParamSet &inCppPs);
    CppParamSet(CppParamSet &&inCppPs) noexcept;
    CppParamSet &operator=(CppParamSet &&inCppPs) noexcept;
    [[nodiscard]] const HksParamSet *GetParamSet() const;

    static constexpr HksTagType GetTagType(enum HksTag tag)
    {
        return static_cast<enum HksTagType>(static_cast<uint32_t>(tag) & static_cast<uint32_t>(HKS_TAG_TYPE_MASK));
    }

    template<HksTag tag>
    auto GetParam() const
    {
        HksParam *param = nullptr;
        int32_t ret = HksGetParam(ptr_, tag, &param);
        if constexpr (GetTagType(tag) == HKS_TAG_TYPE_INT) {
            if (ret == HKS_SUCCESS && param != nullptr) {
                return std::pair<int32_t, int32_t>(ret, param->int32Param);
            }
            return std::pair<int32_t, int32_t>{ret, 0}; 
        }
        if constexpr (GetTagType(tag) == HKS_TAG_TYPE_UINT) {
            if (ret == HKS_SUCCESS && param != nullptr) {
                return std::pair<int32_t, uint32_t>(ret, param->uint32Param);
            }
            return std::pair<int32_t, uint32_t>{ret, 0}; 
        }
        if constexpr (GetTagType(tag) == HKS_TAG_TYPE_ULONG) {
            if (ret == HKS_SUCCESS && param != nullptr) {
                return std::pair<int32_t, uint64_t>(ret, param->uint64Param);
            }
            return std::pair<int32_t, uint64_t>{ret, 0}; 
        }
        if constexpr (GetTagType(tag) == HKS_TAG_TYPE_BOOL) {
            if (ret == HKS_SUCCESS && param != nullptr) {
                return std::pair<int32_t, bool>(ret, param->boolParam);
            }
            return std::pair<int32_t, bool>{ret, false};
        }
        if constexpr (GetTagType(tag) == HKS_TAG_TYPE_BYTES) {
            if (ret == HKS_SUCCESS && param != nullptr) {
                return std::pair<int32_t, std::vector<uint8_t>>(ret, {param->blob.data, param->blob.data + param->blob.size});
            }
            return std::pair<int32_t, std::vector<uint8_t>>{ret, {}}; 
        }
    }
private:
    HksParamSet *ptr_ = nullptr;
};

#endif