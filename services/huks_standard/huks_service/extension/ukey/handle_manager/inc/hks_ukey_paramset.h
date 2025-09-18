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
#include <parcel.h>

namespace OHOS {
namespace Huks {
class CppParamSet : public virtual OHOS::Parcelable{
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

    virtual bool Marshalling(OHOS::Parcel &parcel) const override
    {
        // 首先检查ptr_是否为空
        if (ptr_ == nullptr) {
            return false;
        }
        // 写入paramSetSize和paramsCnt
        if (!parcel.WriteUint32(ptr_->paramSetSize) || !parcel.WriteUint32(ptr_->paramsCnt)) {
            return false;
        }
        // 逐个序列化params数组中的元素
        for (uint32_t i = 0; i < ptr_->paramsCnt; i++) {
            const HksParam &param = ptr_->params[i];
            // 写入tag
            if (!parcel.WriteUint32(param.tag)) {
                return false;
            }
            HksTagType tagType = GetTagType(static_cast<HksTag>(param.tag));
            
            switch (tagType) {
                case HKS_TAG_TYPE_INT:
                    if (!parcel.WriteInt32(param.int32Param)) {
                        return false;
                    }
                    break;
                    
                case HKS_TAG_TYPE_UINT:
                    if (!parcel.WriteUint32(param.uint32Param)) {
                        return false;
                    }
                    break;
                    
                case HKS_TAG_TYPE_ULONG:
                    if (!parcel.WriteUint64(param.uint64Param)) {
                        return false;
                    }
                    break;
                    
                case HKS_TAG_TYPE_BOOL:
                    if (!parcel.WriteBool(param.boolParam)) {
                        return false;
                    }
                    break;
                    
                case HKS_TAG_TYPE_BYTES:
                    // 序列化HksBlob
                    if (!parcel.WriteUint32(param.blob.size)) {
                        return false;
                    }
                    if (param.blob.size > 0 && param.blob.data != nullptr) {
                        if (!parcel.WriteBuffer(param.blob.data, param.blob.size)) {
                            return false;
                        }
                    }
                    break;
                    
                default:
                    return false;
            }
        }
        
        return true;
    }

    static CppParamSet *Unmarshalling(OHOS::Parcel &parcel)
    {
        CppParamSet *cppParamSet = new (std::nothrow) CppParamSet();
        if (cppParamSet == nullptr) {
            return nullptr;
        }

        // 读取paramSetSize和paramsCnt
        uint32_t paramSetSize = parcel.ReadUint32();
        uint32_t paramsCnt = parcel.ReadUint32();

        if (paramSetSize == 0) {
            return cppParamSet;
        }

        // 计算需要分配的内存大小
        size_t allocSize = sizeof(HksParamSet) + paramsCnt * sizeof(HksParam);
        HksParamSet *paramSet = static_cast<HksParamSet*>(malloc(allocSize));
        if (paramSet == nullptr) {
            delete cppParamSet;
            return nullptr;
        }

        paramSet->paramSetSize = paramSetSize;
        paramSet->paramsCnt = paramsCnt;

        // 逐个反序列化params数组中的元素
        for (uint32_t i = 0; i < paramsCnt; i++) {
            HksParam &param = paramSet->params[i];
            
            // 读取tag
            param.tag = parcel.ReadUint32();
            if (parcel.GetReadableBytes() == 0) {
                free(paramSet);
                delete cppParamSet;
                return nullptr;
            }

            // 根据GetParam函数中的逻辑来判断如何反序列化
            HksTagType tagType = GetTagType(static_cast<HksTag>(param.tag));
            
            switch (tagType) {
                case HKS_TAG_TYPE_INT:
                    param.int32Param = parcel.ReadInt32();
                    break;
                    
                case HKS_TAG_TYPE_UINT:
                    param.uint32Param = parcel.ReadUint32();
                    break;
                    
                case HKS_TAG_TYPE_ULONG:
                    param.uint64Param = parcel.ReadUint64();
                    break;
                    
                case HKS_TAG_TYPE_BOOL:
                    param.boolParam = parcel.ReadBool();
                    break;
                    
                case HKS_TAG_TYPE_BYTES:
                    param.blob.size = parcel.ReadUint32();
                    if (param.blob.size > 0) {
                        param.blob.data = const_cast<uint8_t*>(parcel.ReadBuffer(param.blob.size));
                        if (param.blob.data == nullptr) {
                            free(paramSet);
                            delete cppParamSet;
                            return nullptr;
                        }
                    } else {
                        param.blob.data = nullptr;
                    }
                    break;
                    
                default:
                    // 未知的tag类型，反序列化失败
                    free(paramSet);
                    delete cppParamSet;
                    return nullptr;
            }
        }

        cppParamSet->ptr_ = paramSet;
        return cppParamSet;
    }

private:
    HksParamSet *ptr_ = nullptr;
};

}
}
#endif