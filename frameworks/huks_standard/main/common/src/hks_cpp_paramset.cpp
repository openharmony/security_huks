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

#include "hks_cpp_paramset.h"
#include "hks_param.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"

CppParamSet::CppParamSet(const HksParamSet *paramSetIn)
{
    HKS_IF_TRUE_RETURN_VOID(paramSetIn == nullptr);
    int32_t ret = HksInitParamSet(&this->ptr_);
    HKS_IF_TRUE_LOGE_RETURN_VOID(ret != HKS_SUCCESS, "CppParamSet constructor, HksInitParamSet failed, ret = %d", ret);
    do {
        ret = HksAddParams(this->ptr_, paramSetIn->params, paramSetIn->paramsCnt);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "CppParamSet constructor, HksAddParams failed, ret = %d", ret);

        ret = HksBuildParamSet(&this->ptr_);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "CppParamSet constructor, HksBuildParamSet failed, ret = %d", ret);
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&this->ptr_);
        return;
    }
    HKS_LOG_D("CppParamSet constructor success. deep copy paramset.");
}

CppParamSet::CppParamSet(const std::vector<HksParam> &params)
{
    HKS_IF_TRUE_RETURN_VOID(params.empty());
    int32_t ret = HksInitParamSet(&this->ptr_);
    HKS_IF_TRUE_LOGE_RETURN_VOID(ret != HKS_SUCCESS, "CppParamSet constructor, HksInitParamSet failed, ret = %d", ret);
    do {
        ret = HksAddParams(this->ptr_, params.data(), params.size());
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "CppParamSet constructor, HksAddParams failed, ret = %d", ret);

        ret = HksBuildParamSet(&this->ptr_);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "CppParamSet constructor, HksBuildParamSet failed, ret = %d", ret);
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&this->ptr_);
        return;
    }
    HKS_LOG_D("CppParamSet constructor with params success");
}

CppParamSet::CppParamSet(HksParamSet *paramSetIn, bool takeOwnership)
{
    if (takeOwnership) {
        this->ptr_ = paramSetIn;
        paramSetIn = nullptr;
    } else {
        const HksParamSet *constInparamSet = paramSetIn;
        CppParamSet copyOne(constInparamSet);
        if (copyOne.ptr_ != nullptr) {
            this->ptr_ = copyOne.ptr_;
            copyOne.ptr_ = nullptr;
        }
        HKS_LOG_D("CppParamSet constructor copy takeOwnership success");
    }
}

CppParamSet::CppParamSet(const HksBlob &inBlob)
{
    HKS_IF_TRUE_RETURN_VOID(inBlob.size == 0 || inBlob.data == nullptr);
    int32_t ret = HksGetParamSet(reinterpret_cast<HksParamSet *>(inBlob.data), inBlob.size, &this->ptr_);
    HKS_IF_TRUE_LOGE_RETURN_VOID(ret != HKS_SUCCESS, "CppParamSet constructor, HksGetParamSet failed, ret = %d", ret);
    HKS_LOG_D("CppParamSet constructor with blob success");
}

CppParamSet::CppParamSet(const HksParamSet *inPs, const std::vector<HksParam> &params)
{
    HKS_IF_TRUE_RETURN_VOID(inPs == nullptr || params.empty());
    int32_t ret = HksInitParamSet(&this->ptr_);
    HKS_IF_TRUE_LOGE_RETURN_VOID(ret != HKS_SUCCESS, "CppParamSet constructor, HksInitParamSet failed, ret = %d", ret);
    do {
        ret = HksAddParams(this->ptr_, inPs->params, inPs->paramsCnt);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "CppParamSet constructor, add ptr paramset failed, ret = %d", ret);
        ret = HksAddParams(this->ptr_, params.data(), params.size());
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "CppParamSet constructor, add params failed, ret = %d", ret);
        ret = HksBuildParamSet(&this->ptr_);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "CppParamSet constructor, HksBuildParamSet failed, ret = %d", ret);
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&this->ptr_);
        return;
    }
    HKS_LOG_D("CppParamSet constructor with paramset and params success");
}

CppParamSet::CppParamSet(const CppParamSet &inCppPs, const std::vector<HksParam> &params)
{
    CppParamSet copyOne(inCppPs.ptr_, params);
    if (copyOne.ptr_ != nullptr) {
        this->ptr_ = copyOne.ptr_;
        copyOne.ptr_ = nullptr;
    }
    HKS_LOG_D("CppParamSet constructor takeOwnership and add params success");
}

CppParamSet::~CppParamSet()
{
    HksFreeParamSet(&this->ptr_);
}

bool CppParamSet::AddParams(const std::vector<HksParam> &params)
{
    HKS_IF_TRUE_RETURN(params.empty(), false);
    CppParamSet copyOne(this->ptr_, params);
    HKS_IF_TRUE_RETURN(copyOne.ptr_ == nullptr, false);
    HksFreeParamSet(&this->ptr_);
    this->ptr_ = copyOne.ptr_;
    copyOne.ptr_ = nullptr;
    return true;
}

// copy constructor
CppParamSet::CppParamSet(const CppParamSet &inCppPs)
{
    HKS_LOG_D("CppParamSet copy constructor");
    CppParamSet copyOne(inCppPs.ptr_);
    HKS_IF_TRUE_LOGE(copyOne.ptr_ == nullptr, "CppParamSet copy constructor, but copyOne.ptr_ is nullptr");
    if (copyOne.ptr_ != nullptr) {
        this->ptr_ = copyOne.ptr_;
        copyOne.ptr_ = nullptr;
    }
}

// copy assignment
CppParamSet &CppParamSet::operator=(const CppParamSet &inCppPs)
{
    HKS_LOG_D("CppParamSet copy assignment");
    HKS_IF_TRUE_RETURN(this == &inCppPs, *this);
    HksFreeParamSet(&this->ptr_);
    CppParamSet copyOne(inCppPs.ptr_);
    HKS_IF_TRUE_LOGE(copyOne.ptr_ == nullptr, "CppParamSet copy assignment, but copyOne.ptr_ is nullptr");
    this->ptr_ = copyOne.ptr_;
    copyOne.ptr_ = nullptr;
    return *this;
}

// move constructor
CppParamSet::CppParamSet(CppParamSet &&inCppPs) noexcept
{
    HKS_LOG_D("CppParamSet move constructor");
    this->ptr_ = inCppPs.ptr_;
    inCppPs.ptr_ = nullptr;
}

// move assignment
CppParamSet &CppParamSet::operator=(CppParamSet &&inCppPs) noexcept
{
    HKS_LOG_D("CppParamSet move assignment");
    HKS_IF_TRUE_RETURN(this == &inCppPs, *this);
    HksFreeParamSet(&this->ptr_);
    this->ptr_ = inCppPs.ptr_;
    inCppPs.ptr_ = nullptr;
    return *this;
}

[[nodiscard]] const HksParamSet *CppParamSet::GetParamSet() const
{
    return this->ptr_;
}

bool CppParamSet::Marshalling(OHOS::Parcel &parcel) const
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

CppParamSet *CppParamSet::Unmarshalling(OHOS::Parcel &parcel)
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