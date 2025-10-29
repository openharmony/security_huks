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
#include "securec.h"

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
    HKS_LOG_E("CppParamSet Marshalling");
    if (ptr_ == nullptr) {
        HKS_LOG_E("CppParamSet Marshalling nullptr");
        return false;
    }
    if (!parcel.WriteUint32(ptr_->paramSetSize)) {
        HKS_LOG_E("CppParamSet Marshalling paramSetSize failed");
        return false;
    }
    HKS_LOG_I("CppParamSet WriteBuffer size: %" LOG_PUBLIC "d", ptr_->paramSetSize);
    if (!parcel.WriteBuffer(ptr_, ptr_->paramSetSize)) {
        HKS_LOG_E("CppParamSet Marshalling WriteBuffer failed");
        return false;
    }
    HKS_LOG_I("CppParamSet Marshalling success");
    return true;
}

constexpr uint32_t SIZE_OFFSET = 3;
CppParamSet *CppParamSet::Unmarshalling(OHOS::Parcel &parcel)
{
    auto *cppParamSet = new (std::nothrow) CppParamSet();
    if (cppParamSet == nullptr) {
        HKS_LOG_E("CppParamSet UnMarshalling cppParamSet == nullptr");
        return nullptr;
    }
    uint32_t paramSetSize = parcel.ReadUint32();
    if (paramSetSize == 0) {
        HKS_LOG_E("CppParamSet UnMarshalling paramSetSize == 0");
        return cppParamSet;
    }
    if (paramSetSize > HKS_DEFAULT_PARAM_SET_SIZE) {
        HKS_LOG_E("CppParamSet UnMarshalling paramSetSize > 1024");
        return cppParamSet;
    }
    auto *paramSet = static_cast<HksParamSet*>(HksMalloc(paramSetSize));
    if (paramSet == nullptr) {
        HKS_LOG_E("CppParamSet UnMarshalling paramSetSize == nullptr");
        delete cppParamSet;
        return nullptr;
    }
    auto offset = ((paramSetSize + SIZE_OFFSET) & (~SIZE_OFFSET)) - paramSetSize;
    HKS_LOG_I("CppParamSet ReadBuffer offset size: %" LOG_PUBLIC "d", offset);
    const auto *bufferTemp = parcel.ReadBuffer(paramSetSize + offset);
    if (memcpy_s(paramSet, paramSetSize, bufferTemp, paramSetSize) != EOK) {
        HKS_LOG_E("memcpy_s failed");
        HKS_FREE(paramSet);
        delete cppParamSet;
        return nullptr;
    }
    int32_t ret = HksFreshParamSet(paramSet, false);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(paramSet);
        delete cppParamSet;
        return nullptr;
    }

    cppParamSet->ptr_ = paramSet;
    HKS_LOG_E("CppParamSet UnMarshalling success");
    return cppParamSet;
}