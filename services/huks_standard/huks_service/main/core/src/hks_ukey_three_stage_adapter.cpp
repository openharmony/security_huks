/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "hks_ukey_three_stage_adapter.h"
#include "hilog/log_c.h"
#include "hks_cpp_paramset.h"
#include "hks_log.h"
#include "securec.h"
#include "hks_plugin_lifecycle_manager.h"
#include "hks_lib_interface.h"
#include "hks_template.h"
#include "hks_mem.h"
#include "hks_common_check.h"
#include <string>
#include <vector>
#include "hks_template.h"

int32_t HksCheckIsUkeyOperation(const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckParamSetValidity(paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksCheckParamSetValidity fail");
    CppParamSet paramSetCpp(paramSet);
    auto abilityName = paramSetCpp.GetParam<HKS_TAG_KEY_CLASS>();
    if (abilityName.first == HKS_SUCCESS && abilityName.second == HKS_KEY_CLASS_EXTENSION) {
        HKS_LOG_I("HksCheckIsUkeyOperation: is ukey operation");
        return HKS_SUCCESS;
    }
    return HKS_ERROR_INVALID_ARGUMENT;
}

int32_t HksServiceOnUkeyInitSession(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *inParamSet, struct HksBlob *handle)
{
    int32_t ret = HksCheckBlob2(&processInfo->processName, index);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "Hks check processName or index fail")

    std::string cppIndex(reinterpret_cast<const char*>(index->data), index->size);
    CppParamSet cppParamSet(inParamSet);
    uint32_t handleU32 = 0;

    auto libInterface = OHOS::Security::Huks::HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get lib interface instance.")
    
    ret = libInterface->OnInitSession(*processInfo, cppIndex, cppParamSet, handleU32);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnInitSession fail")

    uint64_t handleU64 = static_cast<uint64_t>(handleU32);
    handle->size = static_cast<uint64_t>(sizeof(handleU64));
    handle->data = static_cast<uint8_t *>(HksMalloc(handle->size));
    HKS_IF_TRUE_LOGE_RETURN(handle->data == nullptr, HKS_ERROR_MALLOC_FAIL, "handle malloc fail")

    ret = memcpy_s(handle->data, handle->size, &handleU64, sizeof(handleU64));
    if (ret != EOK) {
        HKS_FREE(handle->data);
        handle->data = nullptr;
        handle->size = 0;
        HKS_LOG_E("memcpy in HksServiceOnUkeyInitSession fail");
        return HKS_ERROR_COPY_FAIL;
    }
    return ret;
}

int32_t HksServiceOnUkeyUpdateSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData)
{
    uint64_t handleU64 = 0;
    if (handle != nullptr && handle->size == sizeof(uint64_t)) {
        if (memcpy_s(&handleU64, sizeof(handleU64), handle->data, handle->size) != EOK) {
            return HKS_ERROR_INSUFFICIENT_MEMORY;
        }
    }

    uint32_t handleU32 = static_cast<uint32_t>(handleU64);
    CppParamSet cppParamSet(paramSet);
    std::vector<uint8_t> indata;
    if (inData != nullptr && inData->data != nullptr) {
        indata.assign(inData->data, inData->data + inData->size);
    }
    std::vector<uint8_t> outdata;

    auto libInterface = OHOS::Security::Huks::HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get lib interface instance.")

    int32_t ret = libInterface->OnUpdateSession(*processInfo, handleU32, cppParamSet, indata, outdata);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnUpdateSession fail")

    HKS_IF_TRUE_LOGI_RETURN(outData->size == 0, ret, "outData size is 0. ret: %" LOG_PUBLIC "d", ret);
    HKS_IF_TRUE_LOGI_RETURN(outData->data == nullptr, ret, "outData data is nullptr. ret: %" LOG_PUBLIC "d", ret);
    outData->size = static_cast<uint32_t>(outdata.size());
    outData->data = static_cast<uint8_t *>(HksMalloc(outData->size));
    HKS_IF_TRUE_LOGE_RETURN(outData->data == nullptr, HKS_ERROR_MALLOC_FAIL, "outData malloc fail")

    ret = memcpy_s(outData->data, outData->size, outdata.data(), outdata.size());
    if (ret != EOK) {
        HKS_FREE(outData->data);
        outData->data = nullptr;
        outData->size = 0;
        HKS_LOG_E("memcpy in HksServiceOnUkeyUpdateSession fail");
        return HKS_ERROR_COPY_FAIL;
    }
    return ret;
}

int32_t HksServiceOnUkeyFinishSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData)
{
    uint64_t handleU64 = 0;
    if (handle != nullptr && handle->size == sizeof(uint64_t)) {
        if (memcpy_s(&handleU64, sizeof(handleU64), handle->data, handle->size) != EOK) {
            return HKS_ERROR_INSUFFICIENT_MEMORY;
        }
    }
    uint32_t handleU32 = static_cast<uint32_t>(handleU64);
    CppParamSet cppParamSet(paramSet);
    std::vector<uint8_t> indata;
    if (inData != nullptr && inData->data != nullptr) {
        indata.assign(inData->data, inData->data + inData->size);
    }
    std::vector<uint8_t> outdata;

    auto libInterface = OHOS::Security::Huks::HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get lib interface instance.")

    int32_t ret = libInterface->OnFinishSession(*processInfo, handleU32, cppParamSet, indata, outdata);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnFinishSession fail")

    HKS_IF_TRUE_LOGI_RETURN(outData->size == 0, ret, "outData size is 0. ret: %" LOG_PUBLIC "d", ret);
    HKS_IF_TRUE_LOGI_RETURN(outData->data == nullptr, ret, "outData data is nullptr. ret: %" LOG_PUBLIC "d", ret);
    outData->size = static_cast<uint32_t>(outdata.size());
    outData->data = static_cast<uint8_t *>(HksMalloc(outData->size));
    HKS_IF_TRUE_LOGE_RETURN(outData->data == nullptr, HKS_ERROR_MALLOC_FAIL, "outData malloc fail")

    ret = memcpy_s(outData->data, outData->size, outdata.data(), outdata.size());
    if (ret != EOK) {
        HKS_FREE(outData->data);
        outData->data = nullptr;
        outData->size = 0;
        HKS_LOG_E("memcpy in HksServiceOnUkeyFinishSession fail");
        return HKS_ERROR_COPY_FAIL;
    }
    return ret;
}