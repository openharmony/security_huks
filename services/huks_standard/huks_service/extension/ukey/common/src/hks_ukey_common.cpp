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

#include "hks_ukey_common.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_json_wrapper.h"
#include "hks_mem.h"
#include "securec.h"

namespace OHOS::Security::Huks {

bool IsHksExtCertInfoSetEmpty(const struct HksExtCertInfoSet& certSet)
{
    return certSet.certs == nullptr || certSet.count == 0;
}

HksBlob Base64StringToBlob(const std::string &inStr)
{
    HksBlob blob = {0, nullptr};
    HKS_IF_TRUE_RETURN(inStr.empty(), blob)
    auto decodeVec = Base64Str2U8Vec(inStr);
    HKS_IF_TRUE_LOGE_RETURN(decodeVec.first != HKS_SUCCESS, blob, "Base64Str2U8Vec failed, ret: %" LOG_PUBLIC "d",
        decodeVec.first)
    blob.data = static_cast<uint8_t*>(HksMalloc(decodeVec.second.size()));
    HKS_IF_NULL_LOGE_RETURN(blob.data, blob, "Failed to allocate memory for HksBlob")
    blob.size = decodeVec.second.size();
    if (memcpy_s(blob.data, blob.size, decodeVec.second.data(), decodeVec.second.size()) != EOK) {
        HKS_LOG_E("memcpy_s failed in StringToBlob");
        HKS_FREE(blob.data);
        blob.data = nullptr;
        blob.size = 0;
    }
    return blob;
}

std::string BlobToBase64String(const struct HksBlob &strBlob)
{
    HKS_IF_TRUE_RETURN(strBlob.data == nullptr || strBlob.size == 0, "")
    return U8Vec2Base64Str({strBlob.data, strBlob.data + strBlob.size}).second;
}

HksBlob StringToBlob(const std::string &inStr)
{
    HksBlob blob = {0, nullptr};
    if (inStr.empty()) {
        return blob;
    }
    blob.size = inStr.size();
    blob.data = static_cast<uint8_t*>(HksMalloc(blob.size));
    if (blob.data != nullptr) {
        if (memcpy_s(blob.data, blob.size, inStr.data(), blob.size) != EOK) {
            HKS_LOG_E("memcpy_s failed in StringToBlob");
            HKS_FREE(blob.data);
            blob.data = nullptr;
            blob.size = 0;
        }
    } else {
        HKS_LOG_E("Failed to allocate memory for HksBlob");
        blob.size = 0;
    }
    return blob;
}

std::string BlobToString(const HksBlob &strBlob)
{
    std::string ret("");
    HKS_IF_TRUE_RETURN(strBlob.size == 0 || strBlob.data == nullptr, ret)
    return std::string(reinterpret_cast<const char*>(strBlob.data), strBlob.size);
}

int32_t CertInfoToString(const struct HksExtCertInfo& certInfo, std::string& jsonStr)
{
    jsonStr.clear();
    auto jsonObj = CommJsonObject::CreateObject();
    HKS_IF_TRUE_LOGE_RETURN(jsonObj.IsNull(), HKS_ERROR_MALLOC_FAIL,
        "Create json object failed");
    if (!jsonObj.SetValue("purpose", certInfo.purpose)) {
        HKS_LOG_E("Set purpose value failed");
        return HKS_ERROR_INTERNAL_ERROR;
    }
    
    std::string index = BlobToString(certInfo.index);
    if (!jsonObj.SetValue("index", index)) {
        HKS_LOG_E("Set index value failed");
        return HKS_ERROR_INTERNAL_ERROR;
    }
    std::string cert = BlobToBase64String(certInfo.cert);
    if (!jsonObj.SetValue("cert", cert)) {
        HKS_LOG_E("Set cert value failed");
        return HKS_ERROR_INTERNAL_ERROR;
    }
    
    jsonStr = jsonObj.Serialize();
    HKS_IF_TRUE_LOGE_RETURN(jsonStr.empty(), HKS_ERROR_INTERNAL_ERROR,
        "Serialize json object failed")
    return HKS_SUCCESS;
}


int32_t JsonArrayToCertInfoSet(const std::string &certJsonArr, struct HksExtCertInfoSet& certSet)
{
    HKS_IF_TRUE_LOGE_RETURN(certJsonArr.empty(), HKS_ERROR_INVALID_ARGUMENT,
        "Input json array string is empty")
    auto jsonArray = CommJsonObject::Parse(certJsonArr);
    HKS_IF_TRUE_LOGE_RETURN(!jsonArray.IsArray(), HKS_ERROR_INVALID_ARGUMENT,
        "Input string is not json array")
    int32_t arraySize = jsonArray.ArraySize();
    HKS_IF_TRUE_LOGE_RETURN(arraySize == 0, HKS_ERROR_INVALID_ARGUMENT,
        "Json array size invalid: %" LOG_PUBLIC "d", arraySize)
    certSet.count = arraySize;
    certSet.certs = (HksExtCertInfo *)HksMalloc(arraySize * sizeof(HksExtCertInfo));
    HKS_IF_NULL_LOGE_RETURN(certSet.certs, HKS_ERROR_MALLOC_FAIL,
        "Malloc for cert set failed, size: %" LOG_PUBLIC "d", arraySize)
    int32_t ret = memset_s(certSet.certs, arraySize * sizeof(HksExtCertInfo), 0,
        arraySize * sizeof(HksExtCertInfo));
    if (ret != EOK) {
        HKS_FREE(certSet.certs);
        certSet.certs = nullptr;
        HKS_LOG_E("memset_s for cert set failed, ret: %" LOG_PUBLIC "d", ret);
        return ret;
    }
    for (int32_t i = 0; i < arraySize; i++) {
        auto element = jsonArray.GetElement(i);
        auto purposeObj = element.GetValue("purpose").ToNumber<int32_t>();
        auto indexObj = element.GetValue("index").ToString();
        auto certObj = element.GetValue("cert").ToString();
        HKS_IF_NOT_TRUE_LOGE_RETURN(purposeObj.first == HKS_SUCCESS && indexObj.first == HKS_SUCCESS &&
            certObj.first == HKS_SUCCESS, HKS_ERROR_JSON_INVALID_VALUE, "element invalid value")
        certSet.certs[i].purpose = purposeObj.second;
        certSet.certs[i].index = StringToBlob(indexObj.second);
        certSet.certs[i].cert = Base64StringToBlob(certObj.second);
    }
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Parse cert info failed: %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
}

}