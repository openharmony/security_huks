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

bool IsHksBlobEmpty(const struct HksBlob& blob)
{
    return blob.data == nullptr || blob.size == 0;
}

bool IsHksExtCertInfoSetEmpty(const struct HksExtCertInfoSet& certSet)
{
    return certSet.certs == nullptr || certSet.count == 0;
}

HksBlob Base64StringToBlob(const std::string &inStr)
{
    HksBlob blob = {0, nullptr};
    if (inStr.empty()) {
        return blob;
    }
    auto decodeVec = Base64Str2U8Vec(inStr);
    HKS_IF_TRUE_LOGE_RETURN(decodeVec.first != HKS_SUCCESS, blob, "Base64Str2U8Vec failed, ret: %" LOG_PUBLIC "d",
        decodeVec.first)
    blob.size = decodeVec.second.size();
    blob.data = static_cast<uint8_t*>(HksMalloc(blob.size));
    if (blob.data != nullptr) {
        if (memcpy_s(blob.data, blob.size, decodeVec.second.data(), decodeVec.second.size()) != EOK) {
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

int32_t StringToCertInfo(const std::string &certInfoJson, struct HksExtCertInfo& certInfo)
{
    HKS_IF_TRUE_LOGE_RETURN(certInfoJson.empty(), HKS_ERROR_INVALID_ARGUMENT,
        "Input json string is empty")
    auto jsonObj = CommJsonObject::Parse(certInfoJson);
    HKS_IF_TRUE_LOGE_RETURN(jsonObj.IsNull(), HKS_ERROR_INVALID_ARGUMENT,
        "Parse json string failed")

    if (jsonObj.HasKey("purpose")) {
        auto purposeObj = jsonObj.GetValue("purpose");
        HKS_IF_TRUE_LOGE_RETURN(!purposeObj.IsNumber(), HKS_ERROR_INVALID_ARGUMENT,
            "Purpose field is not number")
        auto result = purposeObj.ToNumber<int32_t>();
        HKS_IF_NOT_SUCC_LOGE_RETURN(result.first, result.first,
            "Get purpose value failed, ret: %" LOG_PUBLIC "d", result.first)
        certInfo.purpose = result.second;
    }
    
    if (jsonObj.HasKey("index")) {
        auto indexObj = jsonObj.GetValue("index");
        HKS_IF_TRUE_LOGE_RETURN(!indexObj.IsString(), HKS_ERROR_INVALID_ARGUMENT,
            "Index field is not string")
        
        auto result = indexObj.ToString();
        HKS_IF_NOT_SUCC_LOGE_RETURN(result.first, result.first,
            "Get index string failed, ret: %" LOG_PUBLIC "d", result.first)
        
        certInfo.index = StringToBlob(result.second);
    }
    
    if (jsonObj.HasKey("cert")) {
        auto certObj = jsonObj.GetValue("cert");
        HKS_IF_TRUE_LOGE_RETURN(!certObj.IsString(), HKS_ERROR_INVALID_ARGUMENT,
            "Cert field is not string")
        
        auto result = certObj.ToString();
        HKS_IF_NOT_SUCC_LOGE_RETURN(result.first, result.first, 
            "Get cert string failed, ret: %" LOG_PUBLIC "d", result.first)
        
        certInfo.cert = StringToBlob(result.second);
    }
    
    return HKS_SUCCESS;
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
    std::string cert = BlobToString(certInfo.cert);
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
    certSet.certs = (HksExtCertInfo*)HksMalloc(arraySize * sizeof(HksExtCertInfo));
    HKS_IF_NULL_LOGE_RETURN(certSet.certs, HKS_ERROR_MALLOC_FAIL,
        "Malloc for cert set failed, size: %" LOG_PUBLIC "d", arraySize)
    int32_t ret = memset_s(certSet.certs, arraySize * sizeof(HksExtCertInfo), 0,
        arraySize * sizeof(HksExtCertInfo));
    HKS_IF_TRUE_LOGE_RETURN(ret != EOK, HKS_ERROR_INVALID_OPERATION,
        "memset_s for cert set failed, ret: %" LOG_PUBLIC "d", ret)
    for (int32_t i = 0; i < arraySize; i++) {
        auto element = jsonArray.GetElement(i);
        if (element.IsNull() || !element.IsObject()) {
            HKS_LOG_E("Element %" LOG_PUBLIC "d is not valid json object", i);
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }
        auto purposeObj = element.GetValue("purpose");
        auto indexObj = element.GetValue("index");
        auto certObj = element.GetValue("cert");
        HKS_IF_TRUE_LOGE_RETURN(purposeObj.IsNull() || indexObj.IsNull() || certObj.IsNull(),
            HKS_ERROR_INVALID_ARGUMENT, "element is not valid")
        auto purposeRes = purposeObj.ToNumber<int32_t>();
        if (purposeRes.first == HKS_SUCCESS) {
            certSet.certs[i].purpose = purposeRes.second;
        }
        auto indexRes = indexObj.ToString();
        if (indexRes.first == HKS_SUCCESS) {
            certSet.certs[i].index = StringToBlob(indexRes.second);
        }
        auto certRes = certObj.ToString();
        if (certRes.first == HKS_SUCCESS) {
            certSet.certs[i].cert = Base64StringToBlob(certRes.second);
        }
    }
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Parse cert info failed: %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
}

int32_t CertInfoSetToJsonArray(const struct HksExtCertInfoSet& certSet, std::string& jsonArrayStr)
{
    HKS_IF_TRUE_LOGE_RETURN(IsHksExtCertInfoSetEmpty(certSet), HKS_ERROR_INVALID_ARGUMENT,
        "Input cert set is empty")
    
    auto jsonArray = CommJsonObject::CreateArray();
    HKS_IF_TRUE_LOGE_RETURN(jsonArray.IsNull(), HKS_ERROR_MALLOC_FAIL,
        "Create json array failed")
    
    for (uint32_t i = 0; i < certSet.count; i++) {
        auto certInfoObj = CommJsonObject::CreateObject();
        HKS_IF_TRUE_LOGE_BREAK(certInfoObj.IsNull(), "Create json object failed")
        
        if (!certInfoObj.SetValue("purpose", certSet.certs[i].purpose)) {
            HKS_LOG_E("Set purpose value failed for index %u", i);
            return HKS_ERROR_INTERNAL_ERROR;
        }
        std::string index = BlobToString(certSet.certs[i].index);
        if (!certInfoObj.SetValue("index", index)) {
            HKS_LOG_E("Set index value failed for index %u", i);
            return HKS_ERROR_INTERNAL_ERROR;
        }
        std::string cert = BlobToString(certSet.certs[i].cert);
        if (!certInfoObj.SetValue("cert", cert)) {
            HKS_LOG_E("Set cert value failed for index %u", i);
            return HKS_ERROR_INTERNAL_ERROR;
        }
        if (!jsonArray.AppendElement(certInfoObj)) {
            HKS_LOG_E("Append element %u to array failed", i);
            return HKS_ERROR_INTERNAL_ERROR;
        }
    }
    
    jsonArrayStr = jsonArray.Serialize();
    HKS_IF_TRUE_LOGE_RETURN(jsonArrayStr.empty(), HKS_ERROR_INTERNAL_ERROR,
        "Serialize json array failed")
    
    return HKS_SUCCESS;
}

void FreeCertInfoSet(HksExtCertInfoSet &certSet)
{
    if (certSet.certs != nullptr) {
        for (uint32_t i = 0; i < certSet.count; i++) {
            HKS_FREE(certSet.certs[i].index.data);
            HKS_FREE(certSet.certs[i].cert.data);
        }
        HKS_FREE(certSet.certs);
        certSet.certs = nullptr;
    }
    certSet.count = 0;
}
}