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

bool IsHksBlobEmpty(const struct HksBlob& blob) {
    return blob.data == nullptr || blob.size == 0;
}

bool IsHksExtCertInfoSetEmpty(const struct HksExtCertInfoSet& certSet) {
    return certSet.certs == nullptr || certSet.count == 0;
}

void FreeHksExtCertInfoSet(struct HksExtCertInfoSet* certSet) {
    HKS_IF_NULL_RETURN_VOID(certSet);
    
    if (certSet->certs != nullptr) {
        for (uint32_t i = 0; i < certSet->count; i++) {
            if (certSet->certs[i].index.data != nullptr) {
                free(certSet->certs[i].index.data);
                certSet->certs[i].index.data = nullptr;
            }
            if (certSet->certs[i].cert.data != nullptr) {
                free(certSet->certs[i].cert.data);
                certSet->certs[i].cert.data = nullptr;
            }
        }
        free(certSet->certs);
        certSet->certs = nullptr;
    }
    certSet->count = 0;
}

static int32_t HksBlobToBase64(const struct HksBlob& blob, std::string& base64Str) {
    if (IsHksBlobEmpty(blob)) {
        base64Str = "";
        return HKS_SUCCESS;
    }
    
    std::vector<uint8_t> vec(blob.data, blob.data + blob.size);
    auto result = U8Vec2Base64Str(vec);
    HKS_IF_NOT_SUCC_LOGE_RETURN(result.first, result.first, 
        "Convert blob to base64 failed, ret: %d", result.first);
    
    base64Str = result.second;
    return HKS_SUCCESS;
}

static int32_t Base64ToHksBlob(const std::string& base64Str, struct HksBlob& blob) {
    
    if (base64Str.empty()) {
        return HKS_SUCCESS;
    }
    
    auto result = Base64Str2U8Vec(base64Str);
    HKS_IF_NOT_SUCC_LOGE_RETURN(result.first, result.first, 
        "Convert base64 to blob failed, ret: %d", result.first);
    
    blob.size = result.second.size();
    if (blob.size > 0) {
        blob.data = (uint8_t*)malloc(blob.size);
        HKS_IF_NULL_LOGE_RETURN(blob.data, HKS_ERROR_MALLOC_FAIL, 
            "Malloc for blob data failed, size: %u", blob.size);
        
        int32_t ret = memcpy_s(blob.data, blob.size, result.second.data(), blob.size);
        if (ret != EOK) {
            HKS_LOG_E("memcpy_s for blob data failed, ret: %d", ret);
            free(blob.data);
            blob.data = nullptr;
            blob.size = 0;
            return HKS_ERROR_INVALID_OPERATION;
        }
    }
    
    return HKS_SUCCESS;
}

int32_t StringToCertInfo(const std::string &certInfoJson, struct HksExtCertInfo& certInfo) {
    
    HKS_IF_TRUE_LOGE_RETURN(certInfoJson.empty(), HKS_ERROR_INVALID_ARGUMENT, 
        "Input json string is empty");
    
    auto jsonObj = CommJsonObject::Parse(certInfoJson);
    HKS_IF_TRUE_LOGE_RETURN(jsonObj.IsNull(), HKS_ERROR_INVALID_ARGUMENT, 
        "Parse json string failed");
    
    if (jsonObj.HasKey("purpose")) {
        auto purposeObj = jsonObj.GetValue("purpose");
        HKS_IF_TRUE_LOGE_RETURN(!purposeObj.IsNumber(), HKS_ERROR_INVALID_ARGUMENT, 
            "Purpose field is not number");
        
        auto result = purposeObj.ToNumber<int32_t>();
        HKS_IF_NOT_SUCC_LOGE_RETURN(result.first, result.first, 
            "Get purpose value failed, ret: %d", result.first);
        
        certInfo.purpose = result.second;
    }
    
    if (jsonObj.HasKey("index")) {
        auto indexObj = jsonObj.GetValue("index");
        HKS_IF_TRUE_LOGE_RETURN(!indexObj.IsString(), HKS_ERROR_INVALID_ARGUMENT, 
            "Index field is not string");
        
        auto result = indexObj.ToString();
        HKS_IF_NOT_SUCC_LOGE_RETURN(result.first, result.first, 
            "Get index string failed, ret: %d", result.first);
        
        int32_t ret = Base64ToHksBlob(result.second, certInfo.index);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, 
            "Convert index base64 to blob failed, ret: %d", ret);
    }
    
    if (jsonObj.HasKey("cert")) {
        auto certObj = jsonObj.GetValue("cert");
        HKS_IF_TRUE_LOGE_RETURN(!certObj.IsString(), HKS_ERROR_INVALID_ARGUMENT, 
            "Cert field is not string");
        
        auto result = certObj.ToString();
        HKS_IF_NOT_SUCC_LOGE_RETURN(result.first, result.first, 
            "Get cert string failed, ret: %d", result.first);
        
        int32_t ret = Base64ToHksBlob(result.second, certInfo.cert);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, 
            "Convert cert base64 to blob failed, ret: %d", ret);
    }
    
    HKS_LOG_I("Convert json to cert info success, purpose: %d", certInfo.purpose);
    return HKS_SUCCESS;
}

int32_t CertInfoToString(const struct HksExtCertInfo& certInfo, std::string& jsonStr) {
    jsonStr.clear();
    
    auto jsonObj = CommJsonObject::CreateObject();
    HKS_IF_TRUE_LOGE_RETURN(jsonObj.IsNull(), HKS_ERROR_MALLOC_FAIL, 
        "Create json object failed");
    
    if (!jsonObj.SetValue("purpose", certInfo.purpose)) {
        HKS_LOG_E("Set purpose value failed");
        return HKS_ERROR_INTERNAL_ERROR;
    }
    
    std::string indexBase64;
    int32_t ret = HksBlobToBase64(certInfo.index, indexBase64);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Convert index blob to base64 failed, ret: %d", ret);
    
    if (!jsonObj.SetValue("index", indexBase64)) {
        HKS_LOG_E("Set index value failed");
        return HKS_ERROR_INTERNAL_ERROR;
    }
    
    std::string certBase64;
    ret = HksBlobToBase64(certInfo.cert, certBase64);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Convert cert blob to base64 failed, ret: %d", ret);
    
    if (!jsonObj.SetValue("cert", certBase64)) {
        HKS_LOG_E("Set cert value failed");
        return HKS_ERROR_INTERNAL_ERROR;
    }
    
    jsonStr = jsonObj.Serialize();
    HKS_IF_TRUE_LOGE_RETURN(jsonStr.empty(), HKS_ERROR_INTERNAL_ERROR, 
        "Serialize json object failed");
    
    HKS_LOG_I("Convert cert info to json success, purpose: %d", certInfo.purpose);
    return HKS_SUCCESS;
}


int32_t JsonArrayToCertInfoSet(const std::string &certJsonArr, struct HksExtCertInfoSet& certSet) {
    
    HKS_IF_TRUE_LOGE_RETURN(certJsonArr.empty(), HKS_ERROR_INVALID_ARGUMENT, 
        "Input json array string is empty");
    
    auto jsonArray = CommJsonObject::Parse(certJsonArr);
    HKS_IF_TRUE_LOGE_RETURN(!jsonArray.IsArray(), HKS_ERROR_INVALID_ARGUMENT, 
        "Input string is not json array");
    
    int32_t arraySize = jsonArray.ArraySize();
    HKS_IF_TRUE_LOGE_RETURN(arraySize <= 0, HKS_ERROR_INVALID_ARGUMENT, 
        "Json array size invalid: %d", arraySize);
    
    certSet.count = arraySize;
    certSet.certs = (HksExtCertInfo*)malloc(arraySize * sizeof(HksExtCertInfo));
    HKS_IF_NULL_LOGE_RETURN(certSet.certs, HKS_ERROR_MALLOC_FAIL, 
        "Malloc for cert set failed, size: %d", arraySize);
    
    int32_t ret = memset_s(certSet.certs, arraySize * sizeof(HksExtCertInfo), 0, arraySize * sizeof(HksExtCertInfo));
    if (ret != EOK) {
        HKS_LOG_E("memset_s for cert set failed, ret: %d", ret);
        free(certSet.certs);
        certSet.certs = nullptr;
        certSet.count = 0;
        return HKS_ERROR_INVALID_OPERATION;
    }

    for (int32_t i = 0; i < arraySize; i++) {
        auto element = jsonArray.GetElement(i);
        if (element.IsNull() || !element.IsObject()) {
            HKS_LOG_E("Element %d is not valid json object", i);
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }
        
        std::string elementStr = element.ToString().second;
        ret = StringToCertInfo(elementStr, certSet.certs[i]);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("Convert element %d failed, ret: %d", i, ret);
            break;
        }
    }
    
    if (ret != HKS_SUCCESS) {
        FreeHksExtCertInfoSet(&certSet);
        return ret;
    }
    
    HKS_LOG_I("Convert json array to cert set success, count: %u", certSet.count);
    return HKS_SUCCESS;
}

int32_t CertInfoSetToJsonArray(const struct HksExtCertInfoSet& certSet, std::string& jsonArrayStr) {
    
    HKS_IF_TRUE_LOGE_RETURN(IsHksExtCertInfoSetEmpty(certSet), HKS_ERROR_INVALID_ARGUMENT, 
        "Input cert set is empty");
    
    auto jsonArray = CommJsonObject::CreateArray();
    HKS_IF_TRUE_LOGE_RETURN(jsonArray.IsNull(), HKS_ERROR_MALLOC_FAIL, 
        "Create json array failed");
    
    for (uint32_t i = 0; i < certSet.count; i++) {
        std::string certInfoJson;
        int32_t ret = CertInfoToString(certSet.certs[i], certInfoJson);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Convert cert info %u to string failed, ret: %d", i, ret);
        
        auto certInfoObj = CommJsonObject::Parse(certInfoJson);
        HKS_IF_TRUE_LOGE_BREAK(certInfoObj.IsNull(), "Parse cert info json failed");
        
        if (!jsonArray.AppendElement(certInfoObj)) {
            HKS_LOG_E("Append element %u to array failed", i);
            return HKS_ERROR_INTERNAL_ERROR;
        }
    }
    
    jsonArrayStr = jsonArray.Serialize();
    HKS_IF_TRUE_LOGE_RETURN(jsonArrayStr.empty(), HKS_ERROR_INTERNAL_ERROR, 
        "Serialize json array failed");
    
    HKS_LOG_I("Convert cert set to json array success, count: %u", certSet.count);
    return HKS_SUCCESS;
}

}