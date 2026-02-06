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
#include "os_account_manager.h"

namespace OHOS::Security::Huks {

constexpr const uint32_t USERID_FACTOR = 200000;
    
bool CheckStringParamLenIsOk(const std::string &str, uint32_t min, uint32_t max)
{
    if (str.size() < min || str.size() > max) {
        HKS_LOG_E("CheckStringParamLenIsOk failed, str.size: %" LOG_PUBLIC "zu"
            "min: %" LOG_PUBLIC "d, max: %" LOG_PUBLIC "d", str.size(), min, max);
        return false;
    }
    return true;
}

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
    HKS_IF_TRUE_LOGE_RETURN(!jsonObj.SetValue("purpose", certInfo.purpose),
        HKS_ERROR_INTERNAL_ERROR, "Set purpose value failed")
    HKS_IF_TRUE_LOGE_RETURN(!jsonObj.SetValue("index", BlobToString(certInfo.index)),
        HKS_ERROR_INTERNAL_ERROR, "Set index value failed")
    HKS_IF_TRUE_LOGE_RETURN(!jsonObj.SetValue("cert", BlobToBase64String(certInfo.cert)),
        HKS_ERROR_INTERNAL_ERROR, "Set cert value failed")
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
    HKS_IF_TRUE_LOGI_RETURN(arraySize == 0, HKS_SUCCESS, "Notify, CertInfoSet count size is 0")

    std::vector<HksExtCertInfo> tempCertSet{};
    for (int32_t i = 0; i < arraySize; i++) {
        auto element = jsonArray.GetElement(i);
        auto purposeObj = element.GetValue("purpose").ToNumber<int32_t>();
        auto indexObj = element.GetValue("index").ToString();
        auto certObj = element.GetValue("cert").ToString();
        HKS_IF_TRUE_LOGE_CONTINUE(purposeObj.first != HKS_SUCCESS || indexObj.first != HKS_SUCCESS ||
            certObj.first != HKS_SUCCESS, "get cert fail!")

        HksExtCertInfo tempCert = {
            .purpose = purposeObj.second,
            .index = StringToBlob(indexObj.second),
            .cert = Base64StringToBlob(certObj.second),
        };
        if (tempCert.index.size == 0 || tempCert.index.data == nullptr ||
            tempCert.cert.size == 0 || tempCert.cert.data == nullptr) {
            HKS_LOG_E("StringToBlob or Base64StringToBlob fail.");
            HKS_FREE_BLOB(tempCert.index);
            HKS_FREE_BLOB(tempCert.cert);
            continue;
        }
        tempCertSet.push_back(tempCert);
    }

    HKS_IF_TRUE_LOGE_RETURN(tempCertSet.empty(), HKS_SUCCESS, "No valid certificates found")
    certSet.count = static_cast<uint32_t>(tempCertSet.size());
    certSet.certs = (HksExtCertInfo *)HksMalloc(tempCertSet.size() * sizeof(HksExtCertInfo));
    if (certSet.certs == nullptr) {
        HKS_LOG_E("Malloc for cert set failed, size: %" LOG_PUBLIC "d", certSet.count);
        for (uint32_t i = 0; i < certSet.count; i++) {
            HKS_FREE_BLOB(tempCertSet[i].index);
            HKS_FREE_BLOB(tempCertSet[i].cert);
        }
        return HKS_ERROR_MALLOC_FAIL;
    }
    for (uint32_t i = 0; i < certSet.count; i++) {
        certSet.certs[i] = tempCertSet[i];
        tempCertSet[i].index.data = nullptr;
        tempCertSet[i].cert.data = nullptr;
    }
    return HKS_SUCCESS;
}

int32_t ConvertExtensionToHksErrorCode(const int32_t extensionErrorCode, const std::map<int32_t, int32_t> &errorMapping)
{
    auto iter = errorMapping.find(extensionErrorCode);
    if (iter != errorMapping.end()) {
        return iter->second;
    } else {
        return HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR;
    }
}

int32_t HksGetFrontUserId(int32_t &outId)
{
    std::vector<int> ids{};
    int ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    HKS_IF_TRUE_LOGE_RETURN(ret != OHOS::ERR_OK || ids.empty(), HKS_FAILURE,
        "QueryActiveOsAccountIds Failed!! ret = %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("QueryActiveOsAccountIds success: FrontUserId= %" LOG_PUBLIC "d", ids[0]);
    outId = ids[0];
    return HKS_SUCCESS;
}

int32_t HksGetUserIdFromUid(const uint32_t &uid)
{
    return static_cast<int32_t>(uid / USERID_FACTOR);
}

}