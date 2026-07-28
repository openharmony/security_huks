/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hks_ukey_err_code_mapper.h"
#include "hks_error_code.h"
#include "hks_ukey_common.h"

namespace OHOS {
namespace Security {
namespace Huks {

void HksErrCodeMapper::Register(PluginMethodEnum method, const std::map<int32_t, int32_t> &mapping)
{
    mappings_[method] = mapping;
}

void HksErrCodeMapper::AddEntry(PluginMethodEnum method, int32_t extErrCode, int32_t hksErrCode)
{
    mappings_[method][extErrCode] = hksErrCode;
}

int32_t HksErrCodeMapper::Convert(PluginMethodEnum method, int32_t extensionErrorCode) const
{
    auto outerIter = mappings_.find(method);
    if (outerIter == mappings_.end()) {
        return HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR;
    }
    auto innerIter = outerIter->second.find(extensionErrorCode);
    if (innerIter != outerIter->second.end()) {
        return innerIter->second;
    }
    return HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR;
}

static const std::map<int32_t, int32_t> kErrBase = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {HKS_ERROR_EXT_JS_METHOD_ERROR, HUKS_ERR_CODE_BUSY},
};

static std::map<int32_t, int32_t> MergeBase(const std::map<int32_t, int32_t> &overrides)
{
    auto result = kErrBase;
    result.insert(overrides.begin(), overrides.end());
    return result;
}

static const std::map<int32_t, int32_t> kAuthPin = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_CODE_ERROR, HUKS_ERR_CODE_PIN_CODE_ERROR},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
};

static const std::map<int32_t, int32_t> kGetVerifyPin = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
};

static const std::map<int32_t, int32_t> kClearPin = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
};

static const std::map<int32_t, int32_t> kCreateHandle = {
    {EXTENSION_ERRCODE_UKEY_NOT_EXIST, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
};

static const std::map<int32_t, int32_t> kCloseHandle = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HKS_SUCCESS},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HKS_SUCCESS},
};

static const std::map<int32_t, int32_t> kInitSession = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HUKS_ERR_CODE_PIN_NO_AUTH},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
};

static const std::map<int32_t, int32_t> kUpdateSession = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HUKS_ERR_CODE_PIN_NO_AUTH},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
};

static const std::map<int32_t, int32_t> kFinishSession = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HUKS_ERR_CODE_PIN_NO_AUTH},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
};

static const std::map<int32_t, int32_t> kAbortSession = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HKS_SUCCESS},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HKS_SUCCESS},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HKS_SUCCESS},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HKS_SUCCESS},
    {EXTENSION_ERRCODE_PIN_LOCKED, HKS_SUCCESS},
};

static const std::map<int32_t, int32_t> kExportCert = {
    {EXTENSION_ERRCODE_UKEY_NOT_EXIST, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
};

static const std::map<int32_t, int32_t> kExportProvCerts = {
    {EXTENSION_ERRCODE_UKEY_NOT_EXIST, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
};

static const std::map<int32_t, int32_t> kImportCert = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
};

static const std::map<int32_t, int32_t> kGetProperty = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HUKS_ERR_CODE_PIN_NO_AUTH},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
    {HKS_ERROR_EXT_RETURN_VALUE_INCRECT, HKS_ERROR_EXT_RETURN_VALUE_INCRECT},
};

static const std::map<int32_t, int32_t> kGetResourceId = {
    {EXTENSION_ERRCODE_UKEY_NOT_EXIST, HUKS_ERR_CODE_CRYPTO_FAIL},
};

static const std::map<int32_t, int32_t> kGenerateKey = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
};

static const std::map<int32_t, int32_t> kImportWrappedKey = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
};

static const std::map<int32_t, int32_t> kExportPublicKey = {
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
};

// Register 16 actually-used error mappings (g_commonErrCodeMapping is dead code, not registered)
void InitDefaultMappings(HksErrCodeMapper &mapper)
{
    mapper.Register(PluginMethodEnum::FUNC_ON_AUTH_UKEY_PIN, MergeBase(kAuthPin));
    mapper.Register(PluginMethodEnum::FUNC_ON_GET_VERIFY_PIN_STATUS, MergeBase(kGetVerifyPin));
    mapper.Register(PluginMethodEnum::FUNC_ON_CLEAR_PIN_STATUS, MergeBase(kClearPin));
    mapper.Register(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE, MergeBase(kCreateHandle));
    mapper.Register(PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE, MergeBase(kCloseHandle));
    mapper.Register(PluginMethodEnum::FUNC_ON_INIT_SESSION, MergeBase(kInitSession));
    mapper.Register(PluginMethodEnum::FUNC_ON_UPDATE_SESSION, MergeBase(kUpdateSession));
    mapper.Register(PluginMethodEnum::FUNC_ON_FINISH_SESSION, MergeBase(kFinishSession));
    mapper.Register(PluginMethodEnum::FUNC_ON_ABORT_SESSION, MergeBase(kAbortSession));
    mapper.Register(PluginMethodEnum::FUNC_ON_LIST_INDEX_CERTIFICATE, MergeBase(kExportCert));
    mapper.Register(PluginMethodEnum::FUNC_ON_LIST_PROVIDER_ALL_CERTIFICATE, MergeBase(kExportProvCerts));
    mapper.Register(PluginMethodEnum::FUNC_ON_IMPORT_CERTIFICATE, MergeBase(kImportCert));
    mapper.Register(PluginMethodEnum::FUNC_ON_SET_OR_GET_REMOTE_PROPERTY, MergeBase(kGetProperty));
    mapper.Register(PluginMethodEnum::FUNC_ON_GET_RESOURCE_ID, MergeBase(kGetResourceId));
    mapper.Register(PluginMethodEnum::FUNC_ON_GENERATE_KEY, MergeBase(kGenerateKey));
    mapper.Register(PluginMethodEnum::FUNC_ON_IMPORT_WRAPPED_KEY, MergeBase(kImportWrappedKey));
    mapper.Register(PluginMethodEnum::FUNC_ON_EXPORT_PUBLIC_KEY, MergeBase(kExportPublicKey));
}

}
}
}
