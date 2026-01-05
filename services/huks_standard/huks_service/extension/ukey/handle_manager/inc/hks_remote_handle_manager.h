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

#ifndef HKS_REMOTE_HANDLE_MANAGER_H
#define HKS_REMOTE_HANDLE_MANAGER_H

#include "hks_cpp_paramset.h"
#include "hks_plugin_def.h"
#include "hks_provider_life_cycle_manager.h"
#include "singleton.h"
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "safe_map.h"
#include "ihuks_access_ext_base.h"
#include "hks_json_wrapper.h"
#include "hks_ukey_common.h"
namespace OHOS {
namespace Security {
namespace Huks {

const std::map<int32_t, int32_t> g_commonErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_NOT_EXIST, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HKS_ERROR_PIN_NO_AUTH},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_CODE_ERROR, HUKS_ERR_CODE_PIN_CODE_ERROR},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

const std::map<int32_t, int32_t> g_initSessionErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HKS_ERROR_PIN_NO_AUTH},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

const std::map<int32_t, int32_t> g_updateSessionErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HKS_ERROR_PIN_NO_AUTH},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

const std::map<int32_t, int32_t> g_finishSessionErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HKS_ERROR_PIN_NO_AUTH},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

const std::map<int32_t, int32_t> g_abortSessionErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HKS_SUCCESS},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HKS_SUCCESS},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HKS_SUCCESS},
    {EXTENSION_ERRCODE_PIN_LOCKED, HKS_SUCCESS},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

const std::map<int32_t, int32_t> g_exportCertErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_NOT_EXIST, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

const std::map<int32_t, int32_t> g_openResourceErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_NOT_EXIST, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

const std::map<int32_t, int32_t> g_closeResourceErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HKS_SUCCESS},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HKS_SUCCESS},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

const std::map<int32_t, int32_t> g_authPinErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_CODE_ERROR, HUKS_ERR_CODE_PIN_CODE_ERROR},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

const std::map<int32_t, int32_t> g_getPinAuthStateErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

const std::map<int32_t, int32_t> g_getPropertyErrCodeMapping = {
    {EXTENSION_SUCCESS, HKS_SUCCESS},
    {EXTENSION_ERRCODE_OPERATION_FAIL, HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR},
    {EXTENSION_ERRCODE_UKEY_FAIL, HUKS_ERR_CODE_CRYPTO_FAIL},
    {EXTENSION_ERRCODE_PIN_NOT_AUTH, HKS_ERROR_PIN_NO_AUTH},
    {EXTENSION_ERRCODE_HANDLE_NOT_EXIST, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_HANDLE_FAIL, HUKS_ERR_CODE_ITEM_NOT_EXIST},
    {EXTENSION_ERRCODE_PIN_LOCKED, HUKS_ERR_CODE_PIN_LOCKED},
    {HKS_ERROR_EXT_JS_METHON_ERROR, HUKS_ERR_CODE_BUSY}
};

class HksRemoteHandleManager : private OHOS::DelayedSingleton<HksRemoteHandleManager>,
    std::enable_shared_from_this<HksRemoteHandleManager> {
public:

    static std::shared_ptr<HksRemoteHandleManager> GetInstanceWrapper();
    static void ReleaseInstance();
    // handle manager
    int32_t CreateRemoteHandle(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet);
    int32_t CloseRemoteHandle(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet);
    // ukey PIN manager
    int32_t RemoteVerifyPin(const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet,
        int32_t &authState, uint32_t &retryCnt);
    int32_t RemoteVerifyPinStatus(const HksProcessInfo &processInfo,
        const std::string &index, const CppParamSet &paramSet, int32_t &state);
    int32_t RemoteClearPinStatus(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet);
    int32_t CheckAuthStateIsOk(const HksProcessInfo &processInfo, const std::string &index);
    //certificate query
    int32_t FindRemoteCertificate(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet, std::string &certificatesOut);
    int32_t FindRemoteAllCertificate(const HksProcessInfo &processInfo,
        const std::string &providerName, const CppParamSet &paramSet, std::string &certificatesOut);
    int32_t MergeProviderCertificates(const ProviderInfo &providerInfo, const std::string &providerCertVec,
        CommJsonObject &combinedArray);
    //sign and verify
    int32_t RemoteHandleSign(const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet,
        const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData);
    int32_t RemoteHandleVerify(const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet,
        const std::vector<uint8_t> &plainText, std::vector<uint8_t> &signature);

    int32_t GetRemoteProperty(const HksProcessInfo &processInfo, const std::string& index,
        const std::string& propertyId, const CppParamSet& paramSet, CppParamSet& outParams);

    int32_t ClearRemoteHandleMap(const std::string &providerName, const std::string &abilityName,
        const int32_t userid);
    static int32_t ParseIndexAndProviderInfo(const std::string &index,
        ProviderInfo &providerInfo, std::string &newIndex);
    void ClearAuthState(const HksProcessInfo &processInfo);
    int32_t ParseAndValidateIndex(const std::string &index, const uint32_t uid, ProviderInfo &providerInfo,
        std::string &handle);
    int32_t GetProviderProxy(const ProviderInfo &providerInfo, OHOS::sptr<IHuksAccessExtBase> &proxy);
    void ClearMapByHandle(const int32_t &ret, const std::string &handle);
    void ClearMapByUid(const uint32_t uid);
    
private:
    bool IsProviderNumExceedLimit(const ProviderInfo &providerInfo);

    OHOS::SafeMap<std::pair<uint32_t, std::string>, std::string> uidIndexToHandle_;
    OHOS::SafeMap<std::pair<uint32_t, std::string>, int32_t> uidIndexToAuthState_;
    OHOS::SafeMap<ProviderInfo, int32_t> providerInfoToNum_;
};
}
}
}
#endif