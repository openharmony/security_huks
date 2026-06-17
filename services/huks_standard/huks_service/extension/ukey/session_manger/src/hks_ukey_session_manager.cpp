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

#include "hks_error_code.h"
#include "hks_provider_life_cycle_manager.h"
#include "hks_remote_handle_manager.h"
#include "hks_ukey_session_manager.h"
#include "hks_ukey_common.h"
#include "hks_ukey_system_adapter.h"

#include <algorithm>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <random>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include "hks_cpp_paramset.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_type_enum.h"
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
namespace OHOS {
namespace Security {
namespace Huks {

std::shared_ptr<HksSessionManager> HksSessionManager::GetInstanceWrapper()
{
    return HksSessionManager::GetInstance();
}

void HksSessionManager::ReleaseInstance()
{
    HksSessionManager::DestroyInstance();
}

static bool GenerateRand(uint8_t *buf, size_t len)
{
    FILE *randfp = fopen("/dev/random", "rb");
    HKS_IF_TRUE_LOGE_RETURN(randfp == nullptr, false, "fopen file failed")

    size_t readLen = fread(buf, sizeof(uint8_t), len, randfp);
    (void)fclose(randfp);
    HKS_IF_TRUE_LOGE_RETURN(readLen != len, false, "read file failed")
    return true;
}

std::pair<int32_t, uint32_t> HksSessionManager::GenRandomUint32()
{
    uint32_t random = std::numeric_limits<uint32_t>::max();
    auto *randomNumPtr = static_cast<uint8_t *>(static_cast<void *>(&random));
    HKS_IF_TRUE_LOGE_RETURN(!GenerateRand(randomNumPtr, sizeof(uint32_t)),
        std::make_pair(HKS_ERROR_GEN_RANDOM_FAIL, 0), "GenerateRand failed")
    return std::make_pair(HKS_SUCCESS, random);
}

constexpr int32_t MAX_SINGLE_CALLER_HANDLE_SIZE = 32;
bool HksSessionManager::CheckSingleCallerCanInitSession(const HksProcessInfo &processInfo)
{
    uint8_t curHandleNum = 0;
    m_handlers.Iterate([&](const uint32_t &handle, HandleInfo &handleInfo) {
        HKS_IF_TRUE_EXCU(processInfo.uidInt == handleInfo.m_uid, curHandleNum++);
    });
    return curHandleNum < MAX_SINGLE_CALLER_HANDLE_SIZE;
}

int32_t HksSessionManager::CheckParmSetPurposeAndCheckAuth(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet)
{
    auto purpose = paramSet.GetParam<HKS_TAG_PURPOSE>();
    HKS_IF_TRUE_LOGE_RETURN(purpose.first != HKS_SUCCESS, HKS_ERROR_INVALID_ARGUMENT,
        "Get purpose tag failed. ret: %" LOG_PUBLIC "d", purpose.first)
    if (purpose.second == HKS_KEY_PURPOSE_SIGN || purpose.second == HKS_KEY_PURPOSE_DECRYPT) {
        auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
        HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
        HKS_LOG_I("CheckParmSetPurposeAndCheckAuth uid: %" LOG_PUBLIC "d", processInfo.uidInt);
        return handleMgr->CheckAuthStateIsOk(processInfo, index);
    }
    return HKS_SUCCESS;
}

constexpr int32_t MAX_HANDLE_SIZE = 96;
int32_t HksSessionManager::ExtensionInitSession(struct HksProcessWithErrorInfo &processAndError,
    const std::string &index, const CppParamSet &paramSet, uint32_t &handle)
{
    HKS_IF_TRUE_LOGE_RETURN(!CheckSingleCallerCanInitSession(*processAndError.processInfo),
        HKS_ERROR_SESSION_REACHED_LIMIT, "handle too many, please realse the old")
    HKS_IF_TRUE_LOGE_RETURN(m_handlers.Size() >= MAX_HANDLE_SIZE, HKS_ERROR_SESSION_REACHED_LIMIT,
        "The handle maximum quantity has been reached")
    int32_t ret = CheckParmSetPurposeAndCheckAuth(*processAndError.processInfo, index, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "CheckParmSetPurposeAndCheckAuth failed")
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string sIndexHandle;
    ret = HksRemoteHandleManager::GetInstanceWrapper()->ParseAndValidateIndex(index,
        processAndError.processInfo->uidInt, providerInfo, sIndexHandle);
    providerInfo.m_userid = processAndError.processInfo->userIdInt;
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ParseAndValidateIndex failed: %" LOG_PUBLIC "d", ret)

    std::string sessionHandle;
    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = HksRemoteHandleManager::GetInstanceWrapper()->GetProviderProxy(providerInfo, proxy);
    HKS_IF_TRUE_LOGE_RETURN(proxy == nullptr, HKS_ERROR_NOT_EXIST, "GetProviderProxy proxy is null")

    CppParamSet newParamSet{};
    ret = VerifyCallerAndAdjustUidParam(*processAndError.processInfo, paramSet, newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    HksExternalErrorInfoIdl errorInfo = {HKS_ERROR_EXT_JS_METHOD_ERROR, HKS_DEFAULT_ERROR_DESC, false};
    auto ipcCode = proxy->InitSession(sIndexHandle, newParamSet, sessionHandle, errorInfo);
    HKS_IF_TRUE_LOGE_RETURN(ipcCode != EOK, HKS_ERROR_IPC_MSG_FAIL, "proxy InitSession ipcCode: %" LOG_PUBLIC "d",
        ipcCode)
    HKS_IF_TRUE_EXCU(errorInfo.errVal != EXTENSION_SUCCESS,
        processAndError.errInfo = HksCreateExternalErrorInfoWithFlag(errorInfo.errVal,
            errorInfo.errorDesc.c_str(), errorInfo.hasErrorInfo));
    ret = ConvertExtensionToHksErrorCode(errorInfo.errVal, g_initSessionErrCodeMapping);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "proxy InitSession get handle failed: %" LOG_PUBLIC "d", ret)

    auto random = GenRandomUint32();
    HKS_IF_TRUE_LOGE_RETURN(random.first != HKS_SUCCESS, random.first,
        "GenRandomUint32 failed. ret: %" LOG_PUBLIC "d", random.first)

    handle = random.second;
    HandleInfo handleInfo{sessionHandle, providerInfo, processAndError.processInfo->uidInt, index};
    m_handlers.Insert(handle, handleInfo);
    return HKS_SUCCESS;
}

int32_t HksSessionManager::ExtensionUpdateSession(struct HksProcessWithErrorInfo &processAndError,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData)
{
    HandleInfo handleInfo;
    HKS_LOG_I("ExtensionUpdateSession handle: %" LOG_PUBLIC "u", handle);
    int32_t ret = HksGetHandleInfo(*processAndError.processInfo, handle, handleInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksGetHandleInfo ret = %" LOG_PUBLIC "d", ret)

    sptr<IHuksAccessExtBase> proxy{nullptr};
    ret = HksProviderLifeCycleManager::GetInstanceWrapper()->GetExtensionProxy(handleInfo.m_providerInfo,
        proxy);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "GetExtensionProxy failed: %" LOG_PUBLIC "d", ret)

    CppParamSet newParamSet{};
    ret = VerifyCallerAndAdjustUidParam(*processAndError.processInfo, paramSet, newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    HksExternalErrorInfoIdl errorInfo = {HKS_ERROR_EXT_JS_METHOD_ERROR, HKS_DEFAULT_ERROR_DESC, false};
    auto ipcCode = proxy->UpdateSession(handleInfo.m_skfSessionHandle, newParamSet, inData, outData, errorInfo);
    HKS_IF_TRUE_LOGE_RETURN(ipcCode != EOK, HKS_ERROR_IPC_MSG_FAIL, "proxy UpdateSession ipcCode: %" LOG_PUBLIC "d",
        ipcCode)
    HKS_IF_TRUE_EXCU(errorInfo.errVal != EXTENSION_SUCCESS,
        processAndError.errInfo = HksCreateExternalErrorInfoWithFlag(errorInfo.errVal,
            errorInfo.errorDesc.c_str(), errorInfo.hasErrorInfo));
    ret = ConvertExtensionToHksErrorCode(errorInfo.errVal, g_updateSessionErrCodeMapping);
    ClearSessionMapByHandle(ret, handle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "proxy UpdateSession failed: %" LOG_PUBLIC "d", ret)

    return HKS_SUCCESS;
}
int32_t HksSessionManager::ExtensionFinishSession(struct HksProcessWithErrorInfo &processAndError,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData)
{
    HandleInfo handleInfo;
    int32_t ret = HksGetHandleInfo(*processAndError.processInfo, handle, handleInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksGetHandleInfo ret = %" LOG_PUBLIC "d", ret)

    sptr<IHuksAccessExtBase> proxy{nullptr};
    ret = HksProviderLifeCycleManager::GetInstanceWrapper()->GetExtensionProxy(handleInfo.m_providerInfo, proxy);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "GetExtensionProxy failed: %" LOG_PUBLIC "d", ret)

    CppParamSet newParamSet{};
    ret = VerifyCallerAndAdjustUidParam(*processAndError.processInfo, paramSet, newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    HksExternalErrorInfoIdl errorInfo = {HKS_ERROR_EXT_JS_METHOD_ERROR, HKS_DEFAULT_ERROR_DESC, false};
    auto ipcCode = proxy->FinishSession(handleInfo.m_skfSessionHandle, newParamSet, inData, outData, errorInfo);
    HKS_IF_TRUE_LOGE_RETURN(ipcCode != EOK, HKS_ERROR_IPC_MSG_FAIL, "proxy FinishSession ipcCode: %" LOG_PUBLIC "d",
        ipcCode)
    HKS_IF_TRUE_EXCU(errorInfo.errVal != EXTENSION_SUCCESS,
        processAndError.errInfo = HksCreateExternalErrorInfoWithFlag(errorInfo.errVal,
            errorInfo.errorDesc.c_str(), errorInfo.hasErrorInfo));
    ret = ConvertExtensionToHksErrorCode(errorInfo.errVal, g_finishSessionErrCodeMapping);
    ClearSessionMapByHandle(ret, handle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "FinishSession failed: %" LOG_PUBLIC "d", ret)
    m_handlers.Erase(handle);
    return HKS_SUCCESS;
}

int32_t HksSessionManager::ExtensionAbortSession(struct HksProcessWithErrorInfo &processAndError,
    const uint32_t &handle, const CppParamSet &paramSet)
{
    HandleInfo handleInfo;
    int32_t ret = HksGetHandleInfo(*processAndError.processInfo, handle, handleInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksGetHandleInfo ret = %" LOG_PUBLIC "d", ret)

    sptr<IHuksAccessExtBase> proxy{nullptr};
    ret = HksProviderLifeCycleManager::GetInstanceWrapper()->GetExtensionProxy(handleInfo.m_providerInfo, proxy);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "GetExtensionProxy failed: %" LOG_PUBLIC "d", ret)

    CppParamSet newParamSet{};
    ret = VerifyCallerAndAdjustUidParam(*processAndError.processInfo, paramSet, newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    std::vector<uint8_t> tmpVec;
    HksExternalErrorInfoIdl errorInfo = {HKS_ERROR_EXT_JS_METHOD_ERROR, HKS_DEFAULT_ERROR_DESC, false};
    auto ipcCode = proxy->FinishSession(handleInfo.m_skfSessionHandle, newParamSet, tmpVec, tmpVec, errorInfo);
    HKS_IF_TRUE_LOGE_RETURN(ipcCode != EOK, HKS_ERROR_IPC_MSG_FAIL,
        "proxy use CloseRemoteHandle to abort ipcCode: %" LOG_PUBLIC "d", ipcCode)
    HKS_IF_TRUE_EXCU(errorInfo.errVal != EXTENSION_SUCCESS,
        processAndError.errInfo = HksCreateExternalErrorInfoWithFlag(errorInfo.errVal,
            errorInfo.errorDesc.c_str(), errorInfo.hasErrorInfo));
    ret = ConvertExtensionToHksErrorCode(errorInfo.errVal, g_abortSessionErrCodeMapping);
    ClearSessionMapByHandle(ret, handle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "abort closeRemoteHandle failed: %" LOG_PUBLIC "d", ret)
    m_handlers.Erase(handle);
    return HKS_SUCCESS;
}

int32_t HksSessionManager::HksGetHandleInfo(const HksProcessInfo &processInfo, const uint32_t &handle,
    HandleInfo &infos)
{
    HandleInfo infoNew{};
    HKS_IF_TRUE_LOGE_RETURN(!m_handlers.Find(handle, infoNew), HKS_ERROR_NOT_EXIST, "Find handle failed")
    HKS_IF_TRUE_LOGE_RETURN(infoNew.m_uid != processInfo.uidInt, HKS_ERROR_NOT_EXIST,
        "uid not crrect. infoUid: %" LOG_PUBLIC "d, processUid: %" LOG_PUBLIC "d", infoNew.m_uid, processInfo.uidInt)
    infos = std::move(infoNew);
    return HKS_SUCCESS;
}

void HksSessionManager::ClearSessionHandleMap(std::vector<uint32_t> &toRemove)
{
    HksProcessInfo processInfo = {};
    std::vector<uint8_t> tmpVec;
    for (auto item: toRemove) {
        HandleInfo mInfo;
        HKS_IF_TRUE_CONTINUE(!m_handlers.Find(item, mInfo))
        processInfo.uidInt = mInfo.m_uid;
        struct HksParam uid = {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)};
        CppParamSet paramSet = CppParamSet({uid});
        struct HksProcessWithErrorInfo processAndError = { &processInfo, nullptr };
        (void)ExtensionFinishSession(processAndError, item, paramSet, tmpVec, tmpVec);
        m_handlers.Erase(item);
    }
}

std::vector<uint32_t> HksSessionManager::FindToRemoveHandle(const uint32_t &uid, const std::string &abilityName)
{
    std::vector<uint32_t> toRemove;
    m_handlers.Iterate([&](const uint32_t &handle, HandleInfo &handleInfo) {
        HKS_IF_TRUE_EXCU(uid == handleInfo.m_uid && handleInfo.m_providerInfo.m_abilityName == abilityName,
            toRemove.emplace_back(handle));
    });
    return toRemove;
}

std::vector<uint32_t> HksSessionManager::FindToRemoveHandle(const uint32_t &uid)
{
    std::vector<uint32_t> toRemove;
    m_handlers.Iterate([&](const uint32_t &handle, HandleInfo &handleInfo) {
        HKS_IF_TRUE_EXCU(uid == handleInfo.m_uid, toRemove.emplace_back(handle));
    });
    return toRemove;
}

std::vector<uint32_t> HksSessionManager::FindToRemoveHandle(const uint32_t &uid, const std::string &abilityName,
    const std::string &index)
{
    std::vector<uint32_t> toRemove;
    m_handlers.Iterate([&](const uint32_t &handle, HandleInfo &handleInfo) {
        HKS_IF_TRUE_EXCU(uid == handleInfo.m_uid && handleInfo.m_providerInfo.m_abilityName == abilityName &&
            handleInfo.m_index == index, toRemove.emplace_back(handle));
    });
    return toRemove;
}

std::vector<uint32_t> HksSessionManager::FindToRemoveByIndex(const uint32_t &uid, const std::string &index)
{
    std::vector<uint32_t> toRemove;
    m_handlers.Iterate([&](const uint32_t &handle, HandleInfo &handleInfo) {
        HKS_IF_TRUE_EXCU(uid == handleInfo.m_uid && handleInfo.m_index == index, toRemove.emplace_back(handle));
    });
    return toRemove;
}

bool HksSessionManager::HksClearHandle(const HksProcessInfo &processInfo, const CppParamSet &paramSet,
    const std::string &index)
{
    std::vector<uint32_t> toRemove;
    do {
        auto abilityName = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_NAME>();
        if (abilityName.first == HKS_SUCCESS) {
            HKS_IF_TRUE_LOGE_RETURN(abilityName.second.size() >= MAX_ABILITY_NAME_LEN, false,
                "the abilityName is too long. size: %" LOG_PUBLIC "zu", abilityName.second.size())
            std::string abilityNameStr = std::string(abilityName.second.begin(), abilityName.second.end());
            HKS_LOG_I("HksClearHandle get abilityName: %" LOG_PUBLIC "s", abilityNameStr.c_str());
            toRemove = FindToRemoveHandle(processInfo.uidInt, abilityNameStr, index);
            break;
        }
        toRemove = FindToRemoveByIndex(processInfo.uidInt, index);
    } while (false);
    ClearSessionHandleMap(toRemove);
    return true;
}

bool HksSessionManager::HksClearHandle(const HksProcessInfo &processInfo, const CppParamSet &paramSet)
{
    std::vector<uint32_t> toRemove;
    do {
        auto abilityName = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_NAME>();
        if (abilityName.first == HKS_SUCCESS) {
            HKS_IF_TRUE_LOGE_RETURN(abilityName.second.size() >= MAX_ABILITY_NAME_LEN, false,
                "the abilityName is too long. size: %" LOG_PUBLIC "zu", abilityName.second.size())
            std::string abilityNameStr = std::string(abilityName.second.begin(), abilityName.second.end());
            HKS_LOG_I("HksClearHandle get abilityName: %" LOG_PUBLIC "s", abilityNameStr.c_str());
            toRemove = FindToRemoveHandle(processInfo.uidInt, abilityNameStr);
            break;
        }
        toRemove = FindToRemoveHandle(processInfo.uidInt);
    } while (false);
    ClearSessionHandleMap(toRemove);
    return true;
}

void HksSessionManager::HksClearHandle(const ProviderInfo &providerInfo)
{
    std::vector<uint32_t> toRemove;
    m_handlers.Iterate([&](const uint32_t &handle, HandleInfo &info) {
        if (providerInfo.m_providerName == info.m_providerInfo.m_providerName &&
            providerInfo.m_userid == HksGetUserIdFromUid(info.m_uid) &&
            providerInfo.m_bundleName == info.m_providerInfo.m_bundleName &&
            (providerInfo.m_abilityName.empty() || info.m_providerInfo.m_abilityName == providerInfo.m_abilityName)) {
            toRemove.emplace_back(handle);
        }
    });
    ClearSessionHandleMap(toRemove);
}

void HksSessionManager::ClearSessionMapByHandle(int32_t ret, uint32_t handle)
{
    if (ret != HUKS_ERR_CODE_CRYPTO_FAIL && ret != HUKS_ERR_CODE_ITEM_NOT_EXIST) {
        return;
    }
    m_handlers.Erase(handle);
}

}
}
}