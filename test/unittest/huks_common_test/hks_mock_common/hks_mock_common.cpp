/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "hks_mock_common.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "gtest/gtest.h"
#include <mutex>
#include <thread>
#include <iostream>
#include "hks_type.h"
#include "hks_param.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "securec.h"
#include "hks_plugin_def.h"


using namespace OHOS::Security::AccessToken;
namespace {
    std::mutex g_lockSetToken{};
    uint64_t g_shellTokenId = 0;
}

void HksMockCommon::SetTestEvironment(uint64_t shellTokenId)
{
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = shellTokenId;
}

void HksMockCommon::ResetTestEvironment()
{
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = 0;
}

uint64_t HksMockCommon::GetShellTokenId()
{
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    return g_shellTokenId;
}

int32_t HksMockCommon::AllocTestHapToken(
    const HapInfoParams& hapInfo, HapPolicyParams& hapPolicy, AccessTokenIDEx& tokenIdEx)
{
    uint64_t selfTokenId = GetSelfTokenID();
    for (auto& permissionStateFull : hapPolicy.permStateList) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(permissionStateFull.permissionName, permDefResult) != RET_SUCCESS) {
            continue;
        }
        if (permDefResult.availableLevel > hapPolicy.apl) {
            hapPolicy.aclRequestedList.emplace_back(permissionStateFull.permissionName);
        }
    }
    if (HksMockCommon::GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        return AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);
    }

    // set sh token for self
    HksMockNativeToken mock("foundation");
    int32_t ret = AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);

    // restore
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));

    return ret;
}

int32_t HksMockCommon::DeleteTestHapToken(AccessTokenID tokenID)
{
    uint64_t selfTokenId = GetSelfTokenID();
    if (HksMockCommon::GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        return AccessTokenKit::DeleteToken(tokenID);
    }

    // set sh token for self
    HksMockNativeToken mock("foundation");

    int32_t ret = AccessTokenKit::DeleteToken(tokenID);
    // restore
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));
    return ret;
}

AccessTokenID HksMockCommon::GetNativeTokenIdFromProcess(const std::string &process)
{
    uint64_t selfTokenId = GetSelfTokenID();
    EXPECT_EQ(0, SetSelfTokenID(HksMockCommon::GetShellTokenId())); // set shell token

    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = process;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }
    // restore
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));

    std::istringstream iss(numStr);
    AccessTokenID tokenID;
    iss >> tokenID;
    return tokenID;
}

AccessTokenIDEx HksMockCommon::GetHapTokenIdFromBundle(
    int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    uint64_t selfTokenId = GetSelfTokenID();
    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag(static_cast<AccessTokenID>(selfTokenId));
    if (type != TOKEN_NATIVE) {
        AccessTokenID tokenId1 = GetNativeTokenIdFromProcess("accesstoken_service");
        EXPECT_EQ(0, SetSelfTokenID(tokenId1));
    }
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(userID, bundleName, instIndex);

    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));
    return tokenIdEx;
}

HksMockNativeToken::HksMockNativeToken(const std::string& process)
{
    selfToken_ = GetSelfTokenID();
    uint32_t tokenId = HksMockCommon::GetNativeTokenIdFromProcess(process);
    SetSelfTokenID(tokenId);
}

HksMockNativeToken::~HksMockNativeToken()
{
    SetSelfTokenID(selfToken_);
}

HksMockHapToken::HksMockHapToken(
    const std::string& bundle, const std::vector<std::string>& reqPerm, bool isSystemApp)
{
    selfToken_ = GetSelfTokenID();
    HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = bundle,
        .instIndex = 0,
        .appIDDesc = "AccessTokenTestAppID",
        .apiVersion = HksMockCommon::DEFAULT_API_VERSION,
        .isSystemApp = isSystemApp,
        .appDistributionType = "",
    };

    HapPolicyParams policyParams = {
        .apl = APL_NORMAL,
        .domain = "accesstoken_test_domain",
    };
    for (size_t i = 0; i < reqPerm.size(); ++i) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(reqPerm[i], permDefResult) != RET_SUCCESS) {
            continue;
        }
        PermissionStateFull permState = {
            .permissionName = reqPerm[i],
            .isGeneral = true,
            .resDeviceID = {"local3"},
            .grantStatus = {PermissionState::PERMISSION_DENIED},
            .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
        };
        policyParams.permStateList.emplace_back(permState);
        if (permDefResult.availableLevel > policyParams.apl) {
            policyParams.aclRequestedList.emplace_back(reqPerm[i]);
        }
    }

    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, HksMockCommon::AllocTestHapToken(infoParams, policyParams, tokenIdEx));
    mockToken_= tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(mockToken_, INVALID_TOKENID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
}

HksMockHapToken::~HksMockHapToken()
{
    if (mockToken_ != INVALID_TOKENID) {
        EXPECT_EQ(0, HksMockCommon::DeleteTestHapToken(mockToken_));
    }
    EXPECT_EQ(0, SetSelfTokenID(selfToken_));
}

int32_t HksGetProcessInfoForIPC(struct HksProcessInfo *processInfo)
{
    if (processInfo == nullptr) {
        HKS_LOG_D("Don't need get process name in hosp.");
        return HKS_SUCCESS;
    }

    auto callingUid = OHOS::IPCSkeleton::GetCallingUid();
    uint8_t *name = static_cast<uint8_t *>(HksMalloc(sizeof(callingUid)));
    HKS_IF_NULL_LOGE_RETURN(name, HKS_ERROR_MALLOC_FAIL, "GetProcessName malloc failed.")

    (void)memcpy_s(name, sizeof(callingUid), &callingUid, sizeof(callingUid));
    processInfo->processName.size = sizeof(callingUid);
    processInfo->processName.data = name;
    processInfo->uidInt = callingUid;

    int32_t userId = -1;
    (void)OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId);
    uint32_t size;
    if (userId == 0) {
        size = strlen("0");
    } else {
        size = sizeof(userId);
    }

    uint8_t *name1 = static_cast<uint8_t *>(HksMalloc(size));
    if (name1 == nullptr) {
        HKS_LOG_E("user id malloc failed.");
        HKS_FREE(name);
        processInfo->processName.data = nullptr;
        return HKS_ERROR_MALLOC_FAIL;
    }

    if (userId == 0) {
        (void)memcpy_s(name1, size, "0", size); /* ignore \0 at the end */
    } else {
        (void)memcpy_s(name1, size, &userId, size);
    }

    processInfo->userId.size = size;
    processInfo->userId.data = name1;
    processInfo->userIdInt = userId;

#ifdef HKS_SUPPORT_ACCESS_TOKEN
    processInfo->accessTokenId = static_cast<uint64_t>(OHOS::IPCSkeleton::GetCallingTokenID());
    HKS_IF_TRUE_LOGE(processInfo->accessTokenId == 0, "accessTokenId is zero")
#endif
    processInfo->pid = static_cast<int32_t>(OHOS::IPCSkeleton::GetCallingPid());
    HKS_IF_TRUE_LOGE(processInfo->pid == 0, "GetCallingPID is zero")
    return HKS_SUCCESS;
}