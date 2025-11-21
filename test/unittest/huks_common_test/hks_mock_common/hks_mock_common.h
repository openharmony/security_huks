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

 
#ifndef HKS_MOCK_COMMON_H
#define HKS_MOCK_COMMON_H

#ifdef __cplusplus
#include <string>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "gtest/gtest.h"
#include <mutex>
#include <string>
#include <iostream>

using OHOS::Security::AccessToken::AccessTokenIDEx;
using OHOS::Security::AccessToken::AccessTokenID;
using OHOS::Security::AccessToken::HapInfoParams;
using OHOS::Security::AccessToken::HapPolicyParams;

class HksMockCommon {
public:
    static constexpr int32_t DEFAULT_API_VERSION = 12;

    static void SetTestEvironment(uint64_t shellTokenId);
    static void ResetTestEvironment();
    static uint64_t GetShellTokenId();

    static int32_t AllocTestHapToken(const HapInfoParams& hapInfo,
        HapPolicyParams& hapPolicy, AccessTokenIDEx& tokenIdEx);
    static int32_t DeleteTestHapToken(AccessTokenID tokenID);
    static AccessTokenID GetNativeTokenIdFromProcess(const std::string& process);
    static AccessTokenIDEx GetHapTokenIdFromBundle(
        int32_t userID, const std::string& bundleName, int32_t instIndex);
};

class HksMockNativeToken {
public:
    explicit HksMockNativeToken(const std::string& process);
    ~HksMockNativeToken();
private:
    uint64_t selfToken_;
};

class HksMockHapToken {
public:
    explicit HksMockHapToken(
        const std::string& bundle, const std::vector<std::string>& reqPerm, bool isSystemApp = true);
    ~HksMockHapToken();
private:
    uint64_t selfToken_;
    uint32_t mockToken_;
};

#endif

int32_t HksGetProcessInfoForIPC(struct HksProcessInfo *processInfo);
#endif