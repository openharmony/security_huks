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

#include "hks_cpp_paramset.h"
#include "hks_error_code.h"
#include "hks_mem.h"
#include "hks_plugin_def.h"
#include "hks_session_manger.h"
#include "hks_remote_handle_manager.h"
#include "hks_mock_common.h"
#include "hks_type.h"
#include "gtest/gtest.h"
#include <vector>
#include "hks_ukey_common.h"
#include "hks_log.h"
#include "token_setproc.h"
#include "hks_json_wrapper.h"
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Huks {
static uint64_t g_shellTokenId = 0;
class HksSessionMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void HksSessionMgrTest::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksSessionMgrTest::TearDownTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::ResetTestEvironment();
}

void HksSessionMgrTest::SetUp()
{}

void HksSessionMgrTest::TearDown() {
}

/**
* @tc.name: HksSessionMgrTest.HksSessionMgrTest001
* @tc.desc: connect success.
* @tc.type: FUNC
*/
HWTEST_F(HksSessionMgrTest, HksSessionMgrTest001, TestSize.Level0) {
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    EXPECT_NE(sessionMgr, nullptr);
    sessionMgr->ReleaseInstance();
}

HWTEST_F(HksSessionMgrTest, HksSessionMgrTest002, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr)  << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProccess is null";

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksSessionMgrTest002";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    EXPECT_NE(sessionMgr, nullptr);
    uint32_t handle = 0;
    CommJsonObject root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("HksSessionMgrTest002")));
    EXPECT_TRUE(root.SetValue("abilityName", std::string("HiTaiCryptoAbility")));
    EXPECT_TRUE(root.SetValue("bundleName", std::string("com.huawei.extensionhap.test")));
    EXPECT_TRUE(root.SetValue("index", std::string("parse_original_index")));
    std::string wrappedIndex = root.Serialize(false);

    ret = sessionMgr->ExtensionInitSession(processInfo, wrappedIndex, paramSet, handle);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "ExtensionInitSession failed";

    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

HWTEST_F(HksSessionMgrTest, HksSessionMgrTest003, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr)  << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProccess is null";

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN},
        { .tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksSessionMgrTest003";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    EXPECT_NE(sessionMgr, nullptr);
    uint32_t handle = 0;
    CommJsonObject root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("HksSessionMgrTest003")));
    EXPECT_TRUE(root.SetValue("abilityName", std::string("HiTaiCryptoAbility")));
    EXPECT_TRUE(root.SetValue("bundleName", std::string("com.huawei.extensionhap.test")));
    EXPECT_TRUE(root.SetValue("userid", processInfo.userIdInt));
    EXPECT_TRUE(root.SetValue("index", std::string("HksSessionMgrTest003")));
    std::string wrappedIndex = root.Serialize(false);
    
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(handleMgr, nullptr);
    ret = handleMgr->CreateRemoteHandle(processInfo, wrappedIndex, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "CreateRemoteHandle failed";

    int32_t authState{1};
    uint32_t retryCount{0};
    ret = handleMgr->RemoteVerifyPin(processInfo, wrappedIndex, paramSet, authState, retryCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "RemoteVerifyPin failed";

    ret = sessionMgr->ExtensionInitSession(processInfo, wrappedIndex, paramSet, handle);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExtensionInitSession failed";

    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}
}
}
}