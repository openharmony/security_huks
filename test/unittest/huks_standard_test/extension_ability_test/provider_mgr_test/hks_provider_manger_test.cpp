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
#include "hks_mem.h"
#include "hks_plugin_def.h"
#include "hks_provider_life_cycle_manager.h"
#include "hks_mock_common.h"
#include "hks_type.h"
#include "gtest/gtest.h"
#include <vector>
#include "hks_ukey_common.h"
#include "hks_log.h"
#include "token_setproc.h"
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Huks {
static uint64_t g_shellTokenId = 0;
class HksProviderMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void HksProviderMgrTest::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksProviderMgrTest::TearDownTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::ResetTestEvironment();
}

void HksProviderMgrTest::SetUp()
{}

void HksProviderMgrTest::TearDown() {
}

/**
* @tc.name: HksProviderMgrTest.HksProviderMgrTest001
* @tc.desc: connect success.
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest001, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr);
    providerMgr->ReleaseInstance();
}

HWTEST_F(HksProviderMgrTest, HksProviderMgrTest002, TestSize.Level0) {
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
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest002";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](bool deathFlag) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    ProviderInfo providerInfo{};
    ret = HksGetProviderInfo(processInfo, providerName, paramSet, providerInfo);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetProviderInfo failed";

    sptr<IHuksAccessExtBase> proxy = {nullptr};
    ret = providerMgr->GetExtensionProxy(providerInfo, proxy);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GetExtensionProxy failed";

    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

HWTEST_F(HksProviderMgrTest, HksProviderMgrTest003, TestSize.Level0) {
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
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest003";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](bool deathFlag) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

HWTEST_F(HksProviderMgrTest, HksProviderMgrTest004, TestSize.Level0) {
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
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest004";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](bool deathFlag) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    CppParamSet emptyParamSet{};
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, emptyParamSet, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

HWTEST_F(HksProviderMgrTest, HksProviderMgrTest005, TestSize.Level0) {
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
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest005";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](bool deathFlag) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    std::vector<ProviderInfo> providerInfos = {};
    ret = providerMgr->GetAllProviderInfosByProviderName(providerName, providerInfos);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GetAllProviderInfosByProviderName failed";
    EXPECT_EQ(providerInfos.size(), 1);

    std::vector<ProviderInfo> providerInfos2 = {};
    ret = providerMgr->GetAllProviderInfosByProviderName("HksProviderMgrTest005_not_exist", providerInfos2);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "GetAllProviderInfosByProviderName not exist failed";
    EXPECT_EQ(providerInfos2.size(), 0);

    std::vector<ProviderInfo> providerInfos3 = {};
    ret = providerMgr->GetAllProviderInfosByProviderName("HksInnerNullProviderName", providerInfos3);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GetAllProviderInfosByProviderName inner all failed";
    EXPECT_EQ(providerInfos3.size(), 1);

    CppParamSet emptyParamSet{};
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, emptyParamSet, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}
}
}
}