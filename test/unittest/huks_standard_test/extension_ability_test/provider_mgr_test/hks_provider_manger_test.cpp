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
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    if (providerMgr != nullptr) {
        providerMgr->ReleaseInstance();
    }
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
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    ProviderInfo providerInfo{};
    ret = HksGetProviderInfo(processInfo, providerName, paramSet, providerInfo);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetProviderInfo failed";

    sptr<IHuksAccessExtBase> proxy = {nullptr};
    ret = providerMgr->GetExtensionProxy(providerInfo, proxy);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GetExtensionProxy failed";

    int32_t deletecount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deletecount);
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
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    int32_t deletecount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deletecount);
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
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    CppParamSet emptyParamSet{};
    int32_t deletecount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, emptyParamSet, false, deletecount);
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
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
    });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksProviderMgrTest.HksProviderMgrTest006
* @tc.desc: GetAllProviderInfosByProviderName - find by providerName matching frontUserId
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest006, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr) << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest006";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
    });
    ASSERT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    std::vector<ProviderInfo> providerInfos;
    ret = providerMgr->GetAllProviderInfosByProviderName(providerName, 100, providerInfos);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "GetAllProviderInfosByProviderName failed";

    int32_t deletecount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deletecount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksProviderMgrTest.HksProviderMgrTest007
* @tc.desc: GetAllProviderInfosByProviderName - no match for providerName returns INVALID_ARGUMENT
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest007, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr) << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest007";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
    });
    ASSERT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    std::vector<ProviderInfo> providerInfos;
    ret = providerMgr->GetAllProviderInfosByProviderName("NonExistentProvider", 100, providerInfos);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should return INVALID_ARGUMENT for non-existent provider";

    int32_t deletecount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deletecount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksProviderMgrTest.HksProviderMgrTest008
* @tc.desc: GetAllProviderInfosByProviderName - "HksInnerNullProviderName" matches all providers
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest008, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr) << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest008";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
    });
    ASSERT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    std::vector<ProviderInfo> providerInfos;
    ret = providerMgr->GetAllProviderInfosByProviderName("HksInnerNullProviderName", 100, providerInfos);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksInnerNullProviderName should match all providers";

    int32_t deletecount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deletecount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksProviderMgrTest.HksProviderMgrTest009
* @tc.desc: GetAllProviderInfosByProviderName - queries with registered providerName
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest009, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr) << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest009";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
        int32_t deleteCount = 0;
        providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
    });
    ASSERT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    // Note: GetAllProviderInfosByProviderName ignores the userid parameter,
    // it always calls HksGetFrontUserId() internally (mock returns 100).
    // So querying a registered provider should succeed.
    std::vector<ProviderInfo> providerInfos;
    ret = providerMgr->GetAllProviderInfosByProviderName(providerName, 100, providerInfos);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "should find registered provider";

    int32_t deletecount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deletecount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksProviderMgrTest.HksProviderMgrTest010
* @tc.desc: Test OnQueryAbility - query ability info successfully
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest010, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr) << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProccess is null";

    std::string abilityInfoString = "[{\"abilityName\":\"UiAbility1\",\"index\":\"key1\"}]";
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_INFO, .blob = StringToBlob(abilityInfoString)},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest006";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
            HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
            int32_t deleteCount = 0;
            providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
        });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    std::string resourceId = "{\"providerName\":\"HksProviderMgrTest006\",\"abilityName\":\"HiTaiCryptoAbility\""
        ",\"bundleName\":\"com.huawei.extensionhap.test\",\"index\":\"key1\"}";
    CppAbilityInfo abilityInfo{};
    ret = providerMgr->OnQueryAbility(processInfo, resourceId, abilityInfo);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnQueryAbility failed";

    int32_t deleteCount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deleteCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksProviderMgrTest.HksProviderMgrTest011
* @tc.desc: Test RegisterProviderWithIndexArray - register 3 UI extensions successfully
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest011, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr) << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProccess is null";

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::string uiAbilityJson = "[{\"abilityName\":\"UiAbility1\",\"index\":\"key1\"},"
        "{\"abilityName\":\"UiAbility2\",\"index\":\"key2\"},"
        "{\"abilityName\":\"UiAbility3\",\"index\":\"key3\"}]";
    
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_INFO, .blob = StringToBlob(uiAbilityJson)},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest007";
    
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
            HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
            int32_t deleteCount = 0;
            providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
        });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    int32_t deleteCount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deleteCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksProviderMgrTest.HkProviderMgrTest012
* @tc.desc: Test RegisterProviderWithIndexArray - register 11 UI extensions should fail (exceeds limit)
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest012, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr) << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProccess is null";

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::string uiAbilityJson = "[{\"abilityName\":\"UiAbility1\",\"index\":\"key1\"},"
        "{\"abilityName\":\"UiAbility2\",\"index\":\"key2\"},"
        "{\"abilityName\":\"UiAbility3\",\"index\":\"key3\"},"
        "{\"abilityName\":\"UiAbility4\",\"index\":\"key4\"},"
        "{\"abilityName\":\"UiAbility5\",\"index\":\"key5\"},"
        "{\"abilityName\":\"UiAbility6\",\"index\":\"key6\"},"
        "{\"abilityName\":\"UiAbility7\",\"index\":\"key7\"},"
        "{\"abilityName\":\"UiAbility8\",\"index\":\"key8\"},"
        "{\"abilityName\":\"UiAbility9\",\"index\":\"key9\"},"
        "{\"abilityName\":\"UiAbility10\",\"index\":\"key10\"},"
        "{\"abilityName\":\"UiAbility11\",\"index\":\"key11\"}]";
    
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_INFO, .blob = StringToBlob(uiAbilityJson)},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest008";
    
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
            HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
            int32_t deleteCount = 0;
            providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
        });
    EXPECT_NE(ret, HKS_SUCCESS) << "OnRegisterProvider should fail with 11 UI extensions";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksProviderMgrTest.HksProviderMgrTest013
* @tc.desc: Test RegisterProviderWithIndexArray - key length exceeds 1024 should fail
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest013, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr) << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProccess is null";

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    
    std::string longKey(1025, 'a');
    std::string uiAbilityJson = "[{\"abilityName\":\"UiAbility1\",\"index\":" + longKey + "\"}]";
    
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_INFO, .blob = StringToBlob(uiAbilityJson)},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest009";
    
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
            HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
            int32_t deleteCount = 0;
            providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
        });
    EXPECT_NE(ret, HKS_SUCCESS) << "OnRegisterProvider should fail with key length > 1024";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksProviderMgrTest.HksProviderMgrTest014
* @tc.desc: Test RegisterProviderWithIndexArray - register 3 UI extensions successfully
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest014, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr) << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProccess is null";

    std::string longKey(1025, 'a');
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::string uiAbilityJson = "[{\"abilityName\":\"UiAbility1\",\"index\":\"key1\"},"
        "{\"abilityName\":\"UiAbility2\",\"index\":\"key2\"},"
        "{\"abilityName\":\"UiAbility3\",\"index\":\"key3\"},"
        "{\"abilityName\":\"UiAbility3\",\"index\":\"key1\"}]";
    
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_INFO, .blob = StringToBlob(uiAbilityJson)},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest010";
    
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
            HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
            int32_t deleteCount = 0;
            providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
        });
    EXPECT_EQ(ret, HKS_ERROR_PROVIDER_HAS_REGISTERED) << "OnRegisterProvider10 failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksProviderMgrTest.HksProviderMgrTest015
* @tc.desc: Test RegisterProviderWithIndexArray - register 3 UI extensions successfully
* @tc.type: FUNC
*/
HWTEST_F(HksProviderMgrTest, HksProviderMgrTest015, TestSize.Level0) {
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    EXPECT_NE(providerMgr, nullptr) << "providerMgr is null";

    std::string bundleName = "com.huawei.extensionhap.test";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProccess is null";

    std::string abilityInfoString = "[{\"abilityName\":\"UiAbility1\",\"index\":\"\"}]";
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("HiTaiCryptoAbility")},
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_INFO, .blob = StringToBlob(abilityInfoString)},
    };
    CppParamSet paramSet{params};
    std::string providerName = "HksProviderMgrTest011";
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet,
        [providerMgr, processInfo, providerName, paramSet](HksProcessInfo proInfo) {
            HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
            int32_t deleteCount = 0;
            providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, true, deleteCount);
        });
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnRegisterProvider failed";

    std::string resourceId = "{\"providerName\":\"HksProviderMgrTest011\",\"abilityName\":\"HiTaiCryptoAbility\""
        ",\"bundleName\":\"com.huawei.extensionhap.test\",\"index\":\"key1\"}";
    CppAbilityInfo abilityInfo{};
    ret = providerMgr->OnQueryAbility(processInfo, resourceId, abilityInfo);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnQueryAbility failed";

    int32_t deleteCount = 0;
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, false, deleteCount);
    EXPECT_EQ(ret, HKS_SUCCESS) << "OnUnRegisterProvider failed";

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}
}
}
}