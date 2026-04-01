#include "app_observer.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_external_adapter.h"
#include "hks_remote_handle_manager.h"
#include "hks_ukey_session_manager.h"
#include "hks_cpp_paramset.h"
#include "hks_mem.h"
#include "hks_plugin_def.h"
#include "hks_ukey_common.h"
#include "hks_mock_common.h"
#include "hks_type.h"
#include "hks_error_code.h"
#include "gtest/gtest.h"
#include <string>
#include <vector>
#include "token_setproc.h"
#include "../../../../../services/huks_standard/huks_service/extension/ukey/app_observer/app_observer.cpp"
#include "../../../../../services/huks_standard/huks_service/extension/ukey/interface/plugin_interface.cpp"

extern void ResetHandleManagerMockFlags();
extern void ResetSessionManagerMockFlags();
extern bool g_hksClearHandleCalled;
extern bool g_clearAuthStateCalled;
extern bool g_clearMapByUidCalled;
extern uint32_t g_clearMapByUidArg;
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Huks {

static uint64_t g_shellTokenId = 0;

class HksAppObserverTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void HksAppObserverTest::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksAppObserverTest::TearDownTestCase(void)
{
    HksMockCommon::ResetTestEvironment();
}

void HksAppObserverTest::SetUp() {}

void HksAppObserverTest::TearDown() {}

static HksProcessInfo CreateTestProcessInfo()
{
    HksProcessInfo processInfo{};
    processInfo.uidInt = 100;
    processInfo.userIdInt = 100;
    return processInfo;
}

static HksProcessInfo CreateTestProcessInfoFromIPC()
{
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    return processInfo;
}

static CppParamSet CreateParamSetWithAbility(const std::string &abilityName)
{
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(abilityName)},
    };
    return CppParamSet(params);
}

static CppParamSet CreateParamSetWithAbilityAndUid(const std::string &abilityName, int32_t uid)
{
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(abilityName)},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = uid},
    };
    return CppParamSet(params);
}

static CppParamSet CreateEmptyParamSet()
{
    std::vector<HksParam> params = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
    };
    return CppParamSet(params);
}

static CppParamSet CreateSignParamSet()
{
    std::vector<HksParam> params = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = 100},
    };
    return CppParamSet(params);
}

static std::string CreateTestIndex()
{
    CommJsonObject root = CommJsonObject::CreateObject();
    root.SetValue("providerName", std::string("testProvider"));
    root.SetValue("abilityName", std::string("testAbility"));
    root.SetValue("bundleName", std::string("com.test.bundle"));
    root.SetValue("userid", 100);
    root.SetValue("index", std::string("testIndex"));
    return root.Serialize(false);
}

// ==================== app_observer unit tests ====================

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest001
* @tc.desc: Test HksProcessContext with valid abilityName
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest001, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateParamSetWithAbility("TestAbility");

    HksProcessContext ctx(processInfo, paramSet);
    EXPECT_EQ(ctx.uidInt, 100u);
    EXPECT_EQ(ctx.abilityName, "TestAbility");
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest002
* @tc.desc: Test HksProcessContext with no abilityName in paramSet
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest002, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateEmptyParamSet();

    HksProcessContext ctx(processInfo, paramSet);
    EXPECT_EQ(ctx.uidInt, 100u);
    EXPECT_TRUE(ctx.abilityName.empty());
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest003
* @tc.desc: Test HksProcessContext with abilityName too long
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest003, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfo();
    std::string longName(129, 'A');
    CppParamSet paramSet = CreateParamSetWithAbility(longName);

    HksProcessContext ctx(processInfo, paramSet);
    EXPECT_EQ(ctx.uidInt, 100u);
    EXPECT_TRUE(ctx.abilityName.empty());
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest004
* @tc.desc: Test HksAppObserver constructor and GetBundleName
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest004, TestSize.Level0)
{
    HksAppObserver observer("com.test.bundle");
    EXPECT_EQ(observer.GetBundleName(), "com.test.bundle");
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest005
* @tc.desc: Test AddProcessContext - add single context
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest005, TestSize.Level0)
{
    HksAppObserver observer("com.test.bundle");
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateParamSetWithAbility("TestAbility");

    observer.AddProcessContext(processInfo, paramSet);
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest006
* @tc.desc: Test AddProcessContext - same uid overwrites
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest006, TestSize.Level0)
{
    HksAppObserver observer("com.test.bundle");
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet1 = CreateParamSetWithAbility("Ability1");
    CppParamSet paramSet2 = CreateParamSetWithAbility("Ability2");

    observer.AddProcessContext(processInfo, paramSet1);
    observer.AddProcessContext(processInfo, paramSet2);
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest007
* @tc.desc: Test OnAppStopped - bundle name mismatch
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest007, TestSize.Level0)
{
    HksAppObserver observer("com.test.bundle");
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestAbility", 100);
    observer.AddProcessContext(processInfo, paramSet);

    AppExecFwk::AppStateData appState;
    appState.bundleName = "com.other.bundle";
    appState.uid = 100;
    ResetHandleManagerMockFlags();
    ResetSessionManagerMockFlags();

    observer.OnAppStopped(appState);
    EXPECT_FALSE(g_hksClearHandleCalled);
    EXPECT_FALSE(g_clearAuthStateCalled);
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest008
* @tc.desc: Test OnAppStopped - uid not found in map
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest008, TestSize.Level0)
{
    HksAppObserver observer("com.test.bundle");
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestAbility", 100);
    observer.AddProcessContext(processInfo, paramSet);

    AppExecFwk::AppStateData appState;
    appState.bundleName = "com.test.bundle";
    appState.uid = 99999;
    ResetHandleManagerMockFlags();
    ResetSessionManagerMockFlags();

    observer.OnAppStopped(appState);
    EXPECT_FALSE(g_hksClearHandleCalled);
    EXPECT_FALSE(g_clearAuthStateCalled);
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest009
* @tc.desc: Test OnAppStopped - successful cleanup
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest009, TestSize.Level0)
{
    HksAppObserver observer("com.test.bundle");
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestAbility", 100);
    observer.AddProcessContext(processInfo, paramSet);

    AppExecFwk::AppStateData appState;
    appState.bundleName = "com.test.bundle";
    appState.uid = 100;
    ResetHandleManagerMockFlags();
    ResetSessionManagerMockFlags();

    observer.OnAppStopped(appState);
    EXPECT_TRUE(g_hksClearHandleCalled);
    EXPECT_TRUE(g_clearAuthStateCalled);
    EXPECT_TRUE(g_clearMapByUidCalled);
    EXPECT_EQ(g_clearMapByUidArg, 100u);
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest010
* @tc.desc: Test HksAppObserverManager RegisterObserver with SA unavailable
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest010, TestSize.Level0)
{
    auto &manager = HksAppObserverManager::GetInstance();
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestAbility", 100);

    int32_t ret = manager.RegisterObserver(processInfo, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest011
* @tc.desc: Test HksAppObserverManager UnregisterAllObservers with empty observers
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest011, TestSize.Level0)
{
    auto &manager = HksAppObserverManager::GetInstance();

    int32_t ret = manager.UnregisterAllObservers();
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
* @tc.name: HksAppObserverTest.HksAppObserverTest012
* @tc.desc: Test HksAppObserverManager CleanupTriggeredObserver with non-existent observer
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, HksAppObserverTest012, TestSize.Level0)
{
    auto &manager = HksAppObserverManager::GetInstance();
    manager.CleanupTriggeredObserver("com.nonexistent.bundle");
}

// ==================== plugin_interface integration tests ====================

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest001
* @tc.desc: Test HksExtPluginOnRegisterProvider and OnUnRegisterProvider
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest001, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestCryptoAbility", 100);
    std::string providerName = "PluginInterfaceTest001";

    int32_t ret = HksExtPluginOnRegisterProvider(processInfo, providerName, paramSet,
        [](HksProcessInfo proInfo) {});
    EXPECT_EQ(ret, HKS_SUCCESS);

    int32_t deleteCount = 0;
    ret = HksExtPluginOnUnRegisterProvider(processInfo, providerName, paramSet, false, deleteCount);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest002
* @tc.desc: Test HksExtPluginOnOpenRemoteHandle and OnCloseRemoteHandle
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest002, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestCryptoAbility", 100);
    std::string index = CreateTestIndex();

    int32_t ret = HksExtPluginOnOpenRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksExtPluginOnCloseRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest003
* @tc.desc: Test HksExtPluginOnOpenRemoteHandle with UID mismatch
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest003, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    std::vector<HksParam> params = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob("TestCryptoAbility")},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = 99999},
    };
    CppParamSet paramSet(params);
    std::string index = CreateTestIndex();

    int32_t ret = HksExtPluginOnOpenRemoteHandle(processInfo, index, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest004
* @tc.desc: Test HksExtPluginOnAuthUkeyPin
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest004, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestCryptoAbility", 100);
    std::string index = CreateTestIndex();
    int32_t authState = 0;
    uint32_t retryCnt = 0;

    int32_t ret = HksExtPluginOnAuthUkeyPin(processInfo, index, paramSet, authState, retryCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest005
* @tc.desc: Test HksExtPluginOnGetUkeyPinAuthState
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest005, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestCryptoAbility", 100);
    std::string index = CreateTestIndex();
    int32_t state = 0;

    int32_t ret = HksExtPluginOnGetUkeyPinAuthState(processInfo, index, paramSet, state);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest006
* @tc.desc: Test certificate operations
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest006, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestCryptoAbility", 100);
    std::string index = CreateTestIndex();

    std::string certs;
    int32_t ret = HksExtPluginOnExportCerticate(processInfo, index, paramSet, certs);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksExtCertInfo certInfo = {};
    certInfo.purpose = 1;
    certInfo.index = StringToBlob("test_cert_index");
    certInfo.cert = StringToBlob("MIIBIjANBgkqh");
    ret = HksExtPluginOnImportCertificate(processInfo, index, certInfo, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::string allCerts;
    ret = HksExtPluginOnExportProviderCerticates(processInfo, "testProvider", paramSet, allCerts);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(certInfo.index);
    HKS_FREE_BLOB(certInfo.cert);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest007
* @tc.desc: Test HksExtPluginOnGenerateKey
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest007, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestCryptoAbility", 100);
    std::string index = CreateTestIndex();

    int32_t ret = HksExtPluginOnGenerateKey(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest008
* @tc.desc: Test session operations
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest008, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    CppParamSet paramSet = CreateSignParamSet();
    std::string index = CreateTestIndex();

    uint32_t handle = 0;
    int32_t ret = HksExtPluginOnInitSession(processInfo, index, paramSet, handle);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<uint8_t> outData;
    ret = HksExtPluginOnUpdateSession(processInfo, handle, paramSet, {0x01, 0x02}, outData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksExtPluginOnFinishSession(processInfo, handle, paramSet, {0x01}, outData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksExtPluginOnAbortSession(processInfo, handle, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest009
* @tc.desc: Test OnInitSession with invalid purpose
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest009, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    std::vector<HksParam> params = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = 100},
    };
    CppParamSet paramSet(params);
    std::string index = CreateTestIndex();
    uint32_t handle = 0;

    int32_t ret = HksExtPluginOnInitSession(processInfo, index, paramSet, handle);
    EXPECT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest010
* @tc.desc: Test HksExtPluginOnClearUkeyPinAuthState and OnGetRemoteProperty
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest010, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    std::string index = CreateTestIndex();

    int32_t ret = HksExtPluginOnClearUkeyPinAuthState(processInfo, index);
    EXPECT_EQ(ret, HKS_SUCCESS);

    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestCryptoAbility", 100);
    CppParamSet outParams;
    ret = HksExtPluginOnGetRemoteProperty(processInfo, index, "SKF_GetDevInfo", paramSet, outParams);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest011
* @tc.desc: Test HksExtPluginOnImportWrappedKey and OnExportPublicKey
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest011, TestSize.Level0)
{
    HksProcessInfo processInfo = CreateTestProcessInfoFromIPC();
    CppParamSet paramSet = CreateParamSetWithAbilityAndUid("TestCryptoAbility", 100);
    std::string index = CreateTestIndex();
    std::string wrappingKeyIndex = CreateTestIndex();

    std::vector<uint8_t> wrappedData = {0x01, 0x02, 0x03, 0x04};
    int32_t ret = HksExtPluginOnImportWrappedKey(processInfo, index, wrappingKeyIndex, paramSet, wrappedData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<uint8_t> outData;
    ret = HksExtPluginOnExportPublicKey(processInfo, index, paramSet, outData);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_FALSE(outData.empty());

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksAppObserverTest.PluginInterfaceTest012
* @tc.desc: Test HksExtPluginOnUnregisterAllObservers
* @tc.type: FUNC
*/
HWTEST_F(HksAppObserverTest, PluginInterfaceTest012, TestSize.Level0)
{
    int32_t ret = HksExtPluginOnUnregisterAllObservers();
    EXPECT_EQ(ret, HKS_SUCCESS);
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
