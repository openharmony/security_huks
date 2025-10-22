#include <gtest/gtest.h>
#include <memory>

#include "hks_log.h"
#include "hks_json_wrapper.h"
#include "hks_util.h"
#include "hks_provider_life_cycle_manager.h"
#include "hks_remote_handle_manager.cpp"
#include "ihuks_access_ext_base.h"

using namespace testing::ext;
using namespace OHOS::Security::Huks;

namespace Unittest::HandleManager {
class HandleManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void HandleManagerTest::SetUpTestCase(void) {}

void HandleManagerTest::TearDownTestCase(void) {}

void HandleManagerTest::SetUp() 
{
    HksRemoteHandleManager::ReleaseInstance();
}

void HandleManagerTest::TearDown() 
{
    HksRemoteHandleManager::ReleaseInstance();
}
constexpr const char *PROVIDER_NAME_KEY = "providerName";
constexpr const char *ABILITY_NAME_KEY = "abilityName";
constexpr const char *BUNDLE_NAME_KEY = "bundleName";

HWTEST_F(HandleManagerTest, HandleManagerTest001, TestSize.Level0)
{
    ProviderInfo providerInfo;
    providerInfo.m_providerName = "test_provider";
    providerInfo.m_abilityName = "test_ability";
    providerInfo.m_bundleName = "test_bundle";
    
    std::string originalIndex = "original_index_123";
    std::string wrappedIndex;
    
    int32_t ret = WrapIndexWithProviderInfo(providerInfo, originalIndex, wrappedIndex);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_FALSE(wrappedIndex.empty());
    
    auto jsonObj = CommJsonObject::Parse(wrappedIndex);
    EXPECT_FALSE(jsonObj.IsNull());
    EXPECT_TRUE(jsonObj.HasKey(PROVIDER_NAME_KEY));
    EXPECT_TRUE(jsonObj.HasKey(ABILITY_NAME_KEY));
    EXPECT_TRUE(jsonObj.HasKey(BUNDLE_NAME_KEY));
    
    EXPECT_EQ(jsonObj[PROVIDER_NAME_KEY].ToString().second, "test_provider");
    EXPECT_EQ(jsonObj[ABILITY_NAME_KEY].ToString().second, "test_ability");
    EXPECT_EQ(jsonObj[BUNDLE_NAME_KEY].ToString().second, "test_bundle");
}

HWTEST_F(HandleManagerTest, HandleManagerTest002, TestSize.Level0)
{
    ProviderInfo providerInfo;
    providerInfo.m_providerName = "test_provider";
    providerInfo.m_abilityName = "test_ability";
    providerInfo.m_bundleName = "test_bundle";
    
    std::string originalIndex = "original_index";
    std::string wrappedIndex;
    
    int32_t ret = WrapIndexWithProviderInfo(providerInfo, originalIndex, wrappedIndex);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

HWTEST_F(HandleManagerTest, HandleManagerTest003, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager, nullptr);

    std::string wrappedIndex = R"({
        "providerName": "parse_test_provider",
        "abilityName": "parse_test_ability", 
        "bundleName": "parse_test_bundle",
        "originalIndex": "parse_original_index",
        "extraField": "extra_value"
    })";
    
    ProviderInfo providerInfo;
    std::string newIndex;
    
    int32_t ret = manager->ParseIndexAndProviderInfo(wrappedIndex, providerInfo, newIndex);
    
    EXPECT_EQ(ret, HKS_SUCCESS);
}

HWTEST_F(HandleManagerTest, HandleManagerTest004, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager, nullptr);
    
    ProviderInfo providerInfo;
    std::string newIndex;
    
    int32_t ret = manager->ParseIndexAndProviderInfo("", providerInfo, newIndex);
    EXPECT_EQ(ret, HKS_ERROR_JSON_PARSE_FAILED);
    
    ret = manager->ParseIndexAndProviderInfo("invalid json", providerInfo, newIndex);
    EXPECT_EQ(ret, HKS_ERROR_JSON_PARSE_FAILED);
    
    std::string missingFields = R"({"originalIndex": "test"})";
    ret = manager->ParseIndexAndProviderInfo(missingFields, providerInfo, newIndex);
    EXPECT_EQ(ret, HKS_ERROR_JSON_MISSING_KEY);
    
    std::string emptyProviderInfo = R"({
        "providerName": "",
        "abilityName": "test_ability", 
        "bundleName": "test_bundle"
    })";
    ret = manager->ParseIndexAndProviderInfo(emptyProviderInfo, providerInfo, newIndex);
    EXPECT_EQ(ret, HKS_ERROR_JSON_INVALID_VALUE);
}

HWTEST_F(HandleManagerTest, HandleManagerTest005, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager, nullptr);
    
    ProviderInfo providerInfo;
    providerInfo.m_providerName = "cert_provider";
    providerInfo.m_abilityName = "cert_ability";
    providerInfo.m_bundleName = "cert_bundle";
    
    std::string providerCertVec = R"([
        {
            "purpose": 1,
            "index": "cert_index_1",
            "cert": "cert_data_1"
        },
        {
            "purpose": 2,
            "index": "cert_index_2",
            "cert": "cert_data_2"
        }
    ])";
    
    CommJsonObject combinedArray = CommJsonObject::CreateArray();
    int32_t ret = manager->MergeProviderCertificates(providerInfo, providerCertVec, combinedArray);
    
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(combinedArray.ArraySize(), 2);
    
    auto cert1 = combinedArray.GetElement(0);
    auto cert2 = combinedArray.GetElement(1);
    
    EXPECT_FALSE(cert1.IsNull());
    EXPECT_FALSE(cert2.IsNull());
    
    auto index1 = cert1.GetValue("index").ToString();
    auto index2 = cert2.GetValue("index").ToString();
    
    EXPECT_EQ(index1.first, HKS_SUCCESS);
    EXPECT_EQ(index2.first, HKS_SUCCESS);
    
    auto wrappedIndex1 = CommJsonObject::Parse(index1.second);
    auto wrappedIndex2 = CommJsonObject::Parse(index2.second);
    
    EXPECT_EQ(wrappedIndex1[PROVIDER_NAME_KEY].ToString().second, "cert_provider");
    EXPECT_EQ(wrappedIndex1["index"].ToString().second, "cert_index_1");
}

HWTEST_F(HandleManagerTest, HandleManagerTest006, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager, nullptr);
    
    ProviderInfo providerInfo;
    providerInfo.m_providerName = "test_provider";
    
    CommJsonObject combinedArray = CommJsonObject::CreateArray();
    
    std::string emptyCertVec = "";
    int32_t ret = manager->MergeProviderCertificates(providerInfo, emptyCertVec, combinedArray);
    EXPECT_EQ(ret, HKS_ERROR_JSON_PARSE_FAILED);
    
    std::string invalidJson = "invalid json";
    ret = manager->MergeProviderCertificates(providerInfo, invalidJson, combinedArray);
    EXPECT_EQ(ret, HKS_ERROR_JSON_PARSE_FAILED);
    
    std::string nonArrayJson = R"({"key": "value"})";
    ret = manager->MergeProviderCertificates(providerInfo, nonArrayJson, combinedArray);
    EXPECT_EQ(ret, HKS_ERROR_JSON_PARSE_FAILED);
}


HWTEST_F(HandleManagerTest, HandleManagerTest007, TestSize.Level0)
{
    auto manager1 = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager1, nullptr);
    
    auto manager2 = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager2, nullptr);
    
    EXPECT_EQ(manager1.get(), manager2.get());
    HksRemoteHandleManager::ReleaseInstance();
    auto manager3 = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager3, nullptr);
    EXPECT_NE(manager1.get(), manager3.get());
}

HWTEST_F(HandleManagerTest, HandleManagerTest008, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager, nullptr);
    
    int32_t ret = manager->ClearRemoteHandleMap();
    EXPECT_EQ(ret, HKS_SUCCESS);
}

HWTEST_F(HandleManagerTest, HandleManagerTest009, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager, nullptr);
    
    CppParamSet testParamSet;
    
    std::string invalidIndex = "invalid_index";
    
    int32_t ret = manager->CreateRemoteHandle(invalidIndex, testParamSet);
    EXPECT_NE(ret, HKS_SUCCESS);
    
    ret = manager->CloseRemoteHandle(invalidIndex, testParamSet);
    EXPECT_NE(ret, HKS_SUCCESS);
    
    std::vector<uint8_t> inData = {0x01, 0x02, 0x03};
    std::vector<uint8_t> outData;
    ret = manager->RemoteHandleSign(invalidIndex, testParamSet, inData, outData);
    EXPECT_NE(ret, HKS_SUCCESS);
    
    std::vector<uint8_t> signature = {0x04, 0x05, 0x06};
    ret = manager->RemoteHandleVerify(invalidIndex, testParamSet, inData, signature);
    EXPECT_NE(ret, HKS_SUCCESS);
    
    std::string cert;
    ret = manager->FindRemoteCertificate(invalidIndex, testParamSet, cert);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HandleManagerTest, HandleManagerTest010, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager, nullptr);
    
    HksProcessInfo processInfo;
    std::string emptyProviderName = "";
    CppParamSet testParamSet;
    std::string certVec;
    
    int32_t ret = manager->FindRemoteAllCertificate(processInfo, emptyProviderName, testParamSet, certVec);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

HWTEST_F(HandleManagerTest, HandleManagerTest011, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager, nullptr);
    
    std::string invalidIndex = "invalid_index";
    std::string propertyId = "test_property";
    CppParamSet testParamSet;
    CppParamSet outParams;
    
    int32_t ret = manager->GetRemoteProperty(invalidIndex, propertyId, testParamSet, outParams);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(HandleManagerTest, HandleManagerTest012, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    ASSERT_NE(manager, nullptr);
    
    HksProcessInfo processInfo;
    std::string invalidIndex = "invalid_index";
    CppParamSet testParamSet;
    
    int32_t state = 0;
    int32_t ret = manager->RemoteVerifyPinStatus(processInfo, invalidIndex, testParamSet, state);
    EXPECT_NE(ret, HKS_SUCCESS);
    
    int32_t authState = 0;
    uint32_t retryCnt = 0;
    ret = manager->RemoteVerifyPin(processInfo, invalidIndex, testParamSet, authState, retryCnt);
    EXPECT_NE(ret, HKS_SUCCESS);
    
    ret = manager->RemoteClearPinStatus(invalidIndex, testParamSet);
    EXPECT_NE(ret, HKS_SUCCESS);
}

}
