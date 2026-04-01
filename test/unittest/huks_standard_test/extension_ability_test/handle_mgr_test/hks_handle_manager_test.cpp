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

#include "hks_remote_handle_manager.h"
#include "hks_cpp_paramset.h"
#include "hks_mem.h"
#include "hks_plugin_def.h"
#include "hks_log.h"
#include "hks_mock_common.h"
#include "hks_type.h"
#include "hks_json_wrapper.h"
#include "gtest/gtest.h"
#include "../../../../../services/huks_standard/huks_service/extension/ukey/handle_manager/src/hks_remote_handle_manager.cpp"
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace Huks {

class HksRemoteHandleManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

protected:
    std::string CreateTestIndex(const std::string& providerName = "testProvider", 
                               const std::string& abilityName = "testAbility",
                               const std::string& bundleName = "com.test.bundle",
                               const std::string& originalIndex = "testIndex123");
    CppParamSet CreateTestParamSet(int32_t uid);
    CppParamSet CreateTestParamSet();
    HksProcessInfo CreateTestProcessInfo();
};

void HksRemoteHandleManagerTest::SetUpTestCase(void)
{
}

void HksRemoteHandleManagerTest::TearDownTestCase(void)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    if (manager) {
        manager->ReleaseInstance();
    }
}

void HksRemoteHandleManagerTest::SetUp()
{
}

void HksRemoteHandleManagerTest::TearDown()
{
}

std::string HksRemoteHandleManagerTest::CreateTestIndex(const std::string& providerName,
                                                       const std::string& abilityName,
                                                       const std::string& bundleName,
                                                       const std::string& originalIndex)
{
    CommJsonObject root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", providerName));
    EXPECT_TRUE(root.SetValue("abilityName", abilityName));
    EXPECT_TRUE(root.SetValue("bundleName", bundleName));
    EXPECT_TRUE(root.SetValue("userid", 100));
    EXPECT_TRUE(root.SetValue("index", originalIndex));
    return root.Serialize(false);
}

CppParamSet HksRemoteHandleManagerTest::CreateTestParamSet(int32_t uid)
{
    std::vector<HksParam> params = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN},
        {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = uid}
    };
    return CppParamSet(params);
}

CppParamSet HksRemoteHandleManagerTest::CreateTestParamSet()
{
    std::vector<HksParam> params = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN},
    };
    return CppParamSet(params);
}

HksProcessInfo HksRemoteHandleManagerTest::CreateTestProcessInfo()
{
    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);
    return processInfo;
}

/**
 * @tc.name: HksRemoteHandleManagerTest.CreateCloseRemoteHandleTest
 * @tc.desc: Test create and close remote handle
 * @tc.type: FUNC
 */
HWTEST_F(HksRemoteHandleManagerTest, CreateCloseRemoteHandleTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex();
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    int32_t ret = manager->CloseRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    ret = manager->CloseRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    CommJsonObject root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("testProvider")));
    EXPECT_TRUE(root.SetValue("abilityName", std::string("testAbility")));
    EXPECT_TRUE(root.SetValue("bundleName", std::string("com.teds.bundle")));
    EXPECT_TRUE(root.SetValue("userid", 100));
    EXPECT_TRUE(root.SetValue("index", std::string("testIndex3213")));
    std::string index2 = root.Serialize(false);
    ret = manager->CreateRemoteHandle(processInfo, index2, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("testProvider")));
    EXPECT_TRUE(root.SetValue("abilityName", std::string("testAbility")));
    EXPECT_TRUE(root.SetValue("bundleName", std::string("com.teds.bundle")));
    EXPECT_TRUE(root.SetValue("userid", 100));
    EXPECT_TRUE(root.SetValue("index", std::string("testIndexsf123")));
    std::string index3 = root.Serialize(false);
    ret = manager->CreateRemoteHandle(processInfo, index3, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("testProvider")));
    EXPECT_TRUE(root.SetValue("abilityName", std::string("testAbility")));
    EXPECT_TRUE(root.SetValue("bundleName", std::string("com.teds.bundle")));
    EXPECT_TRUE(root.SetValue("userid", 100));
    EXPECT_TRUE(root.SetValue("index", std::string("tes2424")));
    std::string index4 = root.Serialize(false);
    ret = manager->CreateRemoteHandle(processInfo, index4, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    int32_t authState = 1;
    uint32_t retryCnt = 0;
    ret = manager->RemoteVerifyPin(processInfo, index4, paramSet, authState, retryCnt);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    ret = manager->CloseRemoteHandle(processInfo, index4, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
 * @tc.name: HksRemoteHandleManagerTest.CreateRemoteHandleWithInvalidIndex
 * @tc.desc: Test create remote handle with invalid index
 * @tc.type: FUNC
 */
HWTEST_F(HksRemoteHandleManagerTest, CreateRemoteHandleWithInvalidIndex, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);
    HksProcessInfo processInfo = CreateTestProcessInfo();
    // Test with empty index
    int32_t ret = manager->CreateRemoteHandle(processInfo, "", CreateTestParamSet(processInfo.uidInt));
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with invalid JSON index
    ret = manager->CreateRemoteHandle(processInfo, "invalid_json_string", CreateTestParamSet(processInfo.uidInt));
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with missing required fields
    CommJsonObject root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("testProvider")));
    // Missing abilityName and bundleName
    std::string invalidIndex = root.Serialize(false);
    ret = manager->CreateRemoteHandle(processInfo, invalidIndex, CreateTestParamSet(processInfo.uidInt));
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksRemoteHandleManagerTest.SignVerifyTest
 * @tc.desc: Test remote sign and verify operations
 * @tc.type: FUNC
 */
HWTEST_F(HksRemoteHandleManagerTest, SignVerifyTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex();
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    manager->CloseRemoteHandle(processInfo, index, paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
 * @tc.name: HksRemoteHandleManagerTest.PinManagementTest
 * @tc.desc: Test PIN management operations
 * @tc.type: FUNC
 */
HWTEST_F(HksRemoteHandleManagerTest, PinManagementTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex();
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);
    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test verify PIN
    int32_t authState = 1;
    uint32_t retryCnt = 0;
    ret = manager->RemoteVerifyPin(processInfo, index, paramSet, authState, retryCnt);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    int32_t state = 1;
    ret = manager->RemoteVerifyPinStatus(processInfo, index, paramSet, state);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    ret = manager->RemoteClearPinStatus(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    int32_t authOk = manager->CheckAuthStateIsOk(processInfo, index);
    EXPECT_NE(authOk, HKS_SUCCESS);

    manager->ClearAuthState(processInfo);
    manager->CloseRemoteHandle(processInfo, index, paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
 * @tc.name: HksRemoteHandleManagerTest.ClearPinStateTest
 * @tc.desc: Test PIN management operations
 * @tc.type: FUNC
 */
HWTEST_F(HksRemoteHandleManagerTest, ClearPinStateTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex();
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet();
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    int32_t state = 1;
    ret = manager->RemoteVerifyPinStatus(processInfo, index, paramSet, state);
    EXPECT_EQ(ret, HKS_SUCCESS);

    manager->ClearAuthState(processInfo);
    manager->CloseRemoteHandle(processInfo, index, paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
 * @tc.name: HksRemoteHandleManagerTest.CertificateTest
 * @tc.desc: Test certificate operations
 * @tc.type: FUNC
 */
HWTEST_F(HksRemoteHandleManagerTest, CertificateTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex();
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    // Test find certificate
    std::string certificates;
    int32_t ret = manager->FindRemoteCertificate(processInfo, index, paramSet, certificates);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_FALSE(certificates.empty());

    // Test find all certificates
    std::string allCertificates;
    ret = manager->FindRemoteAllCertificate(processInfo, "testProvider", paramSet, allCertificates);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_FALSE(allCertificates.empty());

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
 * @tc.name: HksRemoteHandleManagerTest.PropertyTest
 * @tc.desc: Test property operations
 * @tc.type: FUNC
 */
HWTEST_F(HksRemoteHandleManagerTest, PropertyTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex();
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet();

    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test get property with valid property ID
    CppParamSet outParams;
    ret = manager->GetRemoteProperty(processInfo, index, "SKF_GetDevInfo", paramSet, outParams);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    // Test get property with invalid property ID
    ret = manager->GetRemoteProperty(processInfo, index, "INVALID_PROPERTY", paramSet, outParams);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Cleanup
    manager->CloseRemoteHandle(processInfo, index, paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
 * @tc.name: HksRemoteHandleManagerTest.ClearHandleMapTest
 * @tc.desc: Test clear remote handle map
 * @tc.type: FUNC
 */
HWTEST_F(HksRemoteHandleManagerTest, ClearHandleMapTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    // Create multiple handles
    std::string index1 = CreateTestIndex("provider1", "ability1", "bundle1", "index1");
    std::string index2 = CreateTestIndex("provider1", "ability2", "bundle1", "index2");
    std::string index3 = CreateTestIndex("provider2", "ability1", "bundle2", "index3");
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    manager->CreateRemoteHandle(processInfo, index1, paramSet);
    manager->CreateRemoteHandle(processInfo, index2, paramSet);
    manager->CreateRemoteHandle(processInfo, index3, paramSet);

 // Test clear by provider name
    ProviderInfo providerInfo1{"provider1", "", "bundle1", 100};
    int32_t ret = manager->ClearUidIndexMap(providerInfo1);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test clear by provider name and ability name
    ProviderInfo providerInfo2{"provider2", "", "bundle2", 100};
    ret = manager->ClearUidIndexMap(providerInfo2);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
* @tc.name: HksRemoteHandleManagerTest.ImportWrappedKeyTest
* @tc.desc: Test import wrapped key operation
* @tc.type: FUNC
*/
HWTEST_F(HksRemoteHandleManagerTest, ImportWrappedKeyTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex();
    std::string wrappingKeyIndex = CreateTestIndex("wrapProvider", "wrapAbility", "wrap.bundle", "wrapIndex");
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test import wrapped key with valid data
    std::vector<uint8_t> wrappedData = {0x01, 0x02, 0x03, 0x04};
    ret = manager->RemoteImportWrappedKey(processInfo, index, wrappingKeyIndex, paramSet, wrappedData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Cleanup
    manager->CloseRemoteHandle(processInfo, index, paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksRemoteHandleManagerTest.ImportWrappedKeyWithInvalidIndexTest
* @tc.desc: Test import wrapped key with invalid index
* @tc.type: FUNC
*/
HWTEST_F(HksRemoteHandleManagerTest, ImportWrappedKeyWithInvalidIndexTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    // Test with empty index
    std::string wrappingKeyIndex = CreateTestIndex();
    std::vector<uint8_t> wrappedData = {0x01, 0x02};
    int32_t ret = manager->RemoteImportWrappedKey(processInfo, "", wrappingKeyIndex, paramSet, wrappedData);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with invalid JSON index
    ret = manager->RemoteImportWrappedKey(processInfo, "invalid_json", wrappingKeyIndex, paramSet, wrappedData);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with empty wrapping key index
    ret = manager->RemoteImportWrappedKey(processInfo, CreateTestIndex(), "", paramSet, wrappedData);
    EXPECT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksRemoteHandleManagerTest.ExportPublicKeyTest
* @tc.desc: Test export public key operation
* @tc.type: FUNC
*/
HWTEST_F(HksRemoteHandleManagerTest, ExportPublicKeyTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex();
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test export public key
    std::vector<uint8_t> outData;
    ret = manager->RemoteExportPublicKey(processInfo, index, paramSet, outData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Cleanup
    manager->CloseRemoteHandle(processInfo, index, paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksRemoteHandleManagerTest.ExportPublicKeyWithInvalidIndexTest
* @tc.desc: Test export public key with invalid index
* @tc.type: FUNC
*/
HWTEST_F(HksRemoteHandleManagerTest, ExportPublicKeyWithInvalidIndexTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);
    std::vector<uint8_t> outData;

    // Test with empty index
    int32_t ret = manager->RemoteExportPublicKey(processInfo, "", paramSet, outData);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with invalid JSON index
    ret = manager->RemoteExportPublicKey(processInfo, "invalid_json_string", paramSet, outData);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with index that has no handle
    std::string noHandleIndex = CreateTestIndex("noHandleProvider", "noHandleAbility", "nobundle", "noHandleIndex");
    ret = manager->RemoteExportPublicKey(processInfo, noHandleIndex, paramSet, outData);
    EXPECT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksRemoteHandleManagerTest.GenerateKeyTest
* @tc.desc: Test generate key operation
* @tc.type: FUNC
*/
HWTEST_F(HksRemoteHandleManagerTest, GenerateKeyTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex();
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test generate key
    ret = manager->ExtensionGenerateKey(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Cleanup
    manager->CloseRemoteHandle(processInfo, index, paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksRemoteHandleManagerTest.GenerateKeyWithInvalidIndexTest
* @tc.desc: Test generate key with invalid index
* @tc.type: FUNC
*/
HWTEST_F(HksRemoteHandleManagerTest, GenerateKeyWithInvalidIndexTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    // Test with empty index
    int32_t ret = manager->ExtensionGenerateKey(processInfo, "", paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with invalid JSON index
    ret = manager->ExtensionGenerateKey(processInfo, "invalid_json_string", paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with index that has no handle
    std::string noHandleIndex = CreateTestIndex("noHandleProvider", "noHandleAbility", "nobundle", "noHandleIndex");
    ret = manager->ExtensionGenerateKey(processInfo, noHandleIndex, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksRemoteHandleManagerTest.ImportRemoteCertificateTest
* @tc.desc: Test ImportRemoteCertificate function
* @tc.type: FUNC
*/
HWTEST_F(HksRemoteHandleManagerTest, ImportRemoteCertificateTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex();
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Prepare certificate info
    HksExtCertInfo certInfo = {};
    certInfo.purpose = 1; // Example purpose
    
    // Create index blob
    std::string certIndex = "test_cert_index";
    certInfo.index = StringToBlob(certIndex);
    
    // Create certificate data blob
    std::string certData = "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----";
    certInfo.cert = StringToBlob(certData);

    // Test import certificate
    ret = manager->ImportRemoteCertificate(processInfo, index, certInfo, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    HKS_FREE_BLOB(certInfo.index.data);
    HKS_FREE_BLOB(certInfo.cert.data);

    // Cleanup
    manager->CloseRemoteHandle(processInfo, index, paramSet);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksRemoteHandleManagerTest.ImportRemoteCertificateWithInvalidParamsTest
* @tc.desc: Test ImportRemoteCertificate function with invalid parameters
* @tc.type: FUNC
*/
HWTEST_F(HksRemoteHandleManagerTest, ImportRemoteCertificateWithInvalidParamsTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    // Test with empty index
    HksExtCertInfo certInfo = {};
    certInfo.purpose = 1;
    
    int32_t ret = manager->ImportRemoteCertificate(processInfo, "", certInfo, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with invalid JSON index
    ret = manager->ImportRemoteCertificate(processInfo, "invalid_json", certInfo, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with index that has no handle
    std::string noHandleIndex = CreateTestIndex("noHandleProvider", "noHandleAbility", "nobundle", "noHandleIndex");
    ret = manager->ImportRemoteCertificate(processInfo, noHandleIndex, certInfo, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksExtCertInfo emptyCertInfo = {};
    emptyCertInfo.purpose = 1;
    
    std::string validIndex = CreateTestIndex();
    ret = manager->ImportRemoteCertificate(processInfo, validIndex, emptyCertInfo, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);
    
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksRemoteHandleManagerTest.ClearMapByHandleTest
* @tc.desc: Test ClearMapByHandle function
* @tc.type: FUNC
*/
HWTEST_F(HksRemoteHandleManagerTest, ClearMapByHandleTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index = CreateTestIndex("provider1", "ability1", "bundle1", "index1");
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    manager->ClearMapByHandle(HUKS_ERR_CODE_CRYPTO_FAIL, "non_exist_handle");
    manager->CloseRemoteHandle(processInfo, index, paramSet);

    ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    manager->ClearMapByHandle(HUKS_ERR_CODE_ITEM_NOT_EXIST, "non_exist_handle");
    manager->CloseRemoteHandle(processInfo, index, paramSet);

    ret = manager->CreateRemoteHandle(processInfo, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    manager->ClearMapByHandle(HKS_SUCCESS, "non_exist_handle");
    manager->CloseRemoteHandle(processInfo, index, paramSet);

    manager->ClearMapByHandle(HUKS_ERR_CODE_CRYPTO_FAIL, "");

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
* @tc.name: HksRemoteHandleManagerTest.ClearMapByUidTest
* @tc.desc: Test ClearMapByUid function
* @tc.type: FUNC
*/
HWTEST_F(HksRemoteHandleManagerTest, ClearMapByUidTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    std::string index1 = CreateTestIndex("providerA", "ability1", "bundleA", "index1");
    std::string index2 = CreateTestIndex("providerA", "ability2", "bundleA", "index2");
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);

    int32_t ret1 = manager->CreateRemoteHandle(processInfo, index1, paramSet);
    EXPECT_EQ(ret1, HKS_SUCCESS);
    int32_t ret2 = manager->CreateRemoteHandle(processInfo, index2, paramSet);
    EXPECT_EQ(ret2, HKS_SUCCESS);

    manager->ClearMapByUid(999999);
    manager->ClearMapByUid(0);
    manager->ClearMapByUid(processInfo.uidInt);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
