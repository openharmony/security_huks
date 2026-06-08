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
#include "hks_external_error_info.h"
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
    CppParamSet CreateTestParamSet(int32_t uid, std::string pinStr);
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
    };
    return CppParamSet(params);
}

CppParamSet HksRemoteHandleManagerTest::CreateTestParamSet(int32_t uid, std::string pinStr)
{
    std::vector<HksParam> params = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN},
        {.tag = HKS_EXT_CRYPTO_TAG_UKEY_PIN, .blob = {.size = pinStr.size(), .data = (uint8_t*)pinStr.c_str()}}
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
    struct HksExternalErrorInfo *errInfo = nullptr;

    int32_t ret = manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    ret = manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    CommJsonObject root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("testProvider")));
    EXPECT_TRUE(root.SetValue("abilityName", std::string("testAbility")));
    EXPECT_TRUE(root.SetValue("bundleName", std::string("com.teds.bundle")));
    EXPECT_TRUE(root.SetValue("userid", 100));
    EXPECT_TRUE(root.SetValue("index", std::string("testIndex3213")));
    std::string index2 = root.Serialize(false);
    ret = manager->CreateRemoteHandle(processInfo, index2, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("testProvider")));
    EXPECT_TRUE(root.SetValue("abilityName", std::string("testAbility")));
    EXPECT_TRUE(root.SetValue("bundleName", std::string("com.teds.bundle")));
    EXPECT_TRUE(root.SetValue("userid", 100));
    EXPECT_TRUE(root.SetValue("index", std::string("testIndexsf123")));
    std::string index3 = root.Serialize(false);
    ret = manager->CreateRemoteHandle(processInfo, index3, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("testProvider")));
    EXPECT_TRUE(root.SetValue("abilityName", std::string("testAbility")));
    EXPECT_TRUE(root.SetValue("bundleName", std::string("com.teds.bundle")));
    EXPECT_TRUE(root.SetValue("userid", 100));
    EXPECT_TRUE(root.SetValue("index", std::string("tes2424")));
    std::string index4 = root.Serialize(false);
    ret = manager->CreateRemoteHandle(processInfo, index4, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    ret = manager->CloseRemoteHandle(processInfo, index4, paramSet, &errInfo);
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
    struct HksExternalErrorInfo *errInfo = nullptr;
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);
    // Test with empty index
    int32_t ret = manager->CreateRemoteHandle(processInfo, "", paramSet, &errInfo);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with invalid JSON index
    ret = manager->CreateRemoteHandle(processInfo, "invalid_json_string", paramSet, &errInfo);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with missing required fields
    CommJsonObject root = CommJsonObject::CreateObject();
    EXPECT_TRUE(root.SetValue("providerName", std::string("testProvider")));
    // Missing abilityName and bundleName
    std::string invalidIndex = root.Serialize(false);
    ret = manager->CreateRemoteHandle(processInfo, invalidIndex, paramSet, &errInfo);
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
    struct HksExternalErrorInfo *errInfo = nullptr;

    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);
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
    struct HksExternalErrorInfo *errInfo = nullptr;
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    int32_t state = 1;
    ret = manager->RemoteVerifyPinStatus(processInfo, index, paramSet, state, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    manager->ClearAuthState(processInfo);
    manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);
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
    struct HksExternalErrorInfo *errInfo = nullptr;

    // Test find certificate
    std::string certificates;
    int32_t ret = manager->FindRemoteCertificate(processInfo, index, paramSet, certificates, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_FALSE(certificates.empty());

    // Test find all certificates
    std::string allCertificates;
    ret = manager->FindRemoteAllCertificate(processInfo, "testProvider", paramSet, allCertificates, &errInfo);
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
    struct HksExternalErrorInfo *errInfo = nullptr;

    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test get property with valid property ID
    CppParamSet getPropertyParamSet = CreateTestParamSet();
    struct HksProcessWithErrorInfo processAndError = {&processInfo, nullptr};
    ret = manager->SetOrGetRemoteProperty(processAndError, HKS_EXT_PROPERTY_OPERATION_GET,
        index, "SKF_GetDevInfo", getPropertyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test set property
    CppParamSet setPropertyParamSet = CreateTestParamSet();
    ret = manager->SetOrGetRemoteProperty(processAndError, HKS_EXT_PROPERTY_OPERATION_SET,
        index, "SKF_SetDevInfo", setPropertyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Cleanup
    manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);
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
    struct HksExternalErrorInfo *errInfo = nullptr;

    manager->CreateRemoteHandle(processInfo, index1, paramSet, &errInfo);
    manager->CreateRemoteHandle(processInfo, index2, paramSet, &errInfo);
    manager->CreateRemoteHandle(processInfo, index3, paramSet, &errInfo);

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
    struct HksExternalErrorInfo *errInfo = nullptr;

    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test import wrapped key with valid data
    std::vector<uint8_t> wrappedData = {0x01, 0x02, 0x03, 0x04};
    struct HksProcessWithErrorInfo processAndError = {&processInfo, nullptr};
    ret = manager->RemoteImportWrappedKey(processAndError, index, wrappingKeyIndex, paramSet, wrappedData);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST);

    ret = manager->RemoteImportWrappedKey(processAndError, index, index, paramSet, wrappedData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Cleanup
    manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);
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
    struct HksProcessWithErrorInfo processAndError = {&processInfo, nullptr};
    int32_t ret = manager->RemoteImportWrappedKey(processAndError, "", wrappingKeyIndex, paramSet, wrappedData);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with invalid JSON index
    ret = manager->RemoteImportWrappedKey(processAndError, "invalid_json", wrappingKeyIndex, paramSet, wrappedData);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with empty wrapping key index
    ret = manager->RemoteImportWrappedKey(processAndError, CreateTestIndex(), "", paramSet, wrappedData);
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
    struct HksExternalErrorInfo *errInfo = nullptr;

    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test export public key
    std::vector<uint8_t> outData;
    struct HksProcessWithErrorInfo processAndError = {&processInfo, nullptr};
    ret = manager->RemoteExportPublicKey(processAndError, index, paramSet, outData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Cleanup
    manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);
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

    struct HksProcessWithErrorInfo processAndError = {&processInfo, nullptr};

    // Test with empty index
    int32_t ret = manager->RemoteExportPublicKey(processAndError, "", paramSet, outData);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with invalid JSON index
    ret = manager->RemoteExportPublicKey(processAndError, "invalid_json_string", paramSet, outData);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with index that has no handle
    std::string noHandleIndex = CreateTestIndex("noHandleProvider", "noHandleAbility", "nobundle", "noHandleIndex");
    ret = manager->RemoteExportPublicKey(processAndError, noHandleIndex, paramSet, outData);
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
    struct HksExternalErrorInfo *errInfo = nullptr;

    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Test generate key
    struct HksProcessWithErrorInfo processAndError = { &processInfo, nullptr };
    ret = manager->ExtensionGenerateKey(processAndError, index, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Cleanup
    manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);
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

    struct HksProcessWithErrorInfo processAndError = { &processInfo, nullptr };
    // Test with empty index
    int32_t ret = manager->ExtensionGenerateKey(processAndError, "", paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with invalid JSON index
    ret = manager->ExtensionGenerateKey(processAndError, "invalid_json_string", paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with index that has no handle
    std::string noHandleIndex = CreateTestIndex("noHandleProvider", "noHandleAbility", "nobundle", "noHandleIndex");
    ret = manager->ExtensionGenerateKey(processAndError, noHandleIndex, paramSet);
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
    struct HksExternalErrorInfo *errInfo = nullptr;

    // Create handle first
    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // Prepare certificate info
    HksExtCertInfo certInfo = {};
    certInfo.purpose = 1;
    
    // Create index blob
    std::string certIndex = "test_cert_index";
    certInfo.index = StringToBlob(certIndex);
    
    // Create certificate data blob
    std::string certData = "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----";
    certInfo.cert = StringToBlob(certData);

    // Test import certificate
    ret = manager->ImportRemoteCertificate(processInfo, index, certInfo, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
    HKS_FREE_BLOB(certInfo.index);
    HKS_FREE_BLOB(certInfo.cert);

    // Cleanup
    manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);
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
    struct HksExternalErrorInfo *errInfo = nullptr;

    // Test with empty index
    HksExtCertInfo certInfo = {};
    certInfo.purpose = 1;
    
    int32_t ret = manager->ImportRemoteCertificate(processInfo, "", certInfo, paramSet, &errInfo);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with invalid JSON index
    ret = manager->ImportRemoteCertificate(processInfo, "invalid_json", certInfo, paramSet, &errInfo);
    EXPECT_NE(ret, HKS_SUCCESS);

    // Test with index that has no handle
    std::string noHandleIndex = CreateTestIndex("noHandleProvider", "noHandleAbility", "nobundle", "noHandleIndex");
    ret = manager->ImportRemoteCertificate(processInfo, noHandleIndex, certInfo, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksExtCertInfo emptyCertInfo = {};
    emptyCertInfo.purpose = 1;
    
    std::string validIndex = CreateTestIndex();
    ret = manager->ImportRemoteCertificate(processInfo, validIndex, emptyCertInfo, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    
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

    std::string index = CreateTestIndex("provider3", "ability2", "bundle1", "index1");
    HksProcessInfo processInfo = CreateTestProcessInfo();
    CppParamSet paramSet = CreateTestParamSet(processInfo.uidInt);
    struct HksExternalErrorInfo *errInfo = nullptr;

    int32_t ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    manager->ClearMapByHandle(HUKS_ERR_CODE_CRYPTO_FAIL, "non_exist_handle");
    manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);

    ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    manager->ClearMapByHandle(HUKS_ERR_CODE_ITEM_NOT_EXIST, "non_exist_handle");
    manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);

    ret = manager->CreateRemoteHandle(processInfo, index, paramSet, &errInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    manager->ClearMapByHandle(HKS_SUCCESS, "non_exist_handle");
    manager->CloseRemoteHandle(processInfo, index, paramSet, &errInfo);

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
    struct HksExternalErrorInfo *errInfo = nullptr;

    int32_t ret1 = manager->CreateRemoteHandle(processInfo, index1, paramSet, &errInfo);
    EXPECT_EQ(ret1, HKS_SUCCESS);
    int32_t ret2 = manager->CreateRemoteHandle(processInfo, index2, paramSet, &errInfo);
    EXPECT_EQ(ret2, HKS_SUCCESS);

    manager->ClearMapByUid(999999);
    manager->ClearMapByUid(0);
    manager->ClearMapByUid(processInfo.uidInt);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

/**
 * @tc.name: HksRemoteHandleManagerTest.GenerateResourceIdTest
 * @tc.desc: Cover GenerateResourceId and WrapIndexWithProviderInfo branches
 * @tc.type: FUNC
 */
HWTEST_F(HksRemoteHandleManagerTest, GenerateResourceIdTest, TestSize.Level0)
{
    ProviderInfo providerInfo{"testProvider", "testAbility", "com.test.bundle", 100};

    /* normal path: covers WrapIndexWithProviderInfo success */
    std::string resourceId;
    int32_t ret = GenerateResourceId("short_index", providerInfo, resourceId);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_FALSE(resourceId.empty());

    /* index too long: covers the early return branch */
    std::string longIndex(MAX_INDEX_SIZE + 1, 'a');
    std::string resourceId2;
    ret = GenerateResourceId(longIndex, providerInfo, resourceId2);
    EXPECT_EQ(ret, HKS_ERROR_NEW_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksRemoteHandleManagerTest.GetResourceIdParamValidationTest
 * @tc.desc: Cover GetResourceId parameter validation branches (lines 604-620)
 * @tc.type: FUNC
 */
HWTEST_F(HksRemoteHandleManagerTest, GetResourceIdParamValidationTest, TestSize.Level0)
{
    auto manager = HksRemoteHandleManager::GetInstanceWrapper();
    EXPECT_NE(manager, nullptr);

    HksProcessInfo processInfo = CreateTestProcessInfo();
    std::string resourceId;
    struct HksExternalErrorInfo *errInfo = nullptr;

    std::string abilityName = "testAbility";
    std::string bundleName = "com.test.bundle";
    std::string resourceInfo = "resource_info";

    /* empty providerName */
    std::vector<HksParam> validParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(abilityName)},
        {.tag = HKS_EXT_CRYPTO_TAG_BUNDLE_NAME, .blob = StringToBlob(bundleName)},
        {.tag = HKS_EXT_CRYPTO_TAG_RESOURCE_INFO, .blob = StringToBlob(resourceInfo)},
    };
    CppParamSet validSet(validParams);
    EXPECT_EQ(manager->GetResourceId(processInfo, "", validSet, resourceId, &errInfo), HKS_ERROR_INVALID_ARGUMENT);

    /* missing abilityName */
    std::vector<HksParam> noAbilityParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_BUNDLE_NAME, .blob = StringToBlob(bundleName)},
        {.tag = HKS_EXT_CRYPTO_TAG_RESOURCE_INFO, .blob = StringToBlob(resourceInfo)},
    };
    CppParamSet noAbilitySet(noAbilityParams);
    EXPECT_EQ(manager->GetResourceId(processInfo, "testProvider", noAbilitySet, resourceId, &errInfo),
        HKS_ERROR_ABILITY_NAME_MISSING);

    /* abilityName too long */
    std::string longAbilityName(MAX_ABILITY_NAME_LEN, 'a');
    std::vector<HksParam> longAbilityParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(longAbilityName)},
        {.tag = HKS_EXT_CRYPTO_TAG_BUNDLE_NAME, .blob = StringToBlob(bundleName)},
        {.tag = HKS_EXT_CRYPTO_TAG_RESOURCE_INFO, .blob = StringToBlob(resourceInfo)},
    };
    CppParamSet longAbilitySet(longAbilityParams);
    EXPECT_EQ(manager->GetResourceId(processInfo, "testProvider", longAbilitySet, resourceId, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    /* missing bundleName */
    std::vector<HksParam> noBundleParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(abilityName)},
        {.tag = HKS_EXT_CRYPTO_TAG_RESOURCE_INFO, .blob = StringToBlob(resourceInfo)},
    };
    CppParamSet noBundleSet(noBundleParams);
    EXPECT_EQ(manager->GetResourceId(processInfo, "testProvider", noBundleSet, resourceId, &errInfo),
        HKS_ERROR_BUNDLE_NAME_MISSING);

    /* bundleName too short */
    std::vector<HksParam> shortBundleParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(abilityName)},
        {.tag = HKS_EXT_CRYPTO_TAG_BUNDLE_NAME, .blob = StringToBlob("ab")},
        {.tag = HKS_EXT_CRYPTO_TAG_RESOURCE_INFO, .blob = StringToBlob(resourceInfo)},
    };
    CppParamSet shortBundleSet(shortBundleParams);
    EXPECT_EQ(manager->GetResourceId(processInfo, "testProvider", shortBundleSet, resourceId, &errInfo),
        HKS_ERROR_INVALID_ARGUMENT);

    /* missing resourceInfo */
    std::vector<HksParam> noResourceParams = {
        {.tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME, .blob = StringToBlob(abilityName)},
        {.tag = HKS_EXT_CRYPTO_TAG_BUNDLE_NAME, .blob = StringToBlob(bundleName)},
    };
    CppParamSet noResourceSet(noResourceParams);
    EXPECT_EQ(manager->GetResourceId(processInfo, "testProvider", noResourceSet, resourceId, &errInfo),
        HKS_ERROR_RESOURCE_INFO_MISSING);

    /* valid params but no provider registered: covers GetProviderProxy failure */
    EXPECT_NE(manager->GetResourceId(processInfo, "noSuchProvider", validSet, resourceId, &errInfo), HKS_SUCCESS);

    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(processInfo.processName);
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
