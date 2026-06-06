/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <cstring>

#include "hks_client_ipc.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hks_type_enum.h"

using namespace testing::ext;
namespace Unittest::HksClientServiceIpcTest {
class HksClientServiceIpcTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksClientServiceIpcTest::SetUpTestCase(void) {}
void HksClientServiceIpcTest::TearDownTestCase(void) {}
void HksClientServiceIpcTest::SetUp() {}
void HksClientServiceIpcTest::TearDown() {}

static struct HksBlob MakeBlob(const char *str)
{
    struct HksBlob b;
    b.size = (uint32_t)strlen(str) + 1;
    b.data = (uint8_t *)str;
    return b;
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest001
 * @tc.desc: tdd HksClientRegisterProvider null name, expect error
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest001");
    int32_t ret = HksClientRegisterProvider(nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest002
 * @tc.desc: tdd HksClientRegisterProvider valid path, BuildBlobNotNull+HksAllocInBlob covered
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest002");
    struct HksBlob name = MakeBlob("testProvider");
    int32_t ret = HksClientRegisterProvider(&name, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest003
 * @tc.desc: tdd HksClientUnregisterProvider, expect error (no IPC)
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest003");
    int32_t ret = HksClientUnregisterProvider(nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);

    struct HksBlob name = MakeBlob("testProvider");
    ret = HksClientUnregisterProvider(&name, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest004
 * @tc.desc: tdd HksClientQueryAbilityInfo null resourceId, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest004");
    char bundle[] = "bundle";
    char ability[] = "ability";
    struct HksAbilityInfo abilityInfo;
    abilityInfo.bundleName = MakeBlob(bundle);
    abilityInfo.abilityName = MakeBlob(ability);
    int32_t ret = HksClientQueryAbilityInfo(nullptr, &abilityInfo);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest005
 * @tc.desc: tdd HksClientQueryAbilityInfo valid path, HksAllocInBlobWithThreeBlobs+HksBlob3Pack covered
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest005");
    uint8_t resData[64] = { 0 };
    struct HksBlob resourceId = { .size = sizeof(resData), .data = resData };
    char bundle[] = "com.test.bundle";
    char ability[] = "TestAbility";
    struct HksAbilityInfo abilityInfo;
    abilityInfo.bundleName = MakeBlob(bundle);
    abilityInfo.abilityName = MakeBlob(ability);
    int32_t ret = HksClientQueryAbilityInfo(&resourceId, &abilityInfo);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest006
 * @tc.desc: tdd HksClientExportProviderCertificates null certSet, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest006");
    int32_t ret = HksClientExportProviderCertificates(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest007
 * @tc.desc: tdd HksClientExportProviderCertificates valid certSet, BuildBlobNotNull exercised
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest007");
    struct HksExtCertInfoSet certSet = { .count = 0, .certs = nullptr };
    struct HksBlob providerName = MakeBlob("testProvider");
    int32_t ret = HksClientExportProviderCertificates(&providerName, nullptr, &certSet);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest008
 * @tc.desc: tdd HksClientExportProviderCertificates null providerName, BuildBlobNotNull null path
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest008");
    struct HksExtCertInfoSet certSet = { .count = 0, .certs = nullptr };
    int32_t ret = HksClientExportProviderCertificates(nullptr, nullptr, &certSet);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest009
 * @tc.desc: tdd HksClientExportCertificate invalid certSet, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest009");
    int32_t ret = HksClientExportCertificate(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest010
 * @tc.desc: tdd HksClientExportCertificate valid path
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest010");
    struct HksBlob index = MakeBlob("testIndex");
    struct HksExtCertInfoSet certSet = { .count = 0, .certs = nullptr };
    int32_t ret = HksClientExportCertificate(&index, nullptr, &certSet);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest011
 * @tc.desc: tdd HksClientImportCertificate null params, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest011");
    int32_t ret = HksClientImportCertificate(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest012
 * @tc.desc: tdd HksClientImportCertificate valid path, HksAllocInBlobWithCertInfo covered
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest012");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob resourceId = MakeBlob("testResourceId");
    uint8_t certData[] = "certdata";
    struct HksBlob indexBlob = MakeBlob("idx");
    struct HksBlob certBlob = { .size = sizeof(certData), .data = certData };
    struct HksExtCertInfo certInfo = { .purpose = 0, .index = indexBlob, .cert = certBlob };

    ret = HksClientImportCertificate(&resourceId, &certInfo, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest013
 * @tc.desc: tdd HksClientAuthUkeyPin null retryCount, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest013");
    int32_t ret = HksClientAuthUkeyPin(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest014
 * @tc.desc: tdd HksClientAuthUkeyPin valid path
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest014");
    struct HksBlob index = MakeBlob("testIndex");
    uint32_t retryCount = 0;
    int32_t ret = HksClientAuthUkeyPin(&index, nullptr, &retryCount);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest015
 * @tc.desc: tdd HksClientGetUkeyPinAuthState null status, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest015");
    int32_t ret = HksClientGetUkeyPinAuthState(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest016
 * @tc.desc: tdd HksClientGetUkeyPinAuthState valid path
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest016");
    struct HksBlob index = MakeBlob("testIndex");
    int32_t status = 0;
    int32_t ret = HksClientGetUkeyPinAuthState(&index, nullptr, &status);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest017
 * @tc.desc: tdd HksClientOpenRemoteHandle null params, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest017");
    int32_t ret = HksClientOpenRemoteHandle(nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest018
 * @tc.desc: tdd HksClientOpenRemoteHandle valid path
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest018");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob resourceId = MakeBlob("testResourceId");
    ret = HksClientOpenRemoteHandle(&resourceId, paramSet);
    EXPECT_NE(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest019
 * @tc.desc: tdd HksClientCloseRemoteHandle valid path
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest019");
    struct HksBlob resourceId = MakeBlob("testResourceId");
    int32_t ret = HksClientCloseRemoteHandle(&resourceId, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest020
 * @tc.desc: tdd HksClientSetOrGetRemoteProperty GET with null propertySetOut, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest020, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest020");
    int32_t ret = HksClientSetOrGetRemoteProperty(HKS_EXT_PROPERTY_OPERATION_GET,
        nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest021
 * @tc.desc: tdd HksClientSetOrGetRemoteProperty SET path, HksAllocInBlobForSetOrGetProperty covered
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest021, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest021");
    struct HksBlob resourceId = MakeBlob("testResourceId");
    struct HksBlob propertyId = MakeBlob("testPropertyId");
    int32_t ret = HksClientSetOrGetRemoteProperty(HKS_EXT_PROPERTY_OPERATION_SET,
        &resourceId, &propertyId, nullptr, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest022
 * @tc.desc: tdd HksClientClearPinAuthState null index, expect error
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest022, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest022");
    int32_t ret = HksClientClearPinAuthState(nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest023
 * @tc.desc: tdd HksClientClearPinAuthState valid path
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest023, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest023");
    struct HksBlob index = MakeBlob("testIndex");
    int32_t ret = HksClientClearPinAuthState(&index);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest024
 * @tc.desc: tdd HksClientGetResourceId null resourceId, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest024, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest024");
    int32_t ret = HksClientGetResourceId(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest025
 * @tc.desc: tdd HksClientGetResourceId resourceId->data not null, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest025, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest025");
    uint8_t data[8] = { 0 };
    struct HksBlob resourceId = { .size = sizeof(data), .data = data };
    struct HksBlob providerName = MakeBlob("testProvider");
    int32_t ret = HksClientGetResourceId(&providerName, nullptr, &resourceId);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest026
 * @tc.desc: tdd HksClientGetResourceId valid path
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest026, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest026");
    struct HksBlob resourceId = { .size = 0, .data = nullptr };
    struct HksBlob providerName = MakeBlob("testProvider");
    int32_t ret = HksClientGetResourceId(&providerName, nullptr, &resourceId);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksClientServiceIpcTest.HksClientServiceIpcTest027
 * @tc.desc: tdd HksClientSetOrGetRemoteProperty GET valid path
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceIpcTest, HksClientServiceIpcTest027, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceIpcTest027");
    struct HksBlob resourceId = MakeBlob("testResourceId");
    struct HksBlob propertyId = MakeBlob("testPropertyId");
    struct HksParamSet *propertySetOut = nullptr;
    int32_t ret = HksClientSetOrGetRemoteProperty(HKS_EXT_PROPERTY_OPERATION_GET,
        &resourceId, &propertyId, nullptr, &propertySetOut);
    EXPECT_NE(ret, HKS_SUCCESS);
}
}
