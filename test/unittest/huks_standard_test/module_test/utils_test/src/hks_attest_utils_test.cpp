/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dcm_attest.h"
#include "hks_attest_utils_test.h"

#include "file_ex.h"
#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>

#include "dcm_attest_utils.h"
#include "hks_log.h"
#include "hks_type.h"

using namespace testing::ext;
namespace Unittest::HksAttestUtilsTest {
class HksAttestUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAttestUtilsTest::SetUpTestCase(void)
{
}

void HksAttestUtilsTest::TearDownTestCase(void)
{
}

void HksAttestUtilsTest::SetUp()
{
}

void HksAttestUtilsTest::TearDown()
{
}

/**
 * @tc.name: HksAttestUtilsTest.HksAttestUtilsTest001
 * @tc.desc: tdd DcmInsertClaim, with nullptr input, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestUtilsTest, HksAttestUtilsTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestUtilsTest001");
    uint8_t buffer[1] = { 0 };
    struct HksBlob key = { 1, buffer };
    struct HksBlob oid = { 1, buffer };
    struct HksAsn1Blob fakeBlob = { 0, 1, buffer };
    int32_t ret = DcmInsertClaim(&key, nullptr, &fakeBlob, HKS_SECURITY_LEVEL_LOW);
    ret = DcmInsertClaim(nullptr, &oid, &fakeBlob, HKS_SECURITY_LEVEL_LOW);
    ret = DcmInsertClaim(&key, &oid, nullptr, HKS_SECURITY_LEVEL_LOW);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAttestUtilsTest001 failed, ret = " << ret;
}

/**
 * @tc.name: HksAttestUtilsTest.HksAttestUtilsTest002
 * @tc.desc: tdd DcmInsertClaim, with error data size, expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestUtilsTest, HksAttestUtilsTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestUtilsTest002");
    uint8_t buffer[1] = { 0 };
    struct HksBlob key = { 1, buffer };
    struct HksBlob oid = { 1, buffer };
    struct HksAsn1Blob fakeBlob = { 0, 1, buffer };
    int32_t ret = DcmInsertClaim(&key, &oid, &fakeBlob, HKS_SECURITY_LEVEL_LOW);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL) << "HksAttestUtilsTest002 failed, ret = " << ret;
}

/**
 * @tc.name: HksAttestUtilsTest.HksAttestUtilsTest003
 * @tc.desc: tdd DcmGetPublicKey, with null input, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestUtilsTest, HksAttestUtilsTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestUtilsTest003");
    uint8_t buffer[1] = { 0 };
    struct HksBlob key = { 1, buffer };
    struct HksPubKeyInfo info = { HKS_ALG_RSA, 0, 0, 0, 0};
    struct HksUsageSpec usageSpec = { .algType = HKS_ALG_RSA, .mode = 0xffff };
    int32_t ret = DcmGetPublicKey(nullptr, &info, &usageSpec);
    ret = DcmGetPublicKey(&key, nullptr, &usageSpec);
    ret = DcmGetPublicKey(&key, &info, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAttestUtilsTest003 failed, ret = " << ret;
}

/**
 * @tc.name: HksAttestUtilsTest.HksAttestUtilsTest004
 * @tc.desc: tdd DcmGetPublicKey, with error alg type, expect HKS_ERROR_NOT_SUPPORTED
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestUtilsTest, HksAttestUtilsTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestUtilsTest004");
    uint8_t buffer[1] = { 0 };
    struct HksBlob key = { 1, buffer };
    struct HksPubKeyInfo info = { HKS_ALG_AES, 0, 0, 0, 0};
    struct HksUsageSpec usageSpec = { .algType = HKS_ALG_AES, .mode = 0xffff };
    int32_t ret = DcmGetPublicKey(&key, &info, &usageSpec);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksAttestUtilsTest004 failed, ret = " << ret;
}

/**
 * @tc.name: HksAttestUtilsTest.HksAttestUtilsTest005
 * @tc.desc: tdd DcmGetPublicKey, with small key size in X25519, expect HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestUtilsTest, HksAttestUtilsTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestUtilsTest005");
    uint8_t buffer[ASN_1_MAX_HEADER_LEN + 1] = { 0 };
    struct HksBlob key = { ASN_1_MAX_HEADER_LEN + 1, buffer };
    struct HksPubKeyInfo info = { HKS_ALG_X25519, 0, 0, 0, 0};
    struct HksUsageSpec usageSpec = { .algType = HKS_ALG_X25519, .mode = 0xffff };
    int32_t ret = DcmGetPublicKey(&key, &info, &usageSpec);
    EXPECT_EQ(ret, HKS_ERROR_INSUFFICIENT_MEMORY) << "HksAttestUtilsTest005 failed, ret = " << ret;
}

/**
 * @tc.name: HksAttestUtilsTest.HksAttestUtilsTest006
 * @tc.desc: tdd DcmGetPublicKey, with small key size in RSA, expect HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestUtilsTest, HksAttestUtilsTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestUtilsTest006");
    uint8_t buffer[ASN_1_MAX_HEADER_LEN + 1] = { 0 };
    struct HksBlob key = { ASN_1_MAX_HEADER_LEN + 1, buffer };
    struct HksPubKeyInfo info = { HKS_ALG_RSA, 0, 0, 0, 0};
    struct HksUsageSpec usageSpec = { .algType = HKS_ALG_RSA, .mode = 0xffff };
    int32_t ret = DcmGetPublicKey(&key, &info, &usageSpec);
    EXPECT_EQ(ret, HKS_ERROR_INSUFFICIENT_MEMORY) << "HksAttestUtilsTest006 failed, ret = " << ret;
}

/**
 * @tc.name: HksAttestUtilsTest.HksAttestUtilsTest007
 * @tc.desc: tdd DcmGetPublicKey, with wrong key size for ECC, expect HKS_ERROR_NOT_SUPPORTED
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestUtilsTest, HksAttestUtilsTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestUtilsTest007");
    uint8_t buffer[ASN_1_MAX_HEADER_LEN + 1] = { 0 };
    struct HksBlob key = { ASN_1_MAX_HEADER_LEN + 1, buffer };
    struct HksPubKeyInfo info = { HKS_ALG_ECC, 0, 0, 0, 0};
    struct HksUsageSpec usageSpec = { .algType = HKS_ALG_ECC, .mode = 0xffff };
    int32_t ret = DcmGetPublicKey(&key, &info, &usageSpec);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksAttestUtilsTest007 failed, ret = " << ret;
}

/**
 * @tc.name: HksAttestUtilsTest.HksAttestUtilsTest008
 * @tc.desc: tdd DcmGetPublicKey, get ECC public key which key size is 384 but total size is not equal with key size,
 *    expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestUtilsTest, HksAttestUtilsTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestUtilsTest008");
    uint8_t buffer[ASN_1_MAX_HEADER_LEN + 1] = { 0 };
    struct HksBlob key = { ASN_1_MAX_HEADER_LEN + 1, buffer };
    struct HksPubKeyInfo info = { HKS_ALG_ECC, HKS_ECC_KEY_SIZE_384, HKS_ECC_KEY_SIZE_521, HKS_ECC_KEY_SIZE_521, 0};
    struct HksUsageSpec usageSpec = { .algType = HKS_ALG_ECC, .mode = 0xffff };
    int32_t ret = DcmGetPublicKey(&key, &info, &usageSpec);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL) << "HksAttestUtilsTest008 failed, ret = " << ret;
}

/**
 * @tc.name: HksAttestUtilsTest.HksAttestUtilsTest009
 * @tc.desc: tdd DcmGetPublicKey, get ECC public key which key size is 521 but total size is not equal with key size,
 *    expect HKS_ERROR_BUFFER_TOO_SMALL
 * @tc.type: FUNC
 */
HWTEST_F(HksAttestUtilsTest, HksAttestUtilsTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksAttestUtilsTest009");
    uint8_t buffer[ASN_1_MAX_HEADER_LEN + 1] = { 0 };
    struct HksBlob key = { ASN_1_MAX_HEADER_LEN + 1, buffer };
    struct HksPubKeyInfo info = { HKS_ALG_ECC,  HKS_ECC_KEY_SIZE_521, HKS_ECC_KEY_SIZE_521, HKS_ECC_KEY_SIZE_521, 0};
    struct HksUsageSpec usageSpec = { .algType = HKS_ALG_ECC, .mode = 0xffff };
    int32_t ret = DcmGetPublicKey(&key, &info, &usageSpec);
    EXPECT_EQ(ret, HKS_ERROR_BUFFER_TOO_SMALL) << "HksAttestUtilsTest009 failed, ret = " << ret;
}
}
