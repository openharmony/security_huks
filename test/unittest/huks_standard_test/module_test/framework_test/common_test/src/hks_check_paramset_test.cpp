/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_check_paramset_test.h"

#include <gtest/gtest.h>

#include "base/security/huks/frameworks/huks_standard/main/common/src/hks_check_paramset.c"

#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksCheckParamsetTest {
constexpr uint32_t DEFAULT_VALUE = 16;

class HksCheckParamsetTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCheckParamsetTest::SetUpTestCase(void)
{
}

void HksCheckParamsetTest::TearDownTestCase(void)
{
}

void HksCheckParamsetTest::SetUp()
{
}

void HksCheckParamsetTest::TearDown()
{
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest001
 * @tc.desc: test CheckMutableParams with rsa
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest001");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_RSA, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest002
 * @tc.desc: test CheckMutableParams with ecc
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest002");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_ECC, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest003
 * @tc.desc: test CheckMutableParams with sm2
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest003");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_SM2, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest004
 * @tc.desc: test CheckMutableParams with dsa
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest004");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_DSA, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest005
 * @tc.desc: test CheckMutableParams with ed255129
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest005");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_ED25519, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest007
 * @tc.desc: test CheckMutableParams with x255129
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest007");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_X25519, keyType, &params);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest008
 * @tc.desc: test CheckMutableParams with dh
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest008");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_DH, keyType, &params);
    ASSERT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest009
 * @tc.desc: test CheckMutableParams with dh
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest009");
    uint32_t keyType = HKS_KEY_TYPE_PUBLIC_KEY;
    struct ParamsValues params;
    params.purpose.value = HKS_KEY_PURPOSE_ENCRYPT;
    int32_t ret = CheckMutableParams(HKS_ALG_SM4, keyType, &params);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM);
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest010
 * @tc.desc: tdd HksCheckParamsetTest010, function is CheckImportKeySize
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest010");
    HksBlob key = {
        .size = 0,
        .data = nullptr,
    };
    int32_t ret = CheckImportKeySize(HKS_ALG_ED25519, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_X25519, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_RSA, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_ECC, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_SM2, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_DH, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(HKS_ALG_DSA, nullptr, &key);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksCheckParamsetTest010 failed, ret = " << ret;

    ret = CheckImportKeySize(0, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "HksCheckParamsetTest010 failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest011
 * @tc.desc: tdd HksCheckParamsetTest011, function is CheckRsaKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest011");
    HksBlob key = {
        .size = 0, .data = nullptr,
    };
    int32_t ret = CheckRsaKeyLen(HKS_ALG_ED25519, 0, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;

    struct HksKeyMaterialRsa materialRsa = {
        .keyAlg = HKS_ALG_RSA,
        .keySize = 0,
        .nSize = HKS_RSA_KEY_SIZE_4096,
        .eSize = HKS_RSA_KEY_SIZE_4096,
        .dSize = HKS_RSA_KEY_SIZE_4096,
    };
    key.size = sizeof(struct HksKeyMaterialRsa);
    key.data = reinterpret_cast<uint8_t *>(&materialRsa);
    ret = CheckRsaKeyLen(HKS_ALG_ED25519, 0, nullptr, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;

    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;

    materialRsa.keySize = DEFAULT_VALUE;
    materialRsa.nSize = HKS_RSA_KEY_SIZE_4096 + 1;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;

    materialRsa.nSize = HKS_RSA_KEY_SIZE_4096;
    materialRsa.dSize = HKS_RSA_KEY_SIZE_4096 + 1;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;

    materialRsa.dSize = HKS_RSA_KEY_SIZE_4096;
    materialRsa.eSize = HKS_RSA_KEY_SIZE_4096 + 1;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest011 failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest012
 * @tc.desc: tdd HksCheckParamsetTest012, function is CheckRsaKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest012");
    struct HksKeyMaterialRsa materialRsa = {
        .keyAlg = HKS_ALG_RSA,
        .keySize = DEFAULT_VALUE,
        .nSize = HKS_RSA_KEY_SIZE_4096,
        .eSize = HKS_RSA_KEY_SIZE_4096,
        .dSize = HKS_RSA_KEY_SIZE_4096,
    };

    HksBlob key = {
        .size = sizeof(struct HksKeyMaterialRsa),
        .data = reinterpret_cast<uint8_t *>(&materialRsa),
    };

    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    materialRsa.nSize = 0;
    int32_t ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest012 failed, ret = " << ret;

    materialRsa.nSize = HKS_RSA_KEY_SIZE_4096;
    materialRsa.dSize = 0;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest012 failed, ret = " << ret;

    materialRsa.dSize = HKS_RSA_KEY_SIZE_4096;
    materialRsa.eSize = 0;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest012 failed, ret = " << ret;

    materialRsa.eSize = HKS_RSA_KEY_SIZE_4096;
    ret = CheckRsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest012 failed, ret = " << ret;
}


/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest013
 * @tc.desc: tdd HksCheckParamsetTest013, function is CheckEccKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest013");
    struct HksKeyMaterialEcc materialEcc = {
        .keyAlg = HKS_ALG_ECC,
        .keySize = 0,
        .xSize = HKS_ECC_KEY_SIZE_521,
        .ySize = HKS_ECC_KEY_SIZE_521,
        .zSize = HKS_ECC_KEY_SIZE_521,
    };
    HksBlob key = {
        .size = sizeof(struct HksKeyMaterialRsa),
        .data = reinterpret_cast<uint8_t *>(&materialEcc),
    };
    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    int32_t ret = CheckEccKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    ret = CheckEccKeyLen(HKS_ALG_ECC, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.keySize = DEFAULT_VALUE;
    materialEcc.xSize = HKS_ECC_KEY_SIZE_521 + 1;
    ret = CheckEccKeyLen(HKS_ALG_ECC, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.xSize = HKS_ECC_KEY_SIZE_521;
    materialEcc.ySize = HKS_ECC_KEY_SIZE_521 + 1;
    ret = CheckEccKeyLen(HKS_ALG_ECC, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.ySize = HKS_ECC_KEY_SIZE_521;
    materialEcc.zSize = HKS_ECC_KEY_SIZE_521 + 1;
    ret = CheckEccKeyLen(HKS_ALG_ECC, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.zSize = HKS_ECC_KEY_SIZE_521;
    materialEcc.xSize = 0;
    ret = CheckEccKeyLen(HKS_ALG_ECC, HKS_KEY_TYPE_KEY_PAIR, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.xSize = HKS_ECC_KEY_SIZE_521;
    materialEcc.ySize = 0;
    ret = CheckEccKeyLen(HKS_ALG_ECC, HKS_KEY_TYPE_KEY_PAIR, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;

    materialEcc.ySize = HKS_ECC_KEY_SIZE_521;
    ret = CheckEccKeyLen(HKS_ALG_ECC, HKS_KEY_TYPE_KEY_PAIR, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest013 failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest014
 * @tc.desc: tdd HksCheckParamsetTest014, function is CheckDsaKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest014");
    struct HksKeyMaterialDsa materialDsa = {
        .keyAlg = HKS_ALG_DSA,
        .keySize = 0,
        .xSize = MAX_KEY_SIZE + 1,
        .ySize = MAX_KEY_SIZE + 1,
        .pSize = MAX_KEY_SIZE + 1,
        .qSize = MAX_KEY_SIZE + 1,
        .gSize = MAX_KEY_SIZE + 1,
    };
    HksBlob key = {
        .size = sizeof(struct HksKeyMaterialDsa),
        .data = reinterpret_cast<uint8_t *>(&materialDsa),
    };
    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };
    int32_t ret = CheckDsaKeyLen(HKS_ALG_RSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.keySize = DEFAULT_VALUE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.xSize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.ySize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.pSize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.qSize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;

    materialDsa.gSize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest014 failed, ret = " << ret;
}

/**
 * @tc.name: HksCheckParamsetTest.HksCheckParamsetTest015
 * @tc.desc: tdd HksCheckParamsetTest015, function is CheckDsaKeyLen
 * @tc.type: FUNC
 */
HWTEST_F(HksCheckParamsetTest, HksCheckParamsetTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksCheckParamsetTest015");
    struct HksKeyMaterialDsa materialDsa = {
        .keyAlg = HKS_ALG_DSA,
        .keySize = DEFAULT_VALUE,
        .xSize = MAX_KEY_SIZE,
        .ySize = MAX_KEY_SIZE,
        .pSize = MAX_KEY_SIZE,
        .qSize = MAX_KEY_SIZE,
        .gSize = MAX_KEY_SIZE,
    };
    HksBlob key = {
        .size = sizeof(struct HksKeyMaterialDsa),
        .data = reinterpret_cast<uint8_t *>(&materialDsa),
    };
    ParamsValues values = {
        {.needCheck = true, .value = DEFAULT_VALUE, .isAbsent = false},
        {0}, {0}, {0}, {0},
    };

    materialDsa.xSize = 0;
    int32_t ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;

    materialDsa.xSize = MAX_KEY_SIZE;
    materialDsa.pSize = 0;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;

    materialDsa.pSize = MAX_KEY_SIZE;
    materialDsa.qSize = 0;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;

    materialDsa.qSize = MAX_KEY_SIZE;
    materialDsa.gSize = 0;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;

    materialDsa.gSize = MAX_KEY_SIZE;
    materialDsa.ySize = 0;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, HKS_KEY_TYPE_KEY_PAIR, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;

    materialDsa.ySize = MAX_KEY_SIZE;
    ret = CheckDsaKeyLen(HKS_ALG_DSA, 0, &values, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksCheckParamsetTest015 failed, ret = " << ret;
}

}
