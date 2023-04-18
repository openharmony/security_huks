/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#include "hks_upgrade_rkc_test.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

#include "cstring"
#include "unistd.h"
#include "securec.h"

using namespace testing::ext;
namespace HksUpgradeRkcTest {
class HksUpgradeRkcTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksUpgradeRkcTest::SetUpTestCase(void)
{
}

void HksUpgradeRkcTest::TearDownTestCase(void)
{
}

void HksUpgradeRkcTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksUpgradeRkcTest::TearDown()
{
}

static const char KEY_ALIAS[] = "test_rkc_compatibility_key";
static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = {0};

static const struct HksParam GEN_AES_PARAMS[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};

static const struct HksParam ENCYPT_AES_PARAMS[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

static const struct HksParam DECRYPT_AES_PARAMS[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

static int32_t TestGeneratekey(const struct HksBlob *keyAlias, const struct HksParam *genParams,
    uint32_t genParamsCnt)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = HksInitParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(genParamSet, genParams, genParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&genParamSet);

    return ret;
}

static int32_t TestDoEncrypt(const struct HksBlob *keyAlias, const struct HksParam *encParams, uint32_t encParamsCnt,
    struct HksBlob *plainBlob, struct HksBlob *cipherBlob)
{
    struct HksParamSet *encryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(encryptParamSet, encParams, encParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksEncrypt(keyAlias, encryptParamSet, plainBlob, cipherBlob);

    HksFreeParamSet(&encryptParamSet);
    return ret;
}

static int32_t TestDoDecrypt(const struct HksBlob *keyAlias, const struct HksParam *decParams, uint32_t decParamsCnt,
    struct HksBlob *cipherBlob, struct HksBlob *decryptedBlob)
{
    struct HksParamSet *decryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(decryptParamSet, decParams, decParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksDecrypt(keyAlias, decryptParamSet, cipherBlob, decryptedBlob);

    HksFreeParamSet(&decryptParamSet);
    return ret;
}

/**
 * @tc.name: HksUpgradeRkcTest.HksUpgradeRkcTest001
 * @tc.desc: generate key with old rkc
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeRkcTest, HksUpgradeRkcTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeRkcTest001");
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };

    int32_t ret = TestGeneratekey(&keyAlias, GEN_AES_PARAMS, sizeof(GEN_AES_PARAMS) / sizeof(HksParam));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;
}

/**
 * @tc.name: HksUpgradeRkcTest.HksUpgradeRkcTest002
 * @tc.desc: access key with new rkc
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeRkcTest, HksUpgradeRkcTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeRkcTest002");

    uint8_t plainText[] = "plainText123456";
    uint8_t cipherText[1024] = { 0 };
    struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText};
    struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText};
    struct HksBlob keyAlias = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };

    ret = TestDoEncrypt(&keyAlias, ENCYPT_AES_PARAMS, sizeof(ENCYPT_AES_PARAMS) / sizeof(HksParam), &plainBlob,
        &cipherBlob);

    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    uint8_t decryptedText[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
    struct HksBlob decryptedBlob = { .size = HKS_ARRAY_SIZE(decryptedText), .data = decryptedText};

    ret = TestDoDecrypt(&keyAlias, DECRYPT_AES_PARAMS, sizeof(DECRYPT_AES_PARAMS) / sizeof(HksParam), &cipherBlob,
        &decryptedBlob);

    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    ret = HksMemCmp(decryptedText, plainText, HKS_ARRAY_SIZE(plainText));

    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    (void)HksDeleteKey(&keyAlias, nullptr);
}
}
