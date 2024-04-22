/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "file_ex.h"
#include "hks_api.h"
#include "hks_client_service.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include "hks_test_modify_old_key.h"

using namespace testing::ext;
namespace Unittest::HksUpgradeKeyTest {
class HksUpgradeKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksUpgradeKeyTest::SetUpTestCase(void)
{
}

void HksUpgradeKeyTest::TearDownTestCase(void)
{
}

void HksUpgradeKeyTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
    EXPECT_EQ(HksTestInitialize(), 0);
}

void HksUpgradeKeyTest::TearDown()
{
}

static const uint32_t HUKS_UID = 3510;
static const char KEY_ALIAS[] = "test_compatibility_key";
static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = { 0 };

static struct HksParam GEN_AES_PARAMS[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
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
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }
};

static struct HksParam DECRYPT_AES_PARAMS[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
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
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }
};

static struct HksParam ENCYPT_AES_PARAMS[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
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
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

#define USER_ID "0"

static const uint32_t TEST_PROCESS_UID = 0;
static const struct HksProcessInfo PROCESS_INFO = {
    { strlen(USER_ID), (uint8_t *)USER_ID },
    { sizeof(TEST_PROCESS_UID), (uint8_t *)&TEST_PROCESS_UID },
    0,
    0
};

static int32_t TestGenerateOldkey(const struct HksBlob *keyAlias, const struct HksParam *genParams,
    uint32_t genParamsCnt)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = HksInitParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ret is " << ret;
    ret = HksAddParams(genParamSet, genParams, genParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ret is " << ret;
    ret = HksBuildParamSet(&genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ret is " << ret;

    ret = HksTestGenerateOldKey(keyAlias, genParamSet, &PROCESS_INFO);

    EXPECT_EQ(ret, HKS_SUCCESS) << "ret is " << ret;
    HksFreeParamSet(&genParamSet);

    return ret;
}

static int32_t TestDoEncrypt(const struct HksBlob *keyAlias, const struct HksParam *encParams, uint32_t encParamsCnt,
    struct HksBlob *plainBlob, struct HksBlob *cipherBlob)
{
    struct HksParamSet *encryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ret is " << ret;
    ret = HksAddParams(encryptParamSet, encParams, encParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ret is " << ret;
    ret = HksBuildParamSet(&encryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ret is " << ret;

    ret = HksEncrypt(keyAlias, encryptParamSet, plainBlob, cipherBlob);

    HksFreeParamSet(&encryptParamSet);
    return ret;
}

static int32_t TestDoDecrypt(const struct HksBlob *keyAlias, const struct HksParam *decParams, uint32_t decParamsCnt,
    struct HksBlob *cipherBlob, struct HksBlob *decryptedBlob)
{
    struct HksParamSet *decryptParamSet = nullptr;
    int32_t ret = HksInitParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ret is " << ret;
    ret = HksAddParams(decryptParamSet, decParams, decParamsCnt);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ret is " << ret;
    ret = HksBuildParamSet(&decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ret is " << ret;

    ret = HksDecrypt(keyAlias, decryptParamSet, cipherBlob, decryptedBlob);

    HksFreeParamSet(&decryptParamSet);
    return ret;
}

#define DEFAULT_CIPHER_BUFFER 1024

static int32_t TestCheckKeyVersionIsExpected(struct HksBlob *keyAlias, uint32_t expectedKeyVersion)
{
    const uint32_t keyParamsetSize = 1024;
    struct HksParam getParam = {
        .tag = HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA,
        .blob = { .size = keyParamsetSize, .data = (uint8_t *)HksMalloc(keyParamsetSize) }
    };
    EXPECT_TRUE(getParam.blob.data != nullptr);

    struct HksParamSet *paramOutSet = nullptr;
    (void)HksInitParamSet(&paramOutSet);
    (void)HksAddParams(paramOutSet, &getParam, 1);
    (void)HksBuildParamSet(&paramOutSet);
    HKS_FREE(getParam.blob.data);
    int32_t ret = HksGetKeyParamSet(keyAlias, nullptr, paramOutSet);
    EXPECT_TRUE(ret == HKS_SUCCESS);

    struct HksParam *keyVersion = nullptr;
    ret = HksGetParam(paramOutSet, HKS_TAG_KEY_VERSION, &keyVersion);
    EXPECT_TRUE(ret == HKS_SUCCESS) << "get key version failed : " << ret;
    EXPECT_EQ(keyVersion->uint32Param, expectedKeyVersion);
    HksFreeParamSet(&paramOutSet);
    return ret;
}

/**
 * @tc.name: HksUpgradeKeyTest.HksUpgradeKeyTest001
 * @tc.desc: tdd HksUpgradeKey with key with verion one, then success enc and dec, and the key version in key file is
 *           the newest version number
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyTest, HksUpgradeKeyTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyTest001");
    struct HksBlob keyAliasTest001 = { .size = strlen(KEY_ALIAS), .data = (uint8_t *)KEY_ALIAS };

    int32_t ret = TestGenerateOldkey(&keyAliasTest001, GEN_AES_PARAMS, HKS_ARRAY_SIZE(GEN_AES_PARAMS));
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    HksChangeOldKeyOwner(HKS_CONFIG_KEY_STORE_PATH "/maindata", HUKS_UID);

    uint8_t plainText[] = "plainText123457";
    uint8_t cipherText[DEFAULT_CIPHER_BUFFER] = { 0 };
    struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText};
    struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText};

    ret = TestDoEncrypt(&keyAliasTest001, ENCYPT_AES_PARAMS, HKS_ARRAY_SIZE(ENCYPT_AES_PARAMS), &plainBlob,
        &cipherBlob);

    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    uint8_t decryptedText[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
    struct HksBlob decryptedBlob = { .size = HKS_ARRAY_SIZE(decryptedText), .data = decryptedText};

    ret = TestDoDecrypt(&keyAliasTest001, DECRYPT_AES_PARAMS, HKS_ARRAY_SIZE(DECRYPT_AES_PARAMS),
        &cipherBlob, &decryptedBlob);

    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    ret = HksMemCmp(decryptedText, plainText, HKS_ARRAY_SIZE(plainText));

    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    // test key verion in key file and expect it is the newest upgraded version number
    ret = TestCheckKeyVersionIsExpected(&keyAliasTest001, REAL_HKS_KEY_VERSION);
    ASSERT_TRUE(ret == HKS_SUCCESS) << "ret is " << ret;

    (void)HksDeleteKey(&keyAliasTest001, nullptr);
}
}
