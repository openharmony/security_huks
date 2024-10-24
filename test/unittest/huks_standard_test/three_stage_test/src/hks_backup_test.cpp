/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hks_template.h"
#include "hks_test_adapt_for_de.h"
#include "hks_three_stage_test_common.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "hks_file_operator.h"

#include <gtest/gtest.h>
#include <vector>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::BackupTest {
class HksBackupTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksBackupTest::SetUpTestCase(void)
{
}

void HksBackupTest::TearDownTestCase(void)
{
}

void HksBackupTest::SetUp()
{
    ASSERT_EQ(HksInitialize(), 0);
}

void HksBackupTest::TearDown()
{
}

static const char *STORE_PATH = "/data/service/el1/public/huks_service/maindata/0/0/key/";
static const char *KEY_ALIAS = "test_alias";
static const char *DERIVE_INFO = "Hks_HMAC_Derive_Test_0000000000000000000000000000000000000000000000000000000"
                                "0000000000000000000000000000000000000000000000000000000000000000000000000000"
                                "000000000000000000000000000000000000000000000000000000000000000000000_string";
static const char *HMAC_INFO = "Hks_HMAC_Test_000000000000000000000000000000000000000000000000000000000000000000"
                                "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                "0000000000000000000000000000000000000000000000000000000000000000000000000_string";
static const uint32_t HMAC_COMMON_SIZE = 256;
static const uint32_t DERIVE_KEY_SIZE_48 = 48;
static const uint32_t COMMON_SIZE = 2048;
static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = {0};

static const struct HksParam g_genEncAndDecParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_encryptParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV }},
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_decryptParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV }},
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_genSigAndVerParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_signParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_verifyParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_agreeParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_genDeriveParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_deriveParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HKDF },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
    { .tag = HKS_TAG_DERIVE_KEY_SIZE, .uint32Param = DERIVE_KEY_SIZE_48 },
    { .tag = HKS_TAG_INFO, .blob = { .size = (uint32_t)strlen(DERIVE_INFO), .data = (uint8_t *)DERIVE_INFO } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_genHmacParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HMAC_COMMON_SIZE },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_HmacParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};


static int32_t BuildParamSet(const struct HksParam *param, uint32_t paramCnt, struct HksParamSet **paramSetOut)
{
    int32_t ret;
    struct HksParamSet *paramSet = nullptr;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        if (param != nullptr && paramCnt > 0) {
            ret = HksAddParams(paramSet, param, paramCnt);
            HKS_IF_NOT_SUCC_BREAK(ret)
        }

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
    }
    *paramSetOut = paramSet;
    return HKS_SUCCESS;
}

static int32_t HksModifyKey()
{
    uint32_t sizeOne = HksFileSize(STORE_PATH, KEY_ALIAS);
    uint8_t *bufOne = (uint8_t *)HksMalloc(sizeOne);
    if (bufOne == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    struct HksBlob blobOne = { .size = sizeOne, .data = bufOne };
    uint32_t sizeRead = 0;
    int32_t ret = HksFileRead(STORE_PATH, KEY_ALIAS, 0, &blobOne, &sizeRead);
    (void)memset_s(bufOne, sizeRead, 0, sizeRead);

    ret = HksFileWrite(STORE_PATH, KEY_ALIAS, 0, bufOne, sizeOne);
    HksFreeImpl(bufOne);

    return ret;
}

HWTEST_F(HksBackupTest, HksBackupPartTest001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksBackupPartTest001");

    int32_t ret;
    struct HksParamSet *paramSet0 = nullptr;
    struct HksParamSet *paramSet1 = nullptr;
    struct HksParamSet *paramSet2 = nullptr;
    struct HksBlob keyAlias = { (uint32_t)strlen(KEY_ALIAS), (uint8_t *)KEY_ALIAS };

    ret = BuildParamSet(g_genEncAndDecParams, HKS_ARRAY_SIZE(g_genEncAndDecParams), &paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_encryptParams, HKS_ARRAY_SIZE(g_encryptParams), &paramSet1);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_decryptParams, HKS_ARRAY_SIZE(g_decryptParams), &paramSet2);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, paramSet0, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksFileRemove(STORE_PATH, KEY_ALIAS);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t plainText[] = "plainText123456";
    uint8_t cipherText[1024] = { 0 };
    struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText };
    struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText };
    ret = HksEncrypt(&keyAlias, paramSet1, &plainBlob, &cipherBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksFileRemove(STORE_PATH, KEY_ALIAS);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t decryptedText[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
    struct HksBlob decryptedBlob = { .size = HKS_ARRAY_SIZE(decryptedText), .data = decryptedText };
    ret = HksDecrypt(&keyAlias, paramSet2, &cipherBlob, &decryptedBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksMemCmp(decryptedText, plainText, HKS_ARRAY_SIZE(plainText));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDeleteKey(&keyAlias, paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet0);
    HksFreeParamSet(&paramSet1);
    HksFreeParamSet(&paramSet2);
}

HWTEST_F(HksBackupTest, HksBackupPartTest002, TestSize.Level0)
{
    HKS_LOG_I("Enter HksBackupPartTest002");

    int32_t ret;
    struct HksParamSet *paramSet0 = nullptr;
    struct HksParamSet *paramSet1 = nullptr;
    struct HksParamSet *paramSet2 = nullptr;
    struct HksBlob keyAlias = { (uint32_t)strlen(KEY_ALIAS), (uint8_t *)KEY_ALIAS };

    ret = BuildParamSet(g_genEncAndDecParams, HKS_ARRAY_SIZE(g_genEncAndDecParams), &paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_encryptParams, HKS_ARRAY_SIZE(g_encryptParams), &paramSet1);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_decryptParams, HKS_ARRAY_SIZE(g_decryptParams), &paramSet2);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, paramSet0, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksModifyKey();
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t plainText[] = "plainText123456";
    uint8_t cipherText[1024] = { 0 };
    struct HksBlob plainBlob = { .size = HKS_ARRAY_SIZE(plainText), .data = plainText };
    struct HksBlob cipherBlob = { .size = HKS_ARRAY_SIZE(cipherText), .data = cipherText };
    ret = HksEncrypt(&keyAlias, paramSet1, &plainBlob, &cipherBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksModifyKey();
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t decryptedText[HKS_ARRAY_SIZE(plainText) + 1] = { 0 };
    struct HksBlob decryptedBlob = { .size = HKS_ARRAY_SIZE(decryptedText), .data = decryptedText };
    ret = HksDecrypt(&keyAlias, paramSet2, &cipherBlob, &decryptedBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksMemCmp(decryptedText, plainText, HKS_ARRAY_SIZE(plainText));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDeleteKey(&keyAlias, paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet0);
    HksFreeParamSet(&paramSet1);
    HksFreeParamSet(&paramSet2);
}

HWTEST_F(HksBackupTest, HksBackupPartTest003, TestSize.Level0)
{
    HKS_LOG_I("Enter HksBackupPartTest003");

    int32_t ret;
    struct HksParamSet *paramSet0 = nullptr;
    struct HksParamSet *paramSet1 = nullptr;
    struct HksParamSet *paramSet2 = nullptr;
    struct HksBlob keyAlias = { (uint32_t)strlen(KEY_ALIAS), (uint8_t *)KEY_ALIAS };

    ret = BuildParamSet(g_genSigAndVerParams, HKS_ARRAY_SIZE(g_genSigAndVerParams), &paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_signParams, HKS_ARRAY_SIZE(g_signParams), &paramSet1);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_verifyParams, HKS_ARRAY_SIZE(g_verifyParams), &paramSet2);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, paramSet0, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksFileRemove(STORE_PATH, KEY_ALIAS);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t message[] = "0123456789abcdef";
    uint8_t signData[HKS_ECC_KEY_SIZE_256] = { 0 };
    struct HksBlob messageBlob = { .size = HKS_ARRAY_SIZE(message), .data = message };
    struct HksBlob signDataBlob = { .size = HKS_ARRAY_SIZE(signData), .data = signData };
    ret = HksSign(&keyAlias, paramSet1, &messageBlob, &signDataBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksFileRemove(STORE_PATH, KEY_ALIAS);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksVerify(&keyAlias, paramSet2, &messageBlob, &signDataBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDeleteKey(&keyAlias, paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet0);
    HksFreeParamSet(&paramSet1);
    HksFreeParamSet(&paramSet2);
}

HWTEST_F(HksBackupTest, HksBackupPartTest004, TestSize.Level0)
{
    HKS_LOG_I("Enter HksBackupPartTest004");

    int32_t ret;
    struct HksParamSet *paramSet0 = nullptr;
    struct HksParamSet *paramSet1 = nullptr;
    struct HksParamSet *paramSet2 = nullptr;
    struct HksBlob keyAlias = { (uint32_t)strlen(KEY_ALIAS), (uint8_t *)KEY_ALIAS };

    ret = BuildParamSet(g_genSigAndVerParams, HKS_ARRAY_SIZE(g_genSigAndVerParams), &paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_signParams, HKS_ARRAY_SIZE(g_signParams), &paramSet1);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_verifyParams, HKS_ARRAY_SIZE(g_verifyParams), &paramSet2);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, paramSet0, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksModifyKey();
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t message[] = "0123456789abcdef";
    uint8_t signData[HKS_ECC_KEY_SIZE_256] = { 0 };
    struct HksBlob messageBlob = { .size = HKS_ARRAY_SIZE(message), .data = message };
    struct HksBlob signDataBlob = { .size = HKS_ARRAY_SIZE(signData), .data = signData };
    ret = HksSign(&keyAlias, paramSet1, &messageBlob, &signDataBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksModifyKey();
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksVerify(&keyAlias, paramSet2, &messageBlob, &signDataBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDeleteKey(&keyAlias, paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet0);
    HksFreeParamSet(&paramSet1);
    HksFreeParamSet(&paramSet2);
}

HWTEST_F(HksBackupTest, HksBackupPartTest005, TestSize.Level0)
{
    HKS_LOG_I("Enter HksBackupPartTest005");

    int32_t ret;
    struct HksParamSet *paramSet0 = nullptr;
    struct HksBlob keyAlias = { (uint32_t)strlen(KEY_ALIAS), (uint8_t *)KEY_ALIAS };

    ret = BuildParamSet(g_agreeParams, HKS_ARRAY_SIZE(g_agreeParams), &paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, paramSet0, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t pubKeyText[HKS_DH_KEY_SIZE_2048] = { 0 };
    struct HksBlob pubKey = { .size = HKS_ARRAY_SIZE(pubKeyText), .data = pubKeyText };
    ret = HksExportPublicKey(&keyAlias, paramSet0, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksFileRemove(STORE_PATH, KEY_ALIAS);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t agreeText[COMMON_SIZE] = { 0 };
    struct HksBlob agreeBlob = { .size = HKS_ARRAY_SIZE(agreeText), .data = agreeText };
    ret = HksAgreeKey(paramSet0, &keyAlias, &pubKey, &agreeBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDeleteKey(&keyAlias, paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet0);
}

HWTEST_F(HksBackupTest, HksBackupPartTest006, TestSize.Level0)
{
    HKS_LOG_I("Enter HksBackupPartTest006");

    int32_t ret;
    struct HksParamSet *paramSet0 = nullptr;
    struct HksBlob keyAlias = { (uint32_t)strlen(KEY_ALIAS), (uint8_t *)KEY_ALIAS };

    ret = BuildParamSet(g_agreeParams, HKS_ARRAY_SIZE(g_agreeParams), &paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, paramSet0, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t pubKeyText[HKS_DH_KEY_SIZE_2048] = { 0 };
    struct HksBlob pubKey = { .size = HKS_ARRAY_SIZE(pubKeyText), .data = pubKeyText };
    ret = HksExportPublicKey(&keyAlias, paramSet0, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksModifyKey();
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t agreeText[COMMON_SIZE] = { 0 };
    struct HksBlob agreeBlob = { .size = HKS_ARRAY_SIZE(agreeText), .data = agreeText };
    ret = HksAgreeKey(paramSet0, &keyAlias, &pubKey, &agreeBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDeleteKey(&keyAlias, paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet0);
}

HWTEST_F(HksBackupTest, HksBackupPartTest007, TestSize.Level0)
{
    HKS_LOG_I("Enter HksBackupPartTest007");

    int32_t ret;
    struct HksParamSet *paramSet0 = nullptr;
    struct HksParamSet *paramSet1 = nullptr;
    struct HksBlob keyAlias = { (uint32_t)strlen(KEY_ALIAS), (uint8_t *)KEY_ALIAS };

    ret = BuildParamSet(g_genDeriveParams, HKS_ARRAY_SIZE(g_genDeriveParams), &paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_deriveParams, HKS_ARRAY_SIZE(g_deriveParams), &paramSet1);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, paramSet0, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksFileRemove(STORE_PATH, KEY_ALIAS);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t deriveText[COMMON_SIZE] = { 0 };
    struct HksBlob deriveBlob = { .size = HKS_ARRAY_SIZE(deriveText), .data = deriveText };
    ret = HksDeriveKey(paramSet1, &keyAlias, &deriveBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDeleteKey(&keyAlias, paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet0);
    HksFreeParamSet(&paramSet1);
}

HWTEST_F(HksBackupTest, HksBackupPartTest008, TestSize.Level0)
{
    HKS_LOG_I("Enter HksBackupPartTest008");

    int32_t ret;
    struct HksParamSet *paramSet0 = nullptr;
    struct HksParamSet *paramSet1 = nullptr;
    struct HksBlob keyAlias = { (uint32_t)strlen(KEY_ALIAS), (uint8_t *)KEY_ALIAS };

    ret = BuildParamSet(g_genDeriveParams, HKS_ARRAY_SIZE(g_genDeriveParams), &paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_deriveParams, HKS_ARRAY_SIZE(g_deriveParams), &paramSet1);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, paramSet0, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksModifyKey();
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t deriveText[COMMON_SIZE] = { 0 };
    struct HksBlob deriveBlob = { .size = HKS_ARRAY_SIZE(deriveText), .data = deriveText };
    ret = HksDeriveKey(paramSet1, &keyAlias, &deriveBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDeleteKey(&keyAlias, paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet0);
    HksFreeParamSet(&paramSet1);
}

HWTEST_F(HksBackupTest, HksBackupPartTest009, TestSize.Level0)
{
    HKS_LOG_I("Enter HksBackupPartTest009");

    int32_t ret;
    struct HksParamSet *paramSet0 = nullptr;
    struct HksParamSet *paramSet1 = nullptr;
    struct HksBlob keyAlias = { (uint32_t)strlen(KEY_ALIAS), (uint8_t *)KEY_ALIAS };

    ret = BuildParamSet(g_genHmacParams, HKS_ARRAY_SIZE(g_genHmacParams), &paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_HmacParams, HKS_ARRAY_SIZE(g_HmacParams), &paramSet1);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, paramSet0, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksFileRemove(STORE_PATH, KEY_ALIAS);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t macText[HMAC_COMMON_SIZE] = { 0 };
    struct HksBlob inDataBlob = { .size = (uint32_t)strlen(HMAC_INFO), .data = (uint8_t *)HMAC_INFO };
    struct HksBlob macBlob = { .size = HKS_ARRAY_SIZE(macText), .data = macText };
    ret = HksMac(&keyAlias, paramSet1, &inDataBlob, &macBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDeleteKey(&keyAlias, paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet0);
    HksFreeParamSet(&paramSet1);
}

HWTEST_F(HksBackupTest, HksBackupPartTest010, TestSize.Level0)
{
    HKS_LOG_I("Enter HksBackupPartTest010");

    int32_t ret;
    struct HksParamSet *paramSet0 = nullptr;
    struct HksParamSet *paramSet1 = nullptr;
    struct HksBlob keyAlias = { (uint32_t)strlen(KEY_ALIAS), (uint8_t *)KEY_ALIAS };

    ret = BuildParamSet(g_genHmacParams, HKS_ARRAY_SIZE(g_genHmacParams), &paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = BuildParamSet(g_HmacParams, HKS_ARRAY_SIZE(g_HmacParams), &paramSet1);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKey(&keyAlias, paramSet0, nullptr);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksModifyKey();
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t macText[HMAC_COMMON_SIZE] = { 0 };
    struct HksBlob inDataBlob = { .size = (uint32_t)strlen(HMAC_INFO), .data = (uint8_t *)HMAC_INFO };
    struct HksBlob macBlob = { .size = HKS_ARRAY_SIZE(macText), .data = macText };
    ret = HksMac(&keyAlias, paramSet1, &inDataBlob, &macBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDeleteKey(&keyAlias, paramSet0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet0);
    HksFreeParamSet(&paramSet1);
}
}