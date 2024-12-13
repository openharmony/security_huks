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

#include "hks_des_cipher_test_common.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>
#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::DesCipher {
class HksDesCipherPart1Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksDesCipherPart1Test::SetUpTestCase(void)
{
}

void HksDesCipherPart1Test::TearDownTestCase(void)
{
}

void HksDesCipherPart1Test::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksDesCipherPart1Test::TearDown()
{
}

static struct HksParam g_genParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }
};
static struct HksParam g_encryptParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};
static struct HksParam g_decryptParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

static struct HksParam g_genParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }
};
static struct HksParam g_encryptParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }
};
static struct HksParam g_decryptParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }
};

static struct HksParam g_genParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }
};

static struct HksParam g_genParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }
};
static struct HksParam g_encryptParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CFB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

static struct HksParam g_genParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }
};
static struct HksParam g_encryptParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS7
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

static struct HksParam g_genParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }
};
static struct HksParam g_encryptParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE_INVALID,
            .data = (uint8_t *)IV_INVALID
        }
    }
};

static struct HksParam g_genParams007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }
};
static struct HksParam g_encryptParams007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_DES_KEY_SIZE_64
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

/**
 * @tc.name: HksDesCipherPart1Test.HksDesCipherPart1Test001
 * @tc.desc: alg-DES pur-ENCRYPT&DECRYPT mod-CBC pad-NONE size-64.
 * @tc.type: FUNC
 */
HWTEST_F(HksDesCipherPart1Test, HksDesCipherPart1Test001, TestSize.Level0)
{
    HKS_LOG_I("enter HksDesCipherPart1Test001");
    char tmpKeyAlias[] = "HksDesCipherKeyAliasTest001";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams001, sizeof(g_encryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES_COMMON_SIZE, cipher };
    ret = HksDesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDesCipherTest(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams001, sizeof(g_decryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[DES_COMMON_SIZE] = { 0 };
    struct HksBlob plaintext = { DES_COMMON_SIZE, plain };
    ret = HksDesCipherTest(&keyAlias, decryptParamSet, &ciphertext, &plaintext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDesCipherTest(decrypt) failed.";
    EXPECT_EQ(HksMemCmp(inData.data, plaintext.data, inData.size), HKS_SUCCESS) << "plaintext not equals inData";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksDesCipherPart1Test.HksDesCipherPart1Test002
 * @tc.desc: alg-DES pur-ENCRYPT&DECRYPT mod-ECB pad-NONE size-64.
 * @tc.type: FUNC
 */
HWTEST_F(HksDesCipherPart1Test, HksDesCipherPart1Test002, TestSize.Level0)
{
    HKS_LOG_I("enter HksDesCipherPart1Test002");
    char tmpKeyAlias[] = "HksDesCipherKeyAliasTest002";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams002, sizeof(g_encryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES_COMMON_SIZE, cipher };
    ret = HksDesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDesCipherTest(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams002, sizeof(g_decryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[DES_COMMON_SIZE] = { 0 };
    struct HksBlob plaintext = { DES_COMMON_SIZE, plain };
    ret = HksDesCipherTest(&keyAlias, decryptParamSet, &ciphertext, &plaintext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDesCipherTest(decrypt) failed.";
    EXPECT_EQ(HksMemCmp(inData.data, plaintext.data, inData.size), HKS_SUCCESS) << "plaintext not equals inData";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksDesCipherPart1Test.HksDesCipherPart1Test003
 * @tc.desc: alg-DES pur-ENCRYPT&DECRYPT size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksDesCipherPart1Test, HksDesCipherPart1Test003, TestSize.Level0)
{
    HKS_LOG_I("enter HksDesCipherPart1Test003");
    char tmpKeyAlias[] = "HksDesCipherKeyAliasTest003";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "GenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksDesCipherPart1Test.HksDesCipherPart1Test004
 * @tc.desc: alg-DES pur-ENCRYPT&DECRYPT mod-CFB pad-NONE size-64.
 * @tc.type: FUNC
 */
HWTEST_F(HksDesCipherPart1Test, HksDesCipherPart1Test004, TestSize.Level0)
{
    HKS_LOG_I("enter HksDesCipherPart1Test004");
    char tmpKeyAlias[] = "HksDesCipherKeyAliasTest004";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams004, sizeof(g_genParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams004, sizeof(g_encryptParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES_COMMON_SIZE, cipher };
    ret = HksDesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_ERROR_CHECK_GET_MODE_FAIL) << "HksDesCipherTest(encrypt) failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
}

/**
 * @tc.name: HksDesCipherPart1Test.HksDesCipherPart1Test005
 * @tc.desc: alg-DES pur-ENCRYPT&DECRYPT mod-CBC pad-PKCS7 size-64.
 * @tc.type: FUNC
 */
HWTEST_F(HksDesCipherPart1Test, HksDesCipherPart1Test005, TestSize.Level0)
{
    HKS_LOG_I("enter HksDesCipherPart1Test005");
    char tmpKeyAlias[] = "HksDesCipherKeyAliasTest005";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams005, sizeof(g_genParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams005, sizeof(g_encryptParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES_COMMON_SIZE, cipher };
    ret = HksDesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_PADDING) << "HksDesCipherTest(encrypt) failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
}

/**
 * @tc.name: HksDesCipherPart1Test.HksDesCipherPart1Test006
 * @tc.desc: alg-DES pur-ENCRYPT&DECRYPT mod-CBC pad-NONE size-64 IV-9.
 * @tc.type: FUNC
 */
HWTEST_F(HksDesCipherPart1Test, HksDesCipherPart1Test006, TestSize.Level0)
{
    HKS_LOG_I("enter HksDesCipherPart1Test006");
    char tmpKeyAlias[] = "HksDesCipherKeyAliasTest006";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams006, sizeof(g_genParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams006, sizeof(g_encryptParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES_COMMON_SIZE, cipher };
    ret = HksDesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_IV) << "HksDesCipherTest(encrypt) failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
}

/**
 * @tc.name: HksDesCipherPart1Test.HksDesCipherPart1Test007
 * @tc.desc: alg-DES pur-ENCRYPT&DECRYPT mod-CBC pad-NONE size-64 plaintext-invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HksDesCipherPart1Test, HksDesCipherPart1Test007, TestSize.Level0)
{
    HKS_LOG_I("enter HksDesCipherPart1Test007");
    char tmpKeyAlias[] = "HksDesCipherKeyAliasTest007";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams007, sizeof(g_genParams007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams007, sizeof(g_encryptParams007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES_COMMON_SIZE, cipher };
    ret = HksDesCipherTest(&keyAlias, encryptParamSet, &inDataInvalid, &ciphertext);
    EXPECT_EQ(ret, HKS_FAILURE) << "HksDesCipherTest(encrypt) failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
}
} // namespace Unittest::DesCipher
