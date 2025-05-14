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

#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_rsa_cipher_test_common.h"
#include "hks_test_adapt_for_de.h"
#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::RsaCipher {
class HksRsaCipherPart6Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksRsaCipherPart6Test::SetUpTestCase(void)
{
}

void HksRsaCipherPart6Test::TearDownTestCase(void)
{
}

void HksRsaCipherPart6Test::SetUp()
{
}

void HksRsaCipherPart6Test::TearDown()
{
}

static struct HksParam g_genParams051[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }
};
static struct HksParam g_encryptParams051[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};
static struct HksParam g_decryptParams051[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_genParams052[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }
};
static struct HksParam g_encryptParams052[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};
static struct HksParam g_decryptParams052[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_genParams053[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }
};
static struct HksParam g_encryptParams053[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_OAEP
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};
static struct HksParam g_decryptParams053[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_OAEP
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_genParams054[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_INVALID_FLEX_KEY_SIZE_1540
    }
};

static struct HksParam g_genParams055[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }
};
static struct HksParam g_encryptParams055[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS7
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_genParams056[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }
};
static struct HksParam g_encryptParams056[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }
};
static struct HksParam g_decryptParams056[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }
};

static struct HksParam g_encryptParams057[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }
};
static struct HksParam g_decryptParams057[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }
};
/**
 * @tc.name: HksRsaCipherPart6Test.HksRsaCipherPart6Test051
 * @tc.desc: alg-RSA pur-ENCRYPT-DECRYPT size-1536 pad-NONE mode-ECB.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaCipherPart6Test, HksRsaCipherPart6Test051, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest051";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams051, sizeof(g_genParams051) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams051, sizeof(g_encryptParams051) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { RSA_COMMON_SIZE, cipher };
    ret = HksRsaCipherTest(&keyAlias, encryptParamSet, HKS_KEY_PURPOSE_ENCRYPT, &inData_192, &ciphertext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTest(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams051, sizeof(g_decryptParams051) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob plaintext = { RSA_COMMON_SIZE, plain };
    ret = HksRsaCipherTest(&keyAlias, decryptParamSet, HKS_KEY_PURPOSE_DECRYPT, &ciphertext, &plaintext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTest(decrypt) failed.";
    EXPECT_EQ(HksMemCmp(inData_192.data, plaintext.data, inData_192.size),
        HKS_SUCCESS) << "plaintext not equals inData";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksRsaCipherPart6Test.HksRsaCipherPart6Test052
 * @tc.desc: alg-RSA pur-ENCRYPT-DECRYPT size-1536 pad-PKCS1_V1_5 mode-ECB.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaCipherPart6Test, HksRsaCipherPart6Test052, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest052";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams052, sizeof(g_genParams052) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams052, sizeof(g_encryptParams052) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { RSA_COMMON_SIZE, cipher };
    ret = HksRsaCipherTest(&keyAlias, encryptParamSet, HKS_KEY_PURPOSE_ENCRYPT, &inData_96, &ciphertext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTest(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams052, sizeof(g_decryptParams052) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob plaintext = { RSA_COMMON_SIZE, plain };
    ret = HksRsaCipherTest(&keyAlias, decryptParamSet, HKS_KEY_PURPOSE_DECRYPT, &ciphertext, &plaintext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTest(decrypt) failed.";
    EXPECT_EQ(HksMemCmp(inData_96.data, plaintext.data, inData_96.size), HKS_SUCCESS) << "plaintext not equals inData";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksRsaCipherPart6Test.HksRsaCipherPart6Test053
 * @tc.desc: alg-RSA pur-ENCRYPT-DECRYPT size-1536 pad-OAEP dig-SHA256 mode-ECB.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaCipherPart6Test, HksRsaCipherPart6Test053, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest053";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams053, sizeof(g_genParams053) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams053, sizeof(g_encryptParams053) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { RSA_COMMON_SIZE, cipher };
    ret = HksRsaCipherTest(&keyAlias, encryptParamSet, HKS_KEY_PURPOSE_ENCRYPT, &inData_96, &ciphertext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTest(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams053, sizeof(g_decryptParams053) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob plaintext = { RSA_COMMON_SIZE, plain };
    ret = HksRsaCipherTest(&keyAlias, decryptParamSet, HKS_KEY_PURPOSE_DECRYPT, &ciphertext, &plaintext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTest(decrypt) failed.";
    EXPECT_EQ(HksMemCmp(inData_96.data, plaintext.data, inData_96.size), HKS_SUCCESS) << "plaintext not equals inData";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksRsaCipherPart6Test.HksRsaCipherPart6Test054
 * @tc.desc: alg-RSA pur-ENCRYPT-DECRYPT size-1540 pad-NONE mode-ECB.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaCipherPart6Test, HksRsaCipherPart6Test054, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest054";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams054, sizeof(g_genParams054) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "GenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksRsaCipherPart6Test.HksRsaCipherPart6Test055
 * @tc.desc: alg-RSA pur-ENCRYPT-DECRYPT size-1536 pad-PKCS7 mode-ECB.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaCipherPart6Test, HksRsaCipherPart6Test055, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest055";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams055, sizeof(g_genParams055) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams055, sizeof(g_encryptParams055) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { RSA_COMMON_SIZE, cipher };
    ret = HksRsaCipherTest(&keyAlias, encryptParamSet, HKS_KEY_PURPOSE_ENCRYPT, &inData_192, &ciphertext);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_PADDING) << "HksRsaCipherTest(encrypt) failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
}

/**
 * @tc.name: HksRsaCipherPart6Test.HksRsaCipherPart6Test056
 * @tc.desc: alg-RSA pur-ENCRYPT-DECRYPT size-1536 pad-NONE mode-CBC export import.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaCipherPart6Test, HksRsaCipherPart6Test056, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksRSACipherKeyAliasTest056";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams051, sizeof(g_genParams051) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams051, sizeof(g_encryptParams051) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams051, sizeof(g_decryptParams051) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksRsaCipherTestCase(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, &inData_192);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksRsaCipherPart6Test.HksRsaCipherPart6Test057
 * @tc.desc: alg-RSA pur-ENCRYPT-DECRYPT size-1536 pad-NONE mode-EBC, no digest.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaCipherPart6Test, HksRsaCipherPart6Test057, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksRSACipherKeyAliasTest056";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams056, sizeof(g_genParams056) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams056, sizeof(g_encryptParams056) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams056, sizeof(g_decryptParams056) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksRsaCipherTestCase(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, &inData_192);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksRsaCipherPart6Test.HksRsaCipherPart6Test058
 * @tc.desc: alg-RSA pur-ENCRYPT-DECRYPT size-1536 pad-HKS_PADDING_PKCS1_V1_5 mode-EBC, no digest.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaCipherPart6Test, HksRsaCipherPart6Test058, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest058";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams056, sizeof(g_genParams056) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams057, sizeof(g_encryptParams057) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { RSA_COMMON_SIZE, cipher };
    ret = HksRsaCipherTest(&keyAlias, encryptParamSet, HKS_KEY_PURPOSE_ENCRYPT, &inData_96, &ciphertext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTest(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams057, sizeof(g_decryptParams057) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob plaintext = { RSA_COMMON_SIZE, plain };
    ret = HksRsaCipherTest(&keyAlias, decryptParamSet, HKS_KEY_PURPOSE_DECRYPT, &ciphertext, &plaintext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTest(decrypt) failed.";
    EXPECT_EQ(HksMemCmp(inData_96.data, plaintext.data, inData_96.size), HKS_SUCCESS) << "plaintext not equals inData";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}
} // namespace Unittest::RsaCipher
