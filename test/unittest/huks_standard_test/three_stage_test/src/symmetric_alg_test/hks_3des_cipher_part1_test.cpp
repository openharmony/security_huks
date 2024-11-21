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

#include "hks_3des_cipher_test_common.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>
#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::Des3Cipher {
class Hks3DesCipherPart1Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void Hks3DesCipherPart1Test::SetUpTestCase(void)
{
}

void Hks3DesCipherPart1Test::TearDownTestCase(void)
{
}

void Hks3DesCipherPart1Test::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void Hks3DesCipherPart1Test::TearDown()
{
}

static struct HksParam g_genParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }
};
static struct HksParam g_encryptParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
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
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
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
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_192
    }
};
static struct HksParam g_encryptParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_192
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
static struct HksParam g_decryptParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_192
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

static struct HksParam g_genParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }
};
static struct HksParam g_encryptParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    },
};
static struct HksParam g_decryptParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    },
};

static struct HksParam g_genParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_192
    }
};
static struct HksParam g_encryptParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_192
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    },
};
static struct HksParam g_decryptParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_192
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    },
};

static struct HksParam g_genParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }
};

static struct HksParam g_genParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }
};
static struct HksParam g_encryptParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
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

static struct HksParam g_genParams007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }
};
static struct HksParam g_encryptParams007[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
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

static struct HksParam g_genParams008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }
};
static struct HksParam g_encryptParams008[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
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

static struct HksParam g_genParams009[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }
};
static struct HksParam g_encryptParams009[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
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
 * @tc.name: Hks3DesCipherPart1Test.Hks3DesCipherPart1Test001
 * @tc.desc: alg-3DES pur-ENCRYPT&DECRYPT mod-CBC pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(Hks3DesCipherPart1Test, Hks3DesCipherPart1Test001, TestSize.Level0)
{
    HKS_LOG_I("enter Hks3DesCipherPart1Test001");
    char tmpKeyAlias[] = "Hks3DesCipherKeyAliasTest001";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams001, sizeof(g_encryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES3_COMMON_SIZE, cipher };
    ret = Hks3DesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks3DesCipherTest(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams001, sizeof(g_decryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob plaintext = { DES3_COMMON_SIZE, plain };
    ret = Hks3DesCipherTest(&keyAlias, decryptParamSet, &ciphertext, &plaintext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks3DesCipherTest(decrypt) failed.";
    EXPECT_EQ(HksMemCmp(inData.data, plaintext.data, inData.size), HKS_SUCCESS) << "plaintext not equals inData";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: Hks3DesCipherPart1Test.Hks3DesCipherPart1Test002
 * @tc.desc: alg-3DES pur-ENCRYPT&DECRYPT mod-CBC pad-NONE size-192.
 * @tc.type: FUNC
 */
HWTEST_F(Hks3DesCipherPart1Test, Hks3DesCipherPart1Test002, TestSize.Level0)
{
    HKS_LOG_I("enter Hks3DesCipherPart1Test002");
    char tmpKeyAlias[] = "Hks3DesCipherKeyAliasTest002";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams002, sizeof(g_encryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES3_COMMON_SIZE, cipher };
    ret = Hks3DesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks3DesCipherTest(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams002, sizeof(g_decryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob plaintext = { DES3_COMMON_SIZE, plain };
    ret = Hks3DesCipherTest(&keyAlias, decryptParamSet, &ciphertext, &plaintext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks3DesCipherTest(decrypt) failed.";
    EXPECT_EQ(HksMemCmp(inData.data, plaintext.data, inData.size), HKS_SUCCESS) << "plaintext not equals inData";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: Hks3DesCipherPart1Test.Hks3DesCipherPart1Test003
 * @tc.desc: alg-3DES pur-ENCRYPT&DECRYPT mod-ECB pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(Hks3DesCipherPart1Test, Hks3DesCipherPart1Test003, TestSize.Level0)
{
    HKS_LOG_I("enter Hks3DesCipherPart1Test003");
    char tmpKeyAlias[] = "Hks3DesCipherKeyAliasTest003";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams003, sizeof(g_encryptParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES3_COMMON_SIZE, cipher };
    ret = Hks3DesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks3DesCipherTest(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams003, sizeof(g_decryptParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob plaintext = { DES3_COMMON_SIZE, plain };
    ret = Hks3DesCipherTest(&keyAlias, decryptParamSet, &ciphertext, &plaintext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks3DesCipherTest(decrypt) failed.";
    EXPECT_EQ(HksMemCmp(inData.data, plaintext.data, inData.size), HKS_SUCCESS) << "plaintext not equals inData";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: Hks3DesCipherPart1Test.Hks3DesCipherPart1Test004
 * @tc.desc: alg-3DES pur-ENCRYPT&DECRYPT mod-ECB pad-NONE size-192.
 * @tc.type: FUNC
 */
HWTEST_F(Hks3DesCipherPart1Test, Hks3DesCipherPart1Test004, TestSize.Level0)
{
    HKS_LOG_I("enter Hks3DesCipherPart1Test004");
    char tmpKeyAlias[] = "Hks3DesCipherKeyAliasTest004";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams004, sizeof(g_genParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams004, sizeof(g_encryptParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES3_COMMON_SIZE, cipher };
    ret = Hks3DesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks3DesCipherTest(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams004, sizeof(g_decryptParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t plain[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob plaintext = { DES3_COMMON_SIZE, plain };
    ret = Hks3DesCipherTest(&keyAlias, decryptParamSet, &ciphertext, &plaintext);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Hks3DesCipherTest(decrypt) failed.";
    EXPECT_EQ(HksMemCmp(inData.data, plaintext.data, inData.size), HKS_SUCCESS) << "plaintext not equals inData";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: Hks3DesCipherPart1Test.Hks3DesCipherPart1Test005
 * @tc.desc: alg-3DES pur-ENCRYPT&DECRYPT mod-CBC pad-NONE size-256.
 * @tc.type: FUNC
 */
HWTEST_F(Hks3DesCipherPart1Test, Hks3DesCipherPart1Test005, TestSize.Level0)
{
    HKS_LOG_I("enter Hks3DesCipherPart1Test005");
    char tmpKeyAlias[] = "Hks3DesCipherKeyAliasTest005";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams005, sizeof(g_genParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "GenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: Hks3DesCipherPart1Test.Hks3DesCipherPart1Test006
 * @tc.desc: alg-3DES pur-ENCRYPT&DECRYPT mod-CFB pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(Hks3DesCipherPart1Test, Hks3DesCipherPart1Test006, TestSize.Level0)
{
    HKS_LOG_I("enter Hks3DesCipherPart1Test006");
    char tmpKeyAlias[] = "Hks3DesCipherKeyAliasTest006";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams006, sizeof(g_genParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams006, sizeof(g_encryptParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES3_COMMON_SIZE, cipher };
    ret = Hks3DesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_ERROR_CHECK_GET_MODE_FAIL) << "Hks3DesCipherTest(encrypt) failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
}

/**
 * @tc.name: Hks3DesCipherPart1Test.Hks3DesCipherPart1Test007
 * @tc.desc: alg-3DES pur-ENCRYPT&DECRYPT mod-CBC pad-PKCS7 size-128.
 * @tc.type: FUNC
 */
HWTEST_F(Hks3DesCipherPart1Test, Hks3DesCipherPart1Test007, TestSize.Level0)
{
    HKS_LOG_I("enter Hks3DesCipherPart1Test007");
    char tmpKeyAlias[] = "Hks3DesCipherKeyAliasTest007";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams007, sizeof(g_genParams007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams007, sizeof(g_encryptParams007) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES3_COMMON_SIZE, cipher };
    ret = Hks3DesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_PADDING) << "Hks3DesCipherTest(encrypt) failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
}

/**
 * @tc.name: Hks3DesCipherPart1Test.Hks3DesCipherPart1Test008
 * @tc.desc: alg-3DES pur-ENCRYPT&DECRYPT mod-CBC pad-NONE size-128 IV-9.
 * @tc.type: FUNC
 */
HWTEST_F(Hks3DesCipherPart1Test, Hks3DesCipherPart1Test008, TestSize.Level0)
{
    HKS_LOG_I("enter Hks3DesCipherPart1Test008");
    char tmpKeyAlias[] = "Hks3DesCipherKeyAliasTest008";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams008, sizeof(g_genParams008) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams008, sizeof(g_encryptParams008) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES3_COMMON_SIZE, cipher };
    ret = Hks3DesCipherTest(&keyAlias, encryptParamSet, &inData, &ciphertext);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_IV) << "Hks3DesCipherTest(encrypt) failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
}

/**
 * @tc.name: Hks3DesCipherPart1Test.Hks3DesCipherPart1Test009
 * @tc.desc: alg-3DES pur-ENCRYPT&DECRYPT mod-CBC pad-NONE size-128 plaintext-invalid.
 * @tc.type: FUNC
 */
HWTEST_F(Hks3DesCipherPart1Test, Hks3DesCipherPart1Test009, TestSize.Level0)
{
    HKS_LOG_I("enter Hks3DesCipherPart1Test009");
    char tmpKeyAlias[] = "Hks3DesCipherKeyAliasTest009";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams009, sizeof(g_genParams009) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams009, sizeof(g_encryptParams009) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    uint8_t cipher[DES3_COMMON_SIZE] = { 0 };
    struct HksBlob ciphertext = { DES3_COMMON_SIZE, cipher };
    ret = Hks3DesCipherTest(&keyAlias, encryptParamSet, &inDataInvalid, &ciphertext);
    EXPECT_EQ(ret, HKS_FAILURE) << "Hks3DesCipherTest(encrypt) failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
}


} // namespace Unittest::Des3Cipher
