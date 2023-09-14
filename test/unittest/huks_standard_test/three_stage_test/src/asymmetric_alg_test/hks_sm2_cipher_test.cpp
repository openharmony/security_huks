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

#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_sm2_cipher_test.h"
#include "hks_type.h"
#include "hks_log.h"

#include <cstdint>
#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::Sm2Cipher {
class HksSm2CipherTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksSm2CipherTest::SetUpTestCase(void)
{
}

void HksSm2CipherTest::TearDownTestCase(void)
{
}

void HksSm2CipherTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksSm2CipherTest::TearDown()
{
}

#ifdef _USE_OPENSSL_
static const struct TestCaseParam POSITIVE_CASE_GEN_PARAM = {
    0,
    HKS_SUCCESS,
    {
        {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_SM2
        }, {
            .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = HKS_SM2_KEY_SIZE_256
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SM3
        },
    },
};

static const struct TestCaseParam NEGATIVE_CASE_GEN_PARAMS[] = {
    {
        1,
        HKS_ERROR_INVALID_KEY_SIZE,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM2
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = HKS_AES_KEY_SIZE_512
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SM3
            },
        },
    },

    {
        2,
        HKS_ERROR_INVALID_DIGEST,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM2
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = HKS_SM2_KEY_SIZE_256
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SHA1
            },
        },
    },

    {
        3,
        HKS_ERROR_INVALID_PURPOSE,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM2
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = HKS_SM2_KEY_SIZE_256
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_WRAP
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SM3
            },
        },
    }
};

static const struct TestCaseParam NON_DIGEST_CASE_GEN_PARAM =  {
    4,
    HKS_FAILURE,
    {
        {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_SM2
        }, {
            .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = HKS_SM2_KEY_SIZE_256
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
        }
    },
};

static const struct TestCaseParam POSITIVE_CASE_ENCRYPT_PARAM = {
    0,
    HKS_SUCCESS,
    {
        {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_SM2
        }, {
            .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = HKS_SM2_KEY_SIZE_256
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SM3
        },
    },
};

static const struct TestCaseParam NEGATIVE_CASE_ENCRYPT_PARAMS[] = {
    {
        1,
        HKS_ERROR_INVALID_KEY_SIZE,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM2
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = HKS_AES_KEY_SIZE_512
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SM3
            },
        },
    },

    {
        2,
        HKS_ERROR_INVALID_DIGEST,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM2
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = HKS_SM2_KEY_SIZE_256
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SHA1
            },
        },
    },
    {
        3,
        HKS_ERROR_INVALID_DIGEST,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM2
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = HKS_SM2_KEY_SIZE_256
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_MD5
            },
        },
    },
    {
        4,
        HKS_FAILURE,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM2
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = HKS_SM2_KEY_SIZE_256
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_NONE
            },
        }
    }
};

static const struct TestCaseParam NON_DIGEST_CASE_ENCRYPT_PARAM = {
    4,
    HKS_FAILURE,
    {
        {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_SM2
        }, {
            .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = HKS_SM2_KEY_SIZE_256
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_NONE
        },
    },
};

static const struct TestCaseParam POSITIVE_CASE_DECRYPT_PARAM = {
    0,
    HKS_SUCCESS,
    {
        {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_SM2
        }, {
            .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = HKS_SM2_KEY_SIZE_256
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SM3
        },
    },
};

static const struct TestCaseParam NEGATIVE_CASE_DECRYPT_PARAMS[] = {
    {
        1,
        HKS_ERROR_INVALID_KEY_SIZE,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM2
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = HKS_AES_KEY_SIZE_512
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_DECRYPT
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SM3
            },
        },
    },

    {
        2,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM2
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = HKS_SM2_KEY_SIZE_256
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_DECRYPT
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SHA1
            },
        },
    },
};

static const struct TestCaseParam NON_DIGEST_CASE_DECRYPT_PARAM = {
    4,
    HKS_FAILURE,
    {
        {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_SM2
        }, {
            .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = HKS_SM2_KEY_SIZE_256
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_NONE
        },
    },
};

static int32_t HksSm2CipherTestEncrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *encryptParamSet, const struct HksBlob *inData, struct HksBlob *cipherText)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    int32_t ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksSm2CipherTestEncrypt ->Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = TestUpdateFinish(&handleEncrypt, encryptParamSet, HKS_KEY_PURPOSE_ENCRYPT, inData, cipherText);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_NE(HksMemCmp(inData->data, cipherText->data, inData->size), HKS_SUCCESS) << "cipherText equals inData";

    uint8_t tmpOut[SM2_COMMON_SIZE] = {0};
    struct HksBlob outData = { SM2_COMMON_SIZE, tmpOut };
    ret = HksEncrypt(keyAlias, encryptParamSet, inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEncrypt failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    return HKS_SUCCESS;
}

static int32_t HksSm2CipherTestDecrypt(const struct HksBlob *keyAlias, const struct HksParamSet *decryptParamSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText, const struct HksBlob *inData)
{
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handleD };
    int32_t ret = HksInit(keyAlias, decryptParamSet, &handleDecrypt, nullptr);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = TestUpdateFinish(&handleDecrypt, decryptParamSet, HKS_KEY_PURPOSE_DECRYPT, cipherText, plainText);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(inData->data, plainText->data, inData->size), HKS_SUCCESS) << "plainText not equals inData";

    uint8_t tmpOut[SM2_COMMON_SIZE] = {0};
    struct HksBlob outData = { SM2_COMMON_SIZE, tmpOut };
    ret = HksDecrypt(keyAlias, decryptParamSet, cipherText, &outData);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(outData.data, plainText->data, outData.size), HKS_SUCCESS) << "plainText not equals outData";

    return HKS_SUCCESS;
}

static void FreeBuffAndDeleteKey(struct HksParamSet **paramSet1, struct HksParamSet **paramSet2,
    struct HksParamSet **paramSet3, const struct HksBlob *keyAlias1, const struct HksBlob *keyAlias2)
{
    (void)HksDeleteKey(keyAlias1, *paramSet1);
    (void)HksDeleteKey(keyAlias2, *paramSet1);
    HksFreeParamSet(paramSet1);
    HksFreeParamSet(paramSet2);
    HksFreeParamSet(paramSet3);
}

static int32_t HksSm2CipherTestRun(const struct HksBlob *keyAlias, const GenEncryptDecryptParam &param,
    const struct HksBlob *inData, struct HksBlob *cipherText)
{
    struct HksParamSet *genParamSet, *encryptParamSet, *decryptParamSet;
    int32_t ret = InitParamSet(&genParamSet, param.gen.params.data(), param.gen.params.size());
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitGenParamSet failed.";

    ret = InitParamSet(&encryptParamSet, param.encrypt.params.data(), param.encrypt.params.size());
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitEncryptParamSet failed.";

    char tmpKey[] = "SM2_Encrypt_Decrypt_KeyAlias";
    struct HksBlob newKeyAlias = { .size = strlen(tmpKey), .data = reinterpret_cast<uint8_t *>(tmpKey) };

    uint8_t pubKey[HKS_SM2_KEY_SIZE_256] = {0};
    struct HksBlob publicKey = { HKS_SM2_KEY_SIZE_256, pubKey };

    do {
        ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
        if (ret != HKS_SUCCESS) {
            ret = ((ret == param.gen.result) ? HKS_SUCCESS : ret);
            EXPECT_EQ(ret, HKS_SUCCESS) << "Generate Key err code don't meet expectation.";
            break;
            }
        ret = HksExportPublicKey(keyAlias, genParamSet, &publicKey);
        EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey failed.";

        ret = HksImportKey(&newKeyAlias, encryptParamSet, &publicKey);
        if (ret != HKS_SUCCESS) {
            ret = ((ret == param.encrypt.result) ? HKS_SUCCESS : ret);
            EXPECT_EQ(ret, HKS_SUCCESS) << "Import Key failed.";
            break;
        }
        /* Encrypt Three Stage */
        ret = HksSm2CipherTestEncrypt(&newKeyAlias, encryptParamSet, inData, cipherText);
        if (ret != HKS_SUCCESS) {
            ret = ((ret == param.encrypt.result) ? HKS_SUCCESS : ret);
            break;
        }
        /* Decrypt Three Stage */
        ret = InitParamSet(&decryptParamSet, param.decrypt.params.data(), param.decrypt.params.size());
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitDecryptParamSet failed.";

        uint8_t plain[SM2_COMMON_SIZE] = {0};
        struct HksBlob plainText = { SM2_COMMON_SIZE, plain };
        ret = HksSm2CipherTestDecrypt(keyAlias, decryptParamSet, cipherText, &plainText, inData);
        if (ret != HKS_SUCCESS) {
            ret = ((ret == param.decrypt.result) ? HKS_SUCCESS : ret);
            EXPECT_EQ(ret, HKS_SUCCESS) << "Decrypt Three Stage: err code don't meet expectation.";
            break;
        }
    } while (0);
    FreeBuffAndDeleteKey(&genParamSet, &encryptParamSet, &decryptParamSet, keyAlias, &newKeyAlias);
    return ret;
}

/**
 * @tc.name: HksSm2CipherTest.HksSm2CipherTest001
 * @tc.desc: normal parameter test case : alg-SM2, pur-encrypt/decrypt, keySize-256 and dig-SM3.
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2CipherTest, HksSm2CipherTest001, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2CipherTest001");
    const char *keyAliasString = "HksSm2CipherTest001AliasTest001";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksBlob inData = { g_inData.length(), (uint8_t *)g_inData.c_str() };
    uint8_t cipher[SM2_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { SM2_COMMON_SIZE, cipher };
    GenEncryptDecryptParam param { POSITIVE_CASE_GEN_PARAM, POSITIVE_CASE_ENCRYPT_PARAM,
        POSITIVE_CASE_DECRYPT_PARAM };
    int ret = HksSm2CipherTestRun(&keyAlias, param, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest001 failed.";

    cipher[1] = {0};
    struct HksBlob cipherText2 = { 1, cipher };
    ret = HksSm2CipherTestRun(&keyAlias, param, &inData, &cipherText2);
    EXPECT_NE(ret, HKS_SUCCESS) << "sm2CipherTest001.2 failed.";
}

/**
 * @tc.name: HksSm2CipherTest.HksSm2CipherTest002
 * @tc.desc: abnormal parameter test cases : the abnormal parameter is tag
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2CipherTest, HksSm2CipherTest002, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2CipherTest002");
    const char *keyAliasString = "HksSM2CipherKeyAliasTest002";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksBlob inData = { g_inData.length(), (uint8_t *)g_inData.c_str() };
    uint8_t cipher[SM2_COMMON_SIZE] = {0};
    struct HksBlob cipherText;

    int ret;
    for (const struct TestCaseParam &negativeGenParam : NEGATIVE_CASE_GEN_PARAMS) {
        GenEncryptDecryptParam param { negativeGenParam, POSITIVE_CASE_ENCRYPT_PARAM,
            POSITIVE_CASE_DECRYPT_PARAM };
        cipherText = { SM2_COMMON_SIZE, cipher };
        ret = HksSm2CipherTestRun(&keyAlias, param, &inData, &cipherText);
        EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest002 gen abnormal test failed.";
    }

    for (const struct TestCaseParam &negativeEncryptParam : NEGATIVE_CASE_ENCRYPT_PARAMS) {
        GenEncryptDecryptParam param { POSITIVE_CASE_GEN_PARAM, negativeEncryptParam,
            POSITIVE_CASE_DECRYPT_PARAM };
        cipherText = { SM2_COMMON_SIZE, cipher };
        ret = HksSm2CipherTestRun(&keyAlias, param, &inData, &cipherText);
        EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest002 encrypt abnormal test failed.";
    }

    for (const struct TestCaseParam &negativeDecryptParam : NEGATIVE_CASE_DECRYPT_PARAMS) {
        GenEncryptDecryptParam param { POSITIVE_CASE_GEN_PARAM, POSITIVE_CASE_ENCRYPT_PARAM,
            negativeDecryptParam };
        cipherText = { SM2_COMMON_SIZE, cipher };
        ret = HksSm2CipherTestRun(&keyAlias, param, &inData, &cipherText);
        EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest002 decrypt abnormal test failed.";
    }
}

/**
 * @tc.name: HksSm2CipherTest.HksSm2CipherTest003
 * @tc.desc: normal parameter test case : alg-SM2, pur-encrypt/decrypt,
 *           keySize-256 and dig-NONE, message size is SM3 digest size
 * @tc.type: FUNC
 * @tc.require:issueI611S5
 */
HWTEST_F(HksSm2CipherTest, HksSm2CipherTest003, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2CipherTest003");
    const char *keyAliasString = "HksSM2CipherKeyAliasTest003";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksBlob inData = { sizeof(DATA_AFTER_SHA256_HASH), (uint8_t *)DATA_AFTER_SHA256_HASH };
    uint8_t cipher[SM2_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { SM2_COMMON_SIZE, cipher };
    GenEncryptDecryptParam param { NON_DIGEST_CASE_GEN_PARAM, NON_DIGEST_CASE_ENCRYPT_PARAM,
        NON_DIGEST_CASE_DECRYPT_PARAM };
    int ret = HksSm2CipherTestRun(&keyAlias, param, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest003 failed.";
}

/**
 * @tc.name: HksSm2CipherTest.HksSm2CipherTest004
 * @tc.desc: normal parameter test case : alg-SM2, pur-encrypt/decrypt, keySize-256 and dig-SM3.
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2CipherTest, HksSm2CipherTest004, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2CipherTest004");
    const char *keyAliasString = "HksSm2CipherTest004AliasTest004";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    for (int16_t i = 0; i < INDATA_LEN; i++) {
        struct HksBlob inData = { g_inDataArr[i].length(), (uint8_t *)g_inDataArr[i].c_str() };
        uint8_t cipher[SM2_COMMON_SIZE] = {0};
        struct HksBlob cipherText = { SM2_COMMON_SIZE, cipher };
        GenEncryptDecryptParam param { POSITIVE_CASE_GEN_PARAM, POSITIVE_CASE_ENCRYPT_PARAM,
            POSITIVE_CASE_DECRYPT_PARAM };
        int ret = HksSm2CipherTestRun(&keyAlias, param, &inData, &cipherText);
        EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest004 failed.";
    }
}

static int32_t HksSm2CipherTestEncryptByNdk(const struct OH_Huks_Blob *keyAlias,
    const struct HksParamSet *encryptParamSet, const struct OH_Huks_Blob *inData, struct OH_Huks_Blob *cipherText)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleEncrypt = { sizeof(uint64_t), handleE };
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, (OH_Huks_ParamSet *) encryptParamSet, &handleEncrypt, nullptr);
    EXPECT_EQ(ret.errorCode, HKS_SUCCESS) << "HksSm2CipherTestEncrypt ->Init failed.";
    if (ret.errorCode != HKS_SUCCESS) {
        return ret.errorCode;
    }

    ret = OH_Huks_FinishSession(&handleEncrypt, (OH_Huks_ParamSet *) encryptParamSet, inData, cipherText);
    if (ret.errorCode != HKS_SUCCESS) {
        return ret.errorCode;
    }
    EXPECT_NE(HksMemCmp(inData->data, cipherText->data, inData->size), HKS_SUCCESS) << "cipherText equals inData";

    return ret.errorCode;
}

static int32_t HksSm2CipherTestDecryptByNdk(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *decryptParamSet, const struct OH_Huks_Blob *cipherText,
    struct OH_Huks_Blob *plainText, const struct OH_Huks_Blob *inData)
{
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleDecrypt = { sizeof(uint64_t), handleD };
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, decryptParamSet, &handleDecrypt, nullptr);
    if (ret.errorCode != HKS_SUCCESS) {
        return ret.errorCode;
    }

    ret = OH_Huks_FinishSession(&handleDecrypt, (OH_Huks_ParamSet *) decryptParamSet, cipherText, plainText);
    if (ret.errorCode != HKS_SUCCESS) {
        return ret.errorCode;
    }
    EXPECT_EQ(HksMemCmp(inData->data, plainText->data, inData->size), HKS_SUCCESS) << "plainText not equals inData";

    return ret.errorCode;
}

static int32_t HksSm2CipherTestRunByNdk(const struct OH_Huks_Blob *keyAlias, const GenEncryptDecryptParam &param,
    const struct OH_Huks_Blob *inData)
{
    struct HksParamSet *genParamSet, *encryptParamSet, *decryptParamSet;
    int32_t ret = InitParamSet(&genParamSet, param.gen.params.data(), param.gen.params.size());
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitGenParamSet failed.";

    ret = InitParamSet(&encryptParamSet, param.encrypt.params.data(), param.encrypt.params.size());
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitEncryptParamSet failed.";

    char tmpKey[] = "SM2_Encrypt_Decrypt_KeyAlias";
    struct OH_Huks_Blob newKeyAlias = { .size = strlen(tmpKey), .data = reinterpret_cast<uint8_t *>(tmpKey) };

    uint8_t pubKey[HKS_SM2_KEY_SIZE_256] = {0};
    struct OH_Huks_Blob publicKey = { HKS_SM2_KEY_SIZE_256, pubKey };

    do {
        ret = OH_Huks_GenerateKeyItem(keyAlias, (OH_Huks_ParamSet *) genParamSet, nullptr).errorCode;
        if (ret != HKS_SUCCESS) {
            ret = ((param.gen.result != HKS_SUCCESS) ? HKS_SUCCESS : ret);
            EXPECT_EQ(ret, HKS_SUCCESS) << "OH_Huks_GenerateKeyItem err code don't meet expectation.";
            break;
            }
        ret = OH_Huks_ExportPublicKeyItem(keyAlias, (OH_Huks_ParamSet *) encryptParamSet, &publicKey).errorCode;
        EXPECT_EQ(ret, HKS_SUCCESS) << "OH_Huks_ExportPublicKeyItem failed.";

        ret = OH_Huks_ImportKeyItem(&newKeyAlias, (OH_Huks_ParamSet *) encryptParamSet, &publicKey).errorCode;
        if (ret != HKS_SUCCESS) {
            ret = ((param.encrypt.result != HKS_SUCCESS) ? HKS_SUCCESS : ret);
            EXPECT_EQ(ret, HKS_SUCCESS) << "OH_Huks_ImportKeyItem failed.";
            break;
        }

        /* Encrypt Three Stage */
        uint8_t cipher[SM2_COMMON_SIZE] = {0};
        struct OH_Huks_Blob cipherText = { SM2_COMMON_SIZE, cipher };
        ret = HksSm2CipherTestEncryptByNdk(&newKeyAlias, encryptParamSet, inData, &cipherText);
        if (ret != HKS_SUCCESS) {
            ret = ((param.encrypt.result != HKS_SUCCESS) ? HKS_SUCCESS : ret);
            EXPECT_EQ(ret, HKS_SUCCESS) << "Encrypt Three Stage: err code don't meet expectation.";
            break;
        }
        /* Decrypt Three Stage */
        ret = InitParamSet(&decryptParamSet, param.decrypt.params.data(), param.decrypt.params.size());
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitDecryptParamSet failed.";

        uint8_t plain[SM2_COMMON_SIZE] = {0};
        struct OH_Huks_Blob plainText = { SM2_COMMON_SIZE, plain };
        ret = HksSm2CipherTestDecryptByNdk(keyAlias, (OH_Huks_ParamSet *) decryptParamSet,
            &cipherText, &plainText, inData);
        if (ret != HKS_SUCCESS) {
            ret = ((param.decrypt.result != HKS_SUCCESS) ? HKS_SUCCESS : ret);
            EXPECT_EQ(ret, HKS_SUCCESS) << "Decrypt Three Stage: err code don't meet expectation.";
            break;
        }
    } while (0);
    OH_Huks_Blob *tp_blob = &newKeyAlias;
    FreeBuffAndDeleteKey(&genParamSet, &encryptParamSet, &decryptParamSet,
        (HksBlob *) keyAlias, (HksBlob *) tp_blob);
    return ret;
}

/**
 * @tc.name: HksSm2CipherTest.HksSm2CipherTest005
 * @tc.desc: normal parameter test case : alg-SM2, pur-encrypt/decrypt, keySize-256 and dig-SM3.
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2CipherTest, HksSm2CipherTest005, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2CipherTest005");
    const char *keyAliasString = "HksSm2CipherTest001AliasTest005";
    struct OH_Huks_Blob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct OH_Huks_Blob inData = { g_inData.length(), (uint8_t *)g_inData.c_str() };
    GenEncryptDecryptParam param { POSITIVE_CASE_GEN_PARAM, POSITIVE_CASE_ENCRYPT_PARAM,
        POSITIVE_CASE_DECRYPT_PARAM };
    int ret = HksSm2CipherTestRunByNdk(&keyAlias, param, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest005 failed.";
}

/**
 * @tc.name: HksSm2CipherTest.HksSm2CipherTest006
 * @tc.desc: abnormal parameter test cases : the abnormal parameter is tag
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2CipherTest, HksSm2CipherTest006, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2CipherTest006");
    const char *keyAliasString = "HksSM2CipherKeyAliasTest006";
    struct OH_Huks_Blob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct OH_Huks_Blob inData = { g_inData.length(), (uint8_t *)g_inData.c_str() };

    int ret;
    for (const struct TestCaseParam &negativeGenParam : NEGATIVE_CASE_GEN_PARAMS) {
        GenEncryptDecryptParam param { negativeGenParam, POSITIVE_CASE_ENCRYPT_PARAM,
            POSITIVE_CASE_DECRYPT_PARAM };
        ret = HksSm2CipherTestRunByNdk(&keyAlias, param, &inData);

        EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest006 gen abnormal test failed.";
    }

    for (const struct TestCaseParam &negativeEncryptParam : NEGATIVE_CASE_ENCRYPT_PARAMS) {
        GenEncryptDecryptParam param { POSITIVE_CASE_GEN_PARAM, negativeEncryptParam,
            POSITIVE_CASE_DECRYPT_PARAM };
        ret = HksSm2CipherTestRunByNdk(&keyAlias, param, &inData);
        EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest006 encrypt abnormal test failed.";
    }

    for (const struct TestCaseParam &negativeDecryptParam : NEGATIVE_CASE_DECRYPT_PARAMS) {
        GenEncryptDecryptParam param { POSITIVE_CASE_GEN_PARAM, POSITIVE_CASE_ENCRYPT_PARAM,
            negativeDecryptParam };
        ret = HksSm2CipherTestRunByNdk(&keyAlias, param, &inData);
        EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest006 decrypt abnormal test failed.";
    }
}

/**
 * @tc.name: HksSm2CipherTest.HksSm2CipherTest007
 * @tc.desc: normal parameter test case : alg-SM2, pur-encrypt/decrypt,
 *           keySize-256 and dig-NONE, message size is SM3 digest size
 * @tc.type: FUNC
 * @tc.require:issueI611S5
 */
HWTEST_F(HksSm2CipherTest, HksSm2CipherTest007, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2CipherTest007");
    const char *keyAliasString = "HksSM2CipherKeyAliasTest007";
    struct OH_Huks_Blob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct OH_Huks_Blob inData = { sizeof(DATA_AFTER_SHA256_HASH), (uint8_t *)DATA_AFTER_SHA256_HASH };
    GenEncryptDecryptParam param { NON_DIGEST_CASE_GEN_PARAM, NON_DIGEST_CASE_ENCRYPT_PARAM,
        NON_DIGEST_CASE_DECRYPT_PARAM };
    int ret = HksSm2CipherTestRunByNdk(&keyAlias, param, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "sm2CipherTest007 failed.";
}
#endif
}