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

#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_sm2_sign_verify_test.h"
#include "hks_type.h"

#include <cstdint>
#include <gtest/gtest.h>

#define HKS_SM2_256 \
{ \
    .tag = HKS_TAG_ALGORITHM, \
    .uint32Param = HKS_ALG_SM2 \
}, { \
    .tag = HKS_TAG_KEY_SIZE, \
    .uint32Param = HKS_SM2_KEY_SIZE_256 \
},

using namespace testing::ext;
namespace Unittest::Sm2SignVerify {
class HksSm2SignVerifyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksSm2SignVerifyTest::SetUpTestCase(void)
{
}

void HksSm2SignVerifyTest::TearDownTestCase(void)
{
}

void HksSm2SignVerifyTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksSm2SignVerifyTest::TearDown()
{
}

#ifdef _USE_OPENSSL_
static const struct GenerateKeyCaseParam POSITIVE_CASE_GEN_PARAM = {
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
            .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SM3
        },
    },
};

static const struct GenerateKeyCaseParam NEGATIVE_CASE_GEN_PARAMS[] = {
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
                .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
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
            HKS_SM2_256
            {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
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
            HKS_SM2_256
            {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_WRAP
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SM3
            },
        },
    },
};

static const struct GenerateKeyCaseParam NON_DIGEST_CASE_GEN_PARAM = {
    4,
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
            .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
        }
    },
};

static const struct GenerateKeyCaseParam POSITIVE_CASE_SIGN_PARAM = {
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
            .uint32Param = HKS_KEY_PURPOSE_SIGN
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SM3
        },
    },
};

static const struct GenerateKeyCaseParam NEGATIVE_CASE_SIGN_PARAMS[] = {
    {
        1,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            {
                .tag = HKS_TAG_ALGORITHM,
                .uint32Param = HKS_ALG_SM2
            }, {
                .tag = HKS_TAG_KEY_SIZE,
                .uint32Param = HKS_AES_KEY_SIZE_512
            }, {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_SIGN
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
            HKS_SM2_256
            {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_SIGN
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SHA1
            },
        },
    },

    {
        3,
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
                .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SM3
            },
        },
    },
};

static const struct GenerateKeyCaseParam NON_DIGEST_CASE_SIGN_PARAM = {
    4,
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
            .uint32Param = HKS_KEY_PURPOSE_SIGN
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_NONE
        },
    },
};

static const struct GenerateKeyCaseParam POSITIVE_CASE_VERIFY_PARAM = {
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
            .uint32Param = HKS_KEY_PURPOSE_VERIFY
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SM3
        },
    },
};

static const struct GenerateKeyCaseParam NEGATIVE_CASE_VERIFY_PARAMS[] = {
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
                .uint32Param = HKS_KEY_PURPOSE_VERIFY
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
            HKS_SM2_256
            {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_VERIFY
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
            HKS_SM2_256
            {
                .tag = HKS_TAG_PURPOSE,
                .uint32Param = HKS_KEY_PURPOSE_DECRYPT
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SM3
            },
        },
    },
};

static const struct GenerateKeyCaseParam NON_DIGEST_CASE_VERIFY_PARAM = {
    4,
    HKS_SUCCESS,
    {
        HKS_SM2_256
        {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_VERIFY
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_NONE
        },
    },
};

static int32_t HksTestSignVerify(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    uint8_t tmpHandle[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), tmpHandle };
    int32_t ret;

    struct HksParam *digestAlg = nullptr;
    ret = HksGetParam(paramSet, HKS_TAG_DIGEST, &digestAlg);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GetParam failed.";

    do {
        ret = HksInit(keyAlias, paramSet, &handle, nullptr);
        if (ret != HKS_SUCCESS) {
            break;
        }

        struct HksParam *tmpParamTest = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &tmpParamTest);
        if (ret != HKS_SUCCESS) {
            break;
        }

        ret = TestUpdateFinish(&handle, paramSet, tmpParamTest->uint32Param, inData, outData);
        if (ret != HKS_SUCCESS) {
            break;
        }
        ret = HKS_SUCCESS;
    } while (0);

    (void)HksAbort(&handle, paramSet);
    return ret;
}

static int CreateImportKeyAlias(struct HksBlob *importKeyAlias, const struct HksBlob *keyAlias)
{
    const char *tmp = "new";
    importKeyAlias->size = keyAlias->size + strlen(tmp);
    importKeyAlias->data = (uint8_t *)HksMalloc(importKeyAlias->size);
    if (importKeyAlias->data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    if (memcpy_s(importKeyAlias->data, importKeyAlias->size, keyAlias->data, keyAlias->size) != EOK) {
        HKS_FREE(importKeyAlias->data);
        return HKS_ERROR_BAD_STATE;
    }

    if (memcpy_s(importKeyAlias->data + keyAlias->size,
        importKeyAlias->size - keyAlias->size, tmp, strlen(tmp)) != EOK) {
        HKS_FREE(importKeyAlias->data);
        return HKS_ERROR_BAD_STATE;
    }

    return HKS_SUCCESS;
}

void static FreeBuffAndDeleteKey(struct HksParamSet **paramSet1, struct HksParamSet **paramSet2,
    struct HksParamSet **paramSet3, const struct HksBlob *keyAlias1, const struct HksBlob *keyAlias2)
{
    (void)HksDeleteKey(keyAlias1, *paramSet1);
    (void)HksDeleteKey(keyAlias2, *paramSet1);
    HksFreeParamSet(paramSet1);
    HksFreeParamSet(paramSet2);
    HksFreeParamSet(paramSet3);
}

struct GenSignVerifyParam {
    struct GenerateKeyCaseParam gen;
    struct GenerateKeyCaseParam sign;
    struct GenerateKeyCaseParam verify;
};

static int32_t HksSm2SignVerifyTestRun(const struct HksBlob *keyAlias, const GenSignVerifyParam &param,
    const bool isTestSignData, const struct HksBlob *inData)
{
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    uint8_t outDataS[SM2_COMMON_SIZE] = {0};
    struct HksBlob outDataSign = { SM2_COMMON_SIZE, outDataS };

    uint8_t pubKey[HKS_MAX_KEY_LEN] = {0};
    struct HksBlob publicKey = { HKS_MAX_KEY_LEN, pubKey };

    struct HksBlob importKeyAlias;
    int32_t ret = CreateImportKeyAlias(&importKeyAlias, keyAlias);
    EXPECT_EQ(ret, HKS_SUCCESS) << "createImportKeyAlias failed.";
    do {
        /* 1. Generate Key */
        ret = InitParamSet(&genParamSet, param.gen.params.data(), param.gen.params.size());
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitGenParamSet failed.";
        ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
        if (ret != HKS_SUCCESS) {
            ret = ((ret == param.gen.result) ? HKS_SUCCESS : ret);
            break;
        }

        /* 2. Sign Three Stage */
        ret = InitParamSet(&signParamSet, param.sign.params.data(), param.sign.params.size());
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitSignParamSet failed.";
        ret = HksTestSignVerify(keyAlias, signParamSet, inData, &outDataSign);
        if (ret != HKS_SUCCESS) {
            ret = ((ret == param.sign.result) ? HKS_SUCCESS : ret);
            break;
        }

        /* 3. Export Public Key */
        EXPECT_EQ(HksExportPublicKey(keyAlias, genParamSet, &publicKey), HKS_SUCCESS) << "ExportPublicKey failed.";

        /* 4. Import Key */
        ret = InitParamSet(&verifyParamSet, param.verify.params.data(), param.verify.params.size());
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitVerifyParamSet failed.";
        ret = HksImportKey(&importKeyAlias, verifyParamSet, &publicKey);
        if (ret != HKS_SUCCESS) {
            ret = ((ret == param.verify.result) ? HKS_SUCCESS : ret);
            break;
        }

        /* 5. Verify Three Stage */
        if (isTestSignData) {
            (void)memset_s(outDataSign.data, outDataSign.size, 0, outDataSign.size);
        }
        ret = HksTestSignVerify(&importKeyAlias, verifyParamSet, inData, &outDataSign);
        if (ret != HKS_SUCCESS) {
            ret = ((ret == param.verify.result) ? HKS_SUCCESS : ret);
        }
    } while (0);

    FreeBuffAndDeleteKey(&genParamSet, &signParamSet, &verifyParamSet, keyAlias, &importKeyAlias);
    HKS_FREE(importKeyAlias.data);
    return ret;
}

/**
 * @tc.name: HksSm2SignVerifyTest.HksSm2SignVerifyTest001
 * @tc.desc: normal parameter test case : alg-SM2, pur-Sign/Verify, keySize-256 and dig-SM3.
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2SignVerifyTest, HksSm2SignVerifyTest001, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2SignVerifyTest001");
    const char *keyAliasString = "HksSM2SignVerifyKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksBlob inData = { g_inData.length(), (uint8_t *)g_inData.c_str() };
    GenSignVerifyParam param { POSITIVE_CASE_GEN_PARAM, POSITIVE_CASE_SIGN_PARAM, POSITIVE_CASE_VERIFY_PARAM };
    int ret = HksSm2SignVerifyTestRun(&keyAlias, param, false, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "sm2SignVerifyTest001 failed.";
}

/**
 * @tc.name: HksSm2SignVerifyTest.HksSm2SignVerifyTest002
 * @tc.desc: abnormal parameter test cases : the abnormal parameter is tag
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2SignVerifyTest, HksSm2SignVerifyTest002, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2SignVerifyTest002");
    const char *keyAliasString = "HksSM2SignVerifyKeyAliasTest002";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksBlob inData = { g_inData.length(), (uint8_t *)g_inData.c_str() };

    int ret;
    for (const struct GenerateKeyCaseParam &negativeGenParam : NEGATIVE_CASE_GEN_PARAMS) {
        GenSignVerifyParam param { negativeGenParam, POSITIVE_CASE_SIGN_PARAM, POSITIVE_CASE_VERIFY_PARAM };
        ret = HksSm2SignVerifyTestRun(&keyAlias, param, false, &inData);
        EXPECT_EQ(ret, HKS_SUCCESS) << "sm2SignVerifyTest002 gen abnormal test failed.";
    }

    for (const struct GenerateKeyCaseParam &negativeSignParam : NEGATIVE_CASE_SIGN_PARAMS) {
        GenSignVerifyParam param { POSITIVE_CASE_GEN_PARAM, negativeSignParam, POSITIVE_CASE_VERIFY_PARAM };
        ret = HksSm2SignVerifyTestRun(&keyAlias, param, false, &inData);
        EXPECT_EQ(ret, HKS_SUCCESS) << "sm2SignVerifyTest002 sign abnormal test failed.";
    }

    for (const struct GenerateKeyCaseParam &negativeVerifyParam : NEGATIVE_CASE_VERIFY_PARAMS) {
        GenSignVerifyParam param { POSITIVE_CASE_GEN_PARAM, POSITIVE_CASE_SIGN_PARAM, negativeVerifyParam };
        ret = HksSm2SignVerifyTestRun(&keyAlias, param, false, &inData);
        EXPECT_EQ(ret, HKS_SUCCESS) << "sm2SignVerifyTest002 verify abnormal test failed.";
    }
}

/**
 * @tc.name: HksSm2SignVerifyTest.HksSm2SignVerifyTest003
 * @tc.desc: abnormal parameter test case : the abnormal parameter is verifyData
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2SignVerifyTest, HksSm2SignVerifyTest003, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2SignVerifyTest003");
    const char *keyAliasString = "HksSM2SignVerifyKeyAliasTest003";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksBlob inData = { g_inData.length(), (uint8_t *)g_inData.c_str() };

    GenSignVerifyParam param { POSITIVE_CASE_GEN_PARAM, POSITIVE_CASE_SIGN_PARAM, POSITIVE_CASE_VERIFY_PARAM };
    int ret = HksSm2SignVerifyTestRun(&keyAlias, param, true, &inData);
    EXPECT_EQ(ret, HKS_FAILURE) << "sm2SignVerifyTest003 failed.";
}

/**
 * @tc.name: HksSm2SignVerifyTest.HksSm2SignVerifyTest004
 * @tc.desc: normal parameter test case : alg-SM2, pur-Sign/Verify,
 *           keySize-256 and dig-NONE, message size is SM3 digest size
 * @tc.type: FUNC
 * @tc.require:issueI611S5
 */
HWTEST_F(HksSm2SignVerifyTest, HksSm2SignVerifyTest004, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2SignVerifyTest004");
    const char *keyAliasString = "HksSM2SignVerifyKeyAliasTest004";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksBlob inData = { sizeof(DATA_AFTER_SHA256_HASH), (uint8_t *)DATA_AFTER_SHA256_HASH };
    GenSignVerifyParam param { NON_DIGEST_CASE_GEN_PARAM, NON_DIGEST_CASE_SIGN_PARAM, NON_DIGEST_CASE_VERIFY_PARAM };
    int ret = HksSm2SignVerifyTestRun(&keyAlias, param, false, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "sm2SignVerifyTest004 failed.";
}

/**
 * @tc.name: HksSm2SignVerifyTest.HksSm2SignVerifyTest005
 * @tc.desc: abnormal parameter test case : alg-SM2, pur-Sign/Verify,
 *           keySize-256 and dig-NONE, message size isn't SM3 digest size
 * @tc.type: FUNC
 * @tc.require:issueI611S5
 */
HWTEST_F(HksSm2SignVerifyTest, HksSm2SignVerifyTest005, TestSize.Level0)
{
    HKS_LOG_E("Enter HksSm2SignVerifyTest005");
    const char *keyAliasString = "HksSM2SignVerifyKeyAliasTest005";
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };
    struct HksBlob inData = { g_inData.length(), (uint8_t *)g_inData.c_str() };
    GenSignVerifyParam param { NON_DIGEST_CASE_GEN_PARAM, NON_DIGEST_CASE_SIGN_PARAM, NON_DIGEST_CASE_VERIFY_PARAM };
    int ret = HksSm2SignVerifyTestRun(&keyAlias, param, false, &inData);
    EXPECT_NE(ret, HKS_SUCCESS) << "sm2SignVerifyTest005 failed.";
}
#endif
}
