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

#include "hks_sm2_sign_verify_test.h"

#include <gtest/gtest.h>

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
static const struct GenerateKeyCaseParam g_genParamsTest[] = {
    {   0,
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
    },

    {   1,
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

    {   2,
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
                .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SHA1
            },
        },
    },
};
static const struct GenerateKeyCaseParam g_signParamsTest[] = {
    {   0,
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
    },

    {   1,
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
                .uint32Param = HKS_KEY_PURPOSE_SIGN
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SM3
            },
        },
    },

    {   2,
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
                .uint32Param = HKS_KEY_PURPOSE_SIGN
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SHA1
            },
        },
    },
};
static const struct GenerateKeyCaseParam g_verifyParamsTest[] = {
    {   0,
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
    },

    {   1,
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

    {   2,
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
                .uint32Param = HKS_KEY_PURPOSE_VERIFY
            }, {
                .tag = HKS_TAG_DIGEST,
                .uint32Param = HKS_DIGEST_SHA1
            },
        },
    },
};

static int32_t HksTestSignVerify(struct HksBlob *keyAlias, struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData, bool isSign)
{
    (void)isSign;
    uint8_t tmpHandle[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), tmpHandle };
    int32_t ret = HksInit(keyAlias, paramSet, &handle);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    struct HksParam *tmpParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &tmpParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get tag purpose failed.");
        return HKS_FAILURE;
    }

    ret = TestUpdateFinish(&handle, paramSet, tmpParam->uint32Param, inData, outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateFinish failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    ret = HksAbort(&handle, paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    return ret;
}

static int32_t HksSm2SignVerifyTestNormalCase(struct HksBlob keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet)
{
    struct HksBlob inData = {
        g_inData.length(),
        (uint8_t *)g_inData.c_str()
    };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("GenerateKey failed");
    }

    /* 2. Sign Three Stage */
    uint8_t outDataS[SM2_COMMON_SIZE] = {0};
    struct HksBlob outDataSign = { SM2_COMMON_SIZE, outDataS };
    ret = HksTestSignVerify(&keyAlias, signParamSet, &inData, &outDataSign, true);
    EXPECT_EQ(ret, HKS_SUCCESS) << "outSign failed.";

    /* 3. Export Public Key */
    uint8_t pubKey[HKS_MAX_KEY_LEN] = {0};
    struct HksBlob publicKey = { HKS_MAX_KEY_LEN, pubKey };
    ret = HksExportPublicKey(&keyAlias, genParamSet, &publicKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey failed.";

    /* 4. Import Key */
    char newKey[] = "SM2_Sign_Verify_Import_KeyAlias";
    struct HksBlob newKeyAlias = { .size = strlen(newKey), .data = (uint8_t *)newKey };
    ret = HksImportKey(&newKeyAlias, verifyParamSet, &publicKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ImportKey failed";

    /* 5. Verify Three Stage */
    ret = HksTestSignVerify(&newKeyAlias, verifyParamSet, &inData, &outDataSign, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Verify failed.";

    /* 6. Delete New Key */
    int32_t deleteRet = HksDeleteKey(&newKeyAlias, genParamSet);
    EXPECT_EQ(deleteRet, HKS_SUCCESS) << "Delete key failed.";

    return ret;
}

/**
 * @tc.name: HksSm2SignVerifyTest.HksSm2SignVerifyTest001
 * @tc.desc: alg-SM2 pur-Sign.
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2SignVerifyTest, HksSm2SignVerifyTest001, TestSize.Level0)
{
    const char *keyAliasString = "HksSM2SignVerifyKeyAliasTest001";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    uint32_t index = 0;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_genParamsTest[index].params,
        sizeof(g_genParamsTest[index].params)/sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest[index].params,
        sizeof(g_signParamsTest[index].params)/sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest[index].params,
        sizeof(g_verifyParamsTest[index].params)/sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksSm2SignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
        EXPECT_EQ(ret, HKS_SUCCESS) << "Sm2SignVerify SuccessCase failed.";
    }

    /* Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksSm2SignVerifyTest.HksSm2SignVerifyTest002
 * @tc.desc: alg-SM2 pur-Sign.
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2SignVerifyTest, HksSm2SignVerifyTest002, TestSize.Level0)
{
    const char *keyAliasString = "HksSM2SignVerifyKeyAliasTest002";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    uint32_t index = 1;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_genParamsTest[index].params,
        sizeof(g_genParamsTest[index].params)/sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest[index].params,
        sizeof(g_signParamsTest[index].params)/sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest[index].params,
        sizeof(g_verifyParamsTest[index].params)/sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksSm2SignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
        EXPECT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "Sm2SignVerify FailureCase failed.";
    }

    /* Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "DeleteKey success.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksSm2SignVerifyTest.HksSm2SignVerifyTest002
 * @tc.desc: alg-SM2 pur-Sign.
 * @tc.type: FUNC
 */
HWTEST_F(HksSm2SignVerifyTest, HksSm2SignVerifyTest003, TestSize.Level0)
{
    const char *keyAliasString = "HksSM2SignVerifyKeyAliasTest003";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    uint32_t index = 2;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_genParamsTest[index].params,
        sizeof(g_genParamsTest[index].params)/sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest[index].params,
        sizeof(g_signParamsTest[index].params)/sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest[index].params,
        sizeof(g_verifyParamsTest[index].params)/sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksSm2SignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
        EXPECT_EQ(ret, HKS_ERROR_INVALID_DIGEST) << "Sm2SignVerify FailureCase failed.";
    }

    /* Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST) << "DeleteKey success.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}
#endif
}

