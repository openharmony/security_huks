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
#include "hks_rsa_sign_verify_test_common.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::RsaSignVerify {
class HksRsaSignVerifyPart10Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksRsaSignVerifyPart10Test::SetUpTestCase(void)
{
}

void HksRsaSignVerifyPart10Test::TearDownTestCase(void)
{
}

void HksRsaSignVerifyPart10Test::SetUp()
{
}

void HksRsaSignVerifyPart10Test::TearDown()
{
}

static struct HksParam g_genParamsTest101[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }
};
static struct HksParam g_signParamsTest101[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};
static struct HksParam g_verifyParamsTest101[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_genParamsTest102[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }
};
static struct HksParam g_signParamsTest102[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PSS
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};
static struct HksParam g_verifyParamsTest102[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PSS
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_genParamsTest103[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_INVALID_FLEX_KEY_SIZE_1540
    }
};

static struct HksParam g_genParamsTest104[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }
};
static struct HksParam g_signParamsTest104[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS7
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

#ifndef HKS_UNTRUSTED_RUNNING_ENV
static struct HksParam g_genParamsTest105[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }
};
static struct HksParam g_signParamsTest105[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_ISO_IEC_9796_2
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};
static struct HksParam g_verifyParamsTest105[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_ISO_IEC_9796_2
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA1
    }
};

static struct HksParam g_genParamsTest106[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }
};
static struct HksParam g_signParamsTest106[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = RSA_FLEX_KEY_SIZE_1536
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_ISO_IEC_9796_2
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};
#endif

/**
 * @tc.name: HksRsaSignVerifyPart10Test.HksRsaSignVerifyPart10Test101
 * @tc.desc: rsa sign and verify; alg-RSA, pad-PKCS1_V1_5 and digest-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart10Test, HksRsaSignVerifyPart10Test101, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest101";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest101, sizeof(g_genParamsTest101) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest101, sizeof(g_signParamsTest101) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest101, sizeof(g_verifyParamsTest101) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t out[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { RSA_COMMON_SIZE, out };
    ret = HksRsaVerifyTest(&keyAlias, signParamSet, &inData, &signature, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaVerifyTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart10Test.HksRsaSignVerifyPart10Test102
 * @tc.desc: rsa sign and verify; alg-RSA, pad-PSS and digest-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart10Test, HksRsaSignVerifyPart10Test102, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest102";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest102, sizeof(g_genParamsTest102) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest102, sizeof(g_signParamsTest102) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest102, sizeof(g_verifyParamsTest102) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t out[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { RSA_COMMON_SIZE, out };
    ret = HksRsaVerifyTest(&keyAlias, signParamSet, &inData, &signature, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaVerifyTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart10Test.HksRsaSignVerifyPart10Test103
 * @tc.desc: rsa sign and verify; alg-RSA, pad-PKCS1_V1_5 and digest-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart10Test, HksRsaSignVerifyPart10Test103, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest103";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest103, sizeof(g_genParamsTest103) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "GenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart10Test.HksRsaSignVerifyPart10Test104
 * @tc.desc: rsa sign and verify; alg-RSA, pad-PKCS7 and digest-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart10Test, HksRsaSignVerifyPart10Test104, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest104";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest104, sizeof(g_genParamsTest104) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest104, sizeof(g_signParamsTest104) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_PADDING) << "HksRsaSignTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

#ifndef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.name: HksRsaSignVerifyPart10Test.HksRsaSignVerifyPart10Test105
 * @tc.desc: rsa sign and verify; alg-RSA, pad-ISO_IEC_9796_2 and digest-SHA1.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart10Test, HksRsaSignVerifyPart10Test105, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest105";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest105, sizeof(g_genParamsTest105) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest105, sizeof(g_signParamsTest105) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest105, sizeof(g_verifyParamsTest105) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t out[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { RSA_COMMON_SIZE, out };
    ret = HksRsaVerifyTest(&keyAlias, signParamSet, &inData, &signature, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaVerifyTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart10Test.HksRsaSignVerifyPart10Test106
 * @tc.desc: rsa sign and verify; alg-RSA, pad-ISO_IEC_9796_2 and digest-SHA256.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart10Test, HksRsaSignVerifyPart10Test106, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest106";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest106, sizeof(g_genParamsTest106) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest106, sizeof(g_signParamsTest106) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_DIGEST) << "HksRsaSignTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}
#endif

/**
 * @tc.name: HksRsaSignVerifyPart10Test.HksRsaSignVerifyPart10Test107
 * @tc.desc: rsa sign and verify; alg-RSA, pad-PKCS1_V1_5 and digest-SHA256 export import.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart10Test, HksRsaSignVerifyPart10Test107, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest107";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest101, sizeof(g_genParamsTest101) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest101, sizeof(g_signParamsTest101) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest101, sizeof(g_verifyParamsTest101) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksRsaSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
    }

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";


    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}
} // namespace Unittest::RsaSignVerify
