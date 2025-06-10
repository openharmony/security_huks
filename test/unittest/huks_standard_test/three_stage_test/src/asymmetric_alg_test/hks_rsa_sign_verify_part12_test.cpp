/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "hks_type_enum.h"
#include "hks_rsa_sign_verify_test_common.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::RsaSignVerify {
class HksRsaSignVerifyPart12Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksRsaSignVerifyPart12Test::SetUpTestCase(void)
{
}

void HksRsaSignVerifyPart12Test::TearDownTestCase(void)
{
}

void HksRsaSignVerifyPart12Test::SetUp()
{
}

void HksRsaSignVerifyPart12Test::TearDown()
{
}

static const std::string g_inData224 = "RSA_00000000000000000_string";
static const std::string g_inData256 = "RSA_000000000000000000000_string";
static const std::string g_inData384 = "RSA_0000000000000000000000000000000000000_string";
static const std::string g_inData512 = "RSA_00000000000000000000000000000000000000000000000000000_string";

static struct HksParam g_genParamsTest121[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_1024
    }
};
static struct HksParam g_signParamsTest121[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_1024
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest121[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_1024
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest122[] = {
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
static struct HksParam g_signParamsTest122[] = {
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
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest122[] = {
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
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest123[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_2048
    }
};
static struct HksParam g_signParamsTest123[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_2048
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest123[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_2048
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest124[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_3072
    }
};
static struct HksParam g_signParamsTest124[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_3072
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest124[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_3072
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest125[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_4096
    }
};
static struct HksParam g_signParamsTest125[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_4096
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest125[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_4096
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest126[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_1024
    }
};
static struct HksParam g_signParamsTest126[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_1024
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest127[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_1024
    }
};
static struct HksParam g_signParamsTest127[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_1024
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS1_V1_5
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA224
    }
};

/**
 * @tc.name: HksRsaSignVerifyPart12Test.HksRsaSignVerifyPart12Test121
 * @tc.desc: rsa sign and verify; keySize-1024, alg-RSA, pad-PKCS1_V1_5, digest-NONE, plaintext-256.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart12Test, HksRsaSignVerifyPart12Test121, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest121";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest121, sizeof(g_genParamsTest121) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest121, sizeof(g_signParamsTest121) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData256.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData256.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest121, sizeof(g_verifyParamsTest121) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t out[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { RSA_COMMON_SIZE, out };
    ret = HksRsaVerifyTest(&keyAlias, verifyParamSet, &inData, &signature, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaVerifyTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart12Test.HksRsaSignVerifyPart12Test122
 * @tc.desc: rsa sign and verify; keySize-1536, alg-RSA, pad-PKCS1_V1_5, digest-NONE, plaintext-384.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart12Test, HksRsaSignVerifyPart12Test122, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest122";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest122, sizeof(g_genParamsTest122) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest122, sizeof(g_signParamsTest122) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData384.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData384.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest122, sizeof(g_verifyParamsTest122) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t out[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { RSA_COMMON_SIZE, out };
    ret = HksRsaVerifyTest(&keyAlias, verifyParamSet, &inData, &signature, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaVerifyTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart12Test.HksRsaSignVerifyPart12Test123
 * @tc.desc: rsa sign and verify; keySize-2048, alg-RSA, pad-PKCS1_V1_5, digest-NONE, plaintext-512.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart12Test, HksRsaSignVerifyPart12Test123, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest123";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest123, sizeof(g_genParamsTest123) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest123, sizeof(g_signParamsTest123) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData512.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData512.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest123, sizeof(g_verifyParamsTest123) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t out[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { RSA_COMMON_SIZE, out };
    ret = HksRsaVerifyTest(&keyAlias, verifyParamSet, &inData, &signature, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaVerifyTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart12Test.HksRsaSignVerifyPart12Test124
 * @tc.desc: rsa sign and verify; keySize-3072, alg-RSA, pad-PKCS1_V1_5, digest-NONE, plaintext-256.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart12Test, HksRsaSignVerifyPart12Test124, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest124";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest124, sizeof(g_genParamsTest124) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest124, sizeof(g_signParamsTest124) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData256.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData256.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest124, sizeof(g_verifyParamsTest124) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t out[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { RSA_COMMON_SIZE, out };
    ret = HksRsaVerifyTest(&keyAlias, verifyParamSet, &inData, &signature, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaVerifyTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart12Test.HksRsaSignVerifyPart12Test125
 * @tc.desc: rsa sign and verify; keySize-4096, alg-RSA, pad-PKCS1_V1_5, digest-NONE, plaintext-384.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart12Test, HksRsaSignVerifyPart12Test125, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest125";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest125, sizeof(g_genParamsTest125) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest125, sizeof(g_signParamsTest125) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData384.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData384.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest125, sizeof(g_verifyParamsTest125) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t out[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { RSA_COMMON_SIZE, out };
    ret = HksRsaVerifyTest(&keyAlias, verifyParamSet, &inData, &signature, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaVerifyTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart12Test.HksRsaSignVerifyPart12Test126
 * @tc.desc: rsa sign and verify; keySize-1024, alg-RSA, pad-PKCS1_V1_5, digest-NONE, plaintext-224.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart12Test, HksRsaSignVerifyPart12Test126, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest126";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest126, sizeof(g_genParamsTest126) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest126, sizeof(g_signParamsTest126) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData224.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData224.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksRsaSignTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart12Test.HksRsaSignVerifyPart12Test127
 * @tc.desc: rsa sign and verify; keySize-1024, alg-RSA, pad-PKCS1_V1_5, digest-NONE, plaintext-512.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart12Test, HksRsaSignVerifyPart12Test127, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest127";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest127, sizeof(g_genParamsTest127) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest127, sizeof(g_signParamsTest127) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData512.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData512.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksRsaSignTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}
} // namespace Unittest::RsaSignVerify
