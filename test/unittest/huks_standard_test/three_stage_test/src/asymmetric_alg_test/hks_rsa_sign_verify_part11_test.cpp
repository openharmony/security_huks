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
class HksRsaSignVerifyPart11Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksRsaSignVerifyPart11Test::SetUpTestCase(void)
{
}

void HksRsaSignVerifyPart11Test::TearDownTestCase(void)
{
}

void HksRsaSignVerifyPart11Test::SetUp()
{
}

void HksRsaSignVerifyPart11Test::TearDown()
{
}

static const std::string g_inData512 = "Hks_RSA_Sign_Verify_Test_00000000000000000000000000000000_string";
static const std::string g_inData768 = "Hks_RSA_Sign_Verify_Test_000000000000000000000000000000000000000"
                                       "0000000000000000000000000_string";
static const std::string g_inData1024 = "Hks_RSA_Sign_Verify_Test_000000000000000000000000000000000000000"
                                        "000000000000000000000000000000000000000000000000000000000_string";
static const std::string g_inData1536 = "Hks_RSA_Sign_Verify_Test_000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "000000000000000000000000000000000000000000000000000000000_string";
static const std::string g_inData2048 = "Hks_RSA_Sign_Verify_Test_000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "000000000000000000000000000000000000000000000000000000000_string";
static const std::string g_inData3072 = "Hks_RSA_Sign_Verify_Test_000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "000000000000000000000000000000000000000000000000000000000_string";
static const std::string g_inData4096 = "Hks_RSA_Sign_Verify_Test_000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000000000"
                                        "000000000000000000000000000000000000000000000000000000000_string";

static struct HksParam g_genParamsTest111[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_512
    }
};
static struct HksParam g_signParamsTest111[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_512
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest111[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_512
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest112[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_768
    }
};
static struct HksParam g_signParamsTest112[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_768
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest112[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_RSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_RSA_KEY_SIZE_768
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest113[] = {
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
static struct HksParam g_signParamsTest113[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest113[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest114[] = {
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
static struct HksParam g_signParamsTest114[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest114[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest115[] = {
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
static struct HksParam g_signParamsTest115[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest115[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest116[] = {
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
static struct HksParam g_signParamsTest116[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest116[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest117[] = {
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
static struct HksParam g_signParamsTest117[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};
static struct HksParam g_verifyParamsTest117[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_genParamsTest118[] = {
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
static struct HksParam g_signParamsTest118[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }
};

static struct HksParam g_genParamsTest119[] = {
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
static struct HksParam g_signParamsTest119[] = {
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
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

/**
 * @tc.name: HksRsaSignVerifyPart11Test.HksRsaSignVerifyPart11Test111
 * @tc.desc: rsa sign and verify; keySize-512, alg-RSA, pad-NONE and digest-NONE.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart11Test, HksRsaSignVerifyPart11Test111, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest111";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest111, sizeof(g_genParamsTest111) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest111, sizeof(g_signParamsTest111) / sizeof(HksParam));
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
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest111, sizeof(g_verifyParamsTest111) / sizeof(HksParam));
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
 * @tc.name: HksRsaSignVerifyPart11Test.HksRsaSignVerifyPart11Test112
 * @tc.desc: rsa sign and verify; keySize-768, alg-RSA, pad-NONE and digest-NONE.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart11Test, HksRsaSignVerifyPart11Test112, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest112";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest112, sizeof(g_genParamsTest112) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest112, sizeof(g_signParamsTest112) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData768.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData768.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest112, sizeof(g_verifyParamsTest112) / sizeof(HksParam));
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
 * @tc.name: HksRsaSignVerifyPart11Test.HksRsaSignVerifyPart11Test113
 * @tc.desc: rsa sign and verify; keySize-1024, alg-RSA, pad-NONE and digest-NONE.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart11Test, HksRsaSignVerifyPart11Test113, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest113";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest113, sizeof(g_genParamsTest113) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest113, sizeof(g_signParamsTest113) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData1024.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData1024.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest113, sizeof(g_verifyParamsTest113) / sizeof(HksParam));
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
 * @tc.name: HksRsaSignVerifyPart11Test.HksRsaSignVerifyPart11Test114
 * @tc.desc: rsa sign and verify; keySize-1536, alg-RSA, pad-NONE and digest-NONE.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart11Test, HksRsaSignVerifyPart11Test114, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest114";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest114, sizeof(g_genParamsTest114) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest114, sizeof(g_signParamsTest114) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData1536.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData1536.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest114, sizeof(g_verifyParamsTest114) / sizeof(HksParam));
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
 * @tc.name: HksRsaSignVerifyPart11Test.HksRsaSignVerifyPart11Test115
 * @tc.desc: rsa sign and verify; keySize-2048, alg-RSA, pad-NONE and digest-NONE.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart11Test, HksRsaSignVerifyPart11Test115, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest115";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest115, sizeof(g_genParamsTest115) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest115, sizeof(g_signParamsTest115) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData2048.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData2048.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest115, sizeof(g_verifyParamsTest115) / sizeof(HksParam));
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
 * @tc.name: HksRsaSignVerifyPart11Test.HksRsaSignVerifyPart11Test116
 * @tc.desc: rsa sign and verify; keySize-3072, alg-RSA, pad-NONE and digest-NONE.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart11Test, HksRsaSignVerifyPart11Test116, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest116";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest116, sizeof(g_genParamsTest116) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest116, sizeof(g_signParamsTest116) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData3072.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData3072.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest116, sizeof(g_verifyParamsTest116) / sizeof(HksParam));
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
 * @tc.name: HksRsaSignVerifyPart11Test.HksRsaSignVerifyPart11Test117
 * @tc.desc: rsa sign and verify; keySize-4096, alg-RSA, pad-NONE and digest-NONE.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart11Test, HksRsaSignVerifyPart11Test117, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest117";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest117, sizeof(g_genParamsTest117) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest117, sizeof(g_signParamsTest117) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData4096.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData4096.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaSignTest failed.";

    struct HksParamSet *verifyParamSet = nullptr;
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest117, sizeof(g_verifyParamsTest117) / sizeof(HksParam));
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
 * @tc.name: HksRsaSignVerifyPart11Test.HksRsaSignVerifyPart11Test118
 * @tc.desc: rsa sign and verify; keySize-1024, alg-RSA, pad-NONE and digest-SHA128.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart11Test, HksRsaSignVerifyPart11Test118, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest118";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest118, sizeof(g_genParamsTest118) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest118, sizeof(g_signParamsTest118) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData1024.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData1024.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_DIGEST) << "HksRsaSignTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}

/**
 * @tc.name: HksRsaSignVerifyPart11Test.HksRsaSignVerifyPart11Test119
 * @tc.desc: rsa sign and verify; keySize-1024, alg-RSA, pad-NONE ,digest-NONE, plaintext-2048.
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaSignVerifyPart11Test, HksRsaSignVerifyPart11Test119, TestSize.Level1)
{
    char tmpKeyAlias[] = "HksRsaCipherKeyAliasTest119";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest119, sizeof(g_genParamsTest119) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, g_signParamsTest119, sizeof(g_signParamsTest119) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    static struct HksBlob inData = {
        (uint32_t)g_inData2048.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData2048.c_str()))
    };
    uint8_t sign[RSA_COMMON_SIZE] = { 0 };
    struct HksBlob signature = { RSA_COMMON_SIZE, sign };
    ret = HksRsaSignTest(&keyAlias, signParamSet, &inData, &signature);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksRsaSignTest failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
}
} // namespace Unittest::RsaSignVerify
