/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hks_ml_dsa_sign_verify_test_common.h"
#include "hks_test_adapt_for_de.h"
#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::MlDsaSifnVerify {
class HksMlDsaSignVerifyPart1Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksMlDsaSignVerifyPart1Test::SetUpTestCase(void)
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksMlDsaSignVerifyPart1Test::TearDownTestCase(void)
{
}

void HksMlDsaSignVerifyPart1Test::SetUp()
{
}

void HksMlDsaSignVerifyPart1Test::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
}

static struct HksParam g_genParamsTest001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }
};
static struct HksParam g_signParamsTest001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }
};
static struct HksParam g_verifyParamsTest001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }
};

static struct HksParam g_genParamsTest002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_65
    }
};
static struct HksParam g_signParamsTest002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_65
    }
};
static struct HksParam g_verifyParamsTest002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_65
    }
};

static struct HksParam g_genParamsTest003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_87
    }
};
static struct HksParam g_signParamsTest003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_87
    }
};
static struct HksParam g_verifyParamsTest003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA,
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_87
    }
};

static struct HksParam g_genParamsTest004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44
    }
};

static struct HksParam g_genParamsTest005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_ML_DSA
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_ML_DSA_KEY_PARAM_SET_44 + 1
    }
};

/**
 * @tc.name: HksMlDsaSignVerifyPart1Test.HksMlDsaSignVerifyPart1Test001
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-44
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart1Test, HksMlDsaSignVerifyPart1Test001, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart1Test001";
    struct HksBlob keyAlias = {strlen(keyAliasString), (uint8_t *)keyAliasString};
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest001, sizeof(g_genParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest001, sizeof(g_signParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest001, sizeof(g_verifyParamsTest001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = {0};
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksMlDsaTestSignVerify failed.";

    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksMlDsaTestSignVerify failed.";

    ret = HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksMlDsaSignVerifyPart1Test.HksMlDsaSignVerifyPart1Test002
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-65
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart1Test, HksMlDsaSignVerifyPart1Test002, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart1Test002";
    struct HksBlob keyAlias = {strlen(keyAliasString), (uint8_t *)keyAliasString};
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest002, sizeof(g_genParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest002, sizeof(g_signParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest002, sizeof(g_verifyParamsTest002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = {0};
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksMlDsaTestSignVerify failed.";

    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksMlDsaTestSignVerify failed.";

    ret = HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksMlDsaSignVerifyPart1Test.HksMlDsaSignVerifyPart1Test003
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-87
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart1Test, HksMlDsaSignVerifyPart1Test003, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart1Test003";
    struct HksBlob keyAlias = {strlen(keyAliasString), (uint8_t *)keyAliasString};
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest003, sizeof(g_genParamsTest003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_signParamsTest003, sizeof(g_signParamsTest003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_verifyParamsTest003, sizeof(g_verifyParamsTest003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    uint8_t outDataS[ML_DSA_COMMON_SIZE] = {0};
    struct HksBlob outData = { ML_DSA_COMMON_SIZE, outDataS };
    ret = HksMlDsaTestSignVerify(&keyAlias, signParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksMlDsaTestSignVerify failed.";

    ret = HksMlDsaTestSignVerify(&keyAlias, verifyParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksMlDsaTestSignVerify failed.";

    ret = HksDeleteKeyForDe(&keyAlias, verifyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksMlDsaSignVerifyPart1Test.HksMlDsaSignVerifyPart1Test004
 * @tc.desc: alg-MlDsa, pur-encrypt/decrypt, secId-44
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart1Test, HksMlDsaSignVerifyPart1Test004, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart1Test004";
    struct HksBlob keyAlias = {strlen(keyAliasString), (uint8_t *)keyAliasString};
    struct HksParamSet *genParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest004, sizeof(g_genParamsTest004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "GenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksMlDsaSignVerifyPart1Test.HksMlDsaSignVerifyPart1Test005
 * @tc.desc: alg-MlDsa, pur-sign/verify, secId-45
 * @tc.type: FUNC
 */
HWTEST_F(HksMlDsaSignVerifyPart1Test, HksMlDsaSignVerifyPart1Test005, TestSize.Level0)
{
    const char *keyAliasString = "HksMlDsaSignVerifyPart1Test005";
    struct HksBlob keyAlias = {strlen(keyAliasString), (uint8_t *)keyAliasString};
    struct HksParamSet *genParamSet = nullptr;

    int32_t ret = InitParamSet(&genParamSet, g_genParamsTest005, sizeof(g_genParamsTest005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "GenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}
} // namespace Unittest::SifnVerify