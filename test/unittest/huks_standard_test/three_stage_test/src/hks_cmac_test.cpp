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

#include "parameters.h"
#include "hks_cmac_test.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::Cmac {
class HksCmacTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCmacTest::SetUpTestCase(void)
{
}

void HksCmacTest::TearDownTestCase(void)
{
}

void HksCmacTest::SetUp()
{
}

void HksCmacTest::TearDown()
{
}

static const std::string DEVICE_WEARABLE = "wearable";

static struct HksParam g_genParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }
};
static struct HksParam g_cmacParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_CMAC
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_ISO_IEC_9797_1
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
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_192
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }
};

static struct HksParam g_genParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }
};
static struct HksParam g_cmacParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_CMAC
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_ECB
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_ISO_IEC_9797_1
    }
};

static struct HksParam g_genParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }
};
static struct HksParam g_cmacParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_CMAC
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
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

static struct HksParam g_genParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }
};
static struct HksParam g_cmacParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_CMAC
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_ISO_IEC_9797_1
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE_INVALID,
            .data = (uint8_t *)IV_INVALID
        }
    }
};

static struct HksParam g_genParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_3DES
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }
};
static struct HksParam g_cmacParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_CMAC
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_3DES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_ISO_IEC_9797_1
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

static int32_t HksCmacTestCase(const struct HksBlob *keyAlias, struct HksParamSet *cmacParamSet, struct HksBlob *inData,
    struct HksBlob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };
    int32_t ret = HksInitForDe(keyAlias, cmacParamSet, &handleBlob, nullptr);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    return TestUpdateFinish(&handleBlob, cmacParamSet, HKS_KEY_PURPOSE_MAC, inData, outData);
}

/**
 * @tc.name: HksCmacTest.HksCmacTest001
 * @tc.desc: alg-CMAC pur-MAC size-128 mod-CBC pad-ISO_IEC_9797_1 IV-8.
 * @tc.type: FUNC
 */
HWTEST_F(HksCmacTest, HksCmacTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksCmacKeyAliasTest001";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *cmacParamSet = nullptr;
    ret = InitParamSet(&cmacParamSet, g_cmacParams001, sizeof(g_cmacParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    std::string deviceType = OHOS::system::GetDeviceType();
    EXPECT_NE(deviceType, "") << "GetDeviceType failed.";

    uint8_t mac[CMAC_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { CMAC_COMMON_SIZE, mac };
    ret = HksCmacTestCase(&keyAlias, cmacParamSet, &inData, &outData);
    if (deviceType == DEVICE_WEARABLE) {
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksCmacTestCase failed.";
    } else {
        EXPECT_EQ(ret, HKS_FAILURE) << "HksCmacTestCase failed.";
    }

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&cmacParamSet);
}

/**
 * @tc.name: HksCmacTest.HksCmacTest002
 * @tc.desc: alg-CMAC pur-MAC size-192.
 * @tc.type: FUNC
 */
HWTEST_F(HksCmacTest, HksCmacTest002, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksCmacKeyAliasTest002";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "GenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksCmacTest.HksCmacTest003
 * @tc.desc: alg-CMAC pur-MAC size-128 mod-ECB pad-ISO_IEC_9797_1.
 * @tc.type: FUNC
 */
HWTEST_F(HksCmacTest, HksCmacTest003, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksCmacKeyAliasTest003";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *cmacParamSet = nullptr;
    ret = InitParamSet(&cmacParamSet, g_cmacParams003, sizeof(g_cmacParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t mac[CMAC_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { CMAC_COMMON_SIZE, mac };
    ret = HksCmacTestCase(&keyAlias, cmacParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_ERROR_CHECK_GET_MODE_FAIL) << "HksCmacTestCase failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&cmacParamSet);
}

/**
 * @tc.name: HksCmacTest.HksCmacTest004
 * @tc.desc: alg-CMAC pur-MAC size-128 mod-CBC pad-PKCS7 IV-8.
 * @tc.type: FUNC
 */
HWTEST_F(HksCmacTest, HksCmacTest004, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksCmacKeyAliasTest004";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams004, sizeof(g_genParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *cmacParamSet = nullptr;
    ret = InitParamSet(&cmacParamSet, g_cmacParams004, sizeof(g_cmacParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t mac[CMAC_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { CMAC_COMMON_SIZE, mac };
    ret = HksCmacTestCase(&keyAlias, cmacParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_ERROR_CHECK_GET_PADDING_FAIL) << "HksCmacTestCase failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&cmacParamSet);
}

/**
 * @tc.name: HksCmacTest.HksCmacTest005
 * @tc.desc: alg-CMAC pur-MAC size-128 mod-CBC pad-ISO_IEC_9797_1 IV-9.
 * @tc.type: FUNC
 */
HWTEST_F(HksCmacTest, HksCmacTest005, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksCmacKeyAliasTest005";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams005, sizeof(g_genParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *cmacParamSet = nullptr;
    ret = InitParamSet(&cmacParamSet, g_cmacParams005, sizeof(g_cmacParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    uint8_t mac[CMAC_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { CMAC_COMMON_SIZE, mac };
    ret = HksCmacTestCase(&keyAlias, cmacParamSet, &inData, &outData);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_IV) << "HksCmacTestCase failed.";

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&cmacParamSet);
}

/**
 * @tc.name: HksCmacTest.HksCmacTest006
 * @tc.desc: alg-CMAC pur-MAC size-128 mod-CBC pad-ISO_IEC_9797_1 IV-8.
 * @tc.type: FUNC
 */
HWTEST_F(HksCmacTest, HksCmacTest006, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksCmacKeyAliasTest006";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams006, sizeof(g_genParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksImportKeyForDe(&keyAlias, genParamSet, &keyImported);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    struct HksParamSet *cmacParamSet = nullptr;
    ret = InitParamSet(&cmacParamSet, g_cmacParams006, sizeof(g_cmacParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    std::string deviceType = OHOS::system::GetDeviceType();
    EXPECT_NE(deviceType, "") << "GetDeviceType failed.";

    uint8_t mac[CMAC_COMMON_SIZE] = { 0 };
    struct HksBlob outData = { CMAC_COMMON_SIZE, mac };
    ret = HksCmacTestCase(&keyAlias, cmacParamSet, &inData, &outData);
    if (deviceType == DEVICE_WEARABLE) {
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksCmacTestCase failed.";
        EXPECT_EQ(HksMemCmp(outData.data, macData.data, outData.size), HKS_SUCCESS) << "outData not equals macData";
    } else {
        EXPECT_EQ(ret, HKS_FAILURE) << "HksCmacTestCase failed.";
    }

    ret = HksDeleteKeyForDe(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&cmacParamSet);
}
} // namespace Unittest::Cmac
