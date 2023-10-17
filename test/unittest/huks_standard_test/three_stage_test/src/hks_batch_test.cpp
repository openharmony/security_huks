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

#include "hks_batch_test.h"
#include "hks_aes_cipher_test_common.h"
#include "hks_aes_cipher_part_test_c.h"
#include "hks_access_control_test_common.h"

#include <gtest/gtest.h>
#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_log.h"

using namespace testing::ext;
namespace Unittest::BatchTest {
class HksBatchTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksBatchTest::SetUpTestCase(void)
{
#ifdef L2_STANDARD
    OHOS::SaveStringToFile("/sys/fs/selinux/enforce", "0");
#endif
}

void HksBatchTest::TearDownTestCase(void)
{
#ifdef L2_STANDARD
    OHOS::SaveStringToFile("/sys/fs/selinux/enforce", "1");
#endif
}

void HksBatchTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksBatchTest::TearDown()
{
}

#ifdef USE_HKS_MOCK
static struct HksParam g_genParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_KEY_AUTH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_USER_AUTH_TYPE,
        .uint32Param = HKS_USER_AUTH_TYPE_PIN
    }, {
        .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
    }, {
        .tag = HKS_TAG_CHALLENGE_TYPE,
        .uint32Param = HKS_CHALLENGE_TYPE_NONE
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};
static struct HksParam g_encryptParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_USER_AUTH_TYPE,
        .uint32Param = HKS_USER_AUTH_TYPE_PIN
    }, {
        .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
    }, {
        .tag = HKS_TAG_CHALLENGE_TYPE,
        .uint32Param = HKS_CHALLENGE_TYPE_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = AesCipher::IV_SIZE,
            .data = (uint8_t *)AesCipher::IV
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }
};
static struct HksParam g_decryptParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = AesCipher::NONCE_SIZE,
            .data = (uint8_t *)AesCipher::NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }, {
        .tag = HKS_TAG_IS_BATCH_OPERATION,
        .boolParam = true
    }, {
        .tag = HKS_TAG_BATCH_OPERATION_TIMEOUT,
        .uint32Param = 2000
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};

static struct HksParam g_genParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_KEY_AUTH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_USER_AUTH_TYPE,
        .uint32Param = HKS_USER_AUTH_TYPE_PIN
    }, {
        .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
    }, {
        .tag = HKS_TAG_CHALLENGE_TYPE,
        .uint32Param = HKS_CHALLENGE_TYPE_NONE
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};
static struct HksParam g_encryptParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_USER_AUTH_TYPE,
        .uint32Param = HKS_USER_AUTH_TYPE_PIN
    }, {
        .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
    }, {
        .tag = HKS_TAG_CHALLENGE_TYPE,
        .uint32Param = HKS_CHALLENGE_TYPE_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = AesCipher::IV_SIZE,
            .data = (uint8_t *)AesCipher::IV
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }
};
static struct HksParam g_decryptParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = AesCipher::NONCE_SIZE,
            .data = (uint8_t *)AesCipher::NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }, {
        .tag = HKS_TAG_IS_BATCH_OPERATION,
        .boolParam = true
    }, {
        .tag = HKS_TAG_BATCH_OPERATION_TIMEOUT,
        .uint32Param = 0
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};


#ifdef L2_STANDARD
/**
 * @tc.name: HksBatchTest.HksBatchTest001
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksBatchTest, HksBatchTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksBatchTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams001, sizeof(g_encryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams001, sizeof(g_decryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = AesCipher::HksAesCipherTestCaseGcm4(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksBatchTest.HksBatchTest002
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksBatchTest, HksBatchTest002, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksBatchTest002";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams002, sizeof(g_encryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams002, sizeof(g_decryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = AesCipher::HksAesCipherTestCaseGcm4(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, true);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_TIME_OUT) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}
#endif
#endif

} // namespace Unittest::BatchTest