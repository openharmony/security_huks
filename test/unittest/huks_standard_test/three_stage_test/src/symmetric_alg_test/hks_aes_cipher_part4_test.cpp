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

#include "hks_aes_cipher_part4_test.h"
#include "hks_aes_cipher_test_common.h"
#include "hks_aes_cipher_part_test_c.h"
#include "hks_access_control_test_common.h"

#include <gtest/gtest.h>
#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_log.h"

using namespace testing::ext;
namespace Unittest::AesCipher {
class HksAesCipherPart4Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAesCipherPart4Test::SetUpTestCase(void)
{
}

void HksAesCipherPart4Test::TearDownTestCase(void)
{
}

void HksAesCipherPart4Test::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksAesCipherPart4Test::TearDown()
{
}

static struct HksParam g_genParams026[] = {
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
    }
};
static struct HksParam g_encryptParams026[] = {
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
            .size = AAD_SIZE,
            .data = (uint8_t *)AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AEAD_SIZE,
            .data = (uint8_t *)AEAD
        }
    }
};
static struct HksParam g_decryptParams026[] = {
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
            .size = AAD_SIZE,
            .data = (uint8_t *)AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = NONCE_SIZE,
            .data = (uint8_t *)NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AEAD_SIZE,
            .data = (uint8_t *)AEAD
        }
    }
};

#ifdef USE_HKS_MOCK
static struct HksParam g_genParams027[] = {
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
    }
};
static struct HksParam g_encryptParams027[] = {
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
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = NONCE_SIZE,
            .data = (uint8_t *)NONCE
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AAD_SIZE,
            .data = (uint8_t *)AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AEAD_SIZE,
            .data = (uint8_t *)AEAD
        }
    }
};
static struct HksParam g_decryptParams027[] = {
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
            .size = AAD_SIZE,
            .data = (uint8_t *)AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = NONCE_SIZE,
            .data = (uint8_t *)NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AEAD_SIZE,
            .data = (uint8_t *)AEAD
        }
    }
};

static struct HksParam g_genParams028[] = {
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
    }
};
static struct HksParam g_encryptParams028[] = {
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
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AAD_SIZE,
            .data = (uint8_t *)AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AEAD_SIZE,
            .data = (uint8_t *)AEAD
        }
    }
};
static struct HksParam g_decryptParams028[] = {
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
            .size = AAD_SIZE,
            .data = (uint8_t *)AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = NONCE_SIZE,
            .data = (uint8_t *)NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AEAD_SIZE,
            .data = (uint8_t *)AEAD
        }
    }
};
#endif

#ifdef L2_STANDARD
/**
 * @tc.name: HksAesCipherPart4Test.HksAesCipherPart1Test029
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherPart4Test, HksAesCipherPart4Test029, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest029";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams026, sizeof(g_genParams026) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams026, sizeof(g_encryptParams026) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams026, sizeof(g_decryptParams026) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCipherTestCaseGcm3(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

#ifdef USE_HKS_MOCK
/**
 * @tc.name: HksAesCipherPart4Test.HksAesCipherPart1Test030
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherPart4Test, HksAesCipherPart4Test030, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest030";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams027, sizeof(g_genParams027) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams027, sizeof(g_encryptParams027) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams027, sizeof(g_decryptParams027) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    /* 1. Generate Key */
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. Encrypt Three Stage */
    uint8_t handleE[sizeof(uint64_t)] = {0};
    uint8_t challenge[32] = {0};
    struct HksBlob challengeBlob = { 32, challenge };
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    ret = HksInit(&keyAlias, encryptParamSet, &handleEncrypt, &challengeBlob);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "Init failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksAesCipherPart4Test.HksAesCipherPart1Test031
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherPart4Test, HksAesCipherPart4Test031, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest031";
    struct HksBlob keyAlias = { (uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams028, sizeof(g_genParams028) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams028, sizeof(g_encryptParams028) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams028, sizeof(g_decryptParams028) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCipherTestCaseGcm3(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, true);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}
#endif
#endif
} // namespace Unittest::AesCipher