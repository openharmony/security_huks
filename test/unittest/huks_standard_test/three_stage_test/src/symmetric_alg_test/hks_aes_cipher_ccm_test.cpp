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

#include "hks_aes_cipher_test_common.h"
#include "hks_aes_cipher_part_test_c.h"

#include <gtest/gtest.h>
#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_type_inner.h"
#include "hks_log.h"

using namespace testing::ext;
namespace Unittest::AesCipher {
class HksAesCipherCcmTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

static const uint32_t CCM_COMM_BUFF_SIZE = 10;
static const uint32_t CCM_NONCE_SIZE = 7;
static uint8_t CCM_NONCE[NONCE_SIZE + CCM_COMM_BUFF_SIZE] = {0};
static uint8_t CCM_AAD[AAD_SIZE + CCM_COMM_BUFF_SIZE] = {0};
static uint8_t CCM_AEAD[AEAD_SIZE + CCM_COMM_BUFF_SIZE] = {0};
static uint32_t g_TestSegSize = MAX_UPDATE_SIZE;

static const uint32_t CCM_MIN_AEAD_SIZE  = 4;
static const uint32_t CCM_MAX_AEAD_SIZE  = 16;
static const uint32_t CCM_MIN_NONCE_SIZE = 7;
static const uint32_t CCM_MAX_NONCE_SIZE = 13;
static const uint32_t CCM_MAX_DATA_LEN_FOR_MAX_NONCE = 65535;

static const uint32_t CCM_UPDATE_DATA_SIZE = 10000;
static const uint32_t CCM_TEST_DATA_LEN    = 100;

static const std::string g_AesCcmInData = "Hks_AES_CCM_Cipher_Test_00000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000_string";

static struct HksParam g_genCcmParams[] = {
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
        .uint32Param = HKS_MODE_CCM
    }
};

static struct HksParam g_genCcmParamsAuthPur[] = {
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
        .uint32Param = HKS_MODE_CCM
    }, {
        .tag = HKS_TAG_USER_AUTH_TYPE,
        .uint32Param = HKS_USER_AUTH_TYPE_PIN
    }, {
        .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = HKS_AUTH_ACCESS_ALWAYS_VALID
    }, {
        .tag = HKS_TAG_CHALLENGE_TYPE,
        .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
    }, {
        .tag = HKS_TAG_KEY_AUTH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};

static struct HksParam g_encCcmParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AAD_SIZE,
            .data = (uint8_t *)CCM_AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = NONCE_SIZE,
            .data = (uint8_t *)CCM_NONCE
        }
    }
};

static struct HksParam g_decCcmParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AAD_SIZE,
            .data = (uint8_t *)CCM_AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = NONCE_SIZE,
            .data = (uint8_t *)CCM_NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AEAD_SIZE,
            .data = (uint8_t *)CCM_AEAD
        }
    }
};

static struct HksParam g_encCcmParamsNoNonce[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AAD_SIZE,
            .data = (uint8_t *)CCM_AAD
        }
    }
};

static struct HksParam g_decCcmParamsNoNonce[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AAD_SIZE,
            .data = (uint8_t *)CCM_AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = CCM_NONCE_SIZE,
            .data = (uint8_t *)CCM_NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AEAD_SIZE,
            .data = (uint8_t *)CCM_AEAD
        }
    }
};

static struct HksParam g_encCcmParamsNoAad[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = NONCE_SIZE,
            .data = (uint8_t *)CCM_NONCE
        }
    }
};

static struct HksParam g_decCcmParamsNoAad[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = NONCE_SIZE,
            .data = (uint8_t *)CCM_NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AEAD_SIZE,
            .data = (uint8_t *)CCM_AEAD
        }
    }
};

static struct HksParam g_encCcmParamsNoNonceAndAad[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }
};

static struct HksParam g_decCcmParamsNoNonceAndAad[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = CCM_NONCE_SIZE,
            .data = (uint8_t *)CCM_NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AEAD_SIZE,
            .data = (uint8_t *)CCM_AEAD
        }
    }
};

/* Third-party ecryption test data */
static uint8_t g_testKey[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
static uint8_t g_testPlain[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't'};
static uint8_t g_testNonce[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};

// aad-none cipherText with 8 bytes aead
static uint8_t g_testCipherTextAead8Nonce7NoAad[] = {
    0xA2, 0xE7, 0x4D, 0x41, 0xF1, 0x4D, 0xC5, 0x17,
    0x76, 0x92, 0xC0, 0x1E, 0x20, 0xEF, 0xB4, 0x74,
    0x4F, 0x94, 0xA8, 0xC5, 0xC8, 0x81, 0x5F, 0xD6,
    0x32, 0xA1, 0xB2, 0xBB };
static uint8_t g_testAad[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't'};

// set aad cipherText with 8 bytes aead
static uint8_t g_testCipherTextAead8Nonce7Aad20[] = {
    0xA2, 0xE7, 0x4D, 0x41, 0xF1, 0x4D, 0xC5, 0x17,
    0x76, 0x92, 0xC0, 0x1E, 0x20, 0xEF, 0xB4, 0x74,
    0x4F, 0x94, 0xA8, 0xC5, 0x48, 0xA1, 0x2E, 0x8C,
    0x32, 0xA7, 0x41, 0xD6 };

static uint8_t g_testCipherTextAead4Nonce7Aad20[] = {
    0xA2, 0xE7, 0x4D, 0x41, 0xF1, 0x4D, 0xC5, 0x17,
    0x76, 0x92, 0xC0, 0x1E, 0x20, 0xEF, 0xB4, 0x74,
    0x4F, 0x94, 0xA8, 0xC5, 0x82, 0xF0, 0x3E, 0xAA };
static uint8_t g_testCipherTextAead16Nonce7Aad20[] = {
    0xA2, 0xE7, 0x4D, 0x41, 0xF1, 0x4D, 0xC5, 0x17,
    0x76, 0x92, 0xC0, 0x1E, 0x20, 0xEF, 0xB4, 0x74,
    0x4F, 0x94, 0xA8, 0xC5, 0xA5, 0xB7, 0x01, 0xB0,
    0x17, 0x9C, 0xCB, 0x01, 0xE3, 0xFC, 0x95, 0x88,
    0x03, 0x05, 0xA9, 0x9C };

static uint8_t g_testNonce10[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
static uint8_t g_testCipherTextAead8Nonce10Aad20[] = {
    0x78, 0xC4, 0xF6, 0xB9, 0x38, 0x58, 0x9C, 0xAE,
    0x85, 0x64, 0x5B, 0xAD, 0x89, 0x1C, 0xC7, 0x77,
    0x6F, 0x20, 0xF8, 0x59, 0xAD, 0x7F, 0xF1, 0x25,
    0xAA, 0x61, 0x63, 0x98 };

static uint8_t g_testNonce13[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'};
static uint8_t g_testCipherTextAead8Nonce13Aad20[] = {
    0x84, 0xCD, 0x37, 0xA6, 0x0C, 0xCF, 0x88, 0x57,
    0x2D, 0x92, 0x65, 0x6B, 0x1B, 0x75, 0xD9, 0x92,
    0x98, 0xF8, 0xA3, 0xA4, 0x3B, 0xE0, 0xB8, 0x54,
    0x50, 0x6B, 0x5C, 0xC2 };

/* Third-party decryption test data */
static uint8_t g_testDecKey[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
static uint8_t g_testDecNonce[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
static uint8_t g_testDecAad[] = {0x01};
static uint8_t g_testDecPlain[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't'};
static uint8_t g_testDecCipherTextNonce8Aad1[] = {
    0xc7, 0xa8, 0xb0, 0xc3, 0x1a, 0x82, 0x96, 0x2f,
    0xa2, 0x01, 0xcc, 0xbb, 0xe0, 0xbe, 0x3c, 0xc5,
    0x71, 0xf6, 0xa2, 0x79, 0xdd, 0x53, 0x1c, 0x35,
    0x67, 0xe1, 0x02, 0x71, 0xfe, 0x28, 0xee, 0xff,
    0x60, 0x58, 0xe3, 0x58 };
static uint8_t g_testDecCipherTextNonce8NoAad[] = {
    0xc7, 0xa8, 0xb0, 0xc3, 0x1a, 0x82, 0x96, 0x2f,
    0xa2, 0x01, 0xcc, 0xbb, 0xe0, 0xbe, 0x3c, 0xc5,
    0x71, 0xf6, 0xa2, 0x79, 0x09, 0x68, 0xa7, 0x9f,
    0xc3, 0xdc, 0xf0, 0x82, 0xf1, 0x45, 0x2c, 0x02,
    0xd2, 0x41, 0x73, 0xdb };

static int32_t HksAesSetNonceLen(HksParam *param, uint32_t cnt, uint32_t len, const uint8_t *nonce)
{
    for (uint32_t i = 0; i < cnt; i++) {
        if (param[i].tag == HKS_TAG_NONCE) {
            param[i].blob.size = len;
            if (nonce != NULL) {
                (void)memcpy_s(param[i].blob.data, len, nonce, len);
            }
            return HKS_SUCCESS;
        }
    }

    return HKS_FAILURE;
}

static int32_t HksAesSetAadLen(HksParam *param, uint32_t cnt, uint32_t len, const uint8_t *aad)
{
    for (uint32_t i = 0; i < cnt; i++) {
        if (param[i].tag == HKS_TAG_ASSOCIATED_DATA) {
            param[i].blob.size = len;
            if (aad != NULL) {
                (void)memcpy_s(param[i].blob.data, len, aad, len);
            }
            return HKS_SUCCESS;
        }
    }

    return HKS_FAILURE;
}

static int32_t HksAesSetAeadLen(HksParam *param, uint32_t cnt, uint32_t len, const uint8_t *aead)
{
    for (uint32_t i = 0; i < cnt; i++) {
        if (param[i].tag == HKS_TAG_AE_TAG) {
            param[i].blob.size = len;
            if (aead != NULL) {
                (void)memcpy_s(param[i].blob.data, len, aead, len);
            }
            return HKS_SUCCESS;
        }
    }

    return HKS_FAILURE;
}

static void TestAesCcmCaseInit(void)
{
    g_TestSegSize = MAX_UPDATE_SIZE;

    (void)HksAesSetNonceLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam), NONCE_SIZE, CCM_NONCE);
    (void)HksAesSetAadLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam), AAD_SIZE, CCM_AAD);

    (void)HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), NONCE_SIZE, CCM_NONCE);
    (void)HksAesSetAadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), AAD_SIZE, CCM_AAD);
    (void)HksAesSetAeadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), AEAD_SIZE, CCM_AEAD);

    (void)HksAesSetNonceLen(g_encCcmParamsNoAad, sizeof(g_encCcmParamsNoAad) / sizeof(HksParam), NONCE_SIZE,
        CCM_NONCE);

    (void)HksAesSetNonceLen(g_decCcmParamsNoAad, sizeof(g_decCcmParamsNoAad) / sizeof(HksParam), NONCE_SIZE,
        CCM_NONCE);
    (void)HksAesSetAeadLen(g_decCcmParamsNoAad, sizeof(g_decCcmParamsNoAad) / sizeof(HksParam), AEAD_SIZE,
        CCM_AEAD);
    
    (void)HksAesSetAadLen(g_encCcmParamsNoNonce, sizeof(g_encCcmParamsNoNonce) / sizeof(HksParam), AAD_SIZE,
        CCM_AAD);

    (void)HksAesSetNonceLen(g_decCcmParamsNoNonce, sizeof(g_decCcmParamsNoNonce) / sizeof(HksParam),
        CCM_NONCE_SIZE, CCM_NONCE);
    (void)HksAesSetAadLen(g_decCcmParamsNoNonce, sizeof(g_decCcmParamsNoNonce) / sizeof(HksParam), AAD_SIZE,
        CCM_AAD);
    (void)HksAesSetAeadLen(g_decCcmParamsNoNonce, sizeof(g_decCcmParamsNoNonce) / sizeof(HksParam), AEAD_SIZE,
        CCM_AEAD);
    
    (void)HksAesSetNonceLen(g_decCcmParamsNoNonceAndAad, sizeof(g_decCcmParamsNoNonceAndAad) / sizeof(HksParam),
        CCM_NONCE_SIZE, CCM_NONCE);
    (void)HksAesSetAeadLen(g_decCcmParamsNoNonceAndAad, sizeof(g_decCcmParamsNoNonceAndAad) / sizeof(HksParam),
        AEAD_SIZE, CCM_AEAD);
}

void HksAesCipherCcmTest::SetUpTestCase(void)
{
}

void HksAesCipherCcmTest::TearDownTestCase(void)
{
}

void HksAesCipherCcmTest::SetUp()
{
    TestAesCcmCaseInit();
    EXPECT_EQ(HksInitialize(), 0);
}

void HksAesCipherCcmTest::TearDown()
{
}


#ifdef L2_STANDARD

static int32_t TestAesCcmAbort(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encParamSet, struct HksParamSet *decParamSet, bool isEncrypt, bool isUpdate)
{
    uint32_t dataLen = strlen(g_AesCcmInData.c_str());
    struct HksBlob inData = {dataLen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_AesCcmInData.c_str()))};
    uint8_t *cipher = reinterpret_cast<uint8_t *>(HksMalloc(dataLen + AEAD_SIZE + IV_SIZE));
    if (cipher == NULL) {
        HKS_LOG_E("mallock fail");
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(cipher, dataLen + AEAD_SIZE + IV_SIZE, 0, dataLen + AEAD_SIZE + IV_SIZE);
    struct HksBlob cipherText = { AEAD_SIZE + dataLen + IV_SIZE, cipher };
    
    /* 1. Generate Key */
    int32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    /* 2. Encrypt or Decrypt */
    struct HksParamSet *paramSet = NULL;
    if (isEncrypt) {
        paramSet = encParamSet;
    } else {
        paramSet = decParamSet;
    }
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleE };
    ret = HksInit(keyAlias, paramSet, &handle, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInit failed.";

    if (isUpdate) {
        ret = HksUpdate(&handle, paramSet, &inData, &cipherText);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksUpdate failed.";
    }

    ret = HksAbort(&handle, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAbort failed.";

    /* 3. Delete Key */
    EXPECT_EQ(HksDeleteKey(keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";

    HKS_FREE(cipher);
    return ret;
}

static int32_t TestAesCcmUpdateLoopFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    int32_t ret;
    struct HksBlob inDataSeg = *inData;
    uint8_t *lastPtr = inData->data + inData->size;
    bool isFinished = false;
    HKS_LOG_D("TestAesCcmUpdateLoopFinish with data len %" LOG_PUBLIC "u and frag seg size %" LOG_PUBLIC "u",
        inData->size, g_TestSegSize);
    struct HksBlob tempOutData = *outData;

    while (inDataSeg.data <= lastPtr) {
        if (inDataSeg.data + g_TestSegSize <= lastPtr) {
            inDataSeg.size = g_TestSegSize;
        } else {
            isFinished = true;
            inDataSeg.size = lastPtr - inDataSeg.data;
            break;
        }
        HKS_LOG_D("TestAesCcmUpdateLoopFinish in loop update...");
        ret = HksUpdate(handle, paramSet, &inDataSeg, &tempOutData);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksUpdate Failed.");
            return ret;
        }

        if ((isFinished == false) && (inDataSeg.data + g_TestSegSize > lastPtr)) {
            return HKS_FAILURE;
        }
        inDataSeg.data += g_TestSegSize;
        tempOutData = *outData;
    }

    if (inDataSeg.size != (inData->size % g_TestSegSize)) {
        HKS_LOG_E("TestAesCcmUpdateLoopFinish split in data error inLen %" LOG_PUBLIC "u, final len  %" LOG_PUBLIC "u",
            inData->size, inDataSeg.size);
        return HKS_FAILURE;
    }

    tempOutData = *outData;
    ret = HksFinish(handle, paramSet, &inDataSeg, &tempOutData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksFinish Failed.");
        return ret;
    }
    *outData = tempOutData;
    return HKS_SUCCESS;
}

static int32_t HksAesCcmCipherTestEncrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *encParamSet, const struct HksBlob *inData, struct HksBlob *cipherText)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    int32_t ret = HksInit(keyAlias, encParamSet, &handleEncrypt, nullptr);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Init failed");
        return ret;
    }

    ret = TestAesCcmUpdateLoopFinish(&handleEncrypt, encParamSet, inData, cipherText);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("TestUpdateLoopFinish failed");
        return ret;
    }

    if (HksMemCmp(inData->data, cipherText->data, inData->size) == HKS_SUCCESS) {
        HKS_LOG_E("HksAesCcmCipherTestEncrypt data and encrypt data is same");
        return ret;
    }

    HKS_LOG_D("HksAesCcmCipherTestEncrypt enc data len %" LOG_PUBLIC "u", cipherText->size);
    return HKS_SUCCESS;
}

static int32_t HksAesCcmCipherTestDecrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *decParamSet, struct HksBlob *cipherText, struct HksBlob *plainText,
    const struct HksBlob *inData, uint32_t aeadLen)
{
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handleD };

    HksParam *aeadParam = NULL;
    int32_t ret = HksGetParam(decParamSet, HKS_TAG_AE_TAG, &aeadParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get HKS_TAG_AE_TAG failed");
        return ret;
    }
   
    (void)memcpy_s(aeadParam->blob.data, aeadLen, cipherText->data + cipherText->size - aeadLen, aeadLen);
    cipherText->size -= aeadLen;

    ret = HksInit(keyAlias, decParamSet, &handleDecrypt, nullptr);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Init failed");
        return ret;
    }

    ret = TestAesCcmUpdateLoopFinish(&handleDecrypt, decParamSet, cipherText, plainText);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("TestUpdateLoopFinish failed");
        return ret;
    }

    if (inData->size >= CCM_MIN_AEAD_SIZE) {
        HKS_LOG_D("Original data: 0x%" LOG_PUBLIC "02x 0x%" LOG_PUBLIC "02x 0x%" LOG_PUBLIC "02x 0x%" LOG_PUBLIC "02x",
            inData->data[0], inData->data[0], inData->data[0], inData->data[0]);
    }
    if (plainText->size >= CCM_MIN_AEAD_SIZE) {
        HKS_LOG_D("Decrypt data: 0x%" LOG_PUBLIC "02x 0x%" LOG_PUBLIC "02x 0x%" LOG_PUBLIC "02x 0x%" LOG_PUBLIC "02x",
            plainText->data[0], plainText->data[0], plainText->data[0], plainText->data[0]);
    }

    if (HksMemCmp(inData->data, plainText->data, inData->size) != HKS_SUCCESS) {
        HKS_LOG_E("HksAesCcmCipherTestDecrypt data and encrypt data is not same");
        return HKS_FAILURE;
    }

    return HKS_SUCCESS;
}

static int32_t HksAesCmcCipherTestCaseRun(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encParamSet, struct HksParamSet *decParamSet, uint32_t dataLen)
{
    uint8_t *tempData = reinterpret_cast<uint8_t *>(HksMalloc(dataLen));
    EXPECT_NE(tempData, nullptr);
    if (dataLen > g_AesCcmInData.length()) {
        HKS_LOG_E("HksAesCmcCipherTestCaseOther data too long %" LOG_PUBLIC "u", dataLen);
        (void)memset_s(tempData, dataLen, '0', dataLen);
    } else {
        (void)memcpy_s(tempData, dataLen,
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_AesCcmInData.c_str())), dataLen);
    }
    struct HksBlob inData = {dataLen, tempData};

    /* 1. Generate Key */
    int32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    /* 2. Encrypt */
    uint8_t *cipher = reinterpret_cast<uint8_t *>(HksMalloc(dataLen + AEAD_SIZE + IV_SIZE));
    (void)memset_s(cipher, dataLen + AEAD_SIZE + IV_SIZE, 0, dataLen + AEAD_SIZE + IV_SIZE);
    struct HksBlob cipherText = { AEAD_SIZE + dataLen + IV_SIZE, cipher };

    ret = HksAesCcmCipherTestEncrypt(keyAlias, encParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    /* 3. Decrypt Three Stage */
    uint8_t *plain = reinterpret_cast<uint8_t *>(HksMalloc(dataLen));
    (void)memset_s(plain, dataLen, 0, dataLen);
    struct HksBlob plainText = { dataLen, plain };

    // enc set nonce-none, fill decrypt nonce
    bool isNonceNoExist = false;
    HksParam *nonceParam = NULL;
    ret = HksGetParam(encParamSet, HKS_TAG_NONCE, &nonceParam);
    if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
        isNonceNoExist = true;
    }
    if (isNonceNoExist) {
        ret = HksGetParam(decParamSet, HKS_TAG_NONCE, &nonceParam);
        EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCmcCipherTestCaseRun get nonce failed.";
        (void)memcpy_s(nonceParam->blob.data, CCM_NONCE_SIZE, cipherText.data + cipherText.size - CCM_NONCE_SIZE,
            CCM_NONCE_SIZE);
        nonceParam->blob.size = CCM_NONCE_SIZE;
        cipherText.size -= CCM_NONCE_SIZE;
    }
    
    ret = HksAesCcmCipherTestDecrypt(keyAlias, decParamSet, &cipherText, &plainText, &inData, AEAD_SIZE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    /* 3. Delete Key */
    EXPECT_EQ(HksDeleteKey(keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";

    HKS_FREE(tempData);
    HKS_FREE(cipher);
    HKS_FREE(plain);
    return ret;
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest001
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-12 size-128. datalen=100
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest011";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";


    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, CCM_TEST_DATA_LEN);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest002
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-12 size-192. datalen=100
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest002, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    HksParam *sizeParam = NULL;
    ret = HksGetParam(genParamSet, HKS_TAG_KEY_SIZE, &sizeParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "get HKS_TAG_AE_TAG failed.";
    sizeParam->uint32Param = HKS_AES_KEY_SIZE_192;

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";


    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, CCM_TEST_DATA_LEN);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest003
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-12 size-256. datalen=100
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest003, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    HksParam *sizeParam = NULL;
    ret = HksGetParam(genParamSet, HKS_TAG_KEY_SIZE, &sizeParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "get HKS_TAG_AE_TAG failed.";
    sizeParam->uint32Param = HKS_AES_KEY_SIZE_256;

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";


    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, CCM_TEST_DATA_LEN);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest004
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-NONE  size-128. datalen=100
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest004, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    HksParam *sizeParam = NULL;
    ret = HksGetParam(genParamSet, HKS_TAG_KEY_SIZE, &sizeParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "get HKS_TAG_AE_TAG failed.";
    sizeParam->uint32Param = HKS_AES_KEY_SIZE_256;

    // no nonce
    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParamsNoNonce,
        sizeof(g_encCcmParamsNoNonce) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParamsNoNonce,
        sizeof(g_decCcmParamsNoNonce) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";
    HKS_LOG_E("paramSetSize size %" LOG_PUBLIC "u", decParamSet->paramSetSize);

    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, CCM_TEST_DATA_LEN);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest005
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-7/13 size-128. datalen=100
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest005, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    // set nonce len 7
    ret = HksAesSetNonceLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam),
        CCM_MIN_NONCE_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set enc nonce len failed.";
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        CCM_MIN_NONCE_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, CCM_TEST_DATA_LEN);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);

    // set nonce len 13
    ret = HksAesSetNonceLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam), CCM_MAX_NONCE_SIZE,
        NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set enc nonce len failed.";
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), CCM_MAX_NONCE_SIZE,
        NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";

    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, CCM_TEST_DATA_LEN);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest006
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 size-128. datalen=100 nonce-6-invalid
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest006, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    uint8_t tempInData[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    uint8_t outData[AES_COMMON_SIZE] = {0};
    struct HksBlob inData = {sizeof(tempInData), tempInData};
    struct HksBlob cipherText = { sizeof(outData), outData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *encParamSet = nullptr;
    struct HksParamSet *decParamSet = nullptr;

    // set nonce len 6
    ret = HksAesSetNonceLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam), CCM_MIN_NONCE_SIZE - 1,
        NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set enc nonce len failed.";
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), CCM_MIN_NONCE_SIZE - 1,
        NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestEncrypt(&keyAlias, encParamSet, &inData, &cipherText);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    HksFreeParamSet(&encParamSet);

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &inData, &cipherText, &inData, AEAD_SIZE);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    HksFreeParamSet(&decParamSet);

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest007
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 size-128. datalen<100 nonce-14-invalid
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest007, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    uint8_t tempInData[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    uint8_t outData[AES_COMMON_SIZE] = {0};
    struct HksBlob inData = {sizeof(tempInData), tempInData};
    struct HksBlob cipherText = { sizeof(outData), outData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *encParamSet = nullptr;
    struct HksParamSet *decParamSet = nullptr;

    // set nonce len 14
    ret = HksAesSetNonceLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam), CCM_MAX_NONCE_SIZE + 1,
        NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set enc nonce len failed.";
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), CCM_MAX_NONCE_SIZE + 1,
        NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestEncrypt(&keyAlias, encParamSet, &inData, &cipherText);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    HksFreeParamSet(&encParamSet);

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &inData, &cipherText, &inData, AEAD_SIZE);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    HksFreeParamSet(&decParamSet);

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest008
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-none nonce-12 size-128. datalen=100
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest008, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParamsNoAad, sizeof(g_encCcmParamsNoAad) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParamsNoAad, sizeof(g_decCcmParamsNoAad) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, CCM_TEST_DATA_LEN);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest009
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-12 size-128. datalen=MAX_UPDATE_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest009, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, MAX_UPDATE_SIZE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest010
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-12 size-128. datalen < MAX_UPDATE_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest010, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, MAX_UPDATE_SIZE-1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest011
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-none nonce-none size-128.
 *  datalen = MAX_UPDATE_SIZE-1/MAX_UPDATE_SIZE/MAX_UPDATE_SIZE+1
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest011, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    HksParam *sizeParam = NULL;
    ret = HksGetParam(genParamSet, HKS_TAG_KEY_SIZE, &sizeParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "get HKS_TAG_AE_TAG failed.";
    sizeParam->uint32Param = HKS_AES_KEY_SIZE_256;

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParamsNoNonceAndAad,
        sizeof(g_encCcmParamsNoNonceAndAad) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParamsNoNonceAndAad,
        sizeof(g_decCcmParamsNoNonceAndAad) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    // datalen MAX_UPDATE_SIZE - 1
    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, MAX_UPDATE_SIZE - 1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    // datalen MAX_UPDATE_SIZE
    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, MAX_UPDATE_SIZE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    // datalen MAX_UPDATE_SIZE + 1
    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, MAX_UPDATE_SIZE + 1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest012
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-12 size-128. datalen=1/max
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest012, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    // set nonce len 13, data len max = 2^16
    int32_t ret = HksAesSetNonceLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam),
        CCM_MAX_NONCE_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set enc nonce len failed.";
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), CCM_MAX_NONCE_SIZE,
        NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    // datalen = 1
    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet, 1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    // datalen = max
    g_TestSegSize = CCM_UPDATE_DATA_SIZE;
    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet,
        CCM_MAX_DATA_LEN_FOR_MAX_NONCE - 1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";
    g_TestSegSize = MAX_UPDATE_SIZE;
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest013
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-13 size-128. datalen=0/max+1-invalid
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest013, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    uint8_t *tempData = reinterpret_cast<uint8_t *>(HksMalloc(CCM_MAX_DATA_LEN_FOR_MAX_NONCE + AES_COMMON_SIZE));
    struct HksBlob inData     = {CCM_MAX_DATA_LEN_FOR_MAX_NONCE + AES_COMMON_SIZE, tempData};
    struct HksBlob cipherText = {CCM_MAX_DATA_LEN_FOR_MAX_NONCE + AES_COMMON_SIZE, tempData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *encParamSet = nullptr;
    struct HksParamSet *decParamSet = nullptr;

    ret = HksAesSetNonceLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam), CCM_MAX_NONCE_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set enc nonce len failed.";
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), CCM_MAX_NONCE_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    // datalen = 0 will fail in FinishCachedData
    inData.size = 0;
    ret = HksAesCcmCipherTestEncrypt(&keyAlias, encParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_ERROR_MALLOC_FAIL) << "not HKS_ERROR_MALLOC_FAIL error code.";
    
    // datalen = 0 will fail in FinishCachedData
    inData.size = AEAD_SIZE;
    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &inData, &cipherText, &inData, AEAD_SIZE);
    EXPECT_EQ(ret, HKS_ERROR_MALLOC_FAIL) << "not HKS_ERROR_MALLOC_FAIL error code.";

    // datalen = max+1 will fail in openssl final function
    g_TestSegSize = CCM_UPDATE_DATA_SIZE;
    inData.size = CCM_MAX_DATA_LEN_FOR_MAX_NONCE + 1;
    ret = HksAesCcmCipherTestEncrypt(&keyAlias, encParamSet, &inData, &cipherText);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    inData.size = CCM_MAX_DATA_LEN_FOR_MAX_NONCE + AEAD_SIZE + 1;
    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &inData, &cipherText, &inData, AEAD_SIZE);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    
    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    g_TestSegSize = MAX_UPDATE_SIZE;

    HKS_FREE(tempData);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest014
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-12/none size-128. datalen= 100K
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest014, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    // set nonce len 13, data len max = 2^16 - 1
    int32_t ret = HksAesSetNonceLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam),
        CCM_MIN_NONCE_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set enc nonce len failed.";
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        CCM_MIN_NONCE_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";
    
    // datalen = max
    g_TestSegSize = CCM_UPDATE_DATA_SIZE;
    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet,
        HKS_CIPHER_CCM_MODE_MAX_DATA_LEN);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);

    ret = InitParamSet(&encParamSet, g_encCcmParamsNoNonce,
        sizeof(g_encCcmParamsNoNonce) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParamsNoNonce,
        sizeof(g_decCcmParamsNoNonce) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCmcCipherTestCaseRun(&keyAlias, genParamSet, encParamSet, decParamSet,
        HKS_CIPHER_CCM_MODE_MAX_DATA_LEN);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    g_TestSegSize = MAX_UPDATE_SIZE;
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest015
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-7 size-128. datalen > 100K
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest015, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    uint32_t tempLen = HKS_CIPHER_CCM_MODE_MAX_DATA_LEN + CCM_MAX_AEAD_SIZE + CCM_MAX_NONCE_SIZE;
    uint8_t *tempData = reinterpret_cast<uint8_t *>(HksMalloc(tempLen));
    struct HksBlob inData     = {tempLen, tempData};
    struct HksBlob cipherText = {tempLen, tempData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    // set nonce len 7, data len max = 2^64 - 1
    ret = HksAesSetNonceLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam),
        CCM_MIN_NONCE_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set enc nonce len failed.";
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        CCM_MIN_NONCE_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    g_TestSegSize = CCM_UPDATE_DATA_SIZE;
    inData.size = HKS_CIPHER_CCM_MODE_MAX_DATA_LEN + 1;
    cipherText.size = tempLen;
    ret = HksAesCcmCipherTestEncrypt(&keyAlias, encParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_ERROR_EXCEED_LIMIT) << "not HKS_ERROR_EXCEED_LIMIT error code.";

    inData.size = HKS_CIPHER_CCM_MODE_MAX_DATA_LEN + 1 + AEAD_SIZE;
    cipherText.size = tempLen;
    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &inData, &cipherText, &inData, AEAD_SIZE);
    EXPECT_EQ(ret, HKS_ERROR_EXCEED_LIMIT) << "not HKS_ERROR_EXCEED_LIMIT error code.";
    g_TestSegSize = MAX_UPDATE_SIZE;

    HKS_FREE(tempData);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}


/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest016
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-12 size-128. datalen = ok; abort session test
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest016, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *encParamSet = nullptr;
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = TestAesCcmAbort(&keyAlias, genParamSet, encParamSet, decParamSet, true, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestAesCcmAbort encrypt with no update failed.";

    ret = TestAesCcmAbort(&keyAlias, genParamSet, encParamSet, decParamSet, true, true);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestAesCcmAbort encrypt with update failed.";

    ret = TestAesCcmAbort(&keyAlias, genParamSet, encParamSet, decParamSet, false, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestAesCcmAbort decrypt with no update failed.";

    ret = TestAesCcmAbort(&keyAlias, genParamSet, encParamSet, decParamSet, false, true);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestAesCcmAbort decrypt with update failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest017
 * @tc.desc: alg-AES pur-DECRYPT mod-ccm pad-NONE nonce-7 size-128. datalen=20  aad-none/20
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest017, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksBlob keyBlob = {sizeof(g_testKey), g_testKey};
    
    struct HksBlob inData     = {sizeof(g_testPlain), g_testPlain};
    struct HksBlob cipherText = {sizeof(g_testCipherTextAead8Nonce7NoAad), g_testCipherTextAead8Nonce7NoAad };
    uint8_t outData[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = {sizeof(outData), outData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    ret = HksImportKey(&keyAlias, genParamSet, &keyBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    // none aad
    struct HksParamSet *decParamSet = nullptr;
    ret = HksAesSetNonceLen(g_decCcmParamsNoAad, sizeof(g_decCcmParamsNoAad) / sizeof(HksParam),
        sizeof(g_testNonce), g_testNonce);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = HksAesSetAeadLen(g_decCcmParamsNoAad, sizeof(g_decCcmParamsNoAad) / sizeof(HksParam), 8, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec aead len failed.";

    ret = InitParamSet(&decParamSet, g_decCcmParamsNoAad, sizeof(g_decCcmParamsNoAad) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, 8);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCcmCipherTestDecrypt failed";
    HksFreeParamSet(&decParamSet);

    // has aad
    cipherText.data = g_testCipherTextAead8Nonce7Aad20;
    cipherText.size = sizeof(g_testCipherTextAead8Nonce7Aad20);
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testNonce), g_testNonce);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = HksAesSetAadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testAad), g_testAad);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec aad len failed.";
    ret = HksAesSetAeadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), 8, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec aead len failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, 8);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCcmCipherTestDecrypt failed";
    HksFreeParamSet(&decParamSet);

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest018
 * @tc.desc: alg-AES pur-DECRYPT mod-ccm pad-NONE nonce-7 size-128. datalen=20  aad-20 aead=4/16
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest018, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksBlob keyBlob = {sizeof(g_testKey), g_testKey};
    
    struct HksBlob inData     = {sizeof(g_testPlain), g_testPlain};
    struct HksBlob cipherText = {0, nullptr};
    uint8_t outData[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = {sizeof(outData), outData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    ret = HksImportKey(&keyAlias, genParamSet, &keyBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    // aead len 4
    cipherText.data = g_testCipherTextAead4Nonce7Aad20;
    cipherText.size = sizeof(g_testCipherTextAead4Nonce7Aad20);
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testNonce), g_testNonce);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = HksAesSetAadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testAad), g_testAad);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = HksAesSetAeadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), CCM_MIN_AEAD_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    struct HksParamSet *decParamSet = nullptr;
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, CCM_MIN_AEAD_SIZE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCcmCipherTestDecrypt failed";
    HksFreeParamSet(&decParamSet);

    // aead len 16
    cipherText.data = g_testCipherTextAead16Nonce7Aad20;
    cipherText.size = sizeof(g_testCipherTextAead16Nonce7Aad20);
    ret = HksAesSetAeadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), CCM_MAX_AEAD_SIZE, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, CCM_MAX_AEAD_SIZE);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCcmCipherTestDecrypt failed";
    HksFreeParamSet(&decParamSet);

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest019
 * @tc.desc: alg-AES pur-DECRYPT mod-ccm pad-NONE nonce-7 size-128. datalen=20  aad-20 aead=2/3-invalid
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest019, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksBlob keyBlob = {sizeof(g_testKey), g_testKey};
    
    struct HksBlob inData     = {sizeof(g_testPlain), g_testPlain};
    struct HksBlob cipherText = {0, nullptr};
    uint8_t outData[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = {sizeof(outData), outData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    ret = HksImportKey(&keyAlias, genParamSet, &keyBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    struct HksParamSet *decParamSet = nullptr;

    cipherText.data = g_testCipherTextAead4Nonce7Aad20;
    cipherText.size = sizeof(g_testCipherTextAead4Nonce7Aad20);
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testNonce), g_testNonce);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = HksAesSetAadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testAad), g_testAad);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";

    // aead len 2
    ret = HksAesSetAeadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), CCM_MIN_AEAD_SIZE - 2, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData,
        CCM_MIN_AEAD_SIZE - 2);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    HksFreeParamSet(&decParamSet);
    
    // aead len 3
    cipherText.data = g_testCipherTextAead4Nonce7Aad20;
    cipherText.size = sizeof(g_testCipherTextAead4Nonce7Aad20);
    ret = HksAesSetAeadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), CCM_MIN_AEAD_SIZE - 1, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, CCM_MIN_AEAD_SIZE - 1);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    HksFreeParamSet(&decParamSet);

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest020
 * @tc.desc: alg-AES pur-DECRYPT mod-ccm pad-NONE nonce-7 size-128. datalen=20  aad-20 aead=17/18-invalid
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest020, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = {strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct HksBlob keyBlob = {sizeof(g_testKey), g_testKey};
    
    struct HksBlob inData     = {sizeof(g_testPlain), g_testPlain};
    struct HksBlob cipherText = {0, nullptr};
    uint8_t outData[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = {sizeof(outData), outData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    ret = HksImportKey(&keyAlias, genParamSet, &keyBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    struct HksParamSet *decParamSet = nullptr;

    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testNonce), g_testNonce);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = HksAesSetAadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testAad), g_testAad);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
   
    // aead len 17
    cipherText.data = g_testCipherTextAead16Nonce7Aad20;
    cipherText.size = sizeof(g_testCipherTextAead16Nonce7Aad20);
    ret = HksAesSetAeadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), 17, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, 17);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    HksFreeParamSet(&decParamSet);

    // aead len 18
    cipherText.data = g_testCipherTextAead16Nonce7Aad20;
    cipherText.size = sizeof(g_testCipherTextAead16Nonce7Aad20);
    ret = HksAesSetAeadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), 17, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, 17);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    HksFreeParamSet(&decParamSet);

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest021
 * @tc.desc: alg-AES pur-DECRYPT mod-ccm pad-NONE nonce-10/13 size-128. datalen=20  aad-20 aead=8
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest021, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = {strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct HksBlob keyBlob = {sizeof(g_testKey), g_testKey};
    
    struct HksBlob inData     = {sizeof(g_testPlain), g_testPlain};
    struct HksBlob cipherText = {0, nullptr};
    uint8_t outData[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = {sizeof(outData), outData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    ret = HksImportKey(&keyAlias, genParamSet, &keyBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    struct HksParamSet *decParamSet = nullptr;

    ret = HksAesSetAadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testAad), g_testAad);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = HksAesSetAeadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), 8, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";

    // nonce len 10
    cipherText.data = g_testCipherTextAead8Nonce10Aad20;
    cipherText.size = sizeof(g_testCipherTextAead8Nonce10Aad20);
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testNonce10), g_testNonce10);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, 8);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCcmCipherTestDecrypt failed";
    HksFreeParamSet(&decParamSet);

    // nonce len 13
    cipherText.data = g_testCipherTextAead8Nonce13Aad20;
    cipherText.size = sizeof(g_testCipherTextAead8Nonce13Aad20);
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testNonce13), g_testNonce13);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    (void)memset_s(outData, sizeof(outData), 0, sizeof(outData));
    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, 8);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCcmCipherTestDecrypt failed";
    HksFreeParamSet(&decParamSet);

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest022
 * @tc.desc: alg-AES pur-DECRYPT mod-ccm pad-NONE nonce-6/14-invalid size-128. datalen=20  aad-20 aead=8
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest022, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksBlob keyBlob = {sizeof(g_testKey), g_testKey};
    
    struct HksBlob inData     = {sizeof(g_testPlain), g_testPlain};
    struct HksBlob cipherText = {0, nullptr};
    uint8_t outData[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = {sizeof(outData), outData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    ret = HksImportKey(&keyAlias, genParamSet, &keyBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    struct HksParamSet *decParamSet = nullptr;

    ret = HksAesSetAadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        sizeof(g_testAad), g_testAad);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = HksAesSetAeadLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), 8, NULL);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";

    // nonce len 6
    cipherText.data = g_testCipherTextAead8Nonce10Aad20;
    cipherText.size = sizeof(g_testCipherTextAead8Nonce10Aad20);
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam), 6, g_testNonce);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, 8);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    HksFreeParamSet(&decParamSet);

    // nonce len 14
    cipherText.data = g_testCipherTextAead8Nonce13Aad20;
    cipherText.size = sizeof(g_testCipherTextAead8Nonce13Aad20);
    ret = HksAesSetNonceLen(g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam),
        CCM_MAX_NONCE_SIZE + 1, g_testPlain);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    (void)memset_s(outData, sizeof(outData), 0, sizeof(outData));
    ret = HksAesCcmCipherTestDecrypt(&keyAlias, decParamSet, &cipherText, &plainText, &inData, 8);
#ifdef HKS_UNTRUSTED_RUNNING_ENV
    EXPECT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR) << "not HKS_ERROR_CRYPTO_ENGINE_ERROR error code.";
#else
    EXPECT_EQ(ret, HKS_FAILURE) << "not HKS_FAILURE error code.";
#endif
    HksFreeParamSet(&decParamSet);

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest023
 * @tc.desc: alg-AES pur-Encrypt mod-ccm pad-NONE nonce-8 size-128. datalen=20  aad-1/none aead=16
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest023, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksBlob keyBlob = {sizeof(g_testDecKey), g_testDecKey};
    
    struct HksBlob inData     = {sizeof(g_testDecPlain), g_testDecPlain};
    uint8_t outData[AES_COMMON_SIZE] = {0};
    struct HksBlob cipherText = {sizeof(outData), outData };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParams, sizeof(g_genCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    ret = HksImportKey(&keyAlias, genParamSet, &keyBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    struct HksParamSet *encParamSet = nullptr;

    // has aad
    ret = HksAesSetAadLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam),
        sizeof(g_testDecAad), g_testDecAad);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = HksAesSetNonceLen(g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam), sizeof(g_testDecNonce),
        g_testDecNonce);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&encParamSet, g_encCcmParams, sizeof(g_encCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestEncrypt(&keyAlias, encParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";
    EXPECT_EQ(cipherText.size, sizeof(g_testDecCipherTextNonce8Aad1));
    EXPECT_EQ(HksMemCmp(cipherText.data, g_testDecCipherTextNonce8Aad1, cipherText.size), HKS_SUCCESS);
    HksFreeParamSet(&encParamSet);

    // no aad
    ret = HksAesSetNonceLen(g_encCcmParamsNoAad, sizeof(g_encCcmParamsNoAad) / sizeof(HksParam), sizeof(g_testDecNonce),
        g_testDecNonce);
    EXPECT_EQ(ret, HKS_SUCCESS) << "set dec nonce len failed.";
    ret = InitParamSet(&encParamSet, g_encCcmParamsNoAad, sizeof(g_encCcmParamsNoAad) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAesCcmCipherTestEncrypt(&keyAlias, encParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";
    EXPECT_EQ(cipherText.size, sizeof(g_testDecCipherTextNonce8NoAad));
    EXPECT_EQ(HksMemCmp(cipherText.data, g_testDecCipherTextNonce8NoAad, cipherText.size), HKS_SUCCESS);
    HksFreeParamSet(&encParamSet);

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest024
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-7 size-128. datalen= 30  Decrypt auth contrl
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest024, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParamsAuthPur, sizeof(g_genCcmParamsAuthPur) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *encParamSet = nullptr;
    struct HksParamSet *decParamSet = nullptr;
    
    ret = InitParamSet(&encParamSet, g_encCcmParamsNoNonce,
        sizeof(g_encCcmParamsNoNonce) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t handle[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handle};
    uint8_t tokenBase[TOKEN_SIZE + 1] = {0};
    uint8_t token[TOKEN_SIZE + 1] = {0};
    struct HksBlob tokenBlob = { TOKEN_SIZE + 1, token };
    ret = HksInit(&keyAlias, encParamSet, &handleEncrypt, &tokenBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInit failed.";
    EXPECT_EQ(tokenBlob.size, 0) << "Token len not set 0 with no auth ctrl.";
    ret = HksAbort(&handleEncrypt, encParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAbort failed.";

    tokenBlob.size = sizeof(token);
    ret = HksInit(&keyAlias, decParamSet, &handleEncrypt, &tokenBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInit failed.";
    EXPECT_EQ(tokenBlob.size, TOKEN_SIZE) << "Token len no set";
    EXPECT_NE(HksMemCmp(token, tokenBase, TOKEN_SIZE), HKS_SUCCESS) << "cipherText equals inData";
    ret = HksAbort(&handleEncrypt, decParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAbort failed.";

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

/**
 * @tc.name: HksAesCipherCcmTest.HksAesCipherCcmTest025
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-ccm pad-NONE aad-16 nonce-7 size-128. datalen= 30 Encrypt auth contrl
 * @tc.type: FUNC
 */
HWTEST_F(HksAesCipherCcmTest, HksAesCipherCcmTest025, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAESCipherKeyAliasTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genCcmParamsAuthPur, sizeof(g_genCcmParamsAuthPur) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    
    struct HksParam *authPurParam = NULL;
    ret = HksGetParam(genParamSet, HKS_TAG_KEY_AUTH_PURPOSE, &authPurParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetParam failed.";
    authPurParam->uint32Param = HKS_KEY_PURPOSE_ENCRYPT;

    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *encParamSet = nullptr;
    struct HksParamSet *decParamSet = nullptr;
    
    ret = InitParamSet(&encParamSet, g_encCcmParamsNoNonce,
        sizeof(g_encCcmParamsNoNonce) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";
    ret = InitParamSet(&decParamSet, g_decCcmParams, sizeof(g_decCcmParams) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    uint8_t handle[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handle};
    uint8_t tokenBase[TOKEN_SIZE + 1] = {0};
    uint8_t token[TOKEN_SIZE + 1] = {0};
    struct HksBlob tokenBlob = {TOKEN_SIZE + 1, token };
    ret = HksInit(&keyAlias, encParamSet, &handleEncrypt, &tokenBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInit failed.";
    EXPECT_EQ(tokenBlob.size, TOKEN_SIZE) << "Token len no set";
    EXPECT_NE(HksMemCmp(token, tokenBase, TOKEN_SIZE), HKS_SUCCESS) << "cipherText equals inData";
    ret = HksAbort(&handleEncrypt, encParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAbort failed.";

    tokenBlob.size = sizeof(token);
    ret = HksInit(&keyAlias, decParamSet, &handleEncrypt, &tokenBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksInit failed.";
    EXPECT_EQ(tokenBlob.size, 0) << "Token len not set 0 with no auth ctrl.";
    ret = HksAbort(&handleEncrypt, decParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAbort failed.";

    EXPECT_EQ(HksDeleteKey(&keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encParamSet);
    HksFreeParamSet(&decParamSet);
}

#endif
}
