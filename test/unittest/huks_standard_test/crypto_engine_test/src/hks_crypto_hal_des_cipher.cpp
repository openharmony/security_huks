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

#include <securec.h>
#include <string>

#include <gtest/gtest.h>

#include "file_ex.h"
#include "hks_ability.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
namespace {
struct TestCaseParams {
    HksKeySpec spec = {0};
    HksUsageSpec usageSpec = {0};
    std::string hexData;

    HksErrorCode generateKeyResult = HksErrorCode::HKS_SUCCESS;
    HksErrorCode encryptResult = HksErrorCode::HKS_SUCCESS;
    HksErrorCode decryptResult = HksErrorCode::HKS_SUCCESS;
};

const uint32_t IV_SIZE = 8;
const uint32_t AEAD_SIZE = 16;
const uint8_t IV[IV_SIZE] = {0};
const HksCipherParam TAG_IV = { .iv = { .size = IV_SIZE, .data = (uint8_t *)IV } };

const TestCaseParams HKS_CRYPTO_HAL_DES_CIPHER_001_PARAMS = {
    .spec = {
        .algType = HKS_ALG_DES,
        .keyLen = HKS_DES_KEY_SIZE_64,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_DES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&TAG_IV,
    },
    .hexData = "0011223344556677",
#if defined(HKS_SUPPORT_DES_C) && defined(HKS_SUPPORT_DES_CBC_NOPADDING)
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_DES_CIPHER_002_PARAMS = {
    .spec = {
        .algType = HKS_ALG_DES,
        .keyLen = HKS_DES_KEY_SIZE_64,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_DES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .hexData = "0011223344556677",
#if defined(HKS_SUPPORT_DES_C) && defined(HKS_SUPPORT_DES_ECB_NOPADDING)
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_DES_CIPHER_003_PARAMS = {
    .spec = {
        .algType = HKS_ALG_DES,
        .keyLen = HKS_DES_KEY_SIZE_64,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_DES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&TAG_IV,
    },
    .hexData = "0011223344556677",
#if defined(HKS_SUPPORT_DES_C)
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_ERROR_INVALID_MODE,
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
}  // namespace

class HksCryptoHalDesCipher : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    void RunTestEncrypt(struct HksBlob *key, const TestCaseParams &testCaseParams, struct HksBlob *encryptMsg,
        struct HksBlob *encryptOut, struct HksBlob *tagAead)
    {
        void *encryptCtx = (void *)HksMalloc(HKS_CONTEXT_DATA_MAX);
        ASSERT_EQ(encryptCtx == nullptr, false) << "encryptCtx malloc failed.";
        uint32_t inLen = encryptMsg->size;

        EXPECT_EQ(HksCryptoHalEncryptInit(key, &testCaseParams.usageSpec, &encryptCtx), testCaseParams.encryptResult);
        if (testCaseParams.encryptResult != HKS_SUCCESS) {
            return;
        }

        uint32_t point = 0;
        uint32_t outPoint = 0;
        if (inLen > HKS_UPDATE_DATA_MAX) {
            HksBlob messageUpdate = { .size = HKS_UPDATE_DATA_MAX, .data = (uint8_t *)HksMalloc(HKS_UPDATE_DATA_MAX) };
            HksBlob out = { .size = HKS_UPDATE_DATA_MAX, .data = (uint8_t *)HksMalloc(HKS_UPDATE_DATA_MAX) };
            ASSERT_EQ(messageUpdate.data == nullptr || out.data == nullptr, false) << "malloc failed.";

            while (point < inLen - HKS_UPDATE_DATA_MAX) {
                EXPECT_EQ(memcpy_s(messageUpdate.data, messageUpdate.size,
                    (encryptMsg->data + point), HKS_UPDATE_DATA_MAX), EOK) << "memcpy fail";
                EXPECT_EQ(HksCryptoHalEncryptUpdate(&messageUpdate, encryptCtx, &out, testCaseParams.usageSpec.algType),
                    testCaseParams.encryptResult) << "HksCryptoHalEncryptUpdate failed.";

                (void)memcpy_s((encryptOut->data + outPoint), out.size, out.data, out.size);
                encryptOut->size += out.size;
                point = point + HKS_UPDATE_DATA_MAX;
                outPoint = outPoint + out.size;
            }
            HKS_FREE(out.data);
            HKS_FREE(messageUpdate.data);

            uint32_t lastLen = inLen - point;
            uint32_t lastOutLen = HKS_UPDATE_DATA_MAX + HKS_PADDING_SUPPLENMENT;
            HksBlob enMessageLast = { .size = lastLen, .data = (uint8_t *)HksMalloc(lastLen) };
            HksBlob enMessageLastOut = { .size = lastOutLen, .data = (uint8_t *)HksMalloc(lastOutLen) };
            ASSERT_EQ(enMessageLast.data == nullptr || enMessageLastOut.data == nullptr, false) << "msg malloc failed.";
            (void)memcpy_s(enMessageLast.data, lastLen, (encryptMsg->data + point), lastLen);
            EXPECT_EQ(HksCryptoHalEncryptFinal(&enMessageLast, &encryptCtx, &enMessageLastOut, tagAead,
                testCaseParams.usageSpec.algType), testCaseParams.encryptResult) << "HksCryptoHalEncryptFinal failed.";
            (void)memcpy_s((encryptOut->data + outPoint), enMessageLastOut.size, enMessageLastOut.data,
                enMessageLastOut.size);
            encryptOut->size += enMessageLastOut.size;
            HKS_FREE(enMessageLast.data);
        } else {
            HksBlob out = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
            ASSERT_EQ(out.data == nullptr, false) << "out malloc failed.";
            EXPECT_EQ(HksCryptoHalEncryptUpdate(encryptMsg, encryptCtx, &out, testCaseParams.usageSpec.algType),
                testCaseParams.encryptResult) << "HksCryptoHalEncryptUpdate failed.";
            (void)memcpy_s((encryptOut->data), out.size, out.data, out.size);
            encryptOut->size = out.size;

            HksBlob enMessageLast = { .size = 0, .data = nullptr };
            HksBlob enMessageLastOut = { .size = 0, .data = nullptr };
            EXPECT_EQ(HksCryptoHalEncryptFinal(&enMessageLast, &encryptCtx, &enMessageLastOut, tagAead,
                testCaseParams.usageSpec.algType), testCaseParams.encryptResult) << "HksCryptoHalEncryptFinal failed.";
            HKS_FREE(out.data);
        }
    }

    void RunTestDecrypt(const TestCaseParams &testCaseParams, struct HksBlob *key, struct HksBlob *decryptMsg,
        struct HksBlob *tagAead, struct HksBlob *decryptOut)
    {
        void* decryptCtx = (void *)HksMalloc(HKS_CONTEXT_DATA_MAX);
        ASSERT_EQ(decryptCtx == nullptr, false) << "decryptCtx malloc failed.";
        EXPECT_EQ(HksCryptoHalDecryptInit(key, &testCaseParams.usageSpec, &decryptCtx), testCaseParams.decryptResult);
        uint32_t decrytopoint = 0;
        uint32_t decrytooutPoint = 0;
        uint32_t decrytoinLen = decryptMsg->size;
        if (decrytoinLen > HKS_UPDATE_DATA_MAX) {
            HksBlob messageUpdate = { .size = HKS_UPDATE_DATA_MAX, .data = (uint8_t *)HksMalloc(HKS_UPDATE_DATA_MAX) };
            HksBlob out = { .size = decrytoinLen, .data = (uint8_t *)HksMalloc(decrytoinLen) };
            ASSERT_EQ(messageUpdate.data == nullptr || out.data == nullptr, false) << "malloc failed.";
            while (decrytopoint < decrytoinLen - HKS_UPDATE_DATA_MAX) {
                EXPECT_EQ(memcpy_s(messageUpdate.data, messageUpdate.size, (decryptMsg->data + decrytopoint),
                    HKS_UPDATE_DATA_MAX), EOK) << "memcpy fail";
                EXPECT_EQ(HksCryptoHalDecryptUpdate(&messageUpdate, decryptCtx, &out, testCaseParams.usageSpec.algType),
                    testCaseParams.decryptResult);
                (void)memcpy_s((decryptOut->data + decrytooutPoint), out.size, out.data, out.size);
                decryptOut->size += out.size;
                decrytopoint = decrytopoint + HKS_UPDATE_DATA_MAX;
                decrytooutPoint = decrytooutPoint + out.size;
            }
            HKS_FREE(out.data);
            HKS_FREE(messageUpdate.data);

            uint32_t lastLen = decrytoinLen - decrytopoint;
            HksBlob messageLast = { .size = lastLen, .data = (uint8_t *)HksMalloc(lastLen) };
            HksBlob messageLastOut = {
                .size = HKS_UPDATE_DATA_MAX + HKS_PADDING_SUPPLENMENT,
                .data = (uint8_t *)HksMalloc(HKS_UPDATE_DATA_MAX + HKS_PADDING_SUPPLENMENT)
            };
            ASSERT_EQ(messageLast.data == nullptr || messageLastOut.data == nullptr, false) << "message malloc failed.";

            (void)memcpy_s(messageLast.data, lastLen, (decryptMsg->data + decrytopoint), lastLen);
            EXPECT_EQ(HksCryptoHalDecryptFinal(&messageLast, &decryptCtx, &messageLastOut, tagAead,
                testCaseParams.usageSpec.algType), testCaseParams.decryptResult) << "HksCryptoHalEncryptFinal failed.";
            (void)memcpy_s((decryptOut->data + decrytooutPoint), messageLastOut.size, messageLastOut.data,
                messageLastOut.size);
            decryptOut->size += messageLastOut.size;

            HKS_FREE(messageLast.data);
        } else {
            HksBlob out = { .size = decrytoinLen, .data = (uint8_t *)HksMalloc(decrytoinLen) };
            ASSERT_EQ(out.data == nullptr, false) << "out malloc failed.";
            EXPECT_EQ(HksCryptoHalDecryptUpdate(decryptMsg, decryptCtx, &out,
                testCaseParams.usageSpec.algType), testCaseParams.decryptResult);
            (void)memcpy_s((decryptOut->data), out.size, out.data, out.size);
            decryptOut->size = out.size;

            HksBlob deMessageLast = { .size = 0, .data = nullptr };
            HksBlob messageLastOut = { .size = 0, .data = nullptr };
            EXPECT_EQ(HksCryptoHalDecryptFinal(&deMessageLast, &decryptCtx, &messageLastOut, tagAead,
                testCaseParams.usageSpec.algType), testCaseParams.decryptResult);

            HKS_FREE(deMessageLast.data);
            HKS_FREE(out.data);
        }
    }

    void RunTestCaseThreeStage(const TestCaseParams &testCaseParams)
    {
        HksBlob key = { .size = 0, .data = nullptr };

        uint32_t inLen = testCaseParams.hexData.length() / HKS_COUNT_OF_HALF;
        uint32_t outLen = (inLen + HKS_PADDING_SUPPLENMENT) / HKS_PADDING_SUPPLENMENT * HKS_PADDING_SUPPLENMENT;

        HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        ASSERT_EQ(message.data == nullptr, false) << "message malloc failed.";
        for (uint32_t ii = 0; ii < inLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[HKS_COUNT_OF_HALF * ii]);
        }

        HksBlob tagAead = { .size = AEAD_SIZE, .data = (uint8_t *)HksMalloc(AEAD_SIZE) };
        HksBlob encryptAll = { .size = 0, .data = (uint8_t *)HksMalloc(outLen) };
        HksBlob decryptAll = { .size = 0, .data = (uint8_t *)HksMalloc(outLen) };
        ASSERT_EQ(tagAead.data == nullptr || encryptAll.data == nullptr ||
            decryptAll.data == nullptr, false) << "malloc failed.";

        EXPECT_EQ(HksCryptoHalGenerateKey(&testCaseParams.spec, &key), testCaseParams.generateKeyResult);

        RunTestEncrypt(&key, testCaseParams, &message, &encryptAll, &tagAead);

        if (testCaseParams.encryptResult == HKS_SUCCESS) {
            RunTestDecrypt(testCaseParams, &key, &encryptAll, &tagAead, &decryptAll);
            EXPECT_EQ(message.size, decryptAll.size) << "compare size failed.";
            EXPECT_EQ(HksMemCmp(message.data, decryptAll.data, decryptAll.size), HKS_SUCCESS) << "compare data failed.";
        }

        HKS_FREE(encryptAll.data);
        HKS_FREE(decryptAll.data);
        HKS_FREE(key.data);
        HKS_FREE(tagAead.data);
    }

    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        HksBlob key = { .size = 0, .data = nullptr };

        uint32_t inLen = testCaseParams.hexData.length() / HKS_COUNT_OF_HALF;
        uint32_t outLen = (inLen + HKS_PADDING_SUPPLENMENT) / HKS_PADDING_SUPPLENMENT * HKS_PADDING_SUPPLENMENT;

        HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        ASSERT_EQ(message.data == nullptr, false) << "message malloc failed.";
        for (uint32_t ii = 0; ii < inLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[HKS_COUNT_OF_HALF * ii]);
        }
        HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };
        HksBlob plaintext = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };
        HksBlob tagAead = { .size = AEAD_SIZE, .data = (uint8_t *)HksMalloc(AEAD_SIZE) };
        ASSERT_EQ(cipherText.data == nullptr, false) << "cipherText malloc failed.";
        ASSERT_EQ(plaintext.data == nullptr, false) << "plaintext malloc failed.";
        ASSERT_EQ(tagAead.data == nullptr, false) << "tagAead malloc failed.";

        EXPECT_EQ(HksCryptoHalGenerateKey(&testCaseParams.spec, &key), testCaseParams.generateKeyResult);
        EXPECT_EQ(HksCryptoHalEncrypt(&key, &testCaseParams.usageSpec, &message, &cipherText, &tagAead),
            testCaseParams.encryptResult);
        if (testCaseParams.encryptResult != HKS_ERROR_NOT_SUPPORTED) {
            EXPECT_EQ(HksCryptoHalDecrypt(&key, &testCaseParams.usageSpec, &cipherText, &plaintext),
                testCaseParams.decryptResult);
            EXPECT_EQ(message.size, plaintext.size);
            EXPECT_EQ(HksMemCmp(message.data, plaintext.data, plaintext.size), HKS_SUCCESS);
        }

        HKS_FREE(key.data);
        HKS_FREE(cipherText.data);
        HKS_FREE(plaintext.data);
        HKS_FREE(tagAead.data);
    }
};

void HksCryptoHalDesCipher::SetUpTestCase(void)
{
}

void HksCryptoHalDesCipher::TearDownTestCase(void)
{
}

void HksCryptoHalDesCipher::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalDesCipher::TearDown()
{
}

/**
 * @tc.number    : HksCryptoHalDesCipher_001
 * @tc.name      : HksCryptoHalDesCipher_001
 * @tc.desc      : Generate key and Encrypt / Decrypt DES-64-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalDesCipher, HksCryptoHalDesCipher_001, Function | SmallTest | Level0)
{
    RunTestCaseThreeStage(HKS_CRYPTO_HAL_DES_CIPHER_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalDesCipher_002
 * @tc.name      : HksCryptoHalDesCipher_002
 * @tc.desc      : Generate key and Encrypt / Decrypt DES-64-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalDesCipher, HksCryptoHalDesCipher_002, Function | SmallTest | Level0)
{
    RunTestCaseThreeStage(HKS_CRYPTO_HAL_DES_CIPHER_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalDesCipher_003
 * @tc.name      : HksCryptoHalDesCipher_003
 * @tc.desc      : DES-64-CTR-NOPADDING invalid mode not supported.
 */
HWTEST_F(HksCryptoHalDesCipher, HksCryptoHalDesCipher_003, Function | SmallTest | Level0)
{
    RunTestCaseThreeStage(HKS_CRYPTO_HAL_DES_CIPHER_003_PARAMS);
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS