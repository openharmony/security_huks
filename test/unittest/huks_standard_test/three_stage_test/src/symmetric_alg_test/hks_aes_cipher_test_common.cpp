/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "hks_access_control_test_common.h"
#include "hks_aes_cipher_test_common.h"

#include <gtest/gtest.h>
#include <iostream>
#include <thread>
#include <chrono>

using namespace testing::ext;
using namespace Unittest::HksAccessControlPartTest;
namespace Unittest::AesCipher {
#ifdef L2_STANDARD
int32_t HksAesCipherTestEncrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *encryptParamSet, const struct HksBlob *inData, struct HksBlob *cipherText)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    int32_t ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = TestUpdateLoopFinish(&handleEncrypt, encryptParamSet, inData, cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_NE(HksMemCmp(inData->data, cipherText->data, inData->size), HKS_SUCCESS) << "cipherText equals inData";

    uint8_t tmpOut[AES_COMMON_SIZE] = {0};
    struct HksBlob outData = { AES_COMMON_SIZE, tmpOut };
    ret = HksEncrypt(keyAlias, encryptParamSet, inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEncrypt failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(outData.data, cipherText->data, outData.size), HKS_SUCCESS) << "cipherText not equals outData";

    return HKS_SUCCESS;
}

static int32_t HksAesCipherTestEncryptWithoutNonce(const struct HksBlob *keyAlias,
    struct HksParamSet *encryptParamSet, const struct HksBlob *inData, struct HksBlob *cipherText,
    bool needAccessControl)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    uint8_t challenge[32] = {0};
    struct HksBlob challengeBlob = { 32, challenge };
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    int32_t ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt, &challengeBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

#ifdef USE_HKS_MOCK
    if (needAccessControl) {
        const IDMParams testIDMParams = {
            .secureUid = 1,
            .enrolledId = 1,
            .time = 0,
            .authType = 1
        };
        ret = HksBuildAuthtoken(&encryptParamSet, &challengeBlob, testIDMParams);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_I("HksBuildAuthtoken failed, ret : %" LOG_PUBLIC "d", ret);
            return ret;
        }
    }
#endif

    ret = TestUpdateLoopFinish(&handleEncrypt, encryptParamSet, inData, cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_NE(HksMemCmp(inData->data, cipherText->data, inData->size), HKS_SUCCESS) << "cipherText equals inData";

    return HKS_SUCCESS;
}

int32_t HksAesCipherTestDecrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *decryptParamSet, const struct HksBlob *cipherText, struct HksBlob *plainText,
    const struct HksBlob *inData)
{
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handleD };
    int32_t ret = HksInit(keyAlias, decryptParamSet, &handleDecrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = TestUpdateLoopFinish(&handleDecrypt, decryptParamSet, cipherText, plainText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(inData->data, plainText->data, inData->size), HKS_SUCCESS) << "plainText not equals inData";

    uint8_t tmpOut[AES_COMMON_SIZE] = {0};
    struct HksBlob outData = { AES_COMMON_SIZE, tmpOut };
    ret = HksDecrypt(keyAlias, decryptParamSet, cipherText, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDecrypt failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(outData.data, plainText->data, outData.size), HKS_SUCCESS) << "plainText not equals outData";

    return HKS_SUCCESS;
}

int32_t HksAesCipherTestParamAbsentCase(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet)
{
    (void)decryptParamSet;
    /* 1. Generate Key */
    uint32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    /* 2. Encrypt, init will fail */
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS) << "Init failed.";

    /* 3. Delete Key */
    EXPECT_EQ(HksDeleteKey(keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}

int32_t HksAesCipherTestCaseOther(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet)
{
    char tmpInData[] = "AES_ECB_INDATA_1";
    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };

    struct HksParam *modeParam = nullptr;
    int32_t ret = HksGetParam(genParamSet, HKS_TAG_BLOCK_MODE, &modeParam);
    if ((ret == HKS_SUCCESS) && (modeParam->uint32Param == HKS_MODE_ECB)) {
        inData.size = strlen(tmpInData);
        inData.data = reinterpret_cast<uint8_t *>(tmpInData);
    }

    /* 1. Generate Key */
    ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    /* 2. Encrypt */
    uint8_t cipher[AES_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncrypt(keyAlias, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    /* 3. Decrypt Three Stage */
    uint8_t plain[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = { AES_COMMON_SIZE, plain };
    ret = HksAesCipherTestDecrypt(keyAlias, decryptParamSet, &cipherText, &plainText, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestDecrypt failed.";

    /* 3. Delete Key */
    EXPECT_EQ(HksDeleteKey(keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}

int32_t HksAesCipherTestCaseGcm2(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet, struct HksParamSet *decrypt1ParamSet)
{
    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };

    /* 1. Generate Key */
    int32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    /* 2. Encrypt Three Stage */
    uint8_t cipher[AES_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncrypt(keyAlias, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    uint8_t plain1[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText1 = { AES_COMMON_SIZE, plain1 };
    ret = HksDecrypt(keyAlias, decrypt1ParamSet, &cipherText, &plainText1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDecrypt failed.";

    cipherText.size -= AEAD_SIZE;

    uint32_t i = 0;
    for (i = 0; i < decryptParamSet->paramsCnt; i++) {
        if (decryptParamSet->params[i].tag == HKS_TAG_AE_TAG) {
            uint8_t *tempPtrTest = cipherText.data;
            (void)memcpy_s(decryptParamSet->params[i].blob.data, AEAD_SIZE,
                tempPtrTest + cipherText.size, AEAD_SIZE);
            break;
        }
    }

    /* 3. Decrypt Three Stage */
    // Init
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecryptTest = { sizeof(uint64_t), handleD };
    ret = HksInit(keyAlias, decryptParamSet, &handleDecryptTest, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update & Finish
    uint8_t plain[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = { AES_COMMON_SIZE, plain };
    ret = TestUpdateLoopFinish(&handleDecryptTest, decryptParamSet, &cipherText, &plainText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    EXPECT_EQ(HksMemCmp(inData.data, plainText.data, inData.size), HKS_SUCCESS) << "plainText not equals inData";
    EXPECT_EQ(HksMemCmp(plainText1.data, plainText.data, plainText1.size), HKS_SUCCESS) << "plainText != plainText1";

    /* 3. Delete Key */
    EXPECT_EQ(HksDeleteKey(keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}

int32_t HksAesCipherTestCaseGcm3(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet, bool needAccessControl)
{
    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };

    /* 1. Generate Key */
    int32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    /* 2. Encrypt Three Stage */
    uint8_t cipher[AES_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncryptWithoutNonce(keyAlias, encryptParamSet, &inData, &cipherText, needAccessControl);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";

    cipherText.size -= NONCE_SIZE;
    cipherText.size -= AEAD_SIZE;

    uint32_t i = 0;
    for (i = 0; i < decryptParamSet->paramsCnt; i++) {
        if (decryptParamSet->params[i].tag == HKS_TAG_AE_TAG) {
            uint8_t *tempPtrTest = cipherText.data;
            (void)memcpy_s(decryptParamSet->params[i].blob.data, AEAD_SIZE,
                tempPtrTest + cipherText.size, AEAD_SIZE);
            break;
        }
    }

    for (i = 0; i < decryptParamSet->paramsCnt; i++) {
        if (decryptParamSet->params[i].tag == HKS_TAG_NONCE) {
            uint8_t *tempPtrTest = cipherText.data;
            (void)memcpy_s(decryptParamSet->params[i].blob.data, NONCE_SIZE,
                tempPtrTest + cipherText.size + AEAD_SIZE, NONCE_SIZE);
            break;
        }
    }

    /* 3. Decrypt Three Stage */
    // Init
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecryptTest = { sizeof(uint64_t), handleD };
    ret = HksInit(keyAlias, decryptParamSet, &handleDecryptTest, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update & Finish
    uint8_t plain[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = { AES_COMMON_SIZE, plain };
    ret = TestUpdateLoopFinish(&handleDecryptTest, decryptParamSet, &cipherText, &plainText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    EXPECT_EQ(HksMemCmp(inData.data, plainText.data, inData.size), HKS_SUCCESS) << "plainText not equals inData";

    /* 3. Delete Key */
    ret = HksDeleteKey(keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}

static void HksAesGcmAppendAeadAndNonce(struct HksParamSet *paramSet, struct HksBlob *cipherText)
{
    uint32_t i = 0;
    for (i = 0; i < paramSet->paramsCnt; i++) {
        if (paramSet->params[i].tag == HKS_TAG_AE_TAG) {
            uint8_t *tempPtrTest = cipherText->data;
            (void)memcpy_s(paramSet->params[i].blob.data, AEAD_SIZE,
                tempPtrTest + cipherText->size, AEAD_SIZE);
            break;
        }
    }
    for (i = 0; i < paramSet->paramsCnt; i++) {
        if (paramSet->params[i].tag == HKS_TAG_NONCE) {
            uint8_t *tempPtrTest = cipherText->data;
            (void)memcpy_s(paramSet->params[i].blob.data, NONCE_SIZE,
                tempPtrTest + cipherText->size + AEAD_SIZE, NONCE_SIZE);
            break;
        }
    }
    return;
}

int32_t HksAesCipherTestCaseGcm4(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet, bool isTimeOut)
{
    static const std::string tmp_inData = "Hks_string";

    struct HksBlob inData = {
        tmp_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(tmp_inData.c_str()))
    };

    /* 1. Generate Key */
    int32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    /* 2. Encrypt Three Stage */
    uint8_t cipher[AES_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = HksAesCipherTestEncryptWithoutNonce(keyAlias, encryptParamSet, &inData, &cipherText, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    cipherText.size -= NONCE_SIZE;
    cipherText.size -= AEAD_SIZE;

    HksAesGcmAppendAeadAndNonce(decryptParamSet, &cipherText);

    /* 3. Decrypt Three Stage */
    // Init
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecryptTest = { sizeof(uint64_t), handleD };
    ret = HksInit(keyAlias, decryptParamSet, &handleDecryptTest, nullptr);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    if (isTimeOut) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Update & Finish
    uint8_t plain[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = { AES_COMMON_SIZE, plain };
    ret = TestBatchUpdateLoopFinish(&handleDecryptTest, decryptParamSet, &cipherText, &plainText);
    if (isTimeOut == true) {
        EXPECT_EQ(ret, HKS_ERROR_INVALID_TIME_OUT) << "TestUpdateLoopFinish failed.";
    } else {
        EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    }
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(inData.data, plainText.data, inData.size), HKS_SUCCESS) << "plainText not equals inData";

    /* 3. Delete Key */
    ret = HksDeleteKey(keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}

int32_t HksAesEncryptThreeStage(const struct HksBlob *keyAlias, struct HksParamSet *encryptParamSet,
    const struct HksBlob *inData, struct HksBlob *cipherText)
{
    int32_t ret = HksAesCipherTestEncryptWithoutNonce(keyAlias, encryptParamSet, inData, cipherText, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksAesCipherTestEncrypt failed.";
    return ret;
}

int32_t HksAesDecryptThreeStage(const struct HksBlob *keyAlias, struct HksParamSet *decryptParamSet,
    const struct HksBlob *inData, struct HksBlob *cipherText, struct HksBlob *plainText)
{
    cipherText->size -= NONCE_SIZE;
    cipherText->size -= AEAD_SIZE;

    uint32_t i = 0;
    for (i = 0; i < decryptParamSet->paramsCnt; i++) {
        if (decryptParamSet->params[i].tag == HKS_TAG_AE_TAG) {
            uint8_t *tempPtrTest = cipherText->data;
            (void)memcpy_s(decryptParamSet->params[i].blob.data, AEAD_SIZE,
                tempPtrTest + cipherText->size, AEAD_SIZE);
            break;
        }
    }

    for (i = 0; i < decryptParamSet->paramsCnt; i++) {
        if (decryptParamSet->params[i].tag == HKS_TAG_NONCE) {
            uint8_t *tempPtrTest = cipherText->data;
            (void)memcpy_s(decryptParamSet->params[i].blob.data, NONCE_SIZE,
                tempPtrTest + cipherText->size + AEAD_SIZE, NONCE_SIZE);
            break;
        }
    }

    /* 3. Decrypt Three Stage */
    // Init
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecryptTest = { sizeof(uint64_t), handleD };
    uint8_t challenge[32] = {0};
    struct HksBlob challengeBlob = { 32, challenge };
    int32_t ret = HksInit(keyAlias, decryptParamSet, &handleDecryptTest, &challengeBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    // Update & Finish
    ret = TestUpdateLoopFinish(&handleDecryptTest, decryptParamSet, cipherText, plainText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(inData->data, plainText->data, inData->size), HKS_SUCCESS) << "plainText not equals inData";
    return ret;
}

int32_t HksAesDecryptForBatch(const struct HksBlob *keyAlias, struct HksParamSet *decryptParamSet,
    const struct HksBlob *inData1, struct HksBlob *cipherText1, struct HksBlob *plainText1,
    const struct HksBlob *inData2, struct HksBlob *cipherText2, struct HksBlob *plainText2)
{
    HksAesGcmAppendAeadAndNonce(decryptParamSet, cipherText1);

    // Init
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecryptTest = { sizeof(uint64_t), handleD };
    uint8_t challenge[32] = {0};
    struct HksBlob challengeBlob = { 32, challenge };
    int32_t ret = HksInit(keyAlias, decryptParamSet, &handleDecryptTest, &challengeBlob);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    // Update & Finish
    ret = HksUpdate(&handleDecryptTest, decryptParamSet, cipherText1, plainText1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    HksAesGcmAppendAeadAndNonce(decryptParamSet, cipherText2);

    ret = HksUpdate(&handleDecryptTest, decryptParamSet, cipherText2, plainText2);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    uint8_t finishIn[AES_COMMON_SIZE] = {0};
    struct HksBlob finishInText = { AES_COMMON_SIZE, finishIn };
    uint8_t finishOut[AES_COMMON_SIZE] = {0};
    struct HksBlob finishOutText = { AES_COMMON_SIZE, finishOut };
    ret = HksFinish(&handleDecryptTest, decryptParamSet, &finishInText, &finishOutText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(inData1->data, plainText1->data, inData1->size), HKS_SUCCESS) << "plainText not equals inData";
    EXPECT_EQ(HksMemCmp(inData2->data, plainText2->data, inData2->size), HKS_SUCCESS) << "plainText not equals inData";

    return ret;
}

#else
    int32_t HksAesCipherTestCaseOther(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
        struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet)
{
    struct HksBlob inData = {
        (uint32_t)g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };

    /* 1. Generate Key */
    int32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    /* 2. Encrypt Three Stage */
    // Init
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update & Finish
    uint8_t cipher[AES_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = TestUpdateLoopFinish(&handleEncrypt, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    EXPECT_NE(memcmp(inData.data, cipherText.data, inData.size), HKS_SUCCESS) << "cipherText equals inData";
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(keyAlias, genParamSet);
        return ret;
    }

    HKS_LOG_I("enter Decrypt Three Stage");

    /* 3. Decrypt Three Stage */
    // Init
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handleD };
    ret = HksInit(keyAlias, decryptParamSet, &handleDecrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    HKS_LOG_I("enter Update & Finish");

    // Update & Finish
    uint8_t plain[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = { AES_COMMON_SIZE, plain };
    ret = TestUpdateLoopFinish(&handleDecrypt, decryptParamSet, &cipherText, &plainText);

    HKS_LOG_I("enter memcmp, inData.size %d, plainText.size %d", inData.size, plainText.size);

    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    EXPECT_EQ(inData.size, plainText.size) << "plainText not equals inData";
    if (inData.size != plainText.size) {
        HKS_LOG_E("xxxxxxxxxxx");
        return -1;
    }
    EXPECT_EQ(memcmp(inData.data, plainText.data, inData.size), HKS_SUCCESS) << "plainText not equals inData";
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(keyAlias, genParamSet);
        return ret;
    }

    HKS_LOG_I("enter HksDeleteKey");

    /* 3. Delete Key */
    ret = HksDeleteKey(keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}

int32_t HksAesCipherTestCaseGcm1(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet)
{
    struct HksBlob inData = {
        (uint32_t)g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };

    /* 1. Generate Key */
    int32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    /* 2. Encrypt Three Stage */
    // Init
    uint8_t cipher[AES_COMMON_SIZE] = {0};
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update & Finish
    struct HksBlob cipherText = { AES_COMMON_SIZE, cipher };
    ret = TestUpdateLoopFinish(&handleEncrypt, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    EXPECT_NE(memcmp(inData.data, cipherText.data, inData.size), HKS_SUCCESS) << "cipherText equals inData";
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(keyAlias, genParamSet);
        return ret;
    }

    cipherText.size -= AEAD_SIZE;

    uint32_t i = 0;
    for (i = 0; i < decryptParamSet->paramsCnt; i++) {
        if (decryptParamSet->params[i].tag == HKS_TAG_AE_TAG) {
            uint8_t *tempPtr = cipherText.data;
            (void)memcpy_s(decryptParamSet->params[i].blob.data, AEAD_SIZE,
                tempPtr + cipherText.size, AEAD_SIZE);
            break;
        }
    }

    /* 3. Decrypt Three Stage */
    // Init
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handleD };
    ret = HksInit(keyAlias, decryptParamSet, &handleDecrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update & Finish
    uint8_t plain[AES_COMMON_SIZE] = {0};
    struct HksBlob plainText = { AES_COMMON_SIZE, plain };
    ret = TestUpdateLoopFinish(&handleDecrypt, decryptParamSet, &cipherText, &plainText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateLoopFinish failed.";
    EXPECT_EQ(memcmp(inData.data, plainText.data, inData.size), HKS_SUCCESS) << "plainText not equals inData";
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(keyAlias, genParamSet);
        return ret;
    }

    /* 3. Delete Key */
    ret = HksDeleteKey(keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}
#endif
}
