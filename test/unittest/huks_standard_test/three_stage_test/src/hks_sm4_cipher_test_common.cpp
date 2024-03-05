/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_sm4_cipher_test_common.h"

#include <gtest/gtest.h>
using namespace testing::ext;
namespace Unittest::Sm4Cipher {
#ifdef L2_STANDARD
#ifdef _USE_OPENSSL_
static int32_t HksSm4CipherTestEncrypt(const struct HksBlob *keyAlias,
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

    return HKS_SUCCESS;
}

static int32_t HksSm4CipherTestDecrypt(const struct HksBlob *keyAlias,
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

    return HKS_SUCCESS;
}
int32_t HksSm4CipherTestCaseOther(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet)
{
    char tmpInData[] = "SM4_ECB_INDATA_1";
    struct HksBlob inData = {
        g_inData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
    };

    struct HksParam *modeParam = nullptr;
    int32_t ret = HksGetParam(genParamSet, HKS_TAG_BLOCK_MODE, &modeParam);
    if (ret == HKS_SUCCESS && modeParam->uint32Param == HKS_MODE_ECB) {
        inData.size = strlen(tmpInData);
        inData.data = reinterpret_cast<uint8_t *>(tmpInData);
    }

    /* 1. Generate Key */
    ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("GenerateKey failed");
        return ret;
    }

    /* 2. Encrypt */
    uint8_t cipher[SM4_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { SM4_COMMON_SIZE, cipher };
    ret = HksSm4CipherTestEncrypt(keyAlias, encryptParamSet, &inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksSm4CipherTestEncrypt failed.";

    /* 3. Decrypt Three Stage */
    uint8_t plain[SM4_COMMON_SIZE] = {0};
    struct HksBlob plainText = { SM4_COMMON_SIZE, plain };
    ret = HksSm4CipherTestDecrypt(keyAlias, decryptParamSet, &cipherText, &plainText, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksSm4CipherTestDecrypt failed.";

    /* 3. Delete Key */
    EXPECT_EQ(HksDeleteKey(keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}

#ifndef HKS_UNTRUSTED_RUNNING_ENV
int32_t HksSm4CipherTestCaseGcm(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet)
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
    // Init
    uint8_t cipher[SM4_COMMON_SIZE] = {0};
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";

    // Update & Finish
    struct HksBlob cipherText = { SM4_COMMON_SIZE, cipher };
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
    uint8_t plain[SM4_COMMON_SIZE] = {0};
    struct HksBlob plainText = { SM4_COMMON_SIZE, plain };
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
#endif
#endif
}

