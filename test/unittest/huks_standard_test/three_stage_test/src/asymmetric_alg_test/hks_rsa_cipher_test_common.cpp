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

#include "hks_rsa_cipher_test_common.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>

int32_t Unittest::RsaCipher::HksRsaCipherTestEncryptAbnormal(const struct HksBlob *keyAlias,
    const struct HksParamSet *encryptParamSet, const struct HksBlob *inData, struct HksBlob *cipherText)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    int32_t ret = HksInitForDe(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = TestUpdateFinish(&handleEncrypt, encryptParamSet, HKS_KEY_PURPOSE_ENCRYPT, inData, cipherText);
    EXPECT_EQ(ret, HKS_FAILURE) << "TestUpdateFinish should failed.";
    if (ret != HKS_SUCCESS) {
        int32_t abortRet = HksAbort(&handleEncrypt, encryptParamSet);
        EXPECT_EQ(abortRet, HKS_SUCCESS) << "Abort failed.";
        return ret;
    }
    EXPECT_NE(HksMemCmp(inData->data, cipherText->data, inData->size), HKS_SUCCESS) << "cipherText equals inData";

    uint8_t tmpOut[Unittest::RsaCipher::RSA_COMMON_SIZE] = {0};
    struct HksBlob outData = { Unittest::RsaCipher::RSA_COMMON_SIZE, tmpOut };
    ret = HksEncryptForDe(keyAlias, encryptParamSet, inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEncrypt failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(outData.data, cipherText->data, outData.size), HKS_SUCCESS) << "cipherText not equals outData";

    return HKS_SUCCESS;
}

int32_t Unittest::RsaCipher::HksRsaCipherTestEncrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *encryptParamSet, const struct HksBlob *inData, struct HksBlob *cipherText)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    int32_t ret = HksInitForDe(keyAlias, encryptParamSet, &handleEncrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = TestUpdateFinish(&handleEncrypt, encryptParamSet, HKS_KEY_PURPOSE_ENCRYPT, inData, cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_NE(HksMemCmp(inData->data, cipherText->data, inData->size), HKS_SUCCESS) << "cipherText equals inData";

    uint8_t tmpOut[Unittest::RsaCipher::RSA_COMMON_SIZE] = {0};
    struct HksBlob outData = { Unittest::RsaCipher::RSA_COMMON_SIZE, tmpOut };
    ret = HksEncryptForDe(keyAlias, encryptParamSet, inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEncrypt failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    return HKS_SUCCESS;
}

int32_t Unittest::RsaCipher::HksRsaCipherTestDecrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *decryptParamSet, const struct HksBlob *cipherText, struct HksBlob *plainText,
    const struct HksBlob *inData)
{
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handleD };
    int32_t ret = HksInitForDe(keyAlias, decryptParamSet, &handleDecrypt, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Init failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = TestUpdateFinish(&handleDecrypt, decryptParamSet, HKS_KEY_PURPOSE_DECRYPT, cipherText, plainText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateFinish failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(inData->data, plainText->data, inData->size), HKS_SUCCESS) << "plainText not equals inData";

    uint8_t tmpOut[Unittest::RsaCipher::RSA_COMMON_SIZE] = {0};
    struct HksBlob outData = { Unittest::RsaCipher::RSA_COMMON_SIZE, tmpOut };
    ret = HksDecryptForDe(keyAlias, decryptParamSet, cipherText, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDecrypt failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(outData.data, plainText->data, outData.size), HKS_SUCCESS) << "plainText not equals outData";

    return HKS_SUCCESS;
}

int32_t Unittest::RsaCipher::HksRsaCipherTestCase(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet, const struct HksBlob *inData)
{
    /* 1. Generate Key */
    int32_t ret = HksGenerateKeyForDe(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. Export Public Key */
    uint8_t tmpPublicKey[HKS_RSA_KEY_SIZE_1024] = {0};
    struct HksBlob publicKey = { HKS_RSA_KEY_SIZE_1024, tmpPublicKey };
    ret = HksExportPublicKeyForDe(keyAlias, genParamSet, &publicKey);

    /* 3. Import Key */
    char tmpKey[] = "RSA_Encrypt_Decrypt_KeyAlias";
    struct HksBlob newKeyAlias = { .size = (uint32_t)strlen(tmpKey), .data = reinterpret_cast<uint8_t *>(tmpKey) };
    ret = HksImportKeyForDe(&newKeyAlias, encryptParamSet, &publicKey);

    /* 4. Encrypt Three Stage */
    uint8_t cipher[Unittest::RsaCipher::RSA_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { Unittest::RsaCipher::RSA_COMMON_SIZE, cipher };
    ret = HksRsaCipherTestEncrypt(&newKeyAlias, encryptParamSet, inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTestEncrypt failed.";

    /* 5. Decrypt Three Stage */
    uint8_t plain[Unittest::RsaCipher::RSA_COMMON_SIZE] = {0};
    struct HksBlob plainText = { Unittest::RsaCipher::RSA_COMMON_SIZE, plain };
    ret = HksRsaCipherTestDecrypt(keyAlias, decryptParamSet, &cipherText, &plainText, inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTestDecrypt failed.";

    /* 6. Delete Key */
    EXPECT_EQ(HksDeleteKeyForDe(keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    EXPECT_EQ(HksDeleteKeyForDe(&newKeyAlias, encryptParamSet), HKS_SUCCESS) << "Delete ImportKey failed.";
    return ret;
}

int32_t Unittest::RsaCipher::HksRsaCipherTestCaseAbnormal(const struct HksBlob *keyAlias,
    struct HksParamSet *genParamSet, struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet,
    const struct HksBlob *inData)
{
    /* 1. Generate Key */
    int32_t ret = HksGenerateKeyForDe(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. Export Public Key */
    uint8_t tmpPublicKey[HKS_RSA_KEY_SIZE_1024] = {0};
    struct HksBlob publicKey = { HKS_RSA_KEY_SIZE_1024, tmpPublicKey };
    ret = HksExportPublicKeyForDe(keyAlias, genParamSet, &publicKey);

    /* 3. Import Key */
    char tmpKey[] = "RSA_Encrypt_Decrypt_KeyAlias";
    struct HksBlob newKeyAlias = { .size = (uint32_t)strlen(tmpKey), .data = reinterpret_cast<uint8_t *>(tmpKey) };
    ret = HksImportKeyForDe(&newKeyAlias, encryptParamSet, &publicKey);

    /* 4. Encrypt Three Stage */
    uint8_t cipher[Unittest::RsaCipher::RSA_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { Unittest::RsaCipher::RSA_COMMON_SIZE, cipher };
    ret = HksRsaCipherTestEncryptAbnormal(&newKeyAlias, encryptParamSet, inData, &cipherText);
    EXPECT_EQ(ret, HKS_FAILURE) << "HksRsaCipherTestEncrypt should failed.";

    /* 6. Delete Key */
    EXPECT_EQ(HksDeleteKeyForDe(keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    EXPECT_EQ(HksDeleteKeyForDe(&newKeyAlias, encryptParamSet), HKS_SUCCESS) << "Delete ImportKey failed.";
    return ret;
}

int32_t Unittest::RsaCipher::HksRsaCipherTest(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    uint32_t purpose, const struct HksBlob *inData, struct HksBlob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };
    int32_t ret = HksInitForDe(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    return TestUpdateFinish(&handleBlob, paramSet, purpose, inData, outData);
}
