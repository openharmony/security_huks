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

#include "hks_auth_part_test_common.h"

#include <gtest/gtest.h>
namespace Unittest::AuthPartTest {
void HksAuthAgreeFreeParamSet(struct HksParamSet *paramSet1, struct HksParamSet *paramSet2,
    struct HksParamSet *paramSet3, struct HksParamSet *paramSet4, struct HksParamSet *paramSet5)
{
    HksFreeParamSet(&paramSet1);
    HksFreeParamSet(&paramSet2);
    HksFreeParamSet(&paramSet3);
    HksFreeParamSet(&paramSet4);
    HksFreeParamSet(&paramSet5);
}

void HksAuthAgreeFreeBlob(struct HksBlob *blob1, struct HksBlob *blob2,
    struct HksBlob *blob3, struct HksBlob *blob4)
{
    HksFree(blob1->data);
    HksFree(blob2->data);
    HksFree(blob3->data);
    HksFree(blob4->data);
}

int32_t HksTestSignVerify(struct HksBlob *keyAlias, struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData, bool isSign)
{
    (void)isSign;
    uint8_t tmpHandle[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), tmpHandle };
    int32_t ret = HksInit(keyAlias, paramSet, &handle);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksSignVerifyTestInit failed., ret = %d", ret);
        return ret;
    }

    struct HksParam *tmpParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &tmpParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get tag purpose failed.");
        return HKS_FAILURE;
    }

    ret = TestUpdateFinish(&handle, paramSet, tmpParam->uint32Param, inData, outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "TestUpdateFinish failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }

    ret = HksAbort(&handle, paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    return ret;
}

int32_t HksAuthSignVerifyTestNormalCase(struct HksBlob keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet)
{
    struct HksBlob inData = {
        g_inData.length(),
        (uint8_t *)g_inData.c_str()
    };
    int32_t ret = HKS_FAILURE;

    /* 1. Generate Key */
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. Sign Three Stage */
    uint8_t outDataS[SIGN_COMMON_SIZE] = {0};
    struct HksBlob outDataSign = { SIGN_COMMON_SIZE, outDataS };
    ret = HksTestSignVerify(&keyAlias, signParamSet, &inData, &outDataSign, true);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("outSign failed.");
        return ret;
    }

    /* 3. Export Public Key */
    uint8_t pubKey[HKS_MAX_KEY_LEN] = {0};
    struct HksBlob publicKey = { HKS_MAX_KEY_LEN, pubKey };
    ret = HksExportPublicKey(&keyAlias, genParamSet, &publicKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey failed.";

    /* 4. Import Key */
    char newKey[] = "SM2_Sign_Verify_Import_KeyAlias";
    struct HksBlob newKeyAlias = { .size = strlen(newKey), .data = (uint8_t *)newKey };
    ret = HksImportKey(&newKeyAlias, verifyParamSet, &publicKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ImportKey failed";

    /* 5. Verify Three Stage */
    ret = HksTestSignVerify(&newKeyAlias, verifyParamSet, &inData, &outDataSign, false);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Verify failed.");
        return ret;
    }

    /* 6. Delete New Key */
    int32_t deleteRet = HksDeleteKey(&newKeyAlias, genParamSet);
    EXPECT_EQ(deleteRet, HKS_SUCCESS) << "Delete key failed.";

    return ret;
}

int32_t  HksAuthAgreeFinish(const struct HksBlob *keyAlias, const struct HksBlob *publicKey,
    const struct HksParamSet *initParamSet, const struct HksParamSet *finishParamSet, struct HksBlob *outData)
{
    struct HksBlob inData = {
        g_inData.length(),
        (uint8_t *)g_inData.c_str()
    };

    uint8_t handleU[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleU };
    int32_t ret = HksInit(keyAlias, initParamSet, &handle);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksAgreeTestInit failed., ret = %d", ret);
        return ret;
    }

    struct HksParam *algParam = nullptr;
    HksGetParam(initParamSet, HKS_TAG_ALGORITHM, &algParam);
    if (algParam->uint32Param == HKS_ALG_X25519) {
        uint8_t outDataU[X25519_COMMON_SIZE] = {0};
        struct HksBlob outDataUpdate = { KEY_COMMON_SIZE, outDataU };
        ret = HksUpdate(&handle, initParamSet, publicKey, &outDataUpdate);
        EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";
        if (ret != HKS_SUCCESS) {
            return HKS_FAILURE;
        }
    } else if (algParam->uint32Param == HKS_ALG_DH) {
        uint8_t outDataU[DH_COMMON_SIZE] = {0};
        struct HksBlob outDataUpdate = { KEY_COMMON_SIZE, outDataU };
        ret = HksUpdate(&handle, initParamSet, publicKey, &outDataUpdate);
        EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";
        if (ret != HKS_SUCCESS) {
            return HKS_FAILURE;
        }
    } else if (algParam->uint32Param == HKS_ALG_ECDH) {
        uint8_t outDataU[KEY_COMMON_SIZE] = {0};
        struct HksBlob outDataUpdate = { KEY_COMMON_SIZE, outDataU };
        ret = HksUpdate(&handle, initParamSet, publicKey, &outDataUpdate);
        EXPECT_EQ(ret, HKS_SUCCESS) << "Update failed.";
        if (ret != HKS_SUCCESS) {
            return HKS_FAILURE;
        }
    } else {
        HKS_LOG_E("initParam alg is invalid");
        return HKS_FAILURE;
    }

    ret = HksFinish(&handle, finishParamSet, &inData, outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Finish failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}
    
int32_t HksAuthAgreeExport(const struct HksBlob *keyAlias1, const struct HksBlob *keyAlias2,
    struct HksBlob *publicKey1, struct HksBlob *publicKey2, const struct HksParamSet *genParamSet)
{
    int32_t ret = HksExportPublicKey(keyAlias1, genParamSet, publicKey1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey01 failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    ret = HksExportPublicKey(keyAlias2, genParamSet, publicKey2);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportPublicKey02 failed.";
    if (ret != HKS_SUCCESS) {
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

int32_t HksRsaCipherTestCase(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet, const struct HksBlob *inData)
{
    /* 1. Generate Key */
    int32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    /* 2. Export Public Key */
    uint8_t tmpPublicKey[HKS_RSA_KEY_SIZE_1024] = {0};
    struct HksBlob publicKey = { HKS_RSA_KEY_SIZE_1024, (uint8_t *)tmpPublicKey };
    ret = HksExportPublicKey(keyAlias, genParamSet, &publicKey);

    /* 3. Import Key */
    char tmpKey[] = "RSA_Encrypt_Decrypt_KeyAlias";
    struct HksBlob newKeyAlias = { .size = strlen(tmpKey), .data = (uint8_t *)tmpKey };
    ret = HksImportKey(&newKeyAlias, encryptParamSet, &publicKey);

    /* 4. Encrypt Three Stage */
    uint8_t cipher[KEY_COMMON_SIZE] = {0};
    struct HksBlob cipherText = { KEY_COMMON_SIZE, cipher };
    ret = HksRsaCipherTestEncrypt(&newKeyAlias, encryptParamSet, inData, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTestEncrypt failed.";

    /* 5. Decrypt Three Stage */
    uint8_t plain[KEY_COMMON_SIZE] = {0};
    struct HksBlob plainText = { KEY_COMMON_SIZE, plain };
    ret = HksRsaCipherTestDecrypt(keyAlias, decryptParamSet, &cipherText, &plainText, inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksRsaCipherTestDecrypt failed.";

    /* 6. Delete Key */
    EXPECT_EQ(HksDeleteKey(keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    EXPECT_EQ(HksDeleteKey(&newKeyAlias, encryptParamSet), HKS_SUCCESS) << "Delete ImportKey failed.";
    return ret;
}

int32_t HksRsaCipherTestEncrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *encryptParamSet, const struct HksBlob *inData, struct HksBlob *cipherText)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    int32_t ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt);
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

    uint8_t tmpOut[KEY_COMMON_SIZE] = {0};
    struct HksBlob outData = { KEY_COMMON_SIZE, tmpOut };
    ret = HksEncrypt(keyAlias, encryptParamSet, inData, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEncrypt failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    return HKS_SUCCESS;
}

int32_t HksRsaCipherTestDecrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *decryptParamSet, const struct HksBlob *cipherText, struct HksBlob *plainText,
    const struct HksBlob *inData)
{
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handleD };
    int32_t ret = HksInit(keyAlias, decryptParamSet, &handleDecrypt);
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

    uint8_t tmpOut[KEY_COMMON_SIZE] = {0};
    struct HksBlob outData = { KEY_COMMON_SIZE, tmpOut };
    ret = HksDecrypt(keyAlias, decryptParamSet, cipherText, &outData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDecrypt failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    EXPECT_EQ(HksMemCmp(outData.data, plainText->data, outData.size), HKS_SUCCESS) << "plainText not equals outData";

    return HKS_SUCCESS;
}

int32_t HksAuthCipherTestEncrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *encryptParamSet, const struct HksBlob *inData, struct HksBlob *cipherText)
{
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = { sizeof(uint64_t), handleE };
    int32_t ret = HksInit(keyAlias, encryptParamSet, &handleEncrypt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("EncryptInit failed, ret = %d", ret);
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

int32_t HksAuthCipherTestDecrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *decryptParamSet, const struct HksBlob *cipherText, struct HksBlob *plainText,
    const struct HksBlob *inData)
{
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = { sizeof(uint64_t), handleD };
    int32_t ret = HksInit(keyAlias, decryptParamSet, &handleDecrypt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("DecryptInit failed, ret = %d", ret);
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
int32_t HksAuthCipherTest(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet)
{
    char tmpInData[] = "AUTH_ECB_INDATA_1";
    struct HksBlob inData = {
        g_inData.length(),
        (uint8_t *)g_inData.c_str()
    };

    struct HksParam *modeParam = nullptr;
    HksGetParam(genParamSet, HKS_TAG_BLOCK_MODE, &modeParam);
    if (modeParam->uint32Param == HKS_MODE_ECB) {
        inData.size = strlen(tmpInData);
        inData.data = (uint8_t *)tmpInData;
    }

    /* 1. Generate Key */
    int32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("GenerateKey failed");
        return ret;
    }

    struct HksParam *algParam = nullptr;
    HksGetParam(genParamSet, HKS_TAG_ALGORITHM, &algParam);
    if (algParam->uint32Param == HKS_ALG_AES) {
        uint8_t cipher[KEY_COMMON_SIZE] = {0};
        struct HksBlob cipherText = { KEY_COMMON_SIZE, cipher };
        /* 2. Encrypt */
        ret = HksAuthCipherTestEncrypt(keyAlias, encryptParamSet, &inData, &cipherText);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksAesCipherTestEncrypt failed., ret = %d", ret);
            return ret;
        }
        uint8_t plain[KEY_COMMON_SIZE] = {0};
        struct HksBlob plainText = { KEY_COMMON_SIZE, plain };
        /* 3. Decrypt Three Stage */
        ret = HksAuthCipherTestDecrypt(keyAlias, decryptParamSet, &cipherText, &plainText, &inData);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksAesCipherTestDecrypt failed., ret = %d", ret);
            return ret;
        }
    } else {
        uint8_t cipher[SM4_COMMON_SIZE] = {0};
        struct HksBlob cipherText = { SM4_COMMON_SIZE, cipher };
        /* 2. Encrypt */
        ret = HksAuthCipherTestEncrypt(keyAlias, encryptParamSet, &inData, &cipherText);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksAesCipherTestEncrypt failed., ret = %d", ret);
            return ret;
        }
        uint8_t plain[SM4_COMMON_SIZE] = {0};
        struct HksBlob plainText = { SM4_COMMON_SIZE, plain };
        /* 3. Decrypt Three Stage */
        ret = HksAuthCipherTestDecrypt(keyAlias, decryptParamSet, &cipherText, &plainText, &inData);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksAesCipherTestDecrypt failed., ret = %d", ret);
            return ret;
        }
    }

    /* 3. Delete Key */
    EXPECT_EQ(HksDeleteKey(keyAlias, genParamSet), HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}

int32_t HksHmacTestCase(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *hmacParamSet)
{
    struct HksBlob inData = {g_inData.length(), (uint8_t *)g_inData.c_str()};

    /* 1. Generate Key */
    int32_t ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("GenerateKey failed");
        return ret;
    }

    /* 2. HMAC Three Stage */
    // Init
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct HksBlob handleHMAC = { sizeof(uint64_t), handle };
    ret = HksInit(keyAlias, hmacParamSet, &handleHMAC);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("HksMacInit failed");
        HksDeleteKey(keyAlias, genParamSet);
        return ret;
    }
    // Update & Finish
    uint8_t out[HMAC_COMMON_SIZE] = {0};
    struct HksBlob outData = { HMAC_COMMON_SIZE, out };
    ret = TestUpdateFinish(&handleHMAC, hmacParamSet, HKS_KEY_PURPOSE_MAC, &inData, &outData);
    if (ret != HKS_SUCCESS) {
        HksDeleteKey(keyAlias, genParamSet);
        return ret;
    }

    /* 2. HMAC One Stage */
    uint8_t tmpMac[HMAC_COMMON_SIZE] = {0};
    struct HksBlob mac = { HMAC_COMMON_SIZE, tmpMac };
    ret = HksMac(keyAlias, hmacParamSet, &inData, &mac);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksMac failed.";
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    EXPECT_EQ(HksMemCmp(mac.data, outData.data, outData.size), HKS_SUCCESS);

    /* 3. Delete Key */
    ret = HksDeleteKey(keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";
    return ret;
}

} // namespace Unittest::AuthPartTest

