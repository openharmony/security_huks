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

#include <gtest/gtest.h>
#include <iostream>
#include <securec.h>

#include "file_ex.h"
#include "hks_ability.h"
#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"
#include "securec.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
class HksCryptoHalMlKem : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksCryptoHalMlKem::SetUpTestCase(void)
{
}

void HksCryptoHalMlKem::TearDownTestCase(void)
{
}

void HksCryptoHalMlKem::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalMlKem::TearDown()
{
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_001, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);

    HksKeyMaterialMlKem *keyMaterial = (HksKeyMaterialMlKem *)key.data;
    ASSERT_EQ(keyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_KEM);
    ASSERT_EQ(keyMaterial->keyParamSet, (uint32_t)HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(keyMaterial->pubKeySize, (uint32_t)HKS_ML_KEM_PUB_KEY_SIZE_1184);
    ASSERT_EQ(keyMaterial->priKeySize, (uint32_t)HKS_ML_KEM_PRI_KEY_SIZE_2400);
    ASSERT_EQ(key.size, sizeof(HksKeyMaterialMlKem) + HKS_ML_KEM_PUB_KEY_SIZE_1184 + HKS_ML_KEM_PRI_KEY_SIZE_2400);

    HKS_FREE(key.data);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_002, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_1024,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);

    HksKeyMaterialMlKem *keyMaterial = (HksKeyMaterialMlKem *)key.data;
    ASSERT_EQ(keyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_KEM);
    ASSERT_EQ(keyMaterial->keyParamSet, (uint32_t)HKS_ML_KEM_KEY_PARAM_SET_1024);
    ASSERT_EQ(keyMaterial->pubKeySize, (uint32_t)HKS_ML_KEM_PUB_KEY_SIZE_1568);
    ASSERT_EQ(keyMaterial->priKeySize, (uint32_t)HKS_ML_KEM_PRI_KEY_SIZE_3168);

    HKS_FREE(key.data);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_003, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = 999,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_004, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = 0,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_NE(ret, HKS_SUCCESS);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_005, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint32_t keyOutLen = key.size;
    HksBlob keyOut = { .size = keyOutLen, .data = (uint8_t *)HksMalloc(keyOutLen) };
    ASSERT_NE(keyOut.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksKeyMaterialMlKem *pubKeyMaterial = (HksKeyMaterialMlKem *)keyOut.data;
    ASSERT_EQ(pubKeyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_KEM);
    ASSERT_EQ(pubKeyMaterial->keyParamSet, (uint32_t)HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_NE(pubKeyMaterial->pubKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->priKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->reserved, (uint32_t)0);
    ASSERT_EQ(keyOut.size, sizeof(HksKeyMaterialMlKem) + HKS_ML_KEM_PUB_KEY_SIZE_1184);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(keyOut);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_006, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_1024,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint32_t keyOutLen = key.size;
    HksBlob keyOut = { .size = keyOutLen, .data = (uint8_t *)HksMalloc(keyOutLen) };
    ASSERT_NE(keyOut.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksKeyMaterialMlKem *pubKeyMaterial = (HksKeyMaterialMlKem *)keyOut.data;
    ASSERT_EQ(pubKeyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_KEM);
    ASSERT_EQ(pubKeyMaterial->keyParamSet, (uint32_t)HKS_ML_KEM_KEY_PARAM_SET_1024);
    ASSERT_NE(pubKeyMaterial->pubKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->priKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->reserved, (uint32_t)0);
    ASSERT_EQ(keyOut.size, sizeof(HksKeyMaterialMlKem) + HKS_ML_KEM_PUB_KEY_SIZE_1568);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(keyOut);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_007, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    uint8_t smallBuf[1] = {0};
    HksBlob smallKeyIn = { .size = 1, .data = smallBuf };
    HksBlob keyOut = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGetPubKey(&smallKeyIn, &keyOut);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_008, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    uint8_t fakeData[sizeof(HksKeyMaterialMlKem)] = {0};
    HksKeyMaterialMlKem *fakeMaterial = (HksKeyMaterialMlKem *)fakeData;
    fakeMaterial->keyAlg = HKS_ALG_ML_KEM;
    fakeMaterial->keyParamSet = HKS_ML_KEM_KEY_PARAM_SET_768;
    fakeMaterial->pubKeySize = 0;
    fakeMaterial->priKeySize = 0;
    fakeMaterial->reserved = 0;
    HksBlob fakeKeyIn = { .size = sizeof(HksKeyMaterialMlKem), .data = fakeData };
    uint8_t outBuf[4096] = {0};
    HksBlob keyOut = { .size = 4096, .data = outBuf };
    int32_t ret = HksCryptoHalGetPubKey(&fakeKeyIn, &keyOut);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_009, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    uint8_t fakeData[sizeof(HksKeyMaterialMlKem)] = {0};
    HksKeyMaterialMlKem *fakeMaterial = (HksKeyMaterialMlKem *)fakeData;
    fakeMaterial->keyAlg = HKS_ALG_ML_KEM;
    fakeMaterial->keyParamSet = HKS_ML_KEM_KEY_PARAM_SET_768;
    fakeMaterial->pubKeySize = HKS_ML_KEM_PUB_KEY_SIZE_1184;
    fakeMaterial->priKeySize = 0;
    fakeMaterial->reserved = 0;
    HksBlob fakeKeyIn = { .size = sizeof(HksKeyMaterialMlKem), .data = fakeData };
    uint8_t outBuf[sizeof(HksKeyMaterialMlKem)] = {0};
    HksBlob keyOut = { .size = sizeof(HksKeyMaterialMlKem), .data = outBuf };
    int32_t ret = HksCryptoHalGetPubKey(&fakeKeyIn, &keyOut);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_OPERATION);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_010, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint32_t smallOutLen = sizeof(HksKeyMaterialMlKem) + 10;
    uint8_t *smallOutBuf = (uint8_t *)HksMalloc(smallOutLen);
    ASSERT_NE(smallOutBuf, nullptr);
    HksBlob keyOut = { .size = smallOutLen, .data = smallOutBuf };

    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE(smallOutBuf);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_011, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    ret = HksCryptoHalMlKemEncapsulate(&pubKey, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(encapResult.encapsulatedData.data, nullptr);
    ASSERT_NE(encapResult.encapsulatedData.size, (uint32_t)0);
    ASSERT_NE(encapResult.sharedSecret.data, nullptr);
    ASSERT_EQ(encapResult.sharedSecret.size, (uint32_t)HKS_ML_KEM_SHARED_SECRET_LEN);

    HksBlob sharedSecretDecap = { .size = 0, .data = nullptr };
    ret = HksCryptoHalMlKemDecapsulate(&key, &encapResult.encapsulatedData, &sharedSecretDecap);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(sharedSecretDecap.data, nullptr);
    ASSERT_NE(sharedSecretDecap.size, (uint32_t)0);
    ASSERT_EQ(sharedSecretDecap.size, encapResult.sharedSecret.size);
    ASSERT_EQ(memcmp(sharedSecretDecap.data, encapResult.sharedSecret.data, sharedSecretDecap.size), 0);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    HKS_MEMSET_FREE_BLOB(sharedSecretDecap);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_012, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_1024,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    ret = HksCryptoHalMlKemEncapsulate(&pubKey, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(encapResult.encapsulatedData.data, nullptr);
    ASSERT_NE(encapResult.sharedSecret.data, nullptr);
    ASSERT_EQ(encapResult.sharedSecret.size, (uint32_t)HKS_ML_KEM_SHARED_SECRET_LEN);

    HksBlob sharedSecretDecap = { .size = 0, .data = nullptr };
    ret = HksCryptoHalMlKemDecapsulate(&key, &encapResult.encapsulatedData, &sharedSecretDecap);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(sharedSecretDecap.data, nullptr);
    ASSERT_EQ(sharedSecretDecap.size, encapResult.sharedSecret.size);
    ASSERT_EQ(memcmp(sharedSecretDecap.data, encapResult.sharedSecret.data, sharedSecretDecap.size), 0);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    HKS_MEMSET_FREE_BLOB(sharedSecretDecap);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_013, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    int32_t ret = HksCryptoHalMlKemEncapsulate(nullptr, &encapResult);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_014, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    int32_t encapRet = HksCryptoHalMlKemEncapsulate(&key, nullptr);
    ASSERT_EQ(encapRet, HKS_ERROR_INVALID_ARGUMENT);
    HKS_FREE_BLOB(key);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_015, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    uint8_t cipherData[32] = {0};
    HksBlob ciphertext = { .size = 32, .data = cipherData };
    HksBlob sharedSecret = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalMlKemDecapsulate(nullptr, &ciphertext, &sharedSecret);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_016, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    HksBlob sharedSecret = { .size = 0, .data = nullptr };
    int32_t decapRet = HksCryptoHalMlKemDecapsulate(&key, nullptr, &sharedSecret);
    ASSERT_EQ(decapRet, HKS_ERROR_INVALID_ARGUMENT);
    HKS_FREE_BLOB(key);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_017, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    uint8_t cipherData[32] = {0};
    HksBlob ciphertext = { .size = 32, .data = cipherData };
    int32_t decapRet = HksCryptoHalMlKemDecapsulate(&key, &ciphertext, nullptr);
    ASSERT_EQ(decapRet, HKS_ERROR_INVALID_ARGUMENT);
    HKS_FREE_BLOB(key);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_018, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    uint8_t smallData[1] = {0};
    HksBlob smallKey = { .size = 1, .data = smallData };
    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    int32_t ret = HksCryptoHalMlKemEncapsulate(&smallKey, &encapResult);
    ASSERT_NE(ret, HKS_SUCCESS);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_019, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    uint8_t fakeData[sizeof(HksKeyMaterialMlKem)] = {0};
    HksKeyMaterialMlKem *fakeMaterial = (HksKeyMaterialMlKem *)fakeData;
    fakeMaterial->keyAlg = HKS_ALG_ML_KEM;
    fakeMaterial->keyParamSet = 999;
    fakeMaterial->pubKeySize = 100;
    fakeMaterial->priKeySize = 100;
    fakeMaterial->reserved = 0;
    uint32_t fakeTotalLen = sizeof(HksKeyMaterialMlKem) + 200;
    uint8_t *fakeBuf = (uint8_t *)HksMalloc(fakeTotalLen);
    ASSERT_NE(fakeBuf, nullptr);
    (void)memset_s(fakeBuf, fakeTotalLen, 0, fakeTotalLen);
    (void)memcpy_s(fakeBuf, fakeTotalLen, fakeData, sizeof(HksKeyMaterialMlKem));
    HksBlob fakeKey = { .size = fakeTotalLen, .data = fakeBuf };

    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    int32_t ret = HksCryptoHalMlKemEncapsulate(&fakeKey, &encapResult);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE(fakeBuf);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_020, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    uint8_t smallData[1] = {0};
    HksBlob smallKey = { .size = 1, .data = smallData };
    uint8_t cipherData[32] = {0};
    HksBlob ciphertext = { .size = 32, .data = cipherData };
    HksBlob sharedSecret = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalMlKemDecapsulate(&smallKey, &ciphertext, &sharedSecret);
    ASSERT_NE(ret, HKS_SUCCESS);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_021, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    uint32_t fakeTotalLen = sizeof(HksKeyMaterialMlKem) + 200;
    uint8_t *fakeBuf = (uint8_t *)HksMalloc(fakeTotalLen);
    ASSERT_NE(fakeBuf, nullptr);
    (void)memset_s(fakeBuf, fakeTotalLen, 0, fakeTotalLen);
    HksKeyMaterialMlKem *fakeMaterial = (HksKeyMaterialMlKem *)fakeBuf;
    fakeMaterial->keyAlg = HKS_ALG_ML_KEM;
    fakeMaterial->keyParamSet = 999;
    fakeMaterial->pubKeySize = 100;
    fakeMaterial->priKeySize = 100;
    fakeMaterial->reserved = 0;
    HksBlob fakeKey = { .size = fakeTotalLen, .data = fakeBuf };
    uint8_t cipherData[32] = {0};
    HksBlob ciphertext = { .size = 32, .data = cipherData };
    HksBlob sharedSecret = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalMlKemDecapsulate(&fakeKey, &ciphertext, &sharedSecret);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE(fakeBuf);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_022, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    ret = HksCryptoHalMlKemEncapsulate(&pubKey, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t *tamperedCipher = (uint8_t *)HksMalloc(encapResult.encapsulatedData.size);
    ASSERT_NE(tamperedCipher, nullptr);
    (void)memcpy_s(tamperedCipher, encapResult.encapsulatedData.size,
        encapResult.encapsulatedData.data, encapResult.encapsulatedData.size);
    tamperedCipher[0] ^= 0xFF;

    HksBlob tamperedCiphertext = { .size = encapResult.encapsulatedData.size, .data = tamperedCipher };
    HksBlob sharedSecretDecap = { .size = 0, .data = nullptr };
    ret = HksCryptoHalMlKemDecapsulate(&key, &tamperedCiphertext, &sharedSecretDecap);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(memcmp(sharedSecretDecap.data, encapResult.sharedSecret.data,
        sharedSecretDecap.size), 0);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    HKS_FREE(tamperedCipher);
    HKS_MEMSET_FREE_BLOB(sharedSecretDecap);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_023, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_1024,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr);

    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    ret = HksCryptoHalMlKemEncapsulate(&pubKey, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t *tamperedCipher = (uint8_t *)HksMalloc(encapResult.encapsulatedData.size);
    ASSERT_NE(tamperedCipher, nullptr);
    (void)memcpy_s(tamperedCipher, encapResult.encapsulatedData.size,
        encapResult.encapsulatedData.data, encapResult.encapsulatedData.size);
    tamperedCipher[0] ^= 0xFF;

    HksBlob tamperedCiphertext = { .size = encapResult.encapsulatedData.size, .data = tamperedCipher };
    HksBlob sharedSecretDecap = { .size = 0, .data = nullptr };
    ret = HksCryptoHalMlKemDecapsulate(&key, &tamperedCiphertext, &sharedSecretDecap);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(memcmp(sharedSecretDecap.data, encapResult.sharedSecret.data,
        sharedSecretDecap.size), 0);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    HKS_FREE(tamperedCipher);
    HKS_MEMSET_FREE_BLOB(sharedSecretDecap);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_024, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    uint32_t fakeTotalLen = sizeof(HksKeyMaterialMlKem) + 1;
    uint8_t *fakeBuf = (uint8_t *)HksMalloc(fakeTotalLen);
    ASSERT_NE(fakeBuf, nullptr);
    (void)memset_s(fakeBuf, fakeTotalLen, 0, fakeTotalLen);
    HksKeyMaterialMlKem *fakeMaterial = (HksKeyMaterialMlKem *)fakeBuf;
    fakeMaterial->keyAlg = HKS_ALG_ML_KEM;
    fakeMaterial->keyParamSet = HKS_ML_KEM_KEY_PARAM_SET_768;
    fakeMaterial->pubKeySize = 0;
    fakeMaterial->priKeySize = 0;
    fakeMaterial->reserved = 0;
    HksBlob fakeKey = { .size = fakeTotalLen, .data = fakeBuf };

    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    int32_t ret = HksCryptoHalMlKemEncapsulate(&fakeKey, &encapResult);
    ASSERT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR);

    HKS_FREE(fakeBuf);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_025, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    uint32_t fakeTotalLen = sizeof(HksKeyMaterialMlKem) + 1;
    uint8_t *fakeBuf = (uint8_t *)HksMalloc(fakeTotalLen);
    ASSERT_NE(fakeBuf, nullptr);
    (void)memset_s(fakeBuf, fakeTotalLen, 0, fakeTotalLen);
    HksKeyMaterialMlKem *fakeMaterial = (HksKeyMaterialMlKem *)fakeBuf;
    fakeMaterial->keyAlg = HKS_ALG_ML_KEM;
    fakeMaterial->keyParamSet = HKS_ML_KEM_KEY_PARAM_SET_768;
    fakeMaterial->pubKeySize = 0;
    fakeMaterial->priKeySize = 0;
    fakeMaterial->reserved = 0;
    HksBlob fakeKey = { .size = fakeTotalLen, .data = fakeBuf };
    uint8_t cipherData[32] = {0};
    HksBlob ciphertext = { .size = 32, .data = cipherData };
    HksBlob sharedSecret = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalMlKemDecapsulate(&fakeKey, &ciphertext, &sharedSecret);
    ASSERT_EQ(ret, HKS_ERROR_CRYPTO_ENGINE_ERROR);

    HKS_FREE(fakeBuf);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_026, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey = { .size = 0, .data = nullptr };
    uint32_t pubKeyOutLen = key.size;
    pubKey.data = (uint8_t *)HksMalloc(pubKeyOutLen);
    pubKey.size = pubKeyOutLen;
    ASSERT_NE(pubKey.data, nullptr);
    ret = HksCryptoHalGetPubKey(&key, &pubKey);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t emptyCipher[1] = {0};
    HksBlob emptyCiphertext = { .size = 1, .data = emptyCipher };
    HksBlob sharedSecretDecap = { .size = 0, .data = nullptr };
    ret = HksCryptoHalMlKemDecapsulate(&key, &emptyCiphertext, &sharedSecretDecap);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_027, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec768 = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksKeySpec spec1024 = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_1024,
        .algParam = nullptr,
    };
    HksBlob key768 = { .size = 0, .data = nullptr };
    HksBlob key1024 = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec768, &key768);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksCryptoHalGenerateKey(&spec1024, &key1024);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksBlob pubKey768 = { .size = 0, .data = nullptr };
    uint32_t pubKey768OutLen = key768.size;
    pubKey768.data = (uint8_t *)HksMalloc(pubKey768OutLen);
    pubKey768.size = pubKey768OutLen;
    ASSERT_NE(pubKey768.data, nullptr);
    ret = HksCryptoHalGetPubKey(&key768, &pubKey768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    ret = HksCryptoHalMlKemEncapsulate(&pubKey768, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksBlob sharedSecretDecap = { .size = 0, .data = nullptr };
    ret = HksCryptoHalMlKemDecapsulate(&key1024, &encapResult.encapsulatedData, &sharedSecretDecap);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key768);
    HKS_FREE_BLOB(key1024);
    HKS_FREE_BLOB(pubKey768);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_028, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_768,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    ret = HksCryptoHalMlKemEncapsulate(&key, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(encapResult.encapsulatedData.data, nullptr);
    ASSERT_NE(encapResult.sharedSecret.data, nullptr);

    HksBlob sharedSecretDecap = { .size = 0, .data = nullptr };
    ret = HksCryptoHalMlKemDecapsulate(&key, &encapResult.encapsulatedData, &sharedSecretDecap);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_EQ(sharedSecretDecap.size, encapResult.sharedSecret.size);
    ASSERT_EQ(memcmp(sharedSecretDecap.data, encapResult.sharedSecret.data, sharedSecretDecap.size), 0);

    HKS_FREE_BLOB(key);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    HKS_MEMSET_FREE_BLOB(sharedSecretDecap);
#endif
}

HWTEST_F(HksCryptoHalMlKem, HksCryptoHalMlKem_029, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_KEM) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_KEM,
        .keyLen = HKS_ML_KEM_KEY_PARAM_SET_1024,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    HksEncapsulationResult encapResult = { {0, nullptr}, {0, nullptr} };
    ret = HksCryptoHalMlKemEncapsulate(&key, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(encapResult.encapsulatedData.data, nullptr);
    ASSERT_NE(encapResult.sharedSecret.data, nullptr);

    HksBlob sharedSecretDecap = { .size = 0, .data = nullptr };
    ret = HksCryptoHalMlKemDecapsulate(&key, &encapResult.encapsulatedData, &sharedSecretDecap);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_EQ(sharedSecretDecap.size, encapResult.sharedSecret.size);
    ASSERT_EQ(memcmp(sharedSecretDecap.data, encapResult.sharedSecret.data, sharedSecretDecap.size), 0);

    HKS_FREE_BLOB(key);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    HKS_MEMSET_FREE_BLOB(sharedSecretDecap);
#endif
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS
