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
class HksCryptoHalMlDsa : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksCryptoHalMlDsa::SetUpTestCase(void)
{
}

void HksCryptoHalMlDsa::TearDownTestCase(void)
{
}

void HksCryptoHalMlDsa::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalMlDsa::TearDown()
{
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_001, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);

    HksKeyMaterialMlDsa *keyMaterial = (HksKeyMaterialMlDsa *)key.data;
    ASSERT_EQ(keyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_DSA);
    ASSERT_EQ(keyMaterial->keyParamSet, (uint32_t)HKS_ML_DSA_KEY_PARAM_SET_44);
    ASSERT_EQ(keyMaterial->pubKeySize, (uint32_t)HKS_ML_DSA_PUB_KEY_SIZE_1312);
    ASSERT_EQ(keyMaterial->priKeySize, (uint32_t)HKS_ML_DSA_PRI_KEY_SIZE_2560);
    ASSERT_EQ(key.size, sizeof(HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1312 + HKS_ML_DSA_PRI_KEY_SIZE_2560);

    HKS_FREE(key.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_002, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_65,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);

    HksKeyMaterialMlDsa *keyMaterial = (HksKeyMaterialMlDsa *)key.data;
    ASSERT_EQ(keyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_DSA);
    ASSERT_EQ(keyMaterial->keyParamSet, (uint32_t)HKS_ML_DSA_KEY_PARAM_SET_65);
    ASSERT_EQ(keyMaterial->pubKeySize, (uint32_t)HKS_ML_DSA_PUB_KEY_SIZE_1952);
    ASSERT_EQ(keyMaterial->priKeySize, (uint32_t)HKS_ML_DSA_PRI_KEY_SIZE_4032);

    HKS_FREE(key.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_003, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_87,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_NE((uint32_t)0, key.size);
    ASSERT_NE(nullptr, key.data);

    HksKeyMaterialMlDsa *keyMaterial = (HksKeyMaterialMlDsa *)key.data;
    ASSERT_EQ(keyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_DSA);
    ASSERT_EQ(keyMaterial->keyParamSet, (uint32_t)HKS_ML_DSA_KEY_PARAM_SET_87);
    ASSERT_EQ(keyMaterial->pubKeySize, (uint32_t)HKS_ML_DSA_PUB_KEY_SIZE_2592);
    ASSERT_EQ(keyMaterial->priKeySize, (uint32_t)HKS_ML_DSA_PRI_KEY_SIZE_4896);

    HKS_FREE(key.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_004, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = 999,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_005, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
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

    HksKeyMaterialMlDsa *pubKeyMaterial = (HksKeyMaterialMlDsa *)keyOut.data;
    ASSERT_EQ(pubKeyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_DSA);
    ASSERT_EQ(pubKeyMaterial->keyParamSet, (uint32_t)HKS_ML_DSA_KEY_PARAM_SET_44);
    ASSERT_NE(pubKeyMaterial->pubKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->priKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->reserved, (uint32_t)0);
    ASSERT_EQ(keyOut.size, sizeof(HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1312);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(keyOut);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_006, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_65,
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

    HksKeyMaterialMlDsa *pubKeyMaterial = (HksKeyMaterialMlDsa *)keyOut.data;
    ASSERT_EQ(pubKeyMaterial->keyAlg, (uint32_t)HKS_ALG_ML_DSA);
    ASSERT_EQ(pubKeyMaterial->keyParamSet, (uint32_t)HKS_ML_DSA_KEY_PARAM_SET_65);
    ASSERT_NE(pubKeyMaterial->pubKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->priKeySize, (uint32_t)0);
    ASSERT_EQ(pubKeyMaterial->reserved, (uint32_t)0);
    ASSERT_EQ(keyOut.size, sizeof(HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1952);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(keyOut);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_007, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    uint8_t smallBuf[1] = {0};
    HksBlob smallKeyIn = { .size = 1, .data = smallBuf };
    HksBlob keyOut = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGetPubKey(&smallKeyIn, &keyOut);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_008, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    uint8_t fakeData[sizeof(HksKeyMaterialMlDsa)] = {0};
    HksKeyMaterialMlDsa *fakeMaterial = (HksKeyMaterialMlDsa *)fakeData;
    fakeMaterial->keyAlg = HKS_ALG_ML_DSA;
    fakeMaterial->keyParamSet = HKS_ML_DSA_KEY_PARAM_SET_44;
    fakeMaterial->pubKeySize = 0;
    fakeMaterial->priKeySize = 0;
    fakeMaterial->reserved = 0;
    HksBlob fakeKeyIn = { .size = sizeof(HksKeyMaterialMlDsa), .data = fakeData };
    uint8_t outBuf[4096] = {0};
    HksBlob keyOut = { .size = 4096, .data = outBuf };
    int32_t ret = HksCryptoHalGetPubKey(&fakeKeyIn, &keyOut);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_009, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    uint8_t fakeData[sizeof(HksKeyMaterialMlDsa)] = {0};
    HksKeyMaterialMlDsa *fakeMaterial = (HksKeyMaterialMlDsa *)fakeData;
    fakeMaterial->keyAlg = HKS_ALG_ML_DSA;
    fakeMaterial->keyParamSet = HKS_ML_DSA_KEY_PARAM_SET_44;
    fakeMaterial->pubKeySize = HKS_ML_DSA_PUB_KEY_SIZE_1312;
    fakeMaterial->priKeySize = 0;
    fakeMaterial->reserved = 0;
    HksBlob fakeKeyIn = { .size = sizeof(HksKeyMaterialMlDsa), .data = fakeData };
    uint8_t outBuf[sizeof(HksKeyMaterialMlDsa)] = {0};
    HksBlob keyOut = { .size = sizeof(HksKeyMaterialMlDsa), .data = outBuf };
    int32_t ret = HksCryptoHalGetPubKey(&fakeKeyIn, &keyOut);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_OPERATION);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_010, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint32_t smallOutLen = sizeof(HksKeyMaterialMlDsa) + 10;
    uint8_t *smallOutBuf = (uint8_t *)HksMalloc(smallOutLen);
    ASSERT_NE(smallOutBuf, nullptr);
    HksBlob keyOut = { .size = smallOutLen, .data = smallOutBuf };

    ret = HksCryptoHalGetPubKey(&key, &keyOut);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE(smallOutBuf);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_011, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &usageSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(signature.size, (uint32_t)0);

    HKS_FREE(key.data);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_012, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && \
    defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
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

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };

    HksUsageSpec signSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &signSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_NE(signature.size, (uint32_t)0);

    HksUsageSpec verifySpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    ret = HksCryptoHalVerify(&pubKey, &verifySpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_013, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_65,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &usageSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HKS_FREE(key.data);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_014, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_87,
        .algParam = nullptr,
    };
    HksBlob key = { .size = 0, .data = nullptr };
    int32_t ret = HksCryptoHalGenerateKey(&spec, &key);
    ASSERT_EQ(HKS_SUCCESS, ret);

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &usageSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HKS_FREE(key.data);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_015, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && \
    defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_44,
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

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };

    HksUsageSpec signSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &signSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t tamperedMsgData[dataLen];
    (void)memcpy_s(tamperedMsgData, dataLen, message.data, dataLen);
    tamperedMsgData[0] ^= 0xFF;
    HksBlob tamperedMessage = { .size = dataLen, .data = tamperedMsgData };

    HksUsageSpec verifySpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    ret = HksCryptoHalVerify(&pubKey, &verifySpec, &tamperedMessage, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_016, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    uint8_t smallData[1] = {0};
    HksBlob smallKey = { .size = 1, .data = smallData };
    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };
    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }
    struct HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);

    int32_t ret = HksCryptoHalSign(&smallKey, &usageSpec, &message, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_017, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    uint32_t fakeTotalLen = sizeof(HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1312 + HKS_ML_DSA_PRI_KEY_SIZE_2560;
    uint8_t *fakeBuf = (uint8_t *)HksMalloc(fakeTotalLen);
    ASSERT_NE(fakeBuf, nullptr);
    (void)memset_s(fakeBuf, fakeTotalLen, 0xAA, fakeTotalLen);
    HksKeyMaterialMlDsa *fakeMaterial = (HksKeyMaterialMlDsa *)fakeBuf;
    fakeMaterial->keyAlg = HKS_ALG_ML_DSA;
    fakeMaterial->keyParamSet = 999;
    fakeMaterial->pubKeySize = HKS_ML_DSA_PUB_KEY_SIZE_1312;
    fakeMaterial->priKeySize = HKS_ML_DSA_PRI_KEY_SIZE_2560;
    fakeMaterial->reserved = 0;
    HksBlob fakeKey = { .size = fakeTotalLen, .data = fakeBuf };

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }
    struct HksBlob signature = { .size = ML_DSA_MAX_KEY_SIZE, .data = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE) };
    ASSERT_NE(signature.data, nullptr);

    int32_t ret = HksCryptoHalSign(&fakeKey, &usageSpec, &message, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE(fakeBuf);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_018, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    uint8_t smallData[1] = {0};
    HksBlob smallKey = { .size = 1, .data = smallData };
    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    uint8_t sigData[64] = {0};
    struct HksBlob signature = { .size = 64, .data = sigData };
    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    int32_t ret = HksCryptoHalVerify(&smallKey, &usageSpec, &message, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE(message.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_019, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && \
    defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_65,
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

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };

    HksUsageSpec signSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &signSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksUsageSpec verifySpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    ret = HksCryptoHalVerify(&pubKey, &verifySpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_020, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_GENERATE_KEY) && \
    defined(HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && \
    defined(_USE_OPENSSL_)
    HksKeySpec spec = {
        .algType = HKS_ALG_ML_DSA,
        .keyLen = HKS_ML_DSA_KEY_PARAM_SET_87,
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

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };

    HksUsageSpec signSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN,
        .algParam = &contextBlob,
    };

    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    uint32_t sigLen = ML_DSA_MAX_KEY_SIZE;
    struct HksBlob signature = { .size = sigLen, .data = (uint8_t *)HksMalloc(sigLen) };
    ASSERT_NE(signature.data, nullptr);

    ret = HksCryptoHalSign(&key, &signSpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksUsageSpec verifySpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    ret = HksCryptoHalVerify(&pubKey, &verifySpec, &message, &signature);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(pubKey);
    HKS_FREE(message.data);
    HKS_FREE(signature.data);
#endif
}

HWTEST_F(HksCryptoHalMlDsa, HksCryptoHalMlDsa_021, Function | SmallTest | Level0)
{
#if defined(HKS_SUPPORT_ML_DSA_C) && defined(HKS_SUPPORT_ML_DSA_SIGN_VERIFY) && defined(_USE_OPENSSL_)
    uint32_t fakeTotalLen = sizeof(HksKeyMaterialMlDsa) + HKS_ML_DSA_PUB_KEY_SIZE_1312;
    uint8_t *fakeBuf = (uint8_t *)HksMalloc(fakeTotalLen);
    ASSERT_NE(fakeBuf, nullptr);
    (void)memset_s(fakeBuf, fakeTotalLen, 0xBB, fakeTotalLen);
    HksKeyMaterialMlDsa *fakeMaterial = (HksKeyMaterialMlDsa *)fakeBuf;
    fakeMaterial->keyAlg = HKS_ALG_ML_DSA;
    fakeMaterial->keyParamSet = HKS_ML_DSA_KEY_PARAM_SET_44;
    fakeMaterial->pubKeySize = HKS_ML_DSA_PUB_KEY_SIZE_1312;
    fakeMaterial->priKeySize = 0;
    fakeMaterial->reserved = 0;
    HksBlob fakeKey = { .size = fakeTotalLen, .data = fakeBuf };

    uint8_t contextData[] = "ml-dsa-context";
    HksBlob contextBlob = { .size = sizeof(contextData), .data = contextData };
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_ML_DSA,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_VERIFY,
        .algParam = &contextBlob,
    };

    uint8_t sigData[64] = {0};
    struct HksBlob signature = { .size = 64, .data = sigData };
    const char *hexData = "00112233445566778899aabbccddeeff";
    uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;
    HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
    ASSERT_NE(message.data, nullptr);
    for (uint32_t ii = 0; ii < dataLen; ii++) {
        message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
    }

    int32_t ret = HksCryptoHalVerify(&fakeKey, &usageSpec, &message, &signature);
    ASSERT_NE(ret, HKS_SUCCESS);

    HKS_FREE(fakeBuf);
    HKS_FREE(message.data);
#endif
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS
