/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "hks_error_code.h"
#include "hks_kem_test.h"

#include "file_ex.h"
#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hks_type_inner.h"
#include "securec.h"

using namespace testing::ext;
namespace Unittest::HksKemTest {

static char g_keyAliasStr[] = "kem_test_key_alias";
static char g_keyAlias2Str[] = "kem_test_key_alias2";
static char g_sharedKeyAliasStr[] = "kem_test_shared_key_alias";
static struct HksBlob g_keyAlias = { sizeof(g_keyAliasStr) - 1, (uint8_t *)g_keyAliasStr };
static struct HksBlob g_keyAlias2 = { sizeof(g_keyAlias2Str) - 1, (uint8_t *)g_keyAlias2Str };
static struct HksBlob g_sharedKeyAlias = { sizeof(g_sharedKeyAliasStr) - 1, (uint8_t *)g_sharedKeyAliasStr };

class HksKemTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksKemTest::SetUpTestCase(void)
{
    HksInitialize();
}

void HksKemTest::TearDownTestCase(void)
{
}

void HksKemTest::SetUp()
{
}

void HksKemTest::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
    std::system("find /data/service/el2/public/huks_service -user root -delete");
}

static int32_t BuildParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramsCnt)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    if (params != nullptr && paramsCnt > 0) {
        ret = HksAddParams(*paramSet, params, paramsCnt);
        if (ret != HKS_SUCCESS) {
            HksFreeParamSet(paramSet);
            return ret;
        }
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(paramSet);
        return ret;
    }
    return HKS_SUCCESS;
}

static struct HksBlob GenerateBlob(uint32_t size)
{
    struct HksBlob blob = { size, nullptr };
    if (size > 0) {
        blob.data = static_cast<uint8_t *>(HksMalloc(size));
        if (blob.data != nullptr) {
            (void)memset_s(blob.data, size, 0xAA, size);
        }
    }
    return blob;
}

static int32_t GenerateMlKemKey(const struct HksBlob *keyAlias, uint32_t keySize)
{
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = keySize },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP },
    };

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = HksGenerateKey(keyAlias, paramSet, nullptr);
    HksFreeParamSet(&paramSet);
    return ret;
}

// ========== Null pointer tests ==========

// null keyAlias
HWTEST_F(HksKemTest, HksEncapsulate_Null_001, TestSize.Level0)
{
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(nullptr, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HksFreeParamSet(&paramSet);
}

// null paramSet
HWTEST_F(HksKemTest, HksEncapsulate_Null_002, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    int32_t ret = HksEncapsulate(&keyAlias, nullptr, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

// null encapResult
HWTEST_F(HksKemTest, HksEncapsulate_Null_003, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HksFreeParamSet(&paramSet);
}

// all params null
HWTEST_F(HksKemTest, HksEncapsulate_Null_004, TestSize.Level0)
{
    int32_t ret = HksEncapsulate(nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

// null keyAlias
HWTEST_F(HksKemTest, HksDecapsulate_Null_001, TestSize.Level0)
{
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(nullptr, paramSet, nullptr, nullptr, &sharedSecret);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(sharedSecret);
}

// null paramSet
HWTEST_F(HksKemTest, HksDecapsulate_Null_002, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedSecret = GenerateBlob(32);

    int32_t ret = HksDecapsulate(&keyAlias, nullptr, nullptr, nullptr, &sharedSecret);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HKS_FREE_BLOB(sharedSecret);
}

// null encapOrsharedSecret
HWTEST_F(HksKemTest, HksDecapsulate_Null_003, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    HksFreeParamSet(&paramSet);
}

// all params null
HWTEST_F(HksKemTest, HksDecapsulate_Null_004, TestSize.Level0)
{
    int32_t ret = HksDecapsulate(nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

// ========== Normal encapsulate tests ==========

// encapsulate ML-KEM-768 without shared key
HWTEST_F(HksKemTest, HksEncapsulate_768_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
}

// encapsulate ML-KEM-1024 without shared key
HWTEST_F(HksKemTest, HksEncapsulate_1024_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_1024);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
}

// ========== Normal decapsulate tests ==========

// decapsulate ML-KEM-768, verify shared secret length
HWTEST_F(HksKemTest, HksDecapsulate_768_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = { HKS_ML_KEM_SHARED_SECRET_LEN, nullptr };
    sharedSecret.data = static_cast<uint8_t *>(HksMalloc(HKS_ML_KEM_SHARED_SECRET_LEN));
    ASSERT_NE(sharedSecret.data, nullptr);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult.encapsulatedData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE(sharedSecret.data);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
}

// decapsulate ML-KEM-1024, verify shared secret length
HWTEST_F(HksKemTest, HksDecapsulate_1024_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_1024);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = { HKS_ML_KEM_SHARED_SECRET_LEN, nullptr };
    sharedSecret.data = static_cast<uint8_t *>(HksMalloc(HKS_ML_KEM_SHARED_SECRET_LEN));
    ASSERT_NE(sharedSecret.data, nullptr);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult.encapsulatedData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE(sharedSecret.data);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
}

// ========== Encapsulate + Decapsulate pair tests ==========

// encap+decap ML-KEM-768, verify shared secret consistency
HWTEST_F(HksKemTest, HksEncapsulate_Decapsulate_768_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = { HKS_ML_KEM_SHARED_SECRET_LEN, nullptr };
    sharedSecret.data = static_cast<uint8_t *>(HksMalloc(HKS_ML_KEM_SHARED_SECRET_LEN));
    ASSERT_NE(sharedSecret.data, nullptr);
    (void)memset_s(sharedSecret.data, HKS_ML_KEM_SHARED_SECRET_LEN, 0, HKS_ML_KEM_SHARED_SECRET_LEN);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult.encapsulatedData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE(sharedSecret.data);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
}

// encap+decap ML-KEM-1024, verify shared secret consistency
HWTEST_F(HksKemTest, HksEncapsulate_Decapsulate_1024_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_1024);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = { HKS_ML_KEM_SHARED_SECRET_LEN, nullptr };
    sharedSecret.data = static_cast<uint8_t *>(HksMalloc(HKS_ML_KEM_SHARED_SECRET_LEN));
    ASSERT_NE(sharedSecret.data, nullptr);
    (void)memset_s(sharedSecret.data, HKS_ML_KEM_SHARED_SECRET_LEN, 0, HKS_ML_KEM_SHARED_SECRET_LEN);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult.encapsulatedData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE(sharedSecret.data);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
}

// encap with key1, decap with different key2, expect failure
HWTEST_F(HksKemTest, HksEncapsulate_Decapsulate_KeyMismatch_001, TestSize.Level0)
{
    struct HksBlob keyAlias1 = g_keyAlias;
    struct HksBlob keyAlias2 = g_keyAlias2;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias1, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias1, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(HKS_ML_KEM_SHARED_SECRET_LEN);

    ret = HksDecapsulate(&keyAlias2, paramSet, nullptr, nullptr, &encapResult.encapsulatedData);
    EXPECT_NE(ret, HKS_SUCCESS);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias1, nullptr);
    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(sharedSecret);
}

// ========== Encapsulate + Decapsulate with shared key storage ==========

// encap+decap ML-KEM-768 with sharedKeyAlias, store shared key
HWTEST_F(HksKemTest, HksEncapsulate_Decapsulate_WithSharedKey_768_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = g_sharedKeyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam sharedKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = BuildParamSet(&sharedKeyParamSet, sharedKeyParams, sizeof(sharedKeyParams) / sizeof(sharedKeyParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedKeyParamSet, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksDeleteKey(&sharedKeyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

// encap+decap ML-KEM-1024 with sharedKeyAlias, store shared key
HWTEST_F(HksKemTest, HksEncapsulate_Decapsulate_WithSharedKey_1024_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = g_sharedKeyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_1024);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam sharedKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = BuildParamSet(&sharedKeyParamSet, sharedKeyParams, sizeof(sharedKeyParams) / sizeof(sharedKeyParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedKeyParamSet, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksDeleteKey(&sharedKeyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

// ========== SharedKeyParam tests ==========

// sharedKeyAlias + sharedKeyParamSet with ALG+KEY_SIZE+PURPOSE, store shared key
HWTEST_F(HksKemTest, HksEncapsulate_SharedKeyParam_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = g_sharedKeyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam sharedKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = BuildParamSet(&sharedKeyParamSet, sharedKeyParams, sizeof(sharedKeyParams) / sizeof(sharedKeyParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedKeyParamSet, &encapResult);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksDeleteKey(&sharedKeyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

// sharedKeyAlias + sharedKeyParamSet with ALG+PURPOSE but no KEY_SIZE, service allows success without storage
HWTEST_F(HksKemTest, HksEncapsulate_SharedKeyParam_002, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = g_sharedKeyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam sharedKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = BuildParamSet(&sharedKeyParamSet, sharedKeyParams, sizeof(sharedKeyParams) / sizeof(sharedKeyParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedKeyParamSet, &encapResult);
    EXPECT_EQ(ret, HKS_ERROR_CHECK_GET_KEY_SIZE_FAIL);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

// sharedKeyAlias non-null + sharedKeyParamSet null, expect failure
HWTEST_F(HksKemTest, HksEncapsulate_SharedKeyParam_003, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = g_sharedKeyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, nullptr, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

// null sharedKeyAlias + sharedKeyParamSet with ALG+KEY_SIZE, encapsulate ok without storage
HWTEST_F(HksKemTest, HksEncapsulate_SharedKeyParam_004, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam sharedKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
    };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = BuildParamSet(&sharedKeyParamSet, sharedKeyParams, sizeof(sharedKeyParams) / sizeof(sharedKeyParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, sharedKeyParamSet, &encapResult);
    EXPECT_EQ(ret, HKS_ERROR_NEW_INVALID_ARGUMENT);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

// decapsulate with sharedKeyAlias + ALG+KEY_SIZE+PURPOSE, store shared key
HWTEST_F(HksKemTest, HksDecapsulate_SharedKeyParam_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = g_sharedKeyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));
    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam sharedKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = BuildParamSet(&sharedKeyParamSet, sharedKeyParams, sizeof(sharedKeyParams) / sizeof(sharedKeyParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = { HKS_ML_KEM_SHARED_SECRET_LEN, nullptr };
    sharedSecret.data = static_cast<uint8_t *>(HksMalloc(HKS_ML_KEM_SHARED_SECRET_LEN));
    ASSERT_NE(sharedSecret.data, nullptr);

    ret = HksDecapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedKeyParamSet, &encapResult.encapsulatedData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE(sharedSecret.data);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksDeleteKey(&sharedKeyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

// decapsulate null sharedKeyAlias + sharedKeyParamSet with ALG+KEY_SIZE
HWTEST_F(HksKemTest, HksDecapsulate_SharedKeyParam_002, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));
    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam sharedKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
    };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = BuildParamSet(&sharedKeyParamSet, sharedKeyParams, sizeof(sharedKeyParams) / sizeof(sharedKeyParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, sharedKeyParamSet, &encapResult.encapsulatedData);
    EXPECT_EQ(ret, HKS_ERROR_NEW_INVALID_ARGUMENT);

    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
    HKS_FREE_BLOB(sharedSecret);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
}

// decapsulate with sharedKeyAlias + sharedKeyParamSet with ALG+PURPOSE but no KEY_SIZE
HWTEST_F(HksKemTest, HksDecapsulate_SharedKeyParam_003, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = g_sharedKeyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));
    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam sharedKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
    };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = BuildParamSet(&sharedKeyParamSet, sharedKeyParams, sizeof(sharedKeyParams) / sizeof(sharedKeyParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = { HKS_ML_KEM_SHARED_SECRET_LEN, nullptr };
    sharedSecret.data = static_cast<uint8_t *>(HksMalloc(HKS_ML_KEM_SHARED_SECRET_LEN));
    ASSERT_NE(sharedSecret.data, nullptr);

    ret = HksDecapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedKeyParamSet, &encapResult.encapsulatedData);
    EXPECT_EQ(ret, HKS_ERROR_CHECK_GET_KEY_SIZE_FAIL);

    HKS_FREE(sharedSecret.data);
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

// decapsulate sharedKeyAlias non-null + sharedKeyParamSet null, expect failure
HWTEST_F(HksKemTest, HksDecapsulate_SharedKeyParam_004, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = g_sharedKeyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(&keyAlias, paramSet, &sharedKeyAlias, nullptr, &sharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(sharedSecret);
}

// ========== SharedKeyAlias invalid tests ==========

// sharedKeyAlias with data=null, expect failure
HWTEST_F(HksKemTest, HksEncapsulate_SharedKeyAlias_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = { 32, nullptr };

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam sharedKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
    };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = BuildParamSet(&sharedKeyParamSet, sharedKeyParams, sizeof(sharedKeyParams) / sizeof(sharedKeyParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedKeyParamSet, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
}

// sharedKeyAlias with data=null, expect failure
HWTEST_F(HksKemTest, HksDecapsulate_SharedKeyAlias_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = { 32, nullptr };

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam sharedKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
    };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    ret = BuildParamSet(&sharedKeyParamSet, sharedKeyParams, sizeof(sharedKeyParams) / sizeof(sharedKeyParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(&keyAlias, paramSet, &sharedKeyAlias, sharedKeyParamSet, &sharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
    HKS_FREE_BLOB(sharedSecret);
}

// ========== KeyAlias invalid tests ==========

// keyAlias with zero size
HWTEST_F(HksKemTest, HksEncapsulate_KeyAlias_001, TestSize.Level0)
{
    struct HksBlob keyAlias = { 0, nullptr };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

// keyAlias with data=null
HWTEST_F(HksKemTest, HksEncapsulate_KeyAlias_002, TestSize.Level0)
{
    struct HksBlob keyAlias = { 32, nullptr };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

// keyAlias with zero size
HWTEST_F(HksKemTest, HksDecapsulate_KeyAlias_001, TestSize.Level0)
{
    struct HksBlob keyAlias = { 0, nullptr };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &sharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(sharedSecret);
}

// keyAlias with data=null
HWTEST_F(HksKemTest, HksDecapsulate_KeyAlias_002, TestSize.Level0)
{
    struct HksBlob keyAlias = { 32, nullptr };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &sharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(sharedSecret);
}

// ========== Key not found tests ==========

// encapsulate with non-existent key
HWTEST_F(HksKemTest, HksEncapsulate_KeyNotFound_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

// decapsulate with non-existent key
HWTEST_F(HksKemTest, HksDecapsulate_KeyNotFound_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &sharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(sharedSecret);
}

// ========== ParamSet tests ==========

// invalid paramSet (filled with 0xFF)
HWTEST_F(HksKemTest, HksEncapsulate_ParamSet_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParamSet invalidParamSet;
    (void)memset_s(&invalidParamSet, sizeof(invalidParamSet), 0xFF, sizeof(invalidParamSet));
    invalidParamSet.paramSetSize = sizeof(invalidParamSet);
    invalidParamSet.paramsCnt = 0xFFFF;

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    int32_t ret = HksEncapsulate(&keyAlias, &invalidParamSet, nullptr, nullptr, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);
}

// empty paramSet (no params)
HWTEST_F(HksKemTest, HksEncapsulate_ParamSet_002, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

// paramSet without algorithm tag
HWTEST_F(HksKemTest, HksEncapsulate_ParamSet_003, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

// paramSet with invalid algorithm (0xFFFF)
HWTEST_F(HksKemTest, HksEncapsulate_ParamSet_004, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = 0xFFFF },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

// invalid paramSet (filled with 0xFF)
HWTEST_F(HksKemTest, HksDecapsulate_ParamSet_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParamSet invalidParamSet;
    (void)memset_s(&invalidParamSet, sizeof(invalidParamSet), 0xFF, sizeof(invalidParamSet));
    invalidParamSet.paramSetSize = sizeof(invalidParamSet);
    invalidParamSet.paramsCnt = 0xFFFF;

    struct HksBlob sharedSecret = GenerateBlob(32);

    int32_t ret = HksDecapsulate(&keyAlias, &invalidParamSet, nullptr, nullptr, &sharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HKS_FREE_BLOB(sharedSecret);
}

// empty paramSet (no params)
HWTEST_F(HksKemTest, HksDecapsulate_ParamSet_002, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &sharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(sharedSecret);
}

// paramSet without algorithm tag
HWTEST_F(HksKemTest, HksDecapsulate_ParamSet_003, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &sharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(sharedSecret);
}

// paramSet with invalid algorithm (0xFFFF)
HWTEST_F(HksKemTest, HksDecapsulate_ParamSet_004, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = 0xFFFF },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &sharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(sharedSecret);
}

// ========== Invalid sharedKeyParamSet tests ==========

// invalid sharedKeyParamSet (filled with 0xFF)
HWTEST_F(HksKemTest, HksEncapsulate_SharedKeyParamSetInvalid_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = g_sharedKeyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet invalidSharedParamSet;
    (void)memset_s(&invalidSharedParamSet, sizeof(invalidSharedParamSet), 0xFF, sizeof(invalidSharedParamSet));
    invalidSharedParamSet.paramSetSize = sizeof(invalidSharedParamSet);
    invalidSharedParamSet.paramsCnt = 0xFFFF;

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, &sharedKeyAlias, &invalidSharedParamSet, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

// invalid sharedKeyParamSet (filled with 0xFF)
HWTEST_F(HksKemTest, HksDecapsulate_SharedKeyParamSetInvalid_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;
    struct HksBlob sharedKeyAlias = g_sharedKeyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet invalidSharedParamSet;
    (void)memset_s(&invalidSharedParamSet, sizeof(invalidSharedParamSet), 0xFF, sizeof(invalidSharedParamSet));
    invalidSharedParamSet.paramSetSize = sizeof(invalidSharedParamSet);
    invalidSharedParamSet.paramsCnt = 0xFFFF;

    struct HksBlob sharedSecret = GenerateBlob(32);

    ret = HksDecapsulate(&keyAlias, paramSet, &sharedKeyAlias, &invalidSharedParamSet, &sharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(sharedSecret);
}

// ========== Decapsulate ciphertext tests ==========

// ciphertext with zero size
HWTEST_F(HksKemTest, HksDecapsulate_Ciphertext_001, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob encapData = { 0, nullptr };

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapData);
    EXPECT_NE(ret, HKS_SUCCESS);

    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
}

// ciphertext too small (8 bytes instead of 1088)
HWTEST_F(HksKemTest, HksDecapsulate_Ciphertext_002, TestSize.Level0)
{
    struct HksBlob keyAlias = g_keyAlias;

    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GenerateMlKemKey(&keyAlias, HKS_ML_KEM_KEY_PARAM_SET_768);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    ret = HksEncapsulate(&keyAlias, paramSet, nullptr, nullptr, &encapResult);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob tooSmallData = GenerateBlob(8);

    ret = HksDecapsulate(&keyAlias, paramSet, nullptr, nullptr, &tooSmallData);
    EXPECT_NE(ret, HKS_SUCCESS);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    (void)HksDeleteKey(&keyAlias, nullptr);
    HksFreeParamSet(&paramSet);
    HKS_FREE_BLOB(tooSmallData);
}

// ========== HKS_FREE_ENCAPSULATION_RESULT tests ==========

// both encapsulatedData and sharedSecret valid
HWTEST_F(HksKemTest, HKS_FREE_ENCAPSULATION_RESULT_001, TestSize.Level0)
{
    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    encapResult.encapsulatedData = GenerateBlob(768);
    encapResult.sharedSecret = GenerateBlob(32);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);

    EXPECT_EQ(encapResult.encapsulatedData.size, 0);
    EXPECT_EQ(encapResult.sharedSecret.size, 0);
}

// sharedSecret.data is null
HWTEST_F(HksKemTest, HKS_FREE_ENCAPSULATION_RESULT_002, TestSize.Level0)
{
    struct HksEncapsulationResult encapResult;
    (void)memset_s(&encapResult, sizeof(encapResult), 0, sizeof(encapResult));

    encapResult.encapsulatedData = GenerateBlob(768);
    encapResult.sharedSecret.data = nullptr;
    encapResult.sharedSecret.size = 32;

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);

    EXPECT_EQ(encapResult.encapsulatedData.size, 0);
    EXPECT_EQ(encapResult.sharedSecret.size, 0);
}
}