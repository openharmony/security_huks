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

#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "native_huks_api.h"
#include "native_huks_param.h"
#include "native_huks_type.h"
#include "hks_type.h"
#include "hks_type_enum.h"

using namespace testing::ext;
namespace {
class HksSeTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksSeTest::SetUpTestCase(void)
{
}

void HksSeTest::TearDownTestCase(void)
{
}

void HksSeTest::SetUp()
{
}

void HksSeTest::TearDown()
{
}

OH_Huks_Result InitParamSet(struct OH_Huks_ParamSet **paramSet,
    const struct OH_Huks_Param *params, uint32_t paramCount)
{
    OH_Huks_Result ret = OH_Huks_InitParamSet(paramSet);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_AddParams(*paramSet, params, paramCount);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        OH_Huks_FreeParamSet(paramSet);
        return ret;
    }
    ret = OH_Huks_BuildParamSet(paramSet);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        OH_Huks_FreeParamSet(paramSet);
        return ret;
    }
    return ret;
}

static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = { 0 };

static const uint32_t COMMON_DATA_SIZE = 1024;
static const uint32_t SIGN_OUT_SIZE = 256;
static const uint32_t WRAPPED_KEY_SIZE = 2048;

static struct OH_Huks_Param g_genSm2Params[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_SIGN | OH_HUKS_KEY_PURPOSE_VERIFY},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_genSm2CryptoParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_genSm2NoDigestParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_SIGN | OH_HUKS_KEY_PURPOSE_VERIFY},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_genSm4Params[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE,
     .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_PKCS7},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
    {.tag = OH_HUKS_TAG_IS_ALLOWED_WRAP, .boolParam = true},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_sm2SignParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_SIGN},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3}
};

static struct OH_Huks_Param g_sm2NoDigestSignParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_SIGN},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE}
};

static struct OH_Huks_Param g_sm2VerifyParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_VERIFY},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3}
};

static struct OH_Huks_Param g_sm2NoDigestVerifyParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_VERIFY},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE}
};

static struct OH_Huks_Param g_sm4EncryptParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_PKCS7},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
    {.tag = OH_HUKS_TAG_IV, .blob = {.size = IV_SIZE, .data = (uint8_t *)IV}}
};

static struct OH_Huks_Param g_sm4DecryptParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_PKCS7},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
    {.tag = OH_HUKS_TAG_IV, .blob = {.size = IV_SIZE, .data = (uint8_t *)IV}}
};

static struct OH_Huks_Param g_sm2EncryptParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE}
};

static struct OH_Huks_Param g_sm2DecryptParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE}
};

static struct OH_Huks_Param g_wrapParams[] = {
    {.tag = OH_HUKS_TAG_KEY_WRAP_TYPE, .uint32Param = OH_HUKS_KEY_WRAP_TYPE_HUK_BASED}
};

static struct OH_Huks_Param g_seEnvelopIniSm2[] = {
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT | OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_seEnvelopEnSm2[] = {
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE}
};

static struct OH_Huks_Param g_normalEnvelopIniSm2[] = {
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT | OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE}
};

static struct OH_Huks_Param g_normalEnvelopEnSm2[] = {
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE}
};

static uint8_t g_seSm4KeyData[] = {
    0xb9, 0xef, 0x35, 0x49, 0xb7, 0x00, 0x91, 0x58, 0x0c, 0x6f, 0x43, 0x28, 0xf8, 0x95, 0x1c, 0x02,
};
static struct OH_Huks_Blob g_seSm4Data = {sizeof(g_seSm4KeyData), g_seSm4KeyData};

static void ConcatBlob(const struct OH_Huks_Blob *data1, const struct OH_Huks_Blob *data2,
    struct OH_Huks_Blob *outData)
{
    if (outData == nullptr || data1 == nullptr || data2 == nullptr) {
        return;
    }
    uint32_t offset = 0;
    memcpy_s(outData->data, sizeof(uint32_t), &data1->size, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy_s(outData->data + offset, data1->size, data1->data, data1->size);
    offset += data1->size;
    memcpy_s(outData->data + offset, sizeof(uint32_t), &data2->size, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy_s(outData->data + offset, data2->size, data2->data, data2->size);
    outData->size = data1->size + data2->size + 2 * sizeof(uint32_t);
}

static struct OH_Huks_Param g_seEnvelopIniSm2Sign[] = {
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT | OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_seEnvelopEnSm2Sign[] = {
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE}
};

static struct OH_Huks_Param g_genSm4EcbParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_PKCS7},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_ECB},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_sm4EcbEncryptParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_PKCS7},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_ECB}
};

static struct OH_Huks_Param g_sm4EcbDecryptParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_PKCS7},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_ECB}
};

static struct OH_Huks_Param g_genSm4CtrParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CTR},
    {.tag = OH_HUKS_TAG_IS_ALLOWED_WRAP, .boolParam = true},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_sm4CtrEncryptParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CTR},
    {.tag = OH_HUKS_TAG_IV, .blob = {.size = IV_SIZE, .data = (uint8_t *)IV}}
};

static struct OH_Huks_Param g_sm4CtrDecryptParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CTR},
    {.tag = OH_HUKS_TAG_IV, .blob = {.size = IV_SIZE, .data = (uint8_t *)IV}}
};

static struct OH_Huks_Param g_genSm4CbcNoPaddingParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_sm4CbcNoPaddingEncryptParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
    {.tag = OH_HUKS_TAG_IV, .blob = {.size = IV_SIZE, .data = (uint8_t *)IV}}
};

static struct OH_Huks_Param g_sm4CbcNoPaddingDecryptParams[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
    {.tag = OH_HUKS_TAG_IV, .blob = {.size = IV_SIZE, .data = (uint8_t *)IV}}
};

static struct OH_Huks_Param g_genSm2ParamsNoAuth[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_SIGN | OH_HUKS_KEY_PURPOSE_VERIFY},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_genSm2NoDigestParamsNoAuth[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_SIGN | OH_HUKS_KEY_PURPOSE_VERIFY},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_genSm2CryptoParamsNoAuth[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
    {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_genSm4ParamsNoAuth[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_PKCS7},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
    {.tag = OH_HUKS_TAG_IS_ALLOWED_WRAP, .boolParam = true},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

static struct OH_Huks_Param g_genSm4CbcNoPaddingParamsNoAuth[] = {
    {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
    {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
    {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
    {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
    {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
    {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
};

OH_Huks_Result HksSm2Sign(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, inData, outData);
    return ret;
}

OH_Huks_Result HksSm2Verify(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    const struct OH_Huks_Blob *signature)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }

    uint8_t temp[] = "out";
    struct OH_Huks_Blob verifyOut = {(uint32_t)sizeof(temp), temp};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, inData, &verifyOut);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }

    ret = OH_Huks_FinishSession(&handleBlob, paramSet, signature, &verifyOut);
    return ret;
}

OH_Huks_Result HksSm4Encrypt(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, inData, outData);
    return ret;
}

OH_Huks_Result HksSm4Decrypt(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *cipherText,
    struct OH_Huks_Blob *plainText)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, cipherText, plainText);
    return ret;
}

OH_Huks_Result HksSm2Encrypt(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, inData, outData);
    return ret;
}

OH_Huks_Result HksSm2Decrypt(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *cipherText,
    struct OH_Huks_Blob *plainText)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, cipherText, plainText);
    return ret;
}

OH_Huks_Result HksSm4EncryptUpdateOnce(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t updateOut[1024] = {0};
    struct OH_Huks_Blob updateOutBlob = {1024, updateOut};
    struct OH_Huks_Blob updateIn = {inData->size - 4, inData->data};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &updateIn, &updateOutBlob);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t finishOut[1024] = {0};
    struct OH_Huks_Blob finishOutBlob = {1024, finishOut};
    struct OH_Huks_Blob finishInBlob = {4, inData->data + inData->size - 4};
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, &finishInBlob, &finishOutBlob);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    memcpy_s(outData->data, outData->size, updateOutBlob.data, updateOutBlob.size);
    memcpy_s(outData->data + updateOutBlob.size, outData->size - updateOutBlob.size,
        finishOutBlob.data, finishOutBlob.size);
    outData->size = updateOutBlob.size + finishOutBlob.size;
    return ret;
}

OH_Huks_Result HksSm4DecryptUpdateOnce(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *cipherText,
    struct OH_Huks_Blob *plainText)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, cipherText, plainText);
    return ret;
}

OH_Huks_Result HksSm4EncryptUpdateFiveTimes(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t updateOut[1024] = {0};
    struct OH_Huks_Blob updateOutBlob = {1024, updateOut};
    uint32_t totalUpdateOutSize = 0;
    const uint32_t chunkSize = 16;
    for (uint32_t i = 0; i < 4; i++) {
        struct OH_Huks_Blob chunk = {chunkSize, inData->data + i * chunkSize};
        ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &chunk, &updateOutBlob);
        if (ret.errorCode != OH_HUKS_SUCCESS) {
            return ret;
        }
        memcpy_s(outData->data + totalUpdateOutSize, outData->size - totalUpdateOutSize,
            updateOutBlob.data, updateOutBlob.size);
        totalUpdateOutSize += updateOutBlob.size;
    }
    uint8_t finishOut[1024] = {0};
    struct OH_Huks_Blob finishOutBlob = {1024, finishOut};
    struct OH_Huks_Blob finishInBlob = {inData->size - 64, inData->data + 64};
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, &finishInBlob, &finishOutBlob);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    memcpy_s(outData->data + totalUpdateOutSize, outData->size - totalUpdateOutSize,
        finishOutBlob.data, finishOutBlob.size);
    outData->size = totalUpdateOutSize + finishOutBlob.size;
    return ret;
}

OH_Huks_Result HksSm4DecryptUpdateFiveTimes(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *cipherText,
    struct OH_Huks_Blob *plainText)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, cipherText, plainText);
    return ret;
}

OH_Huks_Result HksSm4NoPaddingEncryptUpdateTwoTimes(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t updateOut[1024] = {0};
    struct OH_Huks_Blob updateOutBlob = {1024, updateOut};
    struct OH_Huks_Blob chunk1 = {32, inData->data};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &chunk1, &updateOutBlob);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t finishOut[1024] = {0};
    struct OH_Huks_Blob finishOutBlob = {1024, finishOut};
    struct OH_Huks_Blob finishInBlob = {inData->size - 32, inData->data + 32};
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, &finishInBlob, &finishOutBlob);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    memcpy_s(outData->data, outData->size, updateOutBlob.data, updateOutBlob.size);
    memcpy_s(outData->data + updateOutBlob.size, outData->size - updateOutBlob.size,
        finishOutBlob.data, finishOutBlob.size);
    outData->size = updateOutBlob.size + finishOutBlob.size;
    return ret;
}

OH_Huks_Result HksSm4NoPaddingDecryptUpdateTwoTimes(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *cipherText,
    struct OH_Huks_Blob *plainText)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, cipherText, plainText);
    return ret;
}

OH_Huks_Result HksSm2EncryptUpdateOnce(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, inData, outData);
    return ret;
}

OH_Huks_Result HksSm2DecryptUpdateOnce(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *cipherText,
    struct OH_Huks_Blob *plainText)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, cipherText, plainText);
    return ret;
}

OH_Huks_Result HksSm2EncryptUpdateTwoTimes(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, inData, outData);
    return ret;
}

OH_Huks_Result HksSm2DecryptUpdateTwoTimes(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *cipherText,
    struct OH_Huks_Blob *plainText)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, cipherText, plainText);
    return ret;
}

OH_Huks_Result HksSm2SignUpdateOnce(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t tempOut[1024] = {0};
    struct OH_Huks_Blob updateOut = {1024, tempOut};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, inData, &updateOut);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t finishIn[1] = {0};
    struct OH_Huks_Blob finishInBlob = {0, finishIn};
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, &finishInBlob, outData);
    return ret;
}

OH_Huks_Result HksSm2SignUpdateFiveTimes(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t tempOut[1024] = {0};
    struct OH_Huks_Blob updateOut = {1024, tempOut};
    const uint32_t chunkSize = 100;
    for (uint32_t i = 0; i < 5; i++) {
        struct OH_Huks_Blob chunk = {chunkSize, inData->data + i * chunkSize};
        ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &chunk, &updateOut);
        if (ret.errorCode != OH_HUKS_SUCCESS) {
            return ret;
        }
    }
    uint8_t finishIn[1] = {0};
    struct OH_Huks_Blob finishInBlob = {0, finishIn};
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, &finishInBlob, outData);
    return ret;
}

OH_Huks_Result HksSm2VerifyUpdateOnce(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    const struct OH_Huks_Blob *signature)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t temp[] = "out";
    struct OH_Huks_Blob verifyOut = {(uint32_t)sizeof(temp), temp};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, inData, &verifyOut);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, signature, &verifyOut);
    return ret;
}

OH_Huks_Result HksSm2VerifyUpdateFiveTimes(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    const struct OH_Huks_Blob *signature)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t temp[] = "out";
    struct OH_Huks_Blob verifyOut = {(uint32_t)sizeof(temp), temp};
    const uint32_t chunkSize = 100;
    for (uint32_t i = 0; i < 5; i++) {
        struct OH_Huks_Blob chunk = {chunkSize, inData->data + i * chunkSize};
        ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &chunk, &verifyOut);
        if (ret.errorCode != OH_HUKS_SUCCESS) {
            return ret;
        }
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, signature, &verifyOut);
    return ret;
}

OH_Huks_Result HksSm2NoDigestSignUpdateThreeTimes(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    struct OH_Huks_Blob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t tempOut[1024] = {0};
    struct OH_Huks_Blob updateOut = {1024, tempOut};
    struct OH_Huks_Blob chunk1 = {10, inData->data};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &chunk1, &updateOut);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    struct OH_Huks_Blob chunk2 = {10, inData->data + 10};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &chunk2, &updateOut);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    struct OH_Huks_Blob chunk3 = {12, inData->data + 20};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &chunk3, &updateOut);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t finishIn[1] = {0};
    struct OH_Huks_Blob finishInBlob = {0, finishIn};
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, &finishInBlob, outData);
    return ret;
}

OH_Huks_Result HksSm2NoDigestVerifyUpdateThreeTimes(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_ParamSet *paramSet, const struct OH_Huks_Blob *inData,
    const struct OH_Huks_Blob *signature)
{
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    OH_Huks_Result ret = OH_Huks_InitSession(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t temp[] = "out";
    struct OH_Huks_Blob verifyOut = {(uint32_t)sizeof(temp), temp};
    struct OH_Huks_Blob chunk1 = {10, inData->data};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &chunk1, &verifyOut);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    struct OH_Huks_Blob chunk2 = {10, inData->data + 10};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &chunk2, &verifyOut);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    struct OH_Huks_Blob chunk3 = {12, inData->data + 20};
    ret = OH_Huks_UpdateSession(&handleBlob, paramSet, &chunk3, &verifyOut);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, paramSet, signature, &verifyOut);
    return ret;
}

static void FreeThreeParamset(OH_Huks_ParamSet **paramSet1,
    OH_Huks_ParamSet **paramSet2, OH_Huks_ParamSet **paramSet3)
{
    OH_Huks_FreeParamSet(paramSet1);
    OH_Huks_FreeParamSet(paramSet2);
    OH_Huks_FreeParamSet(paramSet3);
}

static OH_Huks_Result GenerateSm2Kek(const struct OH_Huks_Blob *kekAlias,
    const struct OH_Huks_Param *genParams, uint32_t genParamCount,
    struct OH_Huks_ParamSet **kekGenParamSet)
{
    OH_Huks_Result ret = InitParamSet(kekGenParamSet, genParams, genParamCount);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_GenerateKeyItem(kekAlias, *kekGenParamSet, nullptr);
    return ret;
}

static OH_Huks_Result EncryptSm4KeyWithSm2Kek(const struct OH_Huks_Blob *kekAlias,
    const struct OH_Huks_Param *encryptParams, uint32_t encryptParamCount,
    const struct OH_Huks_Blob *sm4KeyData, struct OH_Huks_Blob *cipherData,
    struct OH_Huks_ParamSet **encryptParamSet)
{
    OH_Huks_Result ret = InitParamSet(encryptParamSet, encryptParams, encryptParamCount);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    uint8_t handle[sizeof(uint64_t)] = {0};
    struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};
    ret = OH_Huks_InitSession(kekAlias, *encryptParamSet, &handleBlob, nullptr);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    ret = OH_Huks_FinishSession(&handleBlob, *encryptParamSet, sm4KeyData, cipherData);
    return ret;
}

static OH_Huks_Result ImportEnvelopSm2Key(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_Blob *kekAlias, const struct OH_Huks_Param *importParams,
    uint32_t importParamCount, const struct OH_Huks_Blob *cipherData,
    const struct OH_Huks_Blob *privateKeyData, struct OH_Huks_ParamSet **importParamSet)
{
    OH_Huks_Result ret = InitParamSet(importParamSet, importParams, importParamCount);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    
    uint8_t importKeyData[1024] = {0};
    struct OH_Huks_Blob importKeyBlob = {0, importKeyData};
    ConcatBlob(cipherData, privateKeyData, &importKeyBlob);
    
    ret = OH_Huks_ImportWrappedKeyItem(keyAlias, kekAlias, *importParamSet, &importKeyBlob);
    return ret;
}

static OH_Huks_Result ImportEnvelopSm4Key(const struct OH_Huks_Blob *keyAlias,
    const struct OH_Huks_Blob *kekAlias, const struct OH_Huks_Param *importParams,
    uint32_t importParamCount, const struct OH_Huks_Blob *cipherData,
    const struct OH_Huks_Blob *sm4KeyData, struct OH_Huks_ParamSet **importParamSet)
{
    OH_Huks_Result ret = InitParamSet(importParamSet, importParams, importParamCount);
    if (ret.errorCode != OH_HUKS_SUCCESS) {
        return ret;
    }
    
    uint8_t importKeyData[1024] = {0};
    struct OH_Huks_Blob importKeyBlob = {0, importKeyData};
    ConcatBlob(cipherData, sm4KeyData, &importKeyBlob);
    
    ret = OH_Huks_ImportWrappedKeyItem(keyAlias, kekAlias, *importParamSet, &importKeyBlob);
    return ret;
}

HWTEST_F(HksSeTest, HksSeGenKeyTestSm2, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_sign_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2Params,
            sizeof(g_genSm2Params) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";
    } while (0);

    OH_Huks_FreeParamSet(&genParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeGenKeyTestSm4, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm4_sign_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4Params,
            sizeof(g_genSm4Params) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";
    } while (0);

    OH_Huks_FreeParamSet(&genParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeExportKeyTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_export_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2Params,
            sizeof(g_genSm2Params) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        uint8_t publicKey[1024] = {0};
        struct OH_Huks_Blob publicKeyBlob = {1024, publicKey};

        ohResult = OH_Huks_ExportPublicKeyItem(&keyAlias, genParamSet, &publicKeyBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "ExportPublicKeyItem fail";
    } while (0);

    OH_Huks_FreeParamSet(&genParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeExportKeyTest002, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm4_export_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4Params,
            sizeof(g_genSm4Params) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        uint8_t publicKey[1024] = {0};
        struct OH_Huks_Blob publicKeyBlob = {1024, publicKey};

        ohResult = OH_Huks_ExportPublicKeyItem(&keyAlias, genParamSet, &publicKeyBlob);
        EXPECT_NE(ohResult.errorCode, OH_HUKS_SUCCESS) << "ExportPublicKeyItem fail";
    } while (0);

    OH_Huks_FreeParamSet(&genParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeGetKeyParamSet, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_get_param_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *outParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2Params,
            sizeof(g_genSm2Params) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        const size_t paramSetSize = 1024;
        outParamSet = static_cast<struct OH_Huks_ParamSet *>(malloc(paramSetSize));
        outParamSet->paramSetSize = paramSetSize;

        ohResult = OH_Huks_GetKeyItemParamSet(&keyAlias, genParamSet, outParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GetKeyItemParamSet fail";

        OH_Huks_Param *purposeParam = nullptr; // 无需申请内存，获取后指针指向该参数在参数集中所处内存地址
        ohResult = OH_Huks_GetParam(outParamSet, OH_HUKS_TAG_PURPOSE, &purposeParam);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "Get key purpose fail";
    } while (0);

    OH_Huks_FreeParamSet(&genParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeWrapKeyTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm4_wrap_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *wrapParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4Params,
            sizeof(g_genSm4Params) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&wrapParamSet, g_wrapParams,
            sizeof(g_wrapParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t wrappedData[WRAPPED_KEY_SIZE] = {0};
        struct OH_Huks_Blob wrappedKey = {WRAPPED_KEY_SIZE, wrappedData};

        ohResult = OH_Huks_WrapKey(&keyAlias, wrapParamSet, &wrappedKey);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "WrapKey fail";

        (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);

        ohResult = OH_Huks_UnwrapKey(&keyAlias, wrapParamSet, &wrappedKey);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "UnwrapKey fail";
    } while (0);

    OH_Huks_FreeParamSet(&genParamSet);
    OH_Huks_FreeParamSet(&wrapParamSet);
}

HWTEST_F(HksSeTest, HksSeWrapKeyTest002, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_wrap_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *wrapParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2Params,
            sizeof(g_genSm2Params) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&wrapParamSet, g_wrapParams,
            sizeof(g_wrapParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t wrappedData[WRAPPED_KEY_SIZE] = {0};
        struct OH_Huks_Blob wrappedKey = {WRAPPED_KEY_SIZE, wrappedData};

        ohResult = OH_Huks_WrapKey(&keyAlias, wrapParamSet, &wrappedKey);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "WrapKey fail";

        (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);

        ohResult = OH_Huks_UnwrapKey(&keyAlias, wrapParamSet, &wrappedKey);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "UnwrapKey fail";
    } while (0);

    OH_Huks_FreeParamSet(&genParamSet);
    OH_Huks_FreeParamSet(&wrapParamSet);
}

HWTEST_F(HksSeTest, HksSeImportEnvelopSm2Cipher, TestSize.Level0)
{
    struct OH_Huks_ParamSet *kekGenParamSet = nullptr;
    struct OH_Huks_ParamSet *kekEncryptParamSet = nullptr;
    struct OH_Huks_ParamSet *importParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;

    char kekAlias[] = "se_envelop_sm2_cipher_kek";
    struct OH_Huks_Blob kekAliasBlob = {(uint32_t)strlen(kekAlias), (uint8_t *)kekAlias};
    char keyAlias[] = "se_import_envelop_sm2_cipher";
    struct OH_Huks_Blob keyAliasBlob = {(uint32_t)strlen(keyAlias), (uint8_t *)keyAlias};

    static const uint32_t COMMON_SIZE = 1024;
    uint8_t cipher[COMMON_SIZE] = {0};
    struct OH_Huks_Blob cipherData = {COMMON_SIZE, cipher};

    uint8_t sm2PubKey[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x42, 0x00, 0x04, 0x38, 0x9e, 0xd3, 0x95, 0xb7,
        0x98, 0xdf, 0x60, 0xbf, 0x5a, 0x14, 0x71, 0x45, 0x2b, 0xd6, 0xb7, 0x35, 0x1c, 0xd1, 0x38, 0x7a,
        0x11, 0x98, 0x8a, 0x28, 0xd1, 0x37, 0x9b, 0x75, 0x12, 0xd8, 0x06, 0x42, 0xc2, 0xbf, 0x3b, 0x52,
        0x18, 0x6e, 0x9c, 0x41, 0x2d, 0x77, 0xc0, 0xa1, 0x6d, 0x9e, 0x08, 0x9d, 0x4e, 0x16, 0x62, 0x57,
        0x97, 0x56, 0x10, 0xd4, 0x7b, 0x3a, 0x5f, 0x96, 0xf6, 0x8c, 0x19,
    };
    struct OH_Huks_Blob sm2PubKeyBlob = {sizeof(sm2PubKey), sm2PubKey};

    uint8_t sm2PrivateKey[] = {
        0xa7, 0xde, 0x26, 0xf9, 0xe8, 0xad, 0xe8, 0x9b, 0x5a, 0x37, 0xca, 0x5b, 0x70, 0x18, 0x18, 0xe0,
        0x68, 0x04, 0xa9, 0x8b, 0x94, 0x9c, 0xcd, 0x86, 0x90, 0x22, 0x9f, 0x17, 0xfd, 0xc4, 0x9c, 0x51,
    };
    struct OH_Huks_Blob sm2PrivateKeyBlob = {sizeof(sm2PrivateKey), sm2PrivateKey};

    struct OH_Huks_Param sm2CipherImportParams[] = {
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
        {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
        {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
        {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
        {.tag = OH_HUKS_TAG_IMPORT_KEY_TYPE, .uint32Param = OH_HUKS_KEY_TYPE_KEY_PAIR},
        {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = sm2PubKeyBlob},
        {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
    };

    do {
        ohResult = GenerateSm2Kek(&kekAliasBlob, g_seEnvelopIniSm2,
            sizeof(g_seEnvelopIniSm2) / sizeof(OH_Huks_Param), &kekGenParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateSm2Kek failed";

        ohResult = EncryptSm4KeyWithSm2Kek(&kekAliasBlob, g_seEnvelopEnSm2,
            sizeof(g_seEnvelopEnSm2) / sizeof(OH_Huks_Param), &g_seSm4Data, &cipherData, &kekEncryptParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "EncryptSm4KeyWithSm2Kek failed";

        ohResult = ImportEnvelopSm2Key(&keyAliasBlob, &kekAliasBlob, sm2CipherImportParams,
            sizeof(sm2CipherImportParams) / sizeof(OH_Huks_Param), &cipherData, &sm2PrivateKeyBlob, &importParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "ImportEnvelopSm2Key failed";

        ohResult = InitParamSet(&encryptParamSet, g_sm2EncryptParams, sizeof(g_sm2EncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        char inData[] = "HksSeImportEnvelopSm2CipherTest";
        struct OH_Huks_Blob inDataBlob = {(uint32_t)strlen(inData), (uint8_t *)inData};
        uint8_t encryptOut[COMMON_SIZE] = {0};
        struct OH_Huks_Blob encryptOutBlob = {COMMON_SIZE, encryptOut};

        ohResult = HksSm2Encrypt(&keyAliasBlob, encryptParamSet, &inDataBlob, &encryptOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2Encrypt failed";

        ohResult = InitParamSet(&decryptParamSet, g_sm2DecryptParams, sizeof(g_sm2DecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        uint8_t decryptOut[COMMON_SIZE] = {0};
        struct OH_Huks_Blob decryptOutBlob = {COMMON_SIZE, decryptOut};

        ohResult = HksSm2Decrypt(&keyAliasBlob, decryptParamSet, &encryptOutBlob, &decryptOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2Decrypt failed";

        (void)OH_Huks_DeleteKeyItem(&keyAliasBlob, importParamSet);
        (void)OH_Huks_DeleteKeyItem(&kekAliasBlob, kekGenParamSet);
    } while (0);

    OH_Huks_FreeParamSet(&kekGenParamSet);
    OH_Huks_FreeParamSet(&kekEncryptParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
    OH_Huks_FreeParamSet(&encryptParamSet);
    OH_Huks_FreeParamSet(&decryptParamSet);
}

HWTEST_F(HksSeTest, HksSeImportEnvelopSm2SignVerify, TestSize.Level0)
{
    struct OH_Huks_ParamSet *kekGenParamSet = nullptr;
    struct OH_Huks_ParamSet *kekEncryptParamSet = nullptr;
    struct OH_Huks_ParamSet *importParamSet = nullptr;
    struct OH_Huks_ParamSet *signParamSet = nullptr;
    struct OH_Huks_ParamSet *verifyParamSet = nullptr;
    OH_Huks_Result ohResult;

    char kekAlias[] = "se_envelop_sm2_sign_kek";
    struct OH_Huks_Blob kekAliasBlob = {(uint32_t)strlen(kekAlias), (uint8_t *)kekAlias};
    char keyAlias[] = "se_import_envelop_sm2_sign";
    struct OH_Huks_Blob keyAliasBlob = {(uint32_t)strlen(keyAlias), (uint8_t *)keyAlias};

    static const uint32_t COMMON_SIZE = 1024;
    uint8_t cipher[COMMON_SIZE] = {0};
    struct OH_Huks_Blob cipherData = {COMMON_SIZE, cipher};

    uint8_t sm2PubKey[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x42, 0x00, 0x04, 0x38, 0x9e, 0xd3, 0x95, 0xb7,
        0x98, 0xdf, 0x60, 0xbf, 0x5a, 0x14, 0x71, 0x45, 0x2b, 0xd6, 0xb7, 0x35, 0x1c, 0xd1, 0x38, 0x7a,
        0x11, 0x98, 0x8a, 0x28, 0xd1, 0x37, 0x9b, 0x75, 0x12, 0xd8, 0x06, 0x42, 0xc2, 0xbf, 0x3b, 0x52,
        0x18, 0x6e, 0x9c, 0x41, 0x2d, 0x77, 0xc0, 0xa1, 0x6d, 0x9e, 0x08, 0x9d, 0x4e, 0x16, 0x62, 0x57,
        0x97, 0x56, 0x10, 0xd4, 0x7b, 0x3a, 0x5f, 0x96, 0xf6, 0x8c, 0x19,
    };
    struct OH_Huks_Blob sm2PubKeyBlob = {sizeof(sm2PubKey), sm2PubKey};

    uint8_t sm2PrivateKey[] = {
        0xa7, 0xde, 0x26, 0xf9, 0xe8, 0xad, 0xe8, 0x9b, 0x5a, 0x37, 0xca, 0x5b, 0x70, 0x18, 0x18, 0xe0,
        0x68, 0x04, 0xa9, 0x8b, 0x94, 0x9c, 0xcd, 0x86, 0x90, 0x22, 0x9f, 0x17, 0xfd, 0xc4, 0x9c, 0x51,
    };
    struct OH_Huks_Blob sm2PrivateKeyBlob = {sizeof(sm2PrivateKey), sm2PrivateKey};

    struct OH_Huks_Param sm2SignImportParams[] = {
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
        {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_SIGN | OH_HUKS_KEY_PURPOSE_VERIFY},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
        {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
        {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
        {.tag = OH_HUKS_TAG_IMPORT_KEY_TYPE, .uint32Param = OH_HUKS_KEY_TYPE_KEY_PAIR},
        {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = sm2PubKeyBlob},
        {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
    };

    do {
        ohResult = GenerateSm2Kek(&kekAliasBlob, g_seEnvelopIniSm2Sign,
            sizeof(g_seEnvelopIniSm2Sign) / sizeof(OH_Huks_Param), &kekGenParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateSm2Kek failed";

        ohResult = EncryptSm4KeyWithSm2Kek(&kekAliasBlob, g_seEnvelopEnSm2Sign,
            sizeof(g_seEnvelopEnSm2Sign) / sizeof(OH_Huks_Param), &g_seSm4Data, &cipherData, &kekEncryptParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "EncryptSm4KeyWithSm2Kek failed";

        ohResult = ImportEnvelopSm2Key(&keyAliasBlob, &kekAliasBlob, sm2SignImportParams,
            sizeof(sm2SignImportParams) / sizeof(OH_Huks_Param), &cipherData, &sm2PrivateKeyBlob, &importParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "ImportEnvelopSm2Key failed";

        ohResult = InitParamSet(&signParamSet, g_sm2SignParams, sizeof(g_sm2SignParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        char inData[] = "HksSeImportEnvelopSm2SignVerifyTest";
        struct OH_Huks_Blob inDataBlob = {(uint32_t)strlen(inData), (uint8_t *)inData};
        uint8_t signOut[SIGN_OUT_SIZE] = {0};
        struct OH_Huks_Blob signOutBlob = {SIGN_OUT_SIZE, signOut};

        ohResult = HksSm2Sign(&keyAliasBlob, signParamSet, &inDataBlob, &signOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2Sign failed";

        ohResult = InitParamSet(&verifyParamSet, g_sm2VerifyParams, sizeof(g_sm2VerifyParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        ohResult = HksSm2Verify(&keyAliasBlob, verifyParamSet, &inDataBlob, &signOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2Verify failed";

        (void)OH_Huks_DeleteKeyItem(&keyAliasBlob, importParamSet);
        (void)OH_Huks_DeleteKeyItem(&kekAliasBlob, kekGenParamSet);
    } while (0);

    OH_Huks_FreeParamSet(&kekGenParamSet);
    OH_Huks_FreeParamSet(&kekEncryptParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
    OH_Huks_FreeParamSet(&signParamSet);
    OH_Huks_FreeParamSet(&verifyParamSet);
}

HWTEST_F(HksSeTest, HksSeImportEnvelopSm4CipherEcb, TestSize.Level0)
{
    struct OH_Huks_ParamSet *kekGenParamSet = nullptr;
    struct OH_Huks_ParamSet *kekEncryptParamSet = nullptr;
    struct OH_Huks_ParamSet *importParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;

    char kekAlias[] = "se_envelop_sm4_ecb_kek";
    struct OH_Huks_Blob kekAliasBlob = {(uint32_t)strlen(kekAlias), (uint8_t *)kekAlias};
    char keyAlias[] = "se_import_envelop_sm4_ecb";
    struct OH_Huks_Blob keyAliasBlob = {(uint32_t)strlen(keyAlias), (uint8_t *)keyAlias};

    static const uint32_t COMMON_SIZE = 1024;
    uint8_t cipher[COMMON_SIZE] = {0};
    struct OH_Huks_Blob cipherData = {COMMON_SIZE, cipher};

    uint8_t sm4Key[] = {
        0xd0, 0xf2, 0x71, 0x46, 0x8d, 0x2f, 0xe6, 0x67, 0x7a, 0xd1, 0x7d, 0xe9, 0xd9, 0xff, 0x04, 0x7e,
    };
    struct OH_Huks_Blob sm4KeyBlob = {sizeof(sm4Key), sm4Key};

    struct OH_Huks_Param sm4EcbImportParams[] = {
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
        {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_ECB},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
        {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
        {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE},
        {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
        {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
    };

    struct OH_Huks_Param sm4EcbEncryptParams[] = {
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
        {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_ECB}
    };

    struct OH_Huks_Param sm4EcbDecryptParams[] = {
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_DECRYPT},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
        {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_ECB}
    };

    do {
        ohResult = GenerateSm2Kek(&kekAliasBlob, g_seEnvelopIniSm2,
            sizeof(g_seEnvelopIniSm2) / sizeof(OH_Huks_Param), &kekGenParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateSm2Kek failed";

        ohResult = EncryptSm4KeyWithSm2Kek(&kekAliasBlob, g_seEnvelopEnSm2,
            sizeof(g_seEnvelopEnSm2) / sizeof(OH_Huks_Param), &g_seSm4Data, &cipherData, &kekEncryptParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "EncryptSm4KeyWithSm2Kek failed";

        ohResult = ImportEnvelopSm4Key(&keyAliasBlob, &kekAliasBlob, sm4EcbImportParams,
            sizeof(sm4EcbImportParams) / sizeof(OH_Huks_Param), &cipherData, &sm4KeyBlob, &importParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "ImportEnvelopSm4Key failed";

        ohResult = InitParamSet(&encryptParamSet, sm4EcbEncryptParams, sizeof(sm4EcbEncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        char inData[] = "1234567890123456";
        struct OH_Huks_Blob inDataBlob = {(uint32_t)strlen(inData), (uint8_t *)inData};
        uint8_t encryptOut[COMMON_SIZE] = {0};
        struct OH_Huks_Blob encryptOutBlob = {COMMON_SIZE, encryptOut};

        ohResult = HksSm4Encrypt(&keyAliasBlob, encryptParamSet, &inDataBlob, &encryptOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Encrypt failed";

        ohResult = InitParamSet(&decryptParamSet, sm4EcbDecryptParams, sizeof(sm4EcbDecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        uint8_t decryptOut[COMMON_SIZE] = {0};
        struct OH_Huks_Blob decryptOutBlob = {COMMON_SIZE, decryptOut};

        ohResult = HksSm4Decrypt(&keyAliasBlob, decryptParamSet, &encryptOutBlob, &decryptOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Decrypt failed";

        (void)OH_Huks_DeleteKeyItem(&keyAliasBlob, importParamSet);
        (void)OH_Huks_DeleteKeyItem(&kekAliasBlob, kekGenParamSet);
    } while (0);

    OH_Huks_FreeParamSet(&kekGenParamSet);
    OH_Huks_FreeParamSet(&kekEncryptParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
    OH_Huks_FreeParamSet(&encryptParamSet);
    OH_Huks_FreeParamSet(&decryptParamSet);
}

HWTEST_F(HksSeTest, HksSeImportEnvelopSm4CipherCbcPkcs7, TestSize.Level0)
{
    struct OH_Huks_ParamSet *kekGenParamSet = nullptr;
    struct OH_Huks_ParamSet *kekEncryptParamSet = nullptr;
    struct OH_Huks_ParamSet *importParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;

    char kekAlias[] = "se_envelop_sm4_cbc_pkcs7_kek";
    struct OH_Huks_Blob kekAliasBlob = {(uint32_t)strlen(kekAlias), (uint8_t *)kekAlias};
    char keyAlias[] = "se_import_envelop_sm4_cbc_pkcs7";
    struct OH_Huks_Blob keyAliasBlob = {(uint32_t)strlen(keyAlias), (uint8_t *)keyAlias};

    static const uint32_t COMMON_SIZE = 1024;
    uint8_t cipher[COMMON_SIZE] = {0};
    struct OH_Huks_Blob cipherData = {COMMON_SIZE, cipher};

    uint8_t sm4Key[] = {
        0xd0, 0xf2, 0x71, 0x46, 0x8d, 0x2f, 0xe6, 0x67, 0x7a, 0xd1, 0x7d, 0xe9, 0xd9, 0xff, 0x04, 0x7e,
    };
    struct OH_Huks_Blob sm4KeyBlob = {sizeof(sm4Key), sm4Key};

    struct OH_Huks_Param sm4CbcPkcs7ImportParams[] = {
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
        {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_PKCS7},
        {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
        {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE},
        {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
        {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
    };

    do {
        ohResult = GenerateSm2Kek(&kekAliasBlob, g_seEnvelopIniSm2,
            sizeof(g_seEnvelopIniSm2) / sizeof(OH_Huks_Param), &kekGenParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateSm2Kek failed";

        ohResult = EncryptSm4KeyWithSm2Kek(&kekAliasBlob, g_seEnvelopEnSm2,
            sizeof(g_seEnvelopEnSm2) / sizeof(OH_Huks_Param), &g_seSm4Data, &cipherData, &kekEncryptParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "EncryptSm4KeyWithSm2Kek failed";

        ohResult = ImportEnvelopSm4Key(&keyAliasBlob, &kekAliasBlob, sm4CbcPkcs7ImportParams,
            sizeof(sm4CbcPkcs7ImportParams) / sizeof(OH_Huks_Param), &cipherData, &sm4KeyBlob, &importParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "ImportEnvelopSm4Key failed";

        ohResult = InitParamSet(&encryptParamSet, g_sm4EncryptParams, sizeof(g_sm4EncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        char inData[] = "HksSeImportEnvelopSm4CipherCbcPkcs7Test";
        struct OH_Huks_Blob inDataBlob = {(uint32_t)strlen(inData), (uint8_t *)inData};
        uint8_t encryptOut[COMMON_SIZE] = {0};
        struct OH_Huks_Blob encryptOutBlob = {COMMON_SIZE, encryptOut};

        ohResult = HksSm4Encrypt(&keyAliasBlob, encryptParamSet, &inDataBlob, &encryptOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Encrypt failed";

        ohResult = InitParamSet(&decryptParamSet, g_sm4DecryptParams, sizeof(g_sm4DecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        uint8_t decryptOut[COMMON_SIZE] = {0};
        struct OH_Huks_Blob decryptOutBlob = {COMMON_SIZE, decryptOut};

        ohResult = HksSm4Decrypt(&keyAliasBlob, decryptParamSet, &encryptOutBlob, &decryptOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Decrypt failed";

        (void)OH_Huks_DeleteKeyItem(&keyAliasBlob, importParamSet);
        (void)OH_Huks_DeleteKeyItem(&kekAliasBlob, kekGenParamSet);
    } while (0);

    OH_Huks_FreeParamSet(&kekGenParamSet);
    OH_Huks_FreeParamSet(&kekEncryptParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
    OH_Huks_FreeParamSet(&encryptParamSet);
    OH_Huks_FreeParamSet(&decryptParamSet);
}

HWTEST_F(HksSeTest, HksSeImportEnvelopSm4CipherCbcNoPadding, TestSize.Level0)
{
    struct OH_Huks_ParamSet *kekGenParamSet = nullptr;
    struct OH_Huks_ParamSet *kekEncryptParamSet = nullptr;
    struct OH_Huks_ParamSet *importParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;

    char kekAlias[] = "se_envelop_sm4_cbc_nopadding_kek";
    struct OH_Huks_Blob kekAliasBlob = {(uint32_t)strlen(kekAlias), (uint8_t *)kekAlias};
    char keyAlias[] = "se_import_envelop_sm4_cbc_nopadding";
    struct OH_Huks_Blob keyAliasBlob = {(uint32_t)strlen(keyAlias), (uint8_t *)keyAlias};

    static const uint32_t COMMON_SIZE = 1024;
    uint8_t cipher[COMMON_SIZE] = {0};
    struct OH_Huks_Blob cipherData = {COMMON_SIZE, cipher};

    uint8_t sm4Key[] = {
        0xd0, 0xf2, 0x71, 0x46, 0x8d, 0x2f, 0xe6, 0x67, 0x7a, 0xd1, 0x7d, 0xe9, 0xd9, 0xff, 0x04, 0x7e,
    };
    struct OH_Huks_Blob sm4KeyBlob = {sizeof(sm4Key), sm4Key};

    struct OH_Huks_Param sm4CbcNoPaddingImportParams[] = {
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
        {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CBC},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
        {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
        {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE},
        {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
        {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
    };

    do {
        ohResult = GenerateSm2Kek(&kekAliasBlob, g_seEnvelopIniSm2,
            sizeof(g_seEnvelopIniSm2) / sizeof(OH_Huks_Param), &kekGenParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateSm2Kek failed";

        ohResult = EncryptSm4KeyWithSm2Kek(&kekAliasBlob, g_seEnvelopEnSm2,
            sizeof(g_seEnvelopEnSm2) / sizeof(OH_Huks_Param), &g_seSm4Data, &cipherData, &kekEncryptParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "EncryptSm4KeyWithSm2Kek failed";

        ohResult = ImportEnvelopSm4Key(&keyAliasBlob, &kekAliasBlob, sm4CbcNoPaddingImportParams,
            sizeof(sm4CbcNoPaddingImportParams) / sizeof(OH_Huks_Param), &cipherData, &sm4KeyBlob, &importParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "ImportEnvelopSm4Key failed";

        ohResult = InitParamSet(&encryptParamSet, g_sm4CbcNoPaddingEncryptParams,
            sizeof(g_sm4CbcNoPaddingEncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        char inData[] = "1234567890123456";
        struct OH_Huks_Blob inDataBlob = {(uint32_t)strlen(inData), (uint8_t *)inData};
        uint8_t encryptOut[COMMON_SIZE] = {0};
        struct OH_Huks_Blob encryptOutBlob = {COMMON_SIZE, encryptOut};

        ohResult = HksSm4Encrypt(&keyAliasBlob, encryptParamSet, &inDataBlob, &encryptOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Encrypt failed";

        ohResult = InitParamSet(&decryptParamSet, g_sm4CbcNoPaddingDecryptParams,
            sizeof(g_sm4CbcNoPaddingDecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        uint8_t decryptOut[COMMON_SIZE] = {0};
        struct OH_Huks_Blob decryptOutBlob = {COMMON_SIZE, decryptOut};

        ohResult = HksSm4Decrypt(&keyAliasBlob, decryptParamSet, &encryptOutBlob, &decryptOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Decrypt failed";

        (void)OH_Huks_DeleteKeyItem(&keyAliasBlob, importParamSet);
        (void)OH_Huks_DeleteKeyItem(&kekAliasBlob, kekGenParamSet);
    } while (0);

    OH_Huks_FreeParamSet(&kekGenParamSet);
    OH_Huks_FreeParamSet(&kekEncryptParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
    OH_Huks_FreeParamSet(&encryptParamSet);
    OH_Huks_FreeParamSet(&decryptParamSet);
}

HWTEST_F(HksSeTest, HksSeImportEnvelopSm4CipherCtr, TestSize.Level0)
{
    struct OH_Huks_ParamSet *kekGenParamSet = nullptr;
    struct OH_Huks_ParamSet *kekEncryptParamSet = nullptr;
    struct OH_Huks_ParamSet *importParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;

    char kekAlias[] = "se_envelop_sm4_ctr_kek";
    struct OH_Huks_Blob kekAliasBlob = {(uint32_t)strlen(kekAlias), (uint8_t *)kekAlias};
    char keyAlias[] = "se_import_envelop_sm4_ctr";
    struct OH_Huks_Blob keyAliasBlob = {(uint32_t)strlen(keyAlias), (uint8_t *)keyAlias};

    static const uint32_t COMMON_SIZE = 1024;
    uint8_t cipher[COMMON_SIZE] = {0};
    struct OH_Huks_Blob cipherData = {COMMON_SIZE, cipher};

    uint8_t sm4Key[] = {
        0xd0, 0xf2, 0x71, 0x46, 0x8d, 0x2f, 0xe6, 0x67, 0x7a, 0xd1, 0x7d, 0xe9, 0xd9, 0xff, 0x04, 0x7e,
    };
    struct OH_Huks_Blob sm4KeyBlob = {sizeof(sm4Key), sm4Key};

    struct OH_Huks_Param sm4CtrImportParams[] = {
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM4},
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
        {.tag = OH_HUKS_TAG_BLOCK_MODE, .uint32Param = OH_HUKS_MODE_CTR},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
        {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM4_KEY_SIZE_128},
        {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_NONE},
        {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
        {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
    };

    do {
        ohResult = GenerateSm2Kek(&kekAliasBlob, g_seEnvelopIniSm2,
            sizeof(g_seEnvelopIniSm2) / sizeof(OH_Huks_Param), &kekGenParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateSm2Kek failed";

        ohResult = EncryptSm4KeyWithSm2Kek(&kekAliasBlob, g_seEnvelopEnSm2,
            sizeof(g_seEnvelopEnSm2) / sizeof(OH_Huks_Param), &g_seSm4Data, &cipherData, &kekEncryptParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "EncryptSm4KeyWithSm2Kek failed";

        ohResult = ImportEnvelopSm4Key(&keyAliasBlob, &kekAliasBlob, sm4CtrImportParams,
            sizeof(sm4CtrImportParams) / sizeof(OH_Huks_Param), &cipherData, &sm4KeyBlob, &importParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "ImportEnvelopSm4Key failed";

        ohResult = InitParamSet(&encryptParamSet, g_sm4CtrEncryptParams,
            sizeof(g_sm4CtrEncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        char inData[] = "HksSeImportEnvelopSm4CipherCtrTest";
        struct OH_Huks_Blob inDataBlob = {(uint32_t)strlen(inData), (uint8_t *)inData};
        uint8_t encryptOut[COMMON_SIZE] = {0};
        struct OH_Huks_Blob encryptOutBlob = {COMMON_SIZE, encryptOut};

        ohResult = HksSm4Encrypt(&keyAliasBlob, encryptParamSet, &inDataBlob, &encryptOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Encrypt failed";

        ohResult = InitParamSet(&decryptParamSet, g_sm4CtrDecryptParams,
            sizeof(g_sm4CtrDecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet failed";

        uint8_t decryptOut[COMMON_SIZE] = {0};
        struct OH_Huks_Blob decryptOutBlob = {COMMON_SIZE, decryptOut};

        ohResult = HksSm4Decrypt(&keyAliasBlob, decryptParamSet, &encryptOutBlob, &decryptOutBlob);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Decrypt failed";

        (void)OH_Huks_DeleteKeyItem(&keyAliasBlob, importParamSet);
        (void)OH_Huks_DeleteKeyItem(&kekAliasBlob, kekGenParamSet);
    } while (0);

    OH_Huks_FreeParamSet(&kekGenParamSet);
    OH_Huks_FreeParamSet(&kekEncryptParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
    OH_Huks_FreeParamSet(&encryptParamSet);
    OH_Huks_FreeParamSet(&decryptParamSet);
}

HWTEST_F(HksSeTest, HksSeSignVerifyTestSm2Sm3, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_sign_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *signParamSet = nullptr;
    struct OH_Huks_ParamSet *verifyParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2Params,
            sizeof(g_genSm2Params) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&signParamSet, g_sm2SignParams,
            sizeof(g_sm2SignParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        char tmpInData[] = "HksSeSignTest001";
        struct OH_Huks_Blob inData = {(uint32_t)strlen(tmpInData),
            (uint8_t *)tmpInData};
        uint8_t signOut[SIGN_OUT_SIZE] = {0};
        struct OH_Huks_Blob signature = {SIGN_OUT_SIZE, signOut};

        ohResult = HksSm2Sign(&keyAlias, signParamSet, &inData, &signature);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2Sign fail";

        ohResult = InitParamSet(&verifyParamSet, g_sm2VerifyParams,
            sizeof(g_sm2VerifyParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = HksSm2Verify(&keyAlias, verifyParamSet, &inData, &signature);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2Verify fail";
    } while (0);

    FreeThreeParamset(&genParamSet, &signParamSet, &verifyParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeSignVerifyTestSm2NoDigest, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_nodigest_sign_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *signParamSet = nullptr;
    struct OH_Huks_ParamSet *verifyParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2NoDigestParams,
            sizeof(g_genSm2NoDigestParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&signParamSet, g_sm2NoDigestSignParams,
            sizeof(g_sm2NoDigestSignParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        char tmpHashData[] = "12345678901234567890123456789012";
        struct OH_Huks_Blob inData = {(uint32_t)strlen(tmpHashData),
            (uint8_t *)tmpHashData};
        uint8_t signOut[SIGN_OUT_SIZE] = {0};
        struct OH_Huks_Blob signature = {SIGN_OUT_SIZE, signOut};

        ohResult = HksSm2Sign(&keyAlias, signParamSet, &inData, &signature);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2Sign fail";

        ohResult = InitParamSet(&verifyParamSet, g_sm2NoDigestVerifyParams,
            sizeof(g_sm2NoDigestVerifyParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = HksSm2Verify(&keyAlias, verifyParamSet, &inData, &signature);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2Verify fail";
    } while (0);

    FreeThreeParamset(&genParamSet, &signParamSet, &verifyParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeCipherTestSm2Sm3NoPadding, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_sm3_nopadding_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2CryptoParams,
            sizeof(g_genSm2CryptoParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm2EncryptParams,
            sizeof(g_sm2EncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        char tmpInData[] = "HksSeCipherTestSm2Sm3NoPadding";
        struct OH_Huks_Blob inData = {(uint32_t)strlen(tmpInData),
            (uint8_t *)tmpInData};
        uint8_t cipher[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {COMMON_DATA_SIZE, cipher};

        ohResult = HksSm2Encrypt(&keyAlias, encryptParamSet, &inData, &cipherText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2Encrypt fail";

        ohResult = InitParamSet(&decryptParamSet, g_sm2DecryptParams,
            sizeof(g_sm2DecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

uint8_t plain[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob plainText = {COMMON_DATA_SIZE, plain};

        ohResult = HksSm4Decrypt(&keyAlias, decryptParamSet, &cipherText, &plainText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Decrypt fail";
    } while (0);

    FreeThreeParamset(&genParamSet, &encryptParamSet, &decryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeImportEnvelopSecurityLevelMismatch001, TestSize.Level0)
{
    struct OH_Huks_ParamSet *kekGenParamSet = nullptr;
    struct OH_Huks_ParamSet *kekEncryptParamSet = nullptr;
    struct OH_Huks_ParamSet *importParamSet = nullptr;
    OH_Huks_Result ohResult;

    char kekAlias[] = "normal_envelop_kek_for_se_import";
    struct OH_Huks_Blob kekAliasBlob = {(uint32_t)strlen(kekAlias), (uint8_t *)kekAlias};
    char keyAlias[] = "se_import_with_normal_kek";
    struct OH_Huks_Blob keyAliasBlob = {(uint32_t)strlen(keyAlias), (uint8_t *)keyAlias};

    static const uint32_t COMMON_SIZE = 1024;
    uint8_t cipher[COMMON_SIZE] = {0};
    struct OH_Huks_Blob cipherData = {COMMON_SIZE, cipher};

    uint8_t sm2PubKey[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x42, 0x00, 0x04, 0x38, 0x9e, 0xd3, 0x95, 0xb7,
        0x98, 0xdf, 0x60, 0xbf, 0x5a, 0x14, 0x71, 0x45, 0x2b, 0xd6, 0xb7, 0x35, 0x1c, 0xd1, 0x38, 0x7a,
        0x11, 0x98, 0x8a, 0x28, 0xd1, 0x37, 0x9b, 0x75, 0x12, 0xd8, 0x06, 0x42, 0xc2, 0xbf, 0x3b, 0x52,
        0x18, 0x6e, 0x9c, 0x41, 0x2d, 0x77, 0xc0, 0xa1, 0x6d, 0x9e, 0x08, 0x9d, 0x4e, 0x16, 0x62, 0x57,
        0x97, 0x56, 0x10, 0xd4, 0x7b, 0x3a, 0x5f, 0x96, 0xf6, 0x8c, 0x19,
    };
    struct OH_Huks_Blob sm2PubKeyBlob = {sizeof(sm2PubKey), sm2PubKey};

    uint8_t sm2PrivateKey[] = {
        0xa7, 0xde, 0x26, 0xf9, 0xe8, 0xad, 0xe8, 0x9b, 0x5a, 0x37, 0xca, 0x5b, 0x70, 0x18, 0x18, 0xe0,
        0x68, 0x04, 0xa9, 0x8b, 0x94, 0x9c, 0xcd, 0x86, 0x90, 0x22, 0x9f, 0x17, 0xfd, 0xc4, 0x9c, 0x51,
    };
    struct OH_Huks_Blob sm2PrivateKeyBlob = {sizeof(sm2PrivateKey), sm2PrivateKey};

    struct OH_Huks_Param sm2SeImportParams[] = {
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
        {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
        {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
        {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
        {.tag = OH_HUKS_TAG_IMPORT_KEY_TYPE, .uint32Param = OH_HUKS_KEY_TYPE_KEY_PAIR},
        {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = sm2PubKeyBlob},
        {.tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_SE}
    };

    do {
        ohResult = GenerateSm2Kek(&kekAliasBlob, g_normalEnvelopIniSm2,
            sizeof(g_normalEnvelopIniSm2) / sizeof(OH_Huks_Param), &kekGenParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateSm2Kek failed";

        ohResult = EncryptSm4KeyWithSm2Kek(&kekAliasBlob, g_normalEnvelopEnSm2,
            sizeof(g_normalEnvelopEnSm2) / sizeof(OH_Huks_Param), &g_seSm4Data, &cipherData, &kekEncryptParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "EncryptSm4KeyWithSm2Kek failed";

        ohResult = ImportEnvelopSm2Key(&keyAliasBlob, &kekAliasBlob, sm2SeImportParams,
            sizeof(sm2SeImportParams) / sizeof(OH_Huks_Param), &cipherData, &sm2PrivateKeyBlob, &importParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_ERR_CODE_INVALID_ARGUMENT)
            << "ImportEnvelopSm2Key should fail when KEK is normal key but import specifies SE level";

        (void)OH_Huks_DeleteKeyItem(&kekAliasBlob, kekGenParamSet);
    } while (0);

    OH_Huks_FreeParamSet(&kekGenParamSet);
    OH_Huks_FreeParamSet(&kekEncryptParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
}

HWTEST_F(HksSeTest, HksSeImportEnvelopSecurityLevelMismatch002, TestSize.Level0)
{
    struct OH_Huks_ParamSet *kekGenParamSet = nullptr;
    struct OH_Huks_ParamSet *kekEncryptParamSet = nullptr;
    struct OH_Huks_ParamSet *importParamSet = nullptr;
    OH_Huks_Result ohResult;

    char kekAlias[] = "se_envelop_kek_for_normal_import";
    struct OH_Huks_Blob kekAliasBlob = {(uint32_t)strlen(kekAlias), (uint8_t *)kekAlias};
    char keyAlias[] = "normal_import_with_se_kek";
    struct OH_Huks_Blob keyAliasBlob = {(uint32_t)strlen(keyAlias), (uint8_t *)keyAlias};

    static const uint32_t COMMON_SIZE = 1024;
    uint8_t cipher[COMMON_SIZE] = {0};
    struct OH_Huks_Blob cipherData = {COMMON_SIZE, cipher};

    uint8_t sm2PubKey[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x42, 0x00, 0x04, 0x38, 0x9e, 0xd3, 0x95, 0xb7,
        0x98, 0xdf, 0x60, 0xbf, 0x5a, 0x14, 0x71, 0x45, 0x2b, 0xd6, 0xb7, 0x35, 0x1c, 0xd1, 0x38, 0x7a,
        0x11, 0x98, 0x8a, 0x28, 0xd1, 0x37, 0x9b, 0x75, 0x12, 0xd8, 0x06, 0x42, 0xc2, 0xbf, 0x3b, 0x52,
        0x18, 0x6e, 0x9c, 0x41, 0x2d, 0x77, 0xc0, 0xa1, 0x6d, 0x9e, 0x08, 0x9d, 0x4e, 0x16, 0x62, 0x57,
        0x97, 0x56, 0x10, 0xd4, 0x7b, 0x3a, 0x5f, 0x96, 0xf6, 0x8c, 0x19,
    };
    struct OH_Huks_Blob sm2PubKeyBlob = {sizeof(sm2PubKey), sm2PubKey};

    uint8_t sm2PrivateKey[] = {
        0xa7, 0xde, 0x26, 0xf9, 0xe8, 0xad, 0xe8, 0x9b, 0x5a, 0x37, 0xca, 0x5b, 0x70, 0x18, 0x18, 0xe0,
        0x68, 0x04, 0xa9, 0x8b, 0x94, 0x9c, 0xcd, 0x86, 0x90, 0x22, 0x9f, 0x17, 0xfd, 0xc4, 0x9c, 0x51,
    };
    struct OH_Huks_Blob sm2PrivateKeyBlob = {sizeof(sm2PrivateKey), sm2PrivateKey};

    struct OH_Huks_Param sm2NormalImportParams[] = {
        {.tag = OH_HUKS_TAG_ALGORITHM, .uint32Param = OH_HUKS_ALG_SM2},
        {.tag = OH_HUKS_TAG_KEY_SIZE, .uint32Param = OH_HUKS_SM2_KEY_SIZE_256},
        {.tag = OH_HUKS_TAG_PURPOSE, .uint32Param = OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT},
        {.tag = OH_HUKS_TAG_PADDING, .uint32Param = OH_HUKS_PADDING_NONE},
        {.tag = OH_HUKS_TAG_DIGEST, .uint32Param = OH_HUKS_DIGEST_SM3},
        {.tag = OH_HUKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = OH_HUKS_UNWRAP_SUITE_SM2_SM4_ECB_NOPADDING},
        {.tag = OH_HUKS_TAG_IMPORT_KEY_TYPE, .uint32Param = OH_HUKS_KEY_TYPE_KEY_PAIR},
        {.tag = OH_HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, .blob = sm2PubKeyBlob}
    };

    do {
        ohResult = GenerateSm2Kek(&kekAliasBlob, g_seEnvelopIniSm2,
            sizeof(g_seEnvelopIniSm2) / sizeof(OH_Huks_Param), &kekGenParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateSm2Kek failed";

        ohResult = EncryptSm4KeyWithSm2Kek(&kekAliasBlob, g_seEnvelopEnSm2,
            sizeof(g_seEnvelopEnSm2) / sizeof(OH_Huks_Param), &g_seSm4Data, &cipherData, &kekEncryptParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "EncryptSm4KeyWithSm2Kek failed";

        ohResult = ImportEnvelopSm2Key(&keyAliasBlob, &kekAliasBlob, sm2NormalImportParams,
            sizeof(sm2NormalImportParams) / sizeof(OH_Huks_Param), &cipherData, &sm2PrivateKeyBlob, &importParamSet);
        ASSERT_EQ(ohResult.errorCode, HUKS_ERR_CODE_EXTERNAL_ERROR)
            << "ImportEnvelopSm2Key should fail when KEK is SE key but import does not specify SE level";

        (void)OH_Huks_DeleteKeyItem(&kekAliasBlob, kekGenParamSet);
    } while (0);

    OH_Huks_FreeParamSet(&kekGenParamSet);
    OH_Huks_FreeParamSet(&kekEncryptParamSet);
    OH_Huks_FreeParamSet(&importParamSet);
}

HWTEST_F(HksSeTest, HksSeCipherTestSm4CbcPkcs7, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm4_cbc_pkcs7_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4Params,
            sizeof(g_genSm4Params) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm4EncryptParams,
            sizeof(g_sm4EncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        char tmpInData[] = "HksSeCipherTestSm4CbcPkcs7";
        struct OH_Huks_Blob inData = {(uint32_t)strlen(tmpInData),
            (uint8_t *)tmpInData};
        uint8_t cipher[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {COMMON_DATA_SIZE, cipher};

        ohResult = HksSm4Encrypt(&keyAlias, encryptParamSet, &inData, &cipherText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Encrypt fail";

        ohResult = InitParamSet(&decryptParamSet, g_sm4DecryptParams,
            sizeof(g_sm4DecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t plain[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob plainText = {COMMON_DATA_SIZE, plain};

        ohResult = HksSm4Decrypt(&keyAlias, decryptParamSet, &cipherText, &plainText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Decrypt fail";
    } while (0);

    FreeThreeParamset(&genParamSet, &encryptParamSet, &decryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeCipherTestSm4EcbPkcs7, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm4_ecb_pkcs7_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4EcbParams,
            sizeof(g_genSm4EcbParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm4EcbEncryptParams,
            sizeof(g_sm4EcbEncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        char tmpInData[] = "HksSeCipherTestSm4EcbPkcs7";
        struct OH_Huks_Blob inData = {(uint32_t)strlen(tmpInData),
            (uint8_t *)tmpInData};
        uint8_t cipher[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {COMMON_DATA_SIZE, cipher};

        ohResult = HksSm4Encrypt(&keyAlias, encryptParamSet, &inData, &cipherText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Encrypt fail";

        ohResult = InitParamSet(&decryptParamSet, g_sm4EcbDecryptParams,
            sizeof(g_sm4EcbDecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t plain[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob plainText = {COMMON_DATA_SIZE, plain};

        ohResult = HksSm4Decrypt(&keyAlias, decryptParamSet, &cipherText, &plainText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Decrypt fail";
    } while (0);

    FreeThreeParamset(&genParamSet, &encryptParamSet, &decryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeCipherTestSm4CtrNoPadding, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm4_ctr_nopadding_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4CtrParams,
            sizeof(g_genSm4CtrParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm4CtrEncryptParams,
            sizeof(g_sm4CtrEncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        char tmpInData[] = "HksSeCipherTestSm4CtrNoPadding";
        struct OH_Huks_Blob inData = {(uint32_t)strlen(tmpInData),
            (uint8_t *)tmpInData};
        uint8_t cipher[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {COMMON_DATA_SIZE, cipher};

        ohResult = HksSm4Encrypt(&keyAlias, encryptParamSet, &inData, &cipherText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Encrypt fail";

        ohResult = InitParamSet(&decryptParamSet, g_sm4CtrDecryptParams,
            sizeof(g_sm4CtrDecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t plain[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob plainText = {COMMON_DATA_SIZE, plain};

        ohResult = HksSm4Decrypt(&keyAlias, decryptParamSet, &cipherText, &plainText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Decrypt fail";
    } while (0);

    FreeThreeParamset(&genParamSet, &encryptParamSet, &decryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeCipherTestSm4CbcNoPadding, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm4_cbc_nopadding_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias),
        (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4CbcNoPaddingParams,
            sizeof(g_genSm4CbcNoPaddingParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm4CbcNoPaddingEncryptParams,
            sizeof(g_sm4CbcNoPaddingEncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        char tmpInData[] = "1234567890123456";
        struct OH_Huks_Blob inData = {(uint32_t)strlen(tmpInData),
            (uint8_t *)tmpInData};
        uint8_t cipher[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {COMMON_DATA_SIZE, cipher};

        ohResult = HksSm4Encrypt(&keyAlias, encryptParamSet, &inData, &cipherText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Encrypt fail";

        ohResult = InitParamSet(&decryptParamSet, g_sm4CbcNoPaddingDecryptParams,
            sizeof(g_sm4CbcNoPaddingDecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t plain[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob plainText = {COMMON_DATA_SIZE, plain};

        ohResult = HksSm4Decrypt(&keyAlias, decryptParamSet, &cipherText, &plainText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4Decrypt fail";
    } while (0);

    FreeThreeParamset(&genParamSet, &encryptParamSet, &decryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeAbortSessionTest, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_abort_session_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4Params, sizeof(g_genSm4Params) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm4EncryptParams, sizeof(g_sm4EncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t handle[sizeof(uint64_t)] = {0};
        struct OH_Huks_Blob handleBlob = {sizeof(uint64_t), handle};

        ohResult = OH_Huks_InitSession(&keyAlias, encryptParamSet, &handleBlob, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitSession fail";

        ohResult = OH_Huks_AbortSession(&handleBlob, encryptParamSet);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "AbortSession fail";

        char tmpInData[] = "HksSeAbortSessionTest";
        struct OH_Huks_Blob inData = {(uint32_t)strlen(tmpInData), (uint8_t *)tmpInData};
        uint8_t outData[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob outDataBlob = {COMMON_DATA_SIZE, outData};

        ohResult = OH_Huks_FinishSession(&handleBlob, encryptParamSet, &inData, &outDataBlob);
        EXPECT_NE(ohResult.errorCode, OH_HUKS_SUCCESS) << "FinishSession should fail after abort";
    } while (0);

    OH_Huks_FreeParamSet(&genParamSet);
    OH_Huks_FreeParamSet(&encryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

static const uint32_t UPDATE_DATA_SIZE_100 = 100;
static const uint32_t UPDATE_DATA_SIZE_500 = 500;
static const uint32_t UPDATE_DATA_SIZE_80 = 80;
static const uint32_t UPDATE_DATA_SIZE_48 = 48;
static const uint32_t UPDATE_DATA_SIZE_32 = 32;
static const uint32_t UPDATE_DATA_SIZE_16 = 16;

HWTEST_F(HksSeTest, HksSeCipherTestSm4CbcPkcs7NoAuthUpdateOnce, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm4_cbc_pkcs7_no_auth_update_once_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4ParamsNoAuth,
            sizeof(g_genSm4ParamsNoAuth) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm4EncryptParams,
            sizeof(g_sm4EncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t inData[UPDATE_DATA_SIZE_100] = {0};
        for (uint32_t i = 0; i < UPDATE_DATA_SIZE_100; i++) {
            inData[i] = (uint8_t)(i % 256);
        }
        struct OH_Huks_Blob inDataBlob = {UPDATE_DATA_SIZE_100, inData};
        uint8_t cipher[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {COMMON_DATA_SIZE, cipher};

        ohResult = HksSm4EncryptUpdateOnce(&keyAlias, encryptParamSet, &inDataBlob, &cipherText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4EncryptUpdateOnce fail";

        ohResult = InitParamSet(&decryptParamSet, g_sm4DecryptParams,
            sizeof(g_sm4DecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t plain[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob plainText = {COMMON_DATA_SIZE, plain};

        ohResult = HksSm4DecryptUpdateOnce(&keyAlias, decryptParamSet, &cipherText, &plainText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4DecryptUpdateOnce fail";

        ASSERT_EQ(plainText.size, UPDATE_DATA_SIZE_100) << "Decrypted data size mismatch";
        ASSERT_EQ(memcmp(plainText.data, inData, UPDATE_DATA_SIZE_100), 0) << "Decrypted data content mismatch";
    } while (0);

    FreeThreeParamset(&genParamSet, &encryptParamSet, &decryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeCipherTestSm4CbcPkcs7NoAuthUpdateFiveTimes, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm4_cbc_pkcs7_no_auth_update_five_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4ParamsNoAuth,
            sizeof(g_genSm4ParamsNoAuth) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm4EncryptParams,
            sizeof(g_sm4EncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t inData[UPDATE_DATA_SIZE_80] = {0};
        for (uint32_t i = 0; i < UPDATE_DATA_SIZE_80; i++) {
            inData[i] = (uint8_t)(i % 256);
        }
        struct OH_Huks_Blob inDataBlob = {UPDATE_DATA_SIZE_80, inData};
        uint8_t cipher[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {COMMON_DATA_SIZE, cipher};

        ohResult = HksSm4EncryptUpdateFiveTimes(&keyAlias, encryptParamSet, &inDataBlob, &cipherText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4EncryptUpdateFiveTimes fail";

        ohResult = InitParamSet(&decryptParamSet, g_sm4DecryptParams,
            sizeof(g_sm4DecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t plain[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob plainText = {COMMON_DATA_SIZE, plain};

        ohResult = HksSm4DecryptUpdateFiveTimes(&keyAlias, decryptParamSet, &cipherText, &plainText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4DecryptUpdateFiveTimes fail";

        ASSERT_EQ(plainText.size, UPDATE_DATA_SIZE_80) << "Decrypted data size mismatch";
        ASSERT_EQ(memcmp(plainText.data, inData, UPDATE_DATA_SIZE_80), 0) << "Decrypted data content mismatch";
    } while (0);

    FreeThreeParamset(&genParamSet, &encryptParamSet, &decryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeCipherTestSm4CbcNoPaddingNoAuthUpdateTwoTimes, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm4_cbc_nopadding_no_auth_update_two_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm4CbcNoPaddingParamsNoAuth,
            sizeof(g_genSm4CbcNoPaddingParamsNoAuth) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm4CbcNoPaddingEncryptParams,
            sizeof(g_sm4CbcNoPaddingEncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t inData[UPDATE_DATA_SIZE_48] = {0};
        for (uint32_t i = 0; i < UPDATE_DATA_SIZE_48; i++) {
            inData[i] = (uint8_t)(i + 1);
        }
        struct OH_Huks_Blob inDataBlob = {UPDATE_DATA_SIZE_48, inData};
        uint8_t cipher[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {COMMON_DATA_SIZE, cipher};

        ohResult = HksSm4NoPaddingEncryptUpdateTwoTimes(&keyAlias, encryptParamSet, &inDataBlob, &cipherText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4NoPaddingEncryptUpdateTwoTimes fail";

        ohResult = InitParamSet(&decryptParamSet, g_sm4CbcNoPaddingDecryptParams,
            sizeof(g_sm4CbcNoPaddingDecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t plain[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob plainText = {COMMON_DATA_SIZE, plain};

        ohResult = HksSm4NoPaddingDecryptUpdateTwoTimes(&keyAlias, decryptParamSet, &cipherText, &plainText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm4NoPaddingDecryptUpdateTwoTimes fail";

        ASSERT_EQ(plainText.size, UPDATE_DATA_SIZE_48) << "Decrypted data size mismatch";
        ASSERT_EQ(memcmp(plainText.data, inData, UPDATE_DATA_SIZE_48), 0) << "Decrypted data content mismatch";
    } while (0);

    FreeThreeParamset(&genParamSet, &encryptParamSet, &decryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeSignVerifyTestSm2Sm3NoAuthUpdateOnce, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_sm3_no_auth_update_once_sign_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *signParamSet = nullptr;
    struct OH_Huks_ParamSet *verifyParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2ParamsNoAuth,
            sizeof(g_genSm2ParamsNoAuth) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&signParamSet, g_sm2SignParams,
            sizeof(g_sm2SignParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t inData[UPDATE_DATA_SIZE_100] = {0};
        for (uint32_t i = 0; i < UPDATE_DATA_SIZE_100; i++) {
            inData[i] = (uint8_t)(i % 256);
        }
        struct OH_Huks_Blob inDataBlob = {UPDATE_DATA_SIZE_100, inData};
        uint8_t signOut[SIGN_OUT_SIZE] = {0};
        struct OH_Huks_Blob signature = {SIGN_OUT_SIZE, signOut};

        ohResult = HksSm2SignUpdateOnce(&keyAlias, signParamSet, &inDataBlob, &signature);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2SignUpdateOnce fail";

        ohResult = InitParamSet(&verifyParamSet, g_sm2VerifyParams,
            sizeof(g_sm2VerifyParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = HksSm2VerifyUpdateOnce(&keyAlias, verifyParamSet, &inDataBlob, &signature);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2VerifyUpdateOnce fail";
    } while (0);

    FreeThreeParamset(&genParamSet, &signParamSet, &verifyParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeSignVerifyTestSm2Sm3NoAuthUpdateFiveTimes, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_sm3_no_auth_update_five_sign_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *signParamSet = nullptr;
    struct OH_Huks_ParamSet *verifyParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2ParamsNoAuth,
            sizeof(g_genSm2ParamsNoAuth) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&signParamSet, g_sm2SignParams,
            sizeof(g_sm2SignParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t inData[UPDATE_DATA_SIZE_500] = {0};
        for (uint32_t i = 0; i < UPDATE_DATA_SIZE_500; i++) {
            inData[i] = (uint8_t)(i % 256);
        }
        struct OH_Huks_Blob inDataBlob = {UPDATE_DATA_SIZE_500, inData};
        uint8_t signOut[SIGN_OUT_SIZE] = {0};
        struct OH_Huks_Blob signature = {SIGN_OUT_SIZE, signOut};

        ohResult = HksSm2SignUpdateFiveTimes(&keyAlias, signParamSet, &inDataBlob, &signature);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2SignUpdateFiveTimes fail";

        ohResult = InitParamSet(&verifyParamSet, g_sm2VerifyParams,
            sizeof(g_sm2VerifyParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = HksSm2VerifyUpdateFiveTimes(&keyAlias, verifyParamSet, &inDataBlob, &signature);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2VerifyUpdateFiveTimes fail";
    } while (0);

    FreeThreeParamset(&genParamSet, &signParamSet, &verifyParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeSignVerifyTestSm2NoDigestNoAuthUpdateThreeTimes, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_nodigest_no_auth_update_three_sign_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *signParamSet = nullptr;
    struct OH_Huks_ParamSet *verifyParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2NoDigestParamsNoAuth,
            sizeof(g_genSm2NoDigestParamsNoAuth) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&signParamSet, g_sm2NoDigestSignParams,
            sizeof(g_sm2NoDigestSignParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t inData[UPDATE_DATA_SIZE_32] = {0};
        for (uint32_t i = 0; i < UPDATE_DATA_SIZE_32; i++) {
            inData[i] = (uint8_t)(i + 1);
        }
        struct OH_Huks_Blob inDataBlob = {UPDATE_DATA_SIZE_32, inData};
        uint8_t signOut[SIGN_OUT_SIZE] = {0};
        struct OH_Huks_Blob signature = {SIGN_OUT_SIZE, signOut};

        ohResult = HksSm2NoDigestSignUpdateThreeTimes(&keyAlias, signParamSet, &inDataBlob, &signature);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2NoDigestSignUpdateThreeTimes fail";

        ohResult = InitParamSet(&verifyParamSet, g_sm2NoDigestVerifyParams,
            sizeof(g_sm2NoDigestVerifyParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = HksSm2NoDigestVerifyUpdateThreeTimes(&keyAlias, verifyParamSet, &inDataBlob, &signature);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2NoDigestVerifyUpdateThreeTimes fail";
    } while (0);

    FreeThreeParamset(&genParamSet, &signParamSet, &verifyParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeCipherTestSm2Sm3NoPaddingNoAuthUpdateOnce, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_sm3_nopadding_no_auth_update_once_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2CryptoParamsNoAuth,
            sizeof(g_genSm2CryptoParamsNoAuth) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm2EncryptParams,
            sizeof(g_sm2EncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t inData[UPDATE_DATA_SIZE_16] = {0};
        for (uint32_t i = 0; i < UPDATE_DATA_SIZE_16; i++) {
            inData[i] = (uint8_t)(i + 1);
        }
        struct OH_Huks_Blob inDataBlob = {UPDATE_DATA_SIZE_16, inData};
        uint8_t cipher[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {COMMON_DATA_SIZE, cipher};

        ohResult = HksSm2EncryptUpdateOnce(&keyAlias, encryptParamSet, &inDataBlob, &cipherText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2EncryptUpdateOnce fail";

        ohResult = InitParamSet(&decryptParamSet, g_sm2DecryptParams,
            sizeof(g_sm2DecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t plain[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob plainText = {COMMON_DATA_SIZE, plain};

        ohResult = HksSm2DecryptUpdateOnce(&keyAlias, decryptParamSet, &cipherText, &plainText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2DecryptUpdateOnce fail";

        ASSERT_EQ(plainText.size, UPDATE_DATA_SIZE_16) << "Decrypted data size mismatch";
        ASSERT_EQ(memcmp(plainText.data, inData, UPDATE_DATA_SIZE_16), 0) << "Decrypted data content mismatch";
    } while (0);

    FreeThreeParamset(&genParamSet, &encryptParamSet, &decryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}

HWTEST_F(HksSeTest, HksSeCipherTestSm2Sm3NoPaddingNoAuthUpdateTwoTimes, TestSize.Level0)
{
    char tmpKeyAlias[] = "se_sm2_sm3_nopadding_no_auth_update_two_key";
    struct OH_Huks_Blob keyAlias = {(uint32_t)strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias};
    struct OH_Huks_ParamSet *genParamSet = nullptr;
    struct OH_Huks_ParamSet *encryptParamSet = nullptr;
    struct OH_Huks_ParamSet *decryptParamSet = nullptr;
    OH_Huks_Result ohResult;
    do {
        ohResult = InitParamSet(&genParamSet, g_genSm2CryptoParamsNoAuth,
            sizeof(g_genSm2CryptoParamsNoAuth) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        ohResult = OH_Huks_GenerateKeyItem(&keyAlias, genParamSet, nullptr);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "GenerateKeyItem fail";

        ohResult = InitParamSet(&encryptParamSet, g_sm2EncryptParams,
            sizeof(g_sm2EncryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t inData[UPDATE_DATA_SIZE_32] = {0};
        for (uint32_t i = 0; i < UPDATE_DATA_SIZE_32; i++) {
            inData[i] = (uint8_t)(i + 1);
        }
        struct OH_Huks_Blob inDataBlob = {UPDATE_DATA_SIZE_32, inData};
        uint8_t cipher[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob cipherText = {COMMON_DATA_SIZE, cipher};

        ohResult = HksSm2EncryptUpdateTwoTimes(&keyAlias, encryptParamSet, &inDataBlob, &cipherText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2EncryptUpdateTwoTimes fail";

        ohResult = InitParamSet(&decryptParamSet, g_sm2DecryptParams,
            sizeof(g_sm2DecryptParams) / sizeof(OH_Huks_Param));
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "InitParamSet fail";

        uint8_t plain[COMMON_DATA_SIZE] = {0};
        struct OH_Huks_Blob plainText = {COMMON_DATA_SIZE, plain};

        ohResult = HksSm2DecryptUpdateTwoTimes(&keyAlias, decryptParamSet, &cipherText, &plainText);
        ASSERT_EQ(ohResult.errorCode, OH_HUKS_SUCCESS) << "HksSm2DecryptUpdateTwoTimes fail";

        ASSERT_EQ(plainText.size, UPDATE_DATA_SIZE_32) << "Decrypted data size mismatch";
        ASSERT_EQ(memcmp(plainText.data, inData, UPDATE_DATA_SIZE_32), 0) << "Decrypted data content mismatch";
    } while (0);

    FreeThreeParamset(&genParamSet, &encryptParamSet, &decryptParamSet);
    (void)OH_Huks_DeleteKeyItem(&keyAlias, genParamSet);
}
}