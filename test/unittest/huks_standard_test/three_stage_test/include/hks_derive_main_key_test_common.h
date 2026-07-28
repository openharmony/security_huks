/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef HKS_DERIVE_MAIN_KEY_TEST_COMMON_H
#define HKS_DERIVE_MAIN_KEY_TEST_COMMON_H

#include <string>
#include "hks_type.h"

namespace Unittest::HksDeriveMainKeyTest {
static const uint32_t IV_SIZE = 16;
static uint8_t IV[IV_SIZE] = { 0 };
static const uint32_t AES_COMMON_SIZE = 1024;
static const std::string g_inData = "Hks_AES_Cipher_Test_000000000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";

static char g_tmpKeyAlias1[] = "HksDeriveMainKeyPart2Test001";
static char g_tmpKeyAlias2[] = "HksDeriveMainKeyPart2Test002";
static char g_tmpKeyAlias3[] = "HksDeriveMainKeyPart2Test003";
static char g_tmpKeyAlias4[] = "HksDeriveMainKeyPart2Test004";
static char g_tmpKeyAlias5[] = "HksDeriveMainKeyPart2Test005";
static char g_tmpKeyAlias6[] = "HksDeriveMainKeyPart2Test006";

static uint8_t keyData[16] = {
    0x89, 0x37, 0x22, 0xF3, 0xEA, 0x0B, 0xFB, 0x82, 0x1F, 0x3D, 0xE3, 0xA5, 0x34, 0x69, 0x17, 0x36
};
static struct HksBlob keyImported = { .size = 16, .data = keyData };

static uint8_t g_cipher[240] = {
    0xF7, 0xDC, 0xA2, 0xD9, 0xDB, 0xCF, 0x0B, 0x0E, 0x43, 0x53, 0x80, 0x2D, 0x75, 0xF0, 0xBD, 0xC9,
    0x4B, 0x7B, 0xCD, 0xDA, 0xF4, 0x58, 0xCD, 0x76, 0xCC, 0x3D, 0x1C, 0x2B, 0xCD, 0x22, 0x56, 0x76,
    0x85, 0xB7, 0x04, 0x19, 0xAE, 0xE4, 0xFB, 0xEE, 0xAD, 0x4E, 0xB1, 0x1C, 0xF3, 0x31, 0xF9, 0xE8,
    0xAC, 0x75, 0xC1, 0x02, 0x7F, 0x64, 0xD7, 0x60, 0x5D, 0x9A, 0xB2, 0xC9, 0x54, 0xE1, 0xB2, 0x5B,
    0x49, 0xF7, 0xC6, 0x10, 0x83, 0x2A, 0x6F, 0xB5, 0x7F, 0x18, 0xBD, 0x38, 0xD3, 0x07, 0x56, 0x44,
    0x0B, 0xE4, 0x8E, 0x67, 0xE0, 0x47, 0x2A, 0xE1, 0x56, 0x53, 0x6B, 0x2F, 0xBB, 0x56, 0x6D, 0x6A,
    0x8E, 0xAD, 0x5D, 0x8E, 0x6B, 0x40, 0xDF, 0xF1, 0x29, 0xDB, 0x75, 0xC0, 0xBD, 0xD1, 0xF7, 0x28,
    0x64, 0x21, 0xE4, 0x97, 0x61, 0xD6, 0x9B, 0x70, 0x23, 0xB3, 0xE5, 0x5D, 0x3E, 0xFA, 0x1F, 0xCF,
    0x5E, 0x5B, 0x6C, 0x02, 0xA2, 0x73, 0x1B, 0x52, 0x90, 0xF4, 0xD9, 0x6E, 0x9B, 0x69, 0x87, 0x6E,
    0x29, 0x8D, 0x41, 0x7A, 0x42, 0x9C, 0x23, 0xB1, 0x2A, 0x20, 0x57, 0x4B, 0x8F, 0xCB, 0x41, 0x15,
    0x2F, 0x0C, 0x61, 0x12, 0xAB, 0x92, 0x80, 0x1C, 0x61, 0xB4, 0x7D, 0x47, 0x2A, 0x20, 0xFD, 0x1E,
    0x51, 0xF0, 0x1D, 0x9D, 0x5E, 0x5E, 0x31, 0x85, 0x35, 0xBD, 0xFD, 0x79, 0x6A, 0xAE, 0xD0, 0x44,
    0x27, 0xA0, 0xD4, 0x07, 0xAC, 0x5D, 0xF2, 0x4B, 0x86, 0xF6, 0x77, 0xB3, 0x53, 0x71, 0xAB, 0xC2,
    0xF7, 0xC0, 0xE5, 0x6A, 0x3A, 0x23, 0x07, 0xA5, 0x14, 0x79, 0x3E, 0xF8, 0xFB, 0x16, 0x3E, 0xFB,
    0x45, 0x01, 0x64, 0x4F, 0x5F, 0xD1, 0x5D, 0xD5, 0x02, 0xA2, 0x33, 0x33, 0x59, 0xD2, 0xBA, 0xB0
};

static const struct HksParam g_genParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};
static struct HksParam g_encryptParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};
static struct HksParam g_decryptParams001[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static const struct HksParam g_genParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_encryptParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_decryptParams002[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};

static const struct HksParam g_genParams003[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_encryptParams003[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};
static struct HksParam g_decryptParams003[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE },
    { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 100 },
};

int32_t HksAesCipherTestEncrypt(const struct HksBlob *keyAlias, const struct HksParamSet *encryptParamSet,
    const struct HksBlob *inData, struct HksBlob *cipherText);

int32_t HksAesCipherTestDecrypt(const struct HksBlob *keyAlias, const struct HksParamSet *decryptParamSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText, const struct HksBlob *inData);
}
#endif // HKS_DERIVE_MAIN_KEY_TEST_COMMON_H
