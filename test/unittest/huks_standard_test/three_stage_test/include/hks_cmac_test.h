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

#ifndef HKS_CMAC_TEST_H
#define HKS_CMAC_TEST_H

#include <string>
#include "hks_three_stage_test_common.h"
namespace Unittest::Cmac {
const uint32_t CMAC_COMMON_SIZE = 256;
static const uint32_t IV_SIZE = 8;
static const uint32_t IV_SIZE_INVALID = 9;

static uint8_t IV[IV_SIZE] = { 0 };
static uint8_t IV_INVALID[IV_SIZE_INVALID] = { 0 };

static const std::string g_inData = "Hks_CMAC_Test_000000000000000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";
static struct HksBlob inData = {
    (uint32_t)g_inData.length(),
    const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
};

uint8_t keyData[16] = {
    0xBE, 0x61, 0x20, 0xA1, 0x63, 0x4A, 0x7F, 0xEA, 0xD0, 0x3E, 0x2E, 0x40, 0xD3, 0x4F, 0x56, 0x41
};
static struct HksBlob keyImported = { 16, keyData };

uint8_t mac0[8] = {
    0xF9, 0x31, 0xA7, 0x2D, 0x0F, 0xB6, 0x38, 0xE6
};
static struct HksBlob macData = { 8, mac0 };
}
#endif // HKS_CMAC_TEST_H