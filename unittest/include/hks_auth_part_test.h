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

#ifndef HKS_AUTH_PART_TEST_H
#define HKS_AUTH_PART_TEST_H

#include <string>
namespace Unittest::AuthPartTest {
static const uint32_t IV_SIZE = 16;
static const uint32_t AAD_SIZE = 16;
static const uint32_t NONCE_SIZE = 12;
static const uint32_t AEAD_SIZE = 16;

static uint8_t IV[IV_SIZE] = {0};
static uint8_t AAD[AAD_SIZE] = {0};
static uint8_t NONCE[NONCE_SIZE] = {0};
static uint8_t AEAD[AEAD_SIZE] = {0};

int HksAuthSignVerifyTest001(void);
    
int HksAuthSignVerifyTest002(void);
    
int HksAuthSignVerifyTest003(void);

int HksAuthSignVerifyTest004(void);

int HksAuthSignVerifyTest005(void);

int HksAuthSignVerifyTest006(void);

int HksAuthSignVerifyTest007(void);

int HksAuthCipherTest001(void);

int HksAuthCipherTest002(void);

int HksAuthCipherTest003(void);

int HksAuthCipherTest004(void);

int HksAuthCipherTest005(void);

int HksAuthAgreeTest001(void);

int HksAuthAgreeTest002(void);

int HksAuthAgreeTest003(void);

int HksAuthAgreeTest004(void);

int HksAuthAgreeTest005(void);

int HksAuthHmacTest001(void);

int HksAuthHmacTest002(void);

int HksAuthHmacTest003(void);

int HksAuthHmacTest004(void);
}
#endif // HKS_AUTH_PART_TEST_H

