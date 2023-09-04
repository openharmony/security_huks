/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HKS_TEST_AES_C_H
#define HKS_TEST_AES_C_H

#include "hks_test_aes.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_common.h"
#include "hks_test_log.h"

#define TEST_PLAIN_TEST "This is a plain text! Hello world and thanks for watching AES^^"
#define TEST_AES_12 12
#define TEST_AES_16 16
#define TEST_AES_128 128
#define TEST_AES_256 256

static uint8_t g_buffer[TEST_AES_256];
static uint32_t g_bufferSize = TEST_AES_256;

static uint8_t g_nonce[TEST_AES_12] = "hahahahahah";
static uint8_t g_aad[TEST_AES_16] = "bababababababab";
static uint8_t g_iv[TEST_AES_16] = "aabaabaabaabaab";

#ifdef __cplusplus
extern "C" {
#endif
int32_t ConstructParamSetEncryptDecryptAesPre(uint32_t mode, uint32_t padding, bool isEncrypt,
    struct HksParamSet **paramSet);

int32_t ConstructParamSetEncryptDecryptAesPost(uint32_t mode, struct HksParamSet **paramSet);

int32_t ConstructParamSetEncryptDecryptAes(uint32_t mode, uint32_t padding, bool isEncrypt,
    struct HksParamSet **paramSet);

void GenerateBaseKey(const struct HksBlob *alias);

void PlainPubKey(const struct HksBlob *baseKey, const struct HksBlob *peerPubKey,
    struct HksParamSet *paramSet);

void SetKeyAliasTrue(const struct HksBlob *baseKey, const struct HksBlob *peerPubKey,
    struct HksParamSet *paramSet);

void SetKeyAliasWrong(const struct HksBlob *baseKey, const struct HksBlob *peerPubKey,
    struct HksParamSet *paramSet);

void GenerateAesAgreeKey(const struct HksBlob *alias, const struct HksBlob *baseKey,
    const struct HksBlob *peerPubKey, bool isPlainPubKey, bool isSetKeyAliasTrue);

void ExportPubKey(const struct HksBlob *alias, struct HksBlob *pubKey);

void ImportPubKey(const struct HksBlob *alias, const struct HksBlob *pubKey);

int32_t TestAes256ByAgree();

int32_t TestAes256ByAgree1();

int32_t TestAes256ByAgree2();
#ifdef __cplusplus
}
#endif
#endif