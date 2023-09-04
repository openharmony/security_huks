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

#include "hks_test_curve25519.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_log.h"
#include "hks_type.h"

#define TEST_ALIAS_ED25519 "test_ed25519"
#define TEST_PLAIN_TEST_ED25519 "This is a plain text! Hello world and thanks for watching ED25519~"
#define TEST_CURVE_256 256
#define TEST_CURVE_512 512

static uint8_t g_buffer[TEST_CURVE_256];
static uint32_t g_bufferSize = TEST_CURVE_256;
static uint8_t g_pubKey[TEST_CURVE_512] = {0};
static uint32_t g_pubKeyLen = TEST_CURVE_512;

int32_t TestGenerateEd25519Key(struct HksBlob alias);

int32_t TestSignEd25519(struct HksBlob alias);

int32_t TestVerifyEd25519(struct HksBlob alias);

int32_t TestImportEd25519(struct HksBlob alias, struct HksBlob *pubKeyInfo);

int32_t TestExportImportEd25519SignVerify(struct HksBlob alias);

int32_t TestCurve25519All();

int32_t BuildTeeSignParamSet(struct HksParamSet **paramSet);

int32_t BuildLocalVerifyParamSet(struct HksParamSet **paramSet);

int32_t TestEd25519SignTeeVerifyLocal();

int32_t TestSignEd25519Wrong(struct HksBlob alias);

int32_t TestCurve25519SignWrong();

int32_t TestVerifyEd25519Wrong(struct HksBlob alias);

int32_t TestCurve25519verifyWrong();