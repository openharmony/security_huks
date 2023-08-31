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

#include "hks_test_common.h"

#include <limits.h>

#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_log.h"
#include "hks_test_mem.h"

#define HKS_TEST_1024 1024
#define HKS_TEST_COMMON_8 8
#define HKS_TEST_COMMON_128 128

int32_t TestConstuctBlob(struct HksBlob **blob, bool blobExist, uint32_t blobSize,
    bool blobDataExist, uint32_t realBlobDataSize);

int32_t TestGenerateKeyParamSetPre(struct GenerateKeyParamSetStructure *paramStruct, struct HksParamSet *paramSet);

int32_t TestGenerateKeyParamSetPost(struct GenerateKeyParamSetStructure *paramStruct, struct HksParamSet *paramSet);

int32_t TestConstructGenerateKeyParamSet(struct GenerateKeyParamSetStructure *paramStruct);

int32_t TestConstructGenerateKeyParamSetOut(struct HksParamSet **outParamSet,
    bool paramSetExist, uint32_t paramSetSize);

int32_t TestConstructRsaCipherParamSet(struct TestRsaCipherParamSet *paramStruct);

int32_t TestAesCipherParamSetPre(struct AesCipherParamSetStructure *paramStruct, struct HksParamSet *paramSet);

int32_t TestAesCipherParamSetPost(struct AesCipherParamSetStructure *paramStruct, struct HksParamSet *paramSet);

int32_t TestConstructAesCipherParamSet(struct AesCipherParamSetStructure *paramStruct);

int32_t TestConstructMacParamSet(struct TestMacParamSetStructure *paramStruct);

int32_t TestConstructAgreeParamSet(struct TestAgreeParamSetStructure *paramStruct);

int32_t TestDeriveParamSetPre(struct TestDeriveParamSetStructure *paramStruct, struct HksParamSet *paramSet);

int32_t TestDeriveParamSetPost(struct TestDeriveParamSetStructure *paramStruct, struct HksParamSet *paramSet);

int32_t TestConstructDeriveParamSet(struct TestDeriveParamSetStructure *paramStruct);

int32_t TestConstructHashParamSet(struct HksParamSet **outParamSet,
    bool paramSetExist, bool setDigest, uint32_t digest);

int32_t GenerateKey(struct HksBlob **keyAlias, const struct HksTestBlobParams *keyAliasParams,
    const struct HksTestGenKeyParamsParamSet *genKeyParamSetParams,
    const struct HksTestGenKeyParamsParamSetOut *genKeyParamSetParamsOut);

int32_t GenerateLocalRandomKey(struct HksBlob **keyAlias, const struct HksTestBlobParams *localKeyParams);

int32_t TestConstructBlobOut(struct HksBlob **blob, bool blobExist, uint32_t blobSize,
    bool blobDataExist, uint32_t realBlobDataSize);

int32_t GenerateLocalX25519Key(struct HksBlob **privateKey, struct HksBlob **publicKey,
    const struct HksTestBlobParams *localPrivateKeyParams, const struct HksTestBlobParams *localPublicKeyParams);

int32_t TestGenDefaultKeyAndGetAlias(struct HksBlob **keyAlias);

