/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "hks_modify_key_test_c.h"

int32_t ConstructDataToBlob(struct HksBlob **inData, struct HksBlob **outData,
    const struct HksTestBlobParams *inTextParams, const struct HksTestBlobParams *outTextParams)
{
    int32_t ret = TestConstuctBlob(inData,
        inTextParams->blobExist,
        inTextParams->blobSize, inTextParams->blobDataExist,
        inTextParams->blobDataSize);
    HKS_TEST_ASSERT(ret == 0);

    ret = TestConstuctBlob(outData,
        outTextParams->blobExist,
        outTextParams->blobSize,
        outTextParams->blobDataExist, outTextParams->blobDataSize);
    HKS_TEST_ASSERT(ret == 0);
    return ret;
}

int32_t Encrypt(struct CipherEncryptStructure *encryptStruct)
{
    int32_t ret;
    struct HksParamSet *encryptParamSet = NULL;

    uint32_t ivSize = encryptStruct->cipherParms->ivSize;
    uint32_t nonceSize = encryptStruct->cipherParms->nonceSize;
    uint32_t aadSize = encryptStruct->cipherParms->aadSize;
    if (ivSize != 0) {
        ret = TestConstuctBlob(encryptStruct->ivData, true, ivSize, true, ivSize);
        HKS_TEST_ASSERT(ret == 0);
    }
    if (nonceSize != 0) {
        ret = TestConstuctBlob(encryptStruct->nonceData, true, nonceSize, true, nonceSize);
        HKS_TEST_ASSERT(ret == 0);
    }
    if (aadSize != 0) {
        ret = TestConstuctBlob(encryptStruct->aadData, true, aadSize, true, aadSize);
        HKS_TEST_ASSERT(ret == 0);
    }
    struct AesCipherParamSetStructure enParamStruct = {
        &encryptParamSet,
        encryptStruct->cipherParms->paramSetExist,
        encryptStruct->cipherParms->setAlg, encryptStruct->cipherParms->alg,
        encryptStruct->cipherParms->setPurpose, encryptStruct->cipherParms->purpose,
        encryptStruct->cipherParms->setPadding, encryptStruct->cipherParms->padding,
        encryptStruct->cipherParms->setBlockMode, encryptStruct->cipherParms->mode,
        encryptStruct->cipherParms->setIv, *(encryptStruct->ivData),
        encryptStruct->cipherParms->setNonce, *(encryptStruct->nonceData),
        encryptStruct->cipherParms->setAad, *(encryptStruct->aadData),
        encryptStruct->cipherParms->setIsKeyAlias, encryptStruct->cipherParms->isKeyAlias
    };
    ret = TestConstructAesCipherParamSet(&enParamStruct);
    HKS_TEST_ASSERT(ret == 0);

    ret = HksEncryptRun(encryptStruct->keyAlias, encryptParamSet, encryptStruct->plainData, encryptStruct->cipherData,
        encryptStruct->performTimes);
    HksFreeParamSet(&encryptParamSet);
    return ret;
}

int32_t DecryptCipher(struct CipherDecryptStructure *decryptStruct)
{
    int32_t ret = TestConstuctBlob(decryptStruct->decryptedData,
        decryptStruct->cipherParms->decryptedTextParams.blobExist,
        decryptStruct->cipherParms->decryptedTextParams.blobSize,
        decryptStruct->cipherParms->decryptedTextParams.blobDataExist,
        decryptStruct->cipherParms->decryptedTextParams.blobDataSize);
    HKS_TEST_ASSERT(ret == 0);

    struct HksParamSet *decryptParamSet = NULL;
    struct AesCipherParamSetStructure deParamStruct = {
        &decryptParamSet, decryptStruct->cipherParms->decryptParamSetParams.paramSetExist,
        decryptStruct->cipherParms->decryptParamSetParams.setAlg,
        decryptStruct->cipherParms->decryptParamSetParams.alg,
        decryptStruct->cipherParms->decryptParamSetParams.setPurpose,
        decryptStruct->cipherParms->decryptParamSetParams.purpose,
        decryptStruct->cipherParms->decryptParamSetParams.setPadding,
        decryptStruct->cipherParms->decryptParamSetParams.padding,
        decryptStruct->cipherParms->decryptParamSetParams.setBlockMode,
        decryptStruct->cipherParms->decryptParamSetParams.mode,
        decryptStruct->cipherParms->decryptParamSetParams.setIv,
        decryptStruct->ivData,
        decryptStruct->cipherParms->decryptParamSetParams.setNonce, decryptStruct->nonceData,
        decryptStruct->cipherParms->decryptParamSetParams.setAad, decryptStruct->aadData,
        decryptStruct->cipherParms->decryptParamSetParams.setIsKeyAlias,
        decryptStruct->cipherParms->decryptParamSetParams.isKeyAlias
    };
    ret = TestConstructAesCipherParamSet(&deParamStruct);
    HKS_TEST_ASSERT(ret == 0);

    ret = HksDecryptRun(decryptStruct->keyAlias, decryptParamSet, decryptStruct->cipherData,
        *(decryptStruct->decryptedData), decryptStruct->performTimes);
    HksFreeParamSet(&decryptParamSet);
    return ret;
}

int32_t GenerateKeyTwo(struct HksBlob *keyAlias, const struct HksTestBlobParams *keyAliasParams,
    const struct HksTestGenKeyParamsParamSet *genKeyParamSetParams,
    const struct HksTestGenKeyParamsParamSetOut *genKeyParamSetParamsOut)
{
    struct HksParamSet *paramSet = NULL;
    struct GenerateKeyParamSetStructure paramStruct = {
        &paramSet,
        genKeyParamSetParams->paramSetExist,
        genKeyParamSetParams->setAlg, genKeyParamSetParams->alg,
        genKeyParamSetParams->setKeySize, genKeyParamSetParams->keySize,
        genKeyParamSetParams->setPurpose, genKeyParamSetParams->purpose,
        genKeyParamSetParams->setDigest, genKeyParamSetParams->digest,
        genKeyParamSetParams->setPadding, genKeyParamSetParams->padding,
        genKeyParamSetParams->setBlockMode, genKeyParamSetParams->mode,
        genKeyParamSetParams->setKeyStorageFlag, genKeyParamSetParams->keyStorageFlag
    };
    int32_t ret = TestConstructGenerateKeyParamSet(&paramStruct);
    HKS_TEST_ASSERT(ret == 0);

    struct HksParamSet *paramSetOut = NULL;
    if (genKeyParamSetParamsOut != NULL) {
        ret = TestConstructGenerateKeyParamSetOut(&paramSet,
            genKeyParamSetParamsOut->paramSetExist, genKeyParamSetParamsOut->paramSetSize);
        HKS_TEST_ASSERT(ret == 0);
    }

    ret = HksGenerateKey(keyAlias, paramSet, paramSetOut);
    HKS_TEST_ASSERT(ret == 0);

    HksFreeParamSet(&paramSet);
    return ret;
}
