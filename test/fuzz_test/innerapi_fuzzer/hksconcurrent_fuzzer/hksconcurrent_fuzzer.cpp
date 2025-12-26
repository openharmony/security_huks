/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "hksconcurrent_fuzzer.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "huks_service_ipc_interface_code.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <stdio.h>
#include <sys/stat.h>
#include <vector>

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

static ino64_t g_handle = 0;

static void FuzzInitialize(FuzzedDataProvider &fdp) {
    (void)HksInitialize();
}

static void FuzzGenerateKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
    WrapParamSet psOut = {};

    (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
}

static void FuzzImportKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t keySize = fdp.ConsumeIntegralInRange(16, 2048);
    std::vector<uint8_t> keyData = fdp.ConsumeBytes<uint8_t>(keySize);
    struct HksBlob key = { keySize, keyData.data() };

    (void)HksImportKey(&keyAlias, ps.s, &key);
}

static void FuzzExportPublicKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t pubKeySize = fdp.ConsumeIntegralInRange(64, 1024);
    std::vector<uint8_t> pubKeyBuf(pubKeySize);
    struct HksBlob pubKey = { pubKeySize, pubKeyBuf.data() };

    (void)HksExportPublicKey(&keyAlias, ps.s, &pubKey);
}

static void FuzzImportWrappedKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    uint32_t wrapAliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> wrapAlias = fdp.ConsumeBytes<uint8_t>(wrapAliasSize);
    struct HksBlob wrappingKeyAlias = { wrapAliasSize, wrapAlias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&wrappingKeyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t wrappedSize = fdp.ConsumeIntegralInRange(32, 2048);
    std::vector<uint8_t> wrappedDataVec = fdp.ConsumeBytes<uint8_t>(wrappedSize);
    struct HksBlob wrappedData = { wrappedSize, wrappedDataVec.data() };

    (void)HksImportWrappedKey(&keyAlias, &wrappingKeyAlias, ps.s, &wrappedData);
}

static void FuzzDeleteKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    (void)HksDeleteKey(&keyAlias, ps.s);
}

static void FuzzGetKeyParamSet(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet psIn = ConstructParamSetFromFdp(fdp);
    WrapParamSet psOut = {};

    (void)HksGetKeyParamSet(&keyAlias, psIn.s, psOut.s);
}

static void FuzzKeyExist(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    (void)HksKeyExist(&keyAlias, ps.s);
}

static void FuzzGenerateRandom(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t randomSize = fdp.ConsumeIntegralInRange(8, 256);
    std::vector<uint8_t> randomBuf(randomSize);
    struct HksBlob random = { randomSize, randomBuf.data() };

    (void)HksGenerateRandom(ps.s, &random);
}

static void FuzzEncrypt(FuzzedDataProvider &fdp) {
    uint32_t keySize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    struct HksBlob key = { keySize, keyVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&key, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t ptSize = fdp.ConsumeIntegralInRange(1, 512);
    std::vector<uint8_t> pt = fdp.ConsumeBytes<uint8_t>(ptSize);
    struct HksBlob plainText = { ptSize, pt.data() };

    uint32_t ctSize = fdp.ConsumeIntegralInRange(32, 1024);
    std::vector<uint8_t> ctBuf(ctSize);
    struct HksBlob cipherText = { ctSize, ctBuf.data() };

    (void)HksEncrypt(&key, ps.s, &plainText, &cipherText);
}

static void FuzzDecrypt(FuzzedDataProvider &fdp) {
    uint32_t keySize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    struct HksBlob key = { keySize, keyVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&key, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t ctSize = fdp.ConsumeIntegralInRange(32, 1024);
    std::vector<uint8_t> ct = fdp.ConsumeBytes<uint8_t>(ctSize);
    struct HksBlob cipherText = { ctSize, ct.data() };

    uint32_t ptSize = fdp.ConsumeIntegralInRange(1, 512);
    std::vector<uint8_t> ptBuf(ptSize);
    struct HksBlob plainText = { ptSize, ptBuf.data() };

    (void)HksDecrypt(&key, ps.s, &cipherText, &plainText);
}

static void FuzzInit(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksBlob handle = { sizeof(int64_t), (uint8_t *)&g_handle };

    std::vector<uint8_t> tokenBuf(256);
    struct HksBlob token = { 256, tokenBuf.data() };

    (void)HksInit(&keyAlias, ps.s, &handle, &token);
}

static void FuzzUpdate(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeProbability<double>() < 0.90) {
        FuzzInit(fdp);
    }

    struct HksBlob handle = { sizeof(int64_t), (uint8_t *)&g_handle };
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t inSize = fdp.ConsumeIntegralInRange(1, 512);
    std::vector<uint8_t> inData = fdp.ConsumeBytes<uint8_t>(inSize);
    struct HksBlob inBlob = { inSize, inData.data() };

    uint32_t outSize = fdp.ConsumeIntegralInRange(32, 1024);
    std::vector<uint8_t> outBuf(outSize);
    struct HksBlob outBlob = { outSize, outBuf.data() };

    (void)HksUpdate(&handle, ps.s, &inBlob, &outBlob);
}

static void FuzzFinish(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeProbability<double>() < 0.90) {
        FuzzInit(fdp);
    }

    for (uint32_t i = 0; i < static_cast<uint32_t>(fdp.ConsumeIntegralInRange(0, 20)); i++) {
        FuzzUpdate(fdp);
    }

    struct HksBlob handle = { sizeof(int64_t), (uint8_t *)&g_handle };
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t inSize = fdp.ConsumeIntegralInRange(1, 512);
    std::vector<uint8_t> inData = fdp.ConsumeBytes<uint8_t>(inSize);
    struct HksBlob inBlob = { inSize, inData.data() };

    uint32_t outSize = fdp.ConsumeIntegralInRange(32, 1024);
    std::vector<uint8_t> outBuf(outSize);
    struct HksBlob outBlob = { outSize, outBuf.data() };

    (void)HksFinish(&handle, ps.s, &inBlob, &outBlob);
}

static void FuzzAbort(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeProbability<double>() < 0.90) {
        FuzzInit(fdp);
    }

    for (uint32_t i = 0; i < static_cast<uint32_t>(fdp.ConsumeIntegralInRange(0, 5)); i++) {
        FuzzUpdate(fdp);
    }

    struct HksBlob handle = { sizeof(int64_t), (uint8_t *)&g_handle };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    (void)HksAbort(&handle, ps.s);
}

static void FuzzSign(FuzzedDataProvider &fdp) {
    uint32_t keySize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    struct HksBlob key = { keySize, keyVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&key, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t data_size = fdp.ConsumeIntegralInRange(1, 512);
    std::vector<uint8_t> data = fdp.ConsumeBytes<uint8_t>(data_size);
    struct HksBlob srcData = { data_size, data.data() };

    uint32_t sigSize = fdp.ConsumeIntegralInRange(64, 512);
    std::vector<uint8_t> sigBuf(sigSize);
    struct HksBlob signature = { sigSize, sigBuf.data() };

    (void)HksSign(&key, ps.s, &srcData, &signature);
}

static void FuzzVerify(FuzzedDataProvider &fdp) {
    uint32_t keySize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    struct HksBlob key = { keySize, keyVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&key, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t data_size = fdp.ConsumeIntegralInRange(1, 512);
    std::vector<uint8_t> data = fdp.ConsumeBytes<uint8_t>(data_size);
    struct HksBlob srcData = { data_size, data.data() };

    uint32_t sigSize = fdp.ConsumeIntegralInRange(64, 512);
    std::vector<uint8_t> sig = fdp.ConsumeBytes<uint8_t>(sigSize);
    struct HksBlob signature = { sigSize, sig.data() };

    (void)HksVerify(&key, ps.s, &srcData, &signature);
}

static void FuzzAgreeKey(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t privSize = fdp.ConsumeIntegralInRange(32, 512);
    std::vector<uint8_t> priv = fdp.ConsumeBytes<uint8_t>(privSize);
    struct HksBlob privateKey = { privSize, priv.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&privateKey, psIn.s, psOut.s);
    }

    uint32_t pubSize = fdp.ConsumeIntegralInRange(32, 512);
    std::vector<uint8_t> pub = fdp.ConsumeBytes<uint8_t>(pubSize);
    struct HksBlob peerPublicKey = { pubSize, pub.data() };

    uint32_t agreedSize = fdp.ConsumeIntegralInRange(16, 256);
    std::vector<uint8_t> agreedBuf(agreedSize);
    struct HksBlob agreedKey = { agreedSize, agreedBuf.data() };

    (void)HksAgreeKey(ps.s, &privateKey, &peerPublicKey, &agreedKey);
}

static void FuzzDeriveKey(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t mainKeySize = fdp.ConsumeIntegralInRange(16, 512);
    std::vector<uint8_t> mainKeyData = fdp.ConsumeBytes<uint8_t>(mainKeySize);
    struct HksBlob mainKey = { mainKeySize, mainKeyData.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&mainKey, psIn.s, psOut.s);
    }

    uint32_t derivedSize = fdp.ConsumeIntegralInRange(16, 256);
    std::vector<uint8_t> derivedBuf(derivedSize);
    struct HksBlob derivedKey = { derivedSize, derivedBuf.data() };

    (void)HksDeriveKey(ps.s, &mainKey, &derivedKey);
}

static void FuzzMac(FuzzedDataProvider &fdp) {
    uint32_t keySize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    struct HksBlob key = { keySize, keyVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&key, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t data_size = fdp.ConsumeIntegralInRange(1, 512);
    std::vector<uint8_t> data = fdp.ConsumeBytes<uint8_t>(data_size);
    struct HksBlob srcData = { data_size, data.data() };

    uint32_t macSize = fdp.ConsumeIntegralInRange(16, 64);
    std::vector<uint8_t> macBuf(macSize);
    struct HksBlob mac = { macSize, macBuf.data() };

    (void)HksMac(&key, ps.s, &srcData, &mac);
}

static void FuzzHash(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t data_size = fdp.ConsumeIntegralInRange(1, 512);
    std::vector<uint8_t> data = fdp.ConsumeBytes<uint8_t>(data_size);
    struct HksBlob srcData = { data_size, data.data() };

    uint32_t hashSize = fdp.ConsumeIntegralInRange(16, 64);
    std::vector<uint8_t> hashBuf(hashSize);
    struct HksBlob hash = { hashSize, hashBuf.data() };

    (void)HksHash(ps.s, &srcData, &hash);
}

static void FuzzGetKeyInfoList(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t listCount = fdp.ConsumeIntegralInRange(1, 10);
    std::vector<struct HksKeyInfo> keyInfoList(listCount);

    (void)HksGetKeyInfoList(ps.s, keyInfoList.data(), &listCount);
}

static void FuzzAttestKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksCertChain certChain{};

    (void)HksAttestKey(&keyAlias, ps.s, &certChain);
}

static void FuzzAnonAttestKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksCertChain certChain = {};
    (void)HksAnonAttestKey(&keyAlias, ps.s, &certChain);
}

static void FuzzGetCertificateChain(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksCertChain certChain = {};
    (void)HksGetCertificateChain(&keyAlias, ps.s, &certChain);
}

static void FuzzWrapKey(FuzzedDataProvider &fdp) {
    uint32_t keyAliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> keyAliasVec = fdp.ConsumeBytes<uint8_t>(keyAliasSize);
    struct HksBlob keyAlias = { keyAliasSize, keyAliasVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    uint32_t targetAliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> targetAliasVec = fdp.ConsumeBytes<uint8_t>(targetAliasSize);
    struct HksBlob targetKeyAlias = { targetAliasSize, targetAliasVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t wrappedSize = fdp.ConsumeIntegralInRange(32, 1024);
    std::vector<uint8_t> wrappedBuf(wrappedSize);
    struct HksBlob wrappedData = { wrappedSize, wrappedBuf.data() };

    (void)HksWrapKey(&keyAlias, &targetKeyAlias, ps.s, &wrappedData);
}

static void FuzzUnwrapKey(FuzzedDataProvider &fdp) {
    uint32_t keyAliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> keyAliasVec = fdp.ConsumeBytes<uint8_t>(keyAliasSize);
    struct HksBlob keyAlias = { keyAliasSize, keyAliasVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    uint32_t targetAliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> targetAliasVec = fdp.ConsumeBytes<uint8_t>(targetAliasSize);
    struct HksBlob targetKeyAlias = { targetAliasSize, targetAliasVec.data() };

    uint32_t wrappedSize = fdp.ConsumeIntegralInRange(32, 1024);
    std::vector<uint8_t> wrappedVec = fdp.ConsumeBytes<uint8_t>(wrappedSize);
    struct HksBlob wrappedData = { wrappedSize, wrappedVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    (void)HksUnwrapKey(&keyAlias, &targetKeyAlias, &wrappedData, ps.s);
}

static void FuzzBnExpMod(FuzzedDataProvider &fdp) {
    uint32_t xSize = fdp.ConsumeIntegralInRange(32, 512);
    std::vector<uint8_t> xBuf(xSize);
    struct HksBlob x = { xSize, xBuf.data() };

    uint32_t aSize = fdp.ConsumeIntegralInRange(32, 512);
    std::vector<uint8_t> aVec = fdp.ConsumeBytes<uint8_t>(aSize);
    struct HksBlob a = { aSize, aVec.data() };

    uint32_t eSize = fdp.ConsumeIntegralInRange(4, 64);
    std::vector<uint8_t> eVec = fdp.ConsumeBytes<uint8_t>(eSize);
    struct HksBlob e = { eSize, eVec.data() };

    uint32_t nSize = fdp.ConsumeIntegralInRange(32, 512);
    std::vector<uint8_t> nVec = fdp.ConsumeBytes<uint8_t>(nSize);
    struct HksBlob n = { nSize, nVec.data() };

    (void)HksBnExpMod(&x, &a, &e, &n);
}

static void FuzzValidateCertChain(FuzzedDataProvider &fdp) {
    struct HksCertChain certChain = {};
    WrapParamSet psOut = {};
    (void)HksValidateCertChain(&certChain, psOut.s);
}

static void FuzzListAliases(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeProbability<double>() < 0.99) {
        uint32_t keyAliasSize = fdp.ConsumeIntegralInRange(0, 64);
        std::vector<uint8_t> keyAliasVec = fdp.ConsumeBytes<uint8_t>(keyAliasSize);
        struct HksBlob keyAlias = { keyAliasSize, keyAliasVec.data() };
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    struct HksKeyAliasSet *outData = nullptr;
    (void)HksListAliases(ps.s, &outData);
}

static void FuzzRenameKeyAlias(FuzzedDataProvider &fdp) {
    uint32_t oldAliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> oldAlias = fdp.ConsumeBytes<uint8_t>(oldAliasSize);
    struct HksBlob oldKeyAlias = { oldAliasSize, oldAlias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&oldKeyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t newAliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> newAlias = fdp.ConsumeBytes<uint8_t>(newAliasSize);
    struct HksBlob newKeyAlias = { newAliasSize, newAlias.data() };

    (void)HksRenameKeyAlias(&oldKeyAlias, ps.s, &newKeyAlias);
}

static void FuzzChangeStorageLevel(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { aliasSize, alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet srcPs = ConstructParamSetFromFdp(fdp);
    WrapParamSet destPs = ConstructParamSetFromFdp(fdp);

    (void)HksChangeStorageLevel(&keyAlias, srcPs.s, destPs.s);
}

static void FuzzGetErrorMsg(FuzzedDataProvider &fdp) {
    (void)HksGetErrorMsg();
}

static void FuzzExtRegister(FuzzedDataProvider &fdp) {
    uint32_t nameSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> nameVec = fdp.ConsumeBytes<uint8_t>(nameSize);
    struct HksBlob name = { nameSize, nameVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    (void)HksRegisterProvider(&name, ps.s);
}

static void FuzzExtUnregister(FuzzedDataProvider &fdp) {
    uint32_t nameSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> nameVec = fdp.ConsumeBytes<uint8_t>(nameSize);
    struct HksBlob name = { nameSize, nameVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    (void)HksUnregisterProvider(&name, ps.s);
}

static void FuzzExtAuthUkeyPin(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    struct HksBlob resourceId = { resourceIdSize, resourceIdVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t retryCount = 0;

    (void)HksAuthUkeyPin(&resourceId, ps.s, &retryCount);
}

static void FuzzExtGetUkeyPinAuthState(FuzzedDataProvider &fdp) {
    uint32_t nameSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> nameVec = fdp.ConsumeBytes<uint8_t>(nameSize);
    struct HksBlob name = { nameSize, nameVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    int32_t status = 0;

    (void)HksGetUkeyPinAuthState(&name, ps.s, &status);
}

static void FuzzExtOpenRemoteHandle(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    struct HksBlob resourceId = { resourceIdSize, resourceIdVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    (void)HksOpenRemoteHandle(&resourceId, ps.s);
}

static void FuzzExtGetRemoteHandle(FuzzedDataProvider &fdp) {
    // HksGetRemoteHandle not implemented
    return;
}

static void FuzzExtCloseRemoteHandle(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    struct HksBlob resourceId = { resourceIdSize, resourceIdVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    (void)HksCloseRemoteHandle(&resourceId, ps.s);
}

static void FuzzExtUkeySign(FuzzedDataProvider &fdp) {
    FuzzSign(fdp);
}

static void FuzzExtUkeyVerify(FuzzedDataProvider &fdp) {
    FuzzVerify(fdp);
}

static void FuzzExtClearPinAuthState(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    struct HksBlob resourceId = { resourceIdSize, resourceIdVec.data() };

    (void)HksClearUkeyPinAuthState(&resourceId);
}

static void FuzzExtExportProviderCertificates(FuzzedDataProvider &fdp) {
    uint32_t providerNameSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> providerNameVec = fdp.ConsumeBytes<uint8_t>(providerNameSize);
    struct HksBlob providerName = { providerNameSize, providerNameVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksExtCertInfoSet certSet = {};

    (void)HksExportProviderCertificates(&providerName, ps.s, &certSet);
}

static void FuzzExtExportCertificate(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    struct HksBlob resourceId = { resourceIdSize, resourceIdVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksExtCertInfoSet certSet = {};

    (void)HksExportCertificate(&resourceId, ps.s, &certSet);
}

static void FuzzExtGetRemoteProperty(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    struct HksBlob resourceId = { resourceIdSize, resourceIdVec.data() };

    uint32_t propertyIdSize = fdp.ConsumeIntegralInRange(0, 64);
    std::vector<uint8_t> propertyIdVec = fdp.ConsumeBytes<uint8_t>(propertyIdSize);
    struct HksBlob propertyId = { propertyIdSize, propertyIdVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksParamSet *propertySetOut = nullptr;

    (void)HksGetRemoteProperty(&resourceId, &propertyId, ps.s, &propertySetOut);
}

static void FuzzExtGetRemotePropertyReply(FuzzedDataProvider &fdp) {
    // Async reply
    return;
}

typedef void (*FuzzHuksFunc)(FuzzedDataProvider &fdp);
typedef struct FuzzHuksApi {
    FuzzHuksFunc func;
    int32_t code;
} FuzzHuksApi;

static const FuzzHuksApi g_fuzzApis[] = {
    { FuzzGenerateKey,              HKS_MSG_GEN_KEY },
    { FuzzImportKey,                HKS_MSG_IMPORT_KEY },
    { FuzzExportPublicKey,          HKS_MSG_EXPORT_PUBLIC_KEY },
    { FuzzImportWrappedKey,         HKS_MSG_IMPORT_WRAPPED_KEY },
    { FuzzDeleteKey,                HKS_MSG_DELETE_KEY },
    { FuzzGetKeyParamSet,           HKS_MSG_GET_KEY_PARAMSET },
    { FuzzKeyExist,                 HKS_MSG_KEY_EXIST },
    { FuzzGenerateRandom,           HKS_MSG_GENERATE_RANDOM },
    { FuzzSign,                     HKS_MSG_SIGN },
    { FuzzVerify,                   HKS_MSG_VERIFY },
    { FuzzEncrypt,                  HKS_MSG_ENCRYPT },
    { FuzzDecrypt,                  HKS_MSG_DECRYPT },
    { FuzzAgreeKey,                 HKS_MSG_AGREE_KEY },
    { FuzzDeriveKey,                HKS_MSG_DERIVE_KEY },
    { FuzzMac,                      HKS_MSG_MAC },
    { FuzzHash,                     HKS_MSG_MAC },
    { FuzzGetKeyInfoList,           HKS_MSG_GET_KEY_INFO_LIST },
    { FuzzAttestKey,                HKS_MSG_ATTEST_KEY },
    { FuzzAnonAttestKey,            HKS_MSG_ATTEST_KEY_ASYNC_REPLY },
    { FuzzGetCertificateChain,      HKS_MSG_GET_CERTIFICATE_CHAIN },
    { FuzzInit,                     HKS_MSG_INIT },
    { FuzzUpdate,                   HKS_MSG_UPDATE },
    { FuzzFinish,                   HKS_MSG_FINISH },
    { FuzzAbort,                    HKS_MSG_ABORT },
    { FuzzListAliases,              HKS_MSG_LIST_ALIASES },
    { FuzzRenameKeyAlias,           HKS_MSG_RENAME_KEY_ALIAS },
    { FuzzChangeStorageLevel,       HKS_MSG_CHANGE_STORAGE_LEVEL },
    { FuzzWrapKey,                  HKS_MSG_WRAP_KEY },
    { FuzzUnwrapKey,                HKS_MSG_UNWRAP_KEY },
    { FuzzInitialize,               -1 },
    { FuzzGetErrorMsg,              -2 },
    { FuzzBnExpMod,                 -3 },
    { FuzzValidateCertChain,        -4 },

    // EXT APIs
    { FuzzExtRegister,              HKS_MSG_EXT_REGISTER },
    { FuzzExtUnregister,            HKS_MSG_EXT_UNREGISTER },
    { FuzzExtAuthUkeyPin,           HKS_MSG_EXT_AUTH_UKEY_PIN },
    { FuzzExtGetUkeyPinAuthState,   HKS_MSG_EXT_GET_UKEY_PIN_AUTH_STATE },
    { FuzzExtOpenRemoteHandle,      HKS_MSG_EXT_OPEN_REMOTE_HANDLE },
    { FuzzExtGetRemoteHandle,       HKS_MSG_EXT_GET_REMOTE_HANDLE },
    { FuzzExtCloseRemoteHandle,     HKS_MSG_EXT_CLOSE_REMOTE_HANDLE },
    { FuzzExtUkeySign,              HKS_MSG_EXT_UKEY_SIGN },
    { FuzzExtUkeyVerify,            HKS_MSG_EXT_UKEY_VERIFY },
    { FuzzExtClearPinAuthState,     HKS_MSG_EXT_CLEAR_PIN_AUTH_STATE },
    { FuzzExtExportProviderCertificates, HKS_MSG_EXT_EXPORT_PROVIDER_CERTIFICATES },
    { FuzzExtExportCertificate,     HKS_MSG_EXT_EXPORT_CERTIFICATE },
    { FuzzExtGetRemoteProperty,     HKS_MSG_EXT_GET_REMOTE_PROPERTY },
    { FuzzExtGetRemotePropertyReply, HKS_MSG_EXT_GET_REMOTE_PROPERTY_REPLY },
};

static void ConcurrentFuzzHuksService(FuzzedDataProvider &fdp)
{
    auto api = fdp.PickValueInArray(g_fuzzApis);
    printf("ConcurrentFuzz code: %u\n", api.code);
    api.func(fdp);
}

}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Security::Hks::ConcurrentFuzzHuksService(fdp);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // init
    return 0;
}
