/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "hks_log.h"
#include "huks_service_ipc_interface_code.h"

#include <atomic>
#include <map>
#include <mutex>
#include <stdio.h>
#include <sys/stat.h>

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

static ino64_t g_handle = 0;

static std::atomic<size_t> g_global_call_count{0};

struct ThreadStats {
    std::map<int32_t, std::map<int32_t, size_t>> api_error_stats;
    size_t local_call_count = 0;
};

static std::map<int32_t, std::map<int32_t, size_t>> g_merged_stats;
static std::mutex g_stats_mutex;

static thread_local ThreadStats g_thread_stats;

static int32_t FuzzInitialize(FuzzedDataProvider &fdp) {
    return HksInitialize();
}

static int32_t FuzzGenerateKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
    WrapParamSet psOut = {};

    return HksGenerateKey(&keyAlias, psIn.s, psOut.s);
}

static int32_t FuzzImportKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t keySize = fdp.ConsumeIntegralInRange<uint32_t>(16, 2048);
    std::vector<uint8_t> keyData = fdp.ConsumeBytes<uint8_t>(keySize);
    if (keyData.size() == 0) {
        keyData = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob key = { static_cast<uint32_t>(keyData.size()), keyData.data() };

    return HksImportKey(&keyAlias, ps.s, &key);
}

static int32_t FuzzExportPublicKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t pubKeySize = fdp.ConsumeIntegralInRange<uint32_t>(64, 1024);
    std::vector<uint8_t> pubKeyBuf(pubKeySize);
    struct HksBlob pubKey = { static_cast<uint32_t>(pubKeyBuf.size()), pubKeyBuf.data() };

    return HksExportPublicKey(&keyAlias, ps.s, &pubKey);
}

static int32_t FuzzImportWrappedKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    uint32_t wrapAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> wrapAlias = fdp.ConsumeBytes<uint8_t>(wrapAliasSize);
    if (wrapAlias.size() == 0) {
        wrapAlias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob wrappingKeyAlias = { static_cast<uint32_t>(wrapAlias.size()), wrapAlias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&wrappingKeyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t wrappedSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 2048);
    std::vector<uint8_t> wrappedDataVec = fdp.ConsumeBytes<uint8_t>(wrappedSize);
    if (wrappedDataVec.size() == 0) {
        wrappedDataVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob wrappedData = { static_cast<uint32_t>(wrappedDataVec.size()), wrappedDataVec.data() };

    return HksImportWrappedKey(&keyAlias, &wrappingKeyAlias, ps.s, &wrappedData);
}

static int32_t FuzzDeleteKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksDeleteKey(&keyAlias, ps.s);
}

static int32_t FuzzGetKeyParamSet(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet psIn = ConstructParamSetFromFdp(fdp);
    WrapParamSet psOut = {};

    return HksGetKeyParamSet(&keyAlias, psIn.s, psOut.s);
}

static int32_t FuzzKeyExist(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksKeyExist(&keyAlias, ps.s);
}

static int32_t FuzzGenerateRandom(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t randomSize = fdp.ConsumeIntegralInRange<uint32_t>(8, 256);
    std::vector<uint8_t> randomBuf(randomSize);
    struct HksBlob random = { static_cast<uint32_t>(randomBuf.size()), randomBuf.data() };

    return HksGenerateRandom(ps.s, &random);
}

static int32_t FuzzEncrypt(FuzzedDataProvider &fdp) {
    uint32_t keySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    if (keyVec.size() == 0) {
        keyVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob key = { static_cast<uint32_t>(keyVec.size()), keyVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&key, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t ptSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> pt = fdp.ConsumeBytes<uint8_t>(ptSize);
    if (pt.size() == 0) {
        pt = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob plainText = { static_cast<uint32_t>(pt.size()), pt.data() };

    uint32_t ctSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> ctBuf(ctSize);
    struct HksBlob cipherText = { static_cast<uint32_t>(ctBuf.size()), ctBuf.data() };

    return HksEncrypt(&key, ps.s, &plainText, &cipherText);
}

static int32_t FuzzDecrypt(FuzzedDataProvider &fdp) {
    uint32_t keySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    if (keyVec.size() == 0) {
        keyVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob key = { static_cast<uint32_t>(keyVec.size()), keyVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&key, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t ctSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> ct = fdp.ConsumeBytes<uint8_t>(ctSize);
    if (ct.size() == 0) {
        ct = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob cipherText = { static_cast<uint32_t>(ct.size()), ct.data() };

    uint32_t ptSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> ptBuf(ptSize);
    struct HksBlob plainText = { static_cast<uint32_t>(ptBuf.size()), ptBuf.data() };

    return HksDecrypt(&key, ps.s, &cipherText, &plainText);
}

static int32_t FuzzInit(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksBlob handle = { sizeof(int64_t), (uint8_t *)&g_handle };

    std::vector<uint8_t> tokenBuf(256);
    struct HksBlob token = { static_cast<uint32_t>(tokenBuf.size()), tokenBuf.data() };

    return HksInit(&keyAlias, ps.s, &handle, &token);
}

static int32_t FuzzUpdate(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeProbability<double>() < 0.90) {
        (void)FuzzInit(fdp);
    }

    struct HksBlob handle = { sizeof(int64_t), (uint8_t *)&g_handle };
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t inSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    std::vector<uint8_t> inData = fdp.ConsumeBytes<uint8_t>(inSize);
    if (inData.size() == 0) {
        inData = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob inBlob = { static_cast<uint32_t>(inData.size()), inData.data() };

    uint32_t outSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 1024);
    std::vector<uint8_t> outBuf(outSize);
    struct HksBlob outBlob = { static_cast<uint32_t>(outBuf.size()), outBuf.data() };

    return HksUpdate(&handle, ps.s, &inBlob, &outBlob);
}

static int32_t FuzzFinish(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeProbability<double>() < 0.90) {
        (void)FuzzInit(fdp);
    }

    for (uint32_t i = 0; i < static_cast<uint32_t>(fdp.ConsumeIntegralInRange<uint32_t>(1, 20)); i++) {
        (void)FuzzUpdate(fdp);
    }

    struct HksBlob handle = { sizeof(int64_t), (uint8_t *)&g_handle };
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t inSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    std::vector<uint8_t> inData = fdp.ConsumeBytes<uint8_t>(inSize);
    if (inData.size() == 0) {
        inData = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob inBlob = { static_cast<uint32_t>(inData.size()), inData.data() };

    uint32_t outSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 1024);
    std::vector<uint8_t> outBuf(outSize);
    struct HksBlob outBlob = { static_cast<uint32_t>(outBuf.size()), outBuf.data() };

    return HksFinish(&handle, ps.s, &inBlob, &outBlob);
}

static int32_t FuzzAbort(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeProbability<double>() < 0.90) {
        (void)FuzzInit(fdp);
    }

    for (uint32_t i = 0; i < static_cast<uint32_t>(fdp.ConsumeIntegralInRange<uint32_t>(1, 5)); i++) {
        (void)FuzzUpdate(fdp);
    }

    struct HksBlob handle = { sizeof(int64_t), (uint8_t *)&g_handle };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksAbort(&handle, ps.s);
}

static int32_t FuzzSign(FuzzedDataProvider &fdp) {
    uint32_t keySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    if (keyVec.size() == 0) {
        keyVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob key = { static_cast<uint32_t>(keyVec.size()), keyVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&key, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t data_size = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    std::vector<uint8_t> data = fdp.ConsumeBytes<uint8_t>(data_size);
    if (data.size() == 0) {
        data = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob srcData = { static_cast<uint32_t>(data.size()), data.data() };

    uint32_t sigSize = fdp.ConsumeIntegralInRange<uint32_t>(64, 512);
    std::vector<uint8_t> sigBuf(sigSize);
    struct HksBlob signature = { static_cast<uint32_t>(sigBuf.size()), sigBuf.data() };

    return HksSign(&key, ps.s, &srcData, &signature);
}

static int32_t FuzzVerify(FuzzedDataProvider &fdp) {
    uint32_t keySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    if (keyVec.size() == 0) {
        keyVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob key = { static_cast<uint32_t>(keyVec.size()), keyVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&key, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t data_size = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    std::vector<uint8_t> data = fdp.ConsumeBytes<uint8_t>(data_size);
    if (data.size() == 0) {
        data = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob srcData = { static_cast<uint32_t>(data.size()), data.data() };

    uint32_t sigSize = fdp.ConsumeIntegralInRange<uint32_t>(64, 512);
    std::vector<uint8_t> sig = fdp.ConsumeBytes<uint8_t>(sigSize);
    if (sig.size() == 0) {
        sig = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob signature = { static_cast<uint32_t>(sig.size()), sig.data() };

    return HksVerify(&key, ps.s, &srcData, &signature);
}

static int32_t FuzzAgreeKey(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t privSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 512);
    std::vector<uint8_t> priv = fdp.ConsumeBytes<uint8_t>(privSize);
    if (priv.size() == 0) {
        priv = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob privateKey = { static_cast<uint32_t>(priv.size()), priv.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&privateKey, psIn.s, psOut.s);
    }

    uint32_t pubSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 512);
    std::vector<uint8_t> pub = fdp.ConsumeBytes<uint8_t>(pubSize);
    if (pub.size() == 0) {
        pub = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob peerPublicKey = { static_cast<uint32_t>(pub.size()), pub.data() };

    uint32_t agreedSize = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
    std::vector<uint8_t> agreedBuf(agreedSize);
    struct HksBlob agreedKey = { static_cast<uint32_t>(agreedBuf.size()), agreedBuf.data() };

    return HksAgreeKey(ps.s, &privateKey, &peerPublicKey, &agreedKey);
}

static int32_t FuzzDeriveKey(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t mainKeySize = fdp.ConsumeIntegralInRange<uint32_t>(16, 512);
    std::vector<uint8_t> mainKeyData = fdp.ConsumeBytes<uint8_t>(mainKeySize);
    if (mainKeyData.size() == 0) {
        mainKeyData = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob mainKey = { static_cast<uint32_t>(mainKeyData.size()), mainKeyData.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&mainKey, psIn.s, psOut.s);
    }

    uint32_t derivedSize = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
    std::vector<uint8_t> derivedBuf(derivedSize);
    struct HksBlob derivedKey = { static_cast<uint32_t>(derivedBuf.size()), derivedBuf.data() };

    return HksDeriveKey(ps.s, &mainKey, &derivedKey);
}

static int32_t FuzzMac(FuzzedDataProvider &fdp) {
    uint32_t keySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    if (keyVec.size() == 0) {
        keyVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob key = { static_cast<uint32_t>(keyVec.size()), keyVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&key, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t data_size = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    std::vector<uint8_t> data = fdp.ConsumeBytes<uint8_t>(data_size);
    if (data.size() == 0) {
        data = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob srcData = { static_cast<uint32_t>(data.size()), data.data() };

    uint32_t macSize = fdp.ConsumeIntegralInRange<uint32_t>(16, 64);
    std::vector<uint8_t> macBuf(macSize);
    struct HksBlob mac = { static_cast<uint32_t>(macBuf.size()), macBuf.data() };

    return HksMac(&key, ps.s, &srcData, &mac);
}

static int32_t FuzzHash(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t data_size = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    std::vector<uint8_t> data = fdp.ConsumeBytes<uint8_t>(data_size);
    if (data.size() == 0) {
        data = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob srcData = { static_cast<uint32_t>(data.size()), data.data() };

    uint32_t hashSize = fdp.ConsumeIntegralInRange<uint32_t>(16, 64);
    std::vector<uint8_t> hashBuf(hashSize);
    struct HksBlob hash = { static_cast<uint32_t>(hashBuf.size()), hashBuf.data() };

    return HksHash(ps.s, &srcData, &hash);
}

static int32_t FuzzGetKeyInfoList(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t listCount = fdp.ConsumeIntegralInRange<uint32_t>(1, 10);
    std::vector<struct HksKeyInfo> keyInfoList(listCount);

    return HksGetKeyInfoList(ps.s, keyInfoList.data(), &listCount);
}

static int32_t FuzzAttestKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksCertChain certChain{};

    return HksAttestKey(&keyAlias, ps.s, &certChain);
}

static int32_t FuzzAnonAttestKey(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksCertChain certChain = {};
    return HksAnonAttestKey(&keyAlias, ps.s, &certChain);
}

static int32_t FuzzGetCertificateChain(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksCertChain certChain = {};
    return HksGetCertificateChain(&keyAlias, ps.s, &certChain);
}

static int32_t FuzzWrapKey(FuzzedDataProvider &fdp) {
    uint32_t keyAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> keyAliasVec = fdp.ConsumeBytes<uint8_t>(keyAliasSize);
    if (keyAliasVec.size() == 0) {
        keyAliasVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(keyAliasVec.size()), keyAliasVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    uint32_t targetAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> targetAliasVec = fdp.ConsumeBytes<uint8_t>(targetAliasSize);
    if (targetAliasVec.size() == 0) {
        targetAliasVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob targetKeyAlias = { static_cast<uint32_t>(targetAliasVec.size()), targetAliasVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t wrappedSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 1024);
    std::vector<uint8_t> wrappedBuf(wrappedSize);
    struct HksBlob wrappedData = { static_cast<uint32_t>(wrappedBuf.size()), wrappedBuf.data() };

    return HksWrapKey(&keyAlias, &targetKeyAlias, ps.s, &wrappedData);
}

static int32_t FuzzUnwrapKey(FuzzedDataProvider &fdp) {
    uint32_t keyAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> keyAliasVec = fdp.ConsumeBytes<uint8_t>(keyAliasSize);
    if (keyAliasVec.size() == 0) {
        keyAliasVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(keyAliasVec.size()), keyAliasVec.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    uint32_t targetAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> targetAliasVec = fdp.ConsumeBytes<uint8_t>(targetAliasSize);
    if (targetAliasVec.size() == 0) {
        targetAliasVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob targetKeyAlias = { static_cast<uint32_t>(targetAliasVec.size()), targetAliasVec.data() };

    uint32_t wrappedSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 1024);
    std::vector<uint8_t> wrappedVec = fdp.ConsumeBytes<uint8_t>(wrappedSize);
    if (wrappedVec.size() == 0) {
        wrappedVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob wrappedData = { static_cast<uint32_t>(wrappedVec.size()), wrappedVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksUnwrapKey(&keyAlias, &targetKeyAlias, &wrappedData, ps.s);
}

static int32_t FuzzBnExpMod(FuzzedDataProvider &fdp) {
    uint32_t xSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 512);
    std::vector<uint8_t> xBuf(xSize);
    struct HksBlob x = { static_cast<uint32_t>(xBuf.size()), xBuf.data() };

    uint32_t aSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 512);
    std::vector<uint8_t> aVec = fdp.ConsumeBytes<uint8_t>(aSize);
    if (aVec.size() == 0) {
        aVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob a = { static_cast<uint32_t>(aVec.size()), aVec.data() };

    uint32_t eSize = fdp.ConsumeIntegralInRange<uint32_t>(4, 64);
    std::vector<uint8_t> eVec = fdp.ConsumeBytes<uint8_t>(eSize);
    if (eVec.size() == 0) {
        eVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob e = { static_cast<uint32_t>(eVec.size()), eVec.data() };

    uint32_t nSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 512);
    std::vector<uint8_t> nVec = fdp.ConsumeBytes<uint8_t>(nSize);
    if (nVec.size() == 0) {
        nVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob n = { static_cast<uint32_t>(nVec.size()), nVec.data() };

    return HksBnExpMod(&x, &a, &e, &n);
}

static int32_t FuzzValidateCertChain(FuzzedDataProvider &fdp) {
    struct HksCertChain certChain = {};
    WrapParamSet psOut = {};
    return HksValidateCertChain(&certChain, psOut.s);
}

static int32_t FuzzListAliases(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeProbability<double>() < 0.99) {
        uint32_t keyAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
        std::vector<uint8_t> keyAliasVec = fdp.ConsumeBytes<uint8_t>(keyAliasSize);
        if (keyAliasVec.size() == 0) {
            keyAliasVec = std::vector<uint8_t>(1, 0);
        }
        struct HksBlob keyAlias = { static_cast<uint32_t>(keyAliasVec.size()), keyAliasVec.data() };
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    struct HksKeyAliasSet *outData = nullptr;
    return HksListAliases(ps.s, &outData);
}

static int32_t FuzzRenameKeyAlias(FuzzedDataProvider &fdp) {
    uint32_t oldAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> oldAlias = fdp.ConsumeBytes<uint8_t>(oldAliasSize);
    if (oldAlias.size() == 0) {
        oldAlias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob oldKeyAlias = { static_cast<uint32_t>(oldAlias.size()), oldAlias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&oldKeyAlias, psIn.s, psOut.s);
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t newAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> newAlias = fdp.ConsumeBytes<uint8_t>(newAliasSize);
    if (newAlias.size() == 0) {
        newAlias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob newKeyAlias = { static_cast<uint32_t>(newAlias.size()), newAlias.data() };

    return HksRenameKeyAlias(&oldKeyAlias, ps.s, &newKeyAlias);
}

static int32_t FuzzChangeStorageLevel(FuzzedDataProvider &fdp) {
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    if (fdp.ConsumeProbability<double>() < 0.99) {
        WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
        WrapParamSet psOut = {};
        (void)HksGenerateKey(&keyAlias, psIn.s, psOut.s);
    }

    WrapParamSet srcPs = ConstructParamSetFromFdp(fdp);
    WrapParamSet destPs = ConstructParamSetFromFdp(fdp);

    return HksChangeStorageLevel(&keyAlias, srcPs.s, destPs.s);
}

static int32_t FuzzGetErrorMsg(FuzzedDataProvider &fdp) {
    (void)HksGetErrorMsg();
    return HKS_SUCCESS;
}

static int32_t FuzzExtRegister(FuzzedDataProvider &fdp) {
    uint32_t nameSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> nameVec = fdp.ConsumeBytes<uint8_t>(nameSize);
    if (nameVec.size() == 0) {
        nameVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob name = { static_cast<uint32_t>(nameVec.size()), nameVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksRegisterProvider(&name, ps.s);
}

static int32_t FuzzExtUnregister(FuzzedDataProvider &fdp) {
    uint32_t nameSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> nameVec = fdp.ConsumeBytes<uint8_t>(nameSize);
    if (nameVec.size() == 0) {
        nameVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob name = { static_cast<uint32_t>(nameVec.size()), nameVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksUnregisterProvider(&name, ps.s);
}

static int32_t FuzzExtAuthUkeyPin(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    if (resourceIdVec.size() == 0) {
        resourceIdVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob resourceId = { static_cast<uint32_t>(resourceIdVec.size()), resourceIdVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t retryCount = 0;

    return HksAuthUkeyPin(&resourceId, ps.s, &retryCount);
}

static int32_t FuzzExtGetUkeyPinAuthState(FuzzedDataProvider &fdp) {
    uint32_t nameSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> nameVec = fdp.ConsumeBytes<uint8_t>(nameSize);
    if (nameVec.size() == 0) {
        nameVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob name = { static_cast<uint32_t>(nameVec.size()), nameVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    int32_t status = 0;

    return HksGetUkeyPinAuthState(&name, ps.s, &status);
}

static int32_t FuzzExtOpenRemoteHandle(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    if (resourceIdVec.size() == 0) {
        resourceIdVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob resourceId = { static_cast<uint32_t>(resourceIdVec.size()), resourceIdVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksOpenRemoteResource(&resourceId, ps.s);
}

static int32_t FuzzExtGetRemoteHandle(FuzzedDataProvider &fdp) {
    // HksGetRemoteHandle not implemented
    return HKS_ERROR_NOT_SUPPORTED;
}

static int32_t FuzzExtCloseRemoteHandle(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    if (resourceIdVec.size() == 0) {
        resourceIdVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob resourceId = { static_cast<uint32_t>(resourceIdVec.size()), resourceIdVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksCloseRemoteResource(&resourceId, ps.s);
}

static int32_t FuzzExtUkeySign(FuzzedDataProvider &fdp) {
    return FuzzSign(fdp);
}

static int32_t FuzzExtUkeyVerify(FuzzedDataProvider &fdp) {
    return FuzzVerify(fdp);
}

static int32_t FuzzExtClearPinAuthState(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    if (resourceIdVec.size() == 0) {
        resourceIdVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob resourceId = { static_cast<uint32_t>(resourceIdVec.size()), resourceIdVec.data() };

    return HksClearUkeyPinAuthState(&resourceId);
}

static int32_t FuzzExtExportProviderCertificates(FuzzedDataProvider &fdp) {
    uint32_t providerNameSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> providerNameVec = fdp.ConsumeBytes<uint8_t>(providerNameSize);
    if (providerNameVec.size() == 0) {
        providerNameVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob providerName = { static_cast<uint32_t>(providerNameVec.size()), providerNameVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksExtCertInfoSet certSet = {};

    return HksExportProviderCertificates(&providerName, ps.s, &certSet);
}

static int32_t FuzzExtExportCertificate(FuzzedDataProvider &fdp) {
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    if (resourceIdVec.size() == 0) {
        resourceIdVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob resourceId = { static_cast<uint32_t>(resourceIdVec.size()), resourceIdVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksExtCertInfoSet certSet = {};

    return HksExportCertificate(&resourceId, ps.s, &certSet);
}

static int32_t FuzzExtGetRemoteProperty(FuzzedDataProvider &fdp) {
    uint32_t operation = fdp.ConsumeIntegralInRange<uint32_t>(0, 1);
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange<uint32_t>(0, 64);
    std::vector<uint8_t> resourceIdVec = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    if (resourceIdVec.size() == 0) {
        resourceIdVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob resourceId = { static_cast<uint32_t>(resourceIdVec.size()), resourceIdVec.data() };

    uint32_t propertyIdSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> propertyIdVec = fdp.ConsumeBytes<uint8_t>(propertyIdSize);
    if (propertyIdVec.size() == 0) {
        propertyIdVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob propertyId = { static_cast<uint32_t>(propertyIdVec.size()), propertyIdVec.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    struct HksParamSet *propertySetOut = nullptr;

    return HksSetOrGetRemoteProperty(static_cast<enum HksExtPropertyOperation>(operation),
        &resourceId, &propertyId, ps.s, &propertySetOut);
}

static int32_t FuzzExtGetRemotePropertyReply(FuzzedDataProvider &fdp) {
    // Async reply — no sync implementation
    return HKS_ERROR_NOT_SUPPORTED;
}

typedef int32_t (*FuzzHuksFunc)(FuzzedDataProvider &fdp);
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
    { FuzzExtGetRemoteProperty,     HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY },
    { FuzzExtGetRemotePropertyReply, HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY },
};

static void ConcurrentFuzzHuksService(FuzzedDataProvider &fdp)
{
    auto api = fdp.PickValueInArray(g_fuzzApis);
    int32_t ret = api.func(fdp);

    // Update per-thread statistics without any locking (ultra-fast)
    g_thread_stats.api_error_stats[api.code][ret]++;
    g_thread_stats.local_call_count++;

    // Trigger global print every 50000 calls (per-thread threshold)
    if (g_thread_stats.local_call_count >= 50000) {
        // Atomically increment global counter to coordinate printing
        size_t current_global = g_global_call_count.fetch_add(50000, std::memory_order_relaxed);

        // Only the first thread reaching each 50000-boundary triggers printing
        if (current_global % 50000 == 0 && current_global > 0) {
            std::lock_guard<std::mutex> lock(g_stats_mutex);
            g_merged_stats.clear();
            for (const auto &api_entry : g_thread_stats.api_error_stats) {
                int32_t api_code = api_entry.first;
                for (const auto &err_entry : api_entry.second) {
                    int32_t err_code = err_entry.first;
                    size_t count = err_entry.second;
                    g_merged_stats[api_code][err_code] += count;
                }
            }

            printf("\n=== HUKS FUZZ STATISTICS (after %zu calls) ===\n", current_global + 50000);
            for (const auto &api_entry : g_merged_stats) {
                int32_t api_code = api_entry.first;
                const auto &error_map = api_entry.second;
                printf("API Code: %d", api_code);
                for (const auto &err_entry : error_map) {
                    int32_t err_code = err_entry.first;
                    size_t count = err_entry.second;
                    printf(" | Error %d: %zu times", err_code, count);
                }
                printf("\n");
            }
            printf("=============================================\n\n");

            // Reset local call count after printing (stats map remains for accumulation)
            g_thread_stats.local_call_count = 0;
        } else {
            // Other threads just reset local counter without printing
            g_thread_stats.local_call_count = 0;
        }
    }
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
    return OHOS::Security::Hks::HksFuzzInitWithGoldenPath();
}