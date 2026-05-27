/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "hks_fuzz_util.h"

#include <vector>

#include "base/security/huks/frameworks/huks_standard/main/common/include/hks_valid_tags.h"
#include "hks_api.h"
#include "hks_error_code.h"
#include "hks_param.h"
#include "hks_tag.h"
#include "hks_type.h"
#include "hks_type_enum.h"

namespace OHOS {
namespace Security {
namespace Hks {
std::vector<HksParam> ConstructHksParams(uint8_t *&data, size_t &size)
{
    std::vector<HksParam> params {};
    while (size >= sizeof(HksParam)) {
        HksParam *p = ReadData<HksParam *>(data, size, sizeof(HksParam));
        if (GetTagType(static_cast<HksTag>(p->tag)) != HKS_TAG_TYPE_BYTES) {
            params.emplace_back(*p);
            continue;
        }
        if (size < p->blob.size) {
            continue;
        }
        p->blob.data = ReadData<uint8_t *>(data, size, p->blob.size);
        params.emplace_back(*p);
    }
    return params;
}

WrapParamSet ConstructHksParamSetFromFuzz(uint8_t *&data, size_t &size)
{
    auto params = ConstructHksParams(data, size);
    WrapParamSet ps {};
    int32_t ret = HksInitParamSet(&ps.s);
    if (ret != HKS_SUCCESS) {
        return {};
    }
    if (!params.empty()) {
        ret = HksAddParams(ps.s, params.data(), params.size());
        if (ret != HKS_SUCCESS) {
            return {};
        }
    }
    ret = HksBuildParamSet(&ps.s);
    if (ret != HKS_SUCCESS) {
        return {};
    }
    return ps;
}

static void AddParam(uint32_t tag, FuzzedDataProvider &fdp, WrapParamSet &ps,
    std::vector<std::vector<uint8_t>> &blobStorage)
{
    HksParam param = { .tag = tag };
    switch (GetTagType((enum HksTag)tag)) {
        case HKS_TAG_TYPE_INT: {
            param.int32Param = fdp.ConsumeIntegralInRange<int32_t>(1, 1024);
            (void)HksAddParams(ps.s, &param, 1);
            break;
        }
        case HKS_TAG_TYPE_UINT: {
            param.uint32Param = fdp.ConsumeIntegralInRange<uint32_t>(1, 1024);
            (void)HksAddParams(ps.s, &param, 1);
            break;
        }
        case HKS_TAG_TYPE_ULONG: {
            param.uint64Param = fdp.ConsumeIntegralInRange<uint64_t>(1, 1024);
            (void)HksAddParams(ps.s, &param, 1);
            break;
        }
        case HKS_TAG_TYPE_BOOL: {
            param.boolParam = fdp.ConsumeBool();
            (void)HksAddParams(ps.s, &param, 1);
            break;
        }
        case HKS_TAG_TYPE_BYTES: {
            uint32_t size = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
            std::vector<uint8_t> data = fdp.ConsumeBytes<uint8_t>(size);
            if (data.size() == 0) {
                data = std::vector<uint8_t>(size, 0);
            }
            blobStorage.push_back(std::move(data));
            param.blob = { blobStorage.back().size(), blobStorage.back().data() };

            (void)HksAddParams(ps.s, &param, 1);
            break;
        }
        default:
            break;
    }
}

static uint32_t PickRandomHksAlg(FuzzedDataProvider &fdp) {
    static const uint32_t kValidAlgs[] = {
        HKS_ALG_RSA,
        HKS_ALG_ECC,
        HKS_ALG_DSA,
        HKS_ALG_AES,
        HKS_ALG_HMAC,
        HKS_ALG_HKDF,
        HKS_ALG_PBKDF2,
        HKS_ALG_GMKDF,
        HKS_ALG_ECDH,
        HKS_ALG_X25519,
        HKS_ALG_ED25519,
        HKS_ALG_DH,
        HKS_ALG_SM2,
        HKS_ALG_SM3,
        HKS_ALG_SM4,
        HKS_ALG_DES,
        HKS_ALG_3DES,
        HKS_ALG_CMAC,
    };
    return fdp.PickValueInArray(kValidAlgs);
}

static uint32_t PickRandomHksKeySize(FuzzedDataProvider &fdp) {
    static const uint32_t kValidSizes[] = {
        HKS_RSA_KEY_SIZE_512,
        HKS_RSA_KEY_SIZE_768,
        HKS_RSA_KEY_SIZE_1024,
        HKS_RSA_KEY_SIZE_2048,
        HKS_RSA_KEY_SIZE_3072,
        HKS_RSA_KEY_SIZE_4096,

        HKS_ECC_KEY_SIZE_224,
        HKS_ECC_KEY_SIZE_256,
        HKS_ECC_KEY_SIZE_384,
        HKS_ECC_KEY_SIZE_521,

        HKS_AES_KEY_SIZE_128,
        HKS_AES_KEY_SIZE_192,
        HKS_AES_KEY_SIZE_256,
        HKS_AES_KEY_SIZE_512,

        HKS_CURVE25519_KEY_SIZE_256,

        HKS_DH_KEY_SIZE_2048,
        HKS_DH_KEY_SIZE_3072,
        HKS_DH_KEY_SIZE_4096,

        HKS_SM2_KEY_SIZE_256,
        HKS_SM4_KEY_SIZE_128,

        HKS_DES_KEY_SIZE_64,
        HKS_3DES_KEY_SIZE_128,
        HKS_3DES_KEY_SIZE_192,
    };
    return fdp.PickValueInArray(kValidSizes);
}

static uint32_t PickRandomHksKeyPurpose(FuzzedDataProvider &fdp) {
    static const uint32_t kValidPurposes[] = {
        HKS_KEY_PURPOSE_ENCRYPT,
        HKS_KEY_PURPOSE_DECRYPT,
        HKS_KEY_PURPOSE_SIGN,
        HKS_KEY_PURPOSE_VERIFY,
        HKS_KEY_PURPOSE_DERIVE,
        HKS_KEY_PURPOSE_WRAP,
        HKS_KEY_PURPOSE_UNWRAP,
        HKS_KEY_PURPOSE_MAC,
        HKS_KEY_PURPOSE_AGREE,
    };
    return fdp.PickValueInArray(kValidPurposes);
}

static uint32_t PickRandomHksKeyDigest(FuzzedDataProvider &fdp) {
    static const uint32_t kValidDigests[] = {
        HKS_DIGEST_NONE,
        HKS_DIGEST_MD5,
        HKS_DIGEST_SM3,
        HKS_DIGEST_SHA1,
        HKS_DIGEST_SHA224,
        HKS_DIGEST_SHA256,
        HKS_DIGEST_SHA384,
        HKS_DIGEST_SHA512,
    };
    return fdp.PickValueInArray(kValidDigests);
}

static uint32_t PickRandomHksCipherMode(FuzzedDataProvider &fdp) {
    static const uint32_t kValidModes[] = {
        HKS_MODE_ECB,
        HKS_MODE_CBC,
        HKS_MODE_CTR,
        HKS_MODE_OFB,
        HKS_MODE_CFB,
        HKS_MODE_CCM,
        HKS_MODE_GCM,
    };
    return fdp.PickValueInArray(kValidModes);
}

static uint32_t PickRandomHksKeyPadding(FuzzedDataProvider &fdp) {
    static const uint32_t kValidPaddings[] = {
        HKS_PADDING_NONE,
        HKS_PADDING_OAEP,
        HKS_PADDING_PSS,
        HKS_PADDING_PKCS1_V1_5,
        HKS_PADDING_PKCS5,
        HKS_PADDING_PKCS7,
        HKS_PADDING_ISO_IEC_9796_2,
        HKS_PADDING_ISO_IEC_9797_1,
    };
    return fdp.PickValueInArray(kValidPaddings);
}

static void AddKeyParams(FuzzedDataProvider &fdp, WrapParamSet &ps, std::vector<std::vector<uint8_t>> &blobStorage)
{
    std::vector<struct HksParam> params;

    if (fdp.ConsumeProbability<double>() < 0.999) {
        uint32_t alg = PickRandomHksAlg(fdp);
        params.push_back({ .tag = HKS_TAG_ALGORITHM, .uint32Param = alg });
    }

    if (fdp.ConsumeProbability<double>() < 0.99) {
        uint32_t keySize = PickRandomHksKeySize(fdp);
        params.push_back({ .tag = HKS_TAG_KEY_SIZE, .uint32Param = keySize });
    }

    if (fdp.ConsumeProbability<double>() < 0.99) {
        uint32_t purpose = PickRandomHksKeyPurpose(fdp);
        if (fdp.ConsumeProbability<double>() < 0.1) {
            purpose |= PickRandomHksKeyPurpose(fdp);
        }
        params.push_back({ .tag = HKS_TAG_PURPOSE, .uint32Param = purpose });
    }

    if (fdp.ConsumeProbability<double>() < 0.5) {
        uint32_t digest = PickRandomHksKeyDigest(fdp);
        params.push_back({ .tag = HKS_TAG_DIGEST, .uint32Param = digest });
    }

    if (fdp.ConsumeProbability<double>() < 0.5) {
        uint32_t mode = PickRandomHksCipherMode(fdp);
        params.push_back({ .tag = HKS_TAG_BLOCK_MODE, .uint32Param = mode });
    }

    if (fdp.ConsumeProbability<double>() < 0.5) {
        uint32_t padding = PickRandomHksKeyPadding(fdp);
        params.push_back({ .tag = HKS_TAG_PADDING, .uint32Param = padding });
    }

    if (fdp.ConsumeProbability<double>() < 0.1) {
        bool val = fdp.ConsumeBool();
        params.push_back({ .tag = HKS_TAG_KEY_OVERRIDE, .boolParam = val });
    }

    if (fdp.ConsumeProbability<double>() < 0.1) {
        bool val = fdp.ConsumeBool();
        params.push_back({ .tag = HKS_TAG_IS_ALLOWED_WRAP, .boolParam = val });
    }

    if (fdp.ConsumeProbability<double>() < 0.01) {
        uint32_t groupSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
        std::vector<uint8_t> groupData = fdp.ConsumeBytes<uint8_t>(groupSize);
        blobStorage.push_back(std::move(groupData));
        HksBlob blob = { blobStorage.back().size(), blobStorage.back().data() };

        struct HksParam param = {
            .tag = HKS_TAG_KEY_ACCESS_GROUP,
            .blob = blob
        };
        params.push_back(param);
    }

    if (!params.empty()) {
        HksAddParams(ps.s, params.data(), params.size());
    }
}

WrapParamSet ConstructParamSetFromFdp(FuzzedDataProvider &fdp)
{
    WrapParamSet ps{};
    if (HksInitParamSet(&ps.s) != HKS_SUCCESS) {
        return ps;
    }

    std::vector<std::vector<uint8_t>> blobStorage;

    AddKeyParams(fdp, ps, blobStorage);

    uint32_t numParams = fdp.ConsumeIntegralInRange<uint32_t>(1, 10);
    for (uint32_t i = 0; i < numParams && (fdp.remaining_bytes() > sizeof(HksParam)); i++) {
        uint32_t index = fdp.ConsumeIntegralInRange<uint32_t>(0, HKS_VALID_TAGS_COUNT - 1);
        uint32_t tag = HKS_VALID_TAGS[index];

        AddParam(tag, fdp, ps, blobStorage);
    }

    (void)HksBuildParamSet(&ps.s);
    return ps;
}

WrapParamSet ConstructParamSetAddFuzzData(const WrapParamSet &p, FuzzedDataProvider &fdp)
{
    WrapParamSet ps{};
    if (HksInitParamSet(&ps.s) != HKS_SUCCESS) {
        return ps;
    }

    (void)HksAddParams(ps.s, p.s->params, p.s->paramsCnt);

    std::vector<std::vector<uint8_t>> blobStorage;

    AddKeyParams(fdp, ps, blobStorage);

    uint32_t numParams = fdp.ConsumeIntegralInRange<uint32_t>(0, 9);
    for (uint32_t i = 0; i < numParams && (fdp.remaining_bytes() > sizeof(HksParam)); i++) {
        uint32_t index = fdp.ConsumeIntegralInRange<uint32_t>(0, HKS_VALID_TAGS_COUNT - 1);
        uint32_t tag = HKS_VALID_TAGS[index];

        AddParam(tag, fdp, ps, blobStorage);
    }

    (void)HksBuildParamSet(&ps.s);
    return ps;
}

WrapParamSet ConstructGenKeyParamSetFromFdp(FuzzedDataProvider &fdp)
{
    WrapParamSet ps{};
    if (HksInitParamSet(&ps.s) != HKS_SUCCESS) {
        return ps;
    }

    std::vector<std::vector<uint8_t>> blobStorage;
    AddKeyParams(fdp, ps, blobStorage);

    uint32_t numParams = fdp.ConsumeIntegralInRange<uint32_t>(0, 5);
    for (uint32_t i = 0; i < numParams && (fdp.remaining_bytes() > sizeof(HksParam)); i++) {
        uint32_t index = fdp.ConsumeIntegralInRange<uint32_t>(0, HKS_VALID_TAGS_COUNT - 1);
        uint32_t tag = HKS_VALID_TAGS[index];

        AddParam(tag, fdp, ps, blobStorage);
    }

    (void)HksBuildParamSet(&ps.s);
    return ps;
}

int32_t HksFuzzGenerateKey(FuzzedDataProvider &fdp, struct HksBlob &keyAlias)
{
    WrapParamSet psIn = ConstructGenKeyParamSetFromFdp(fdp);
    WrapParamSet psOut = {};

    return HksGenerateKey(&keyAlias, psIn.s, psOut.s);
}

static WrapParamSet BuildFixedParamSet(std::vector<struct HksParam> params)
{
    WrapParamSet ps{};
    if (HksInitParamSet(&ps.s) != HKS_SUCCESS) {
        return ps;
    }
    if (!params.empty()) {
        (void)HksAddParams(ps.s, params.data(), params.size());
    }
    (void)HksBuildParamSet(&ps.s);
    return ps;
}

static void FuzzGoldenPathLocalEngine()
{
    struct HksBlob srcData = { 4, reinterpret_cast<uint8_t *>(const_cast<char *>("test")) };
    struct HksBlob hash = { 64, static_cast<uint8_t *>(calloc(64, 1)) };
    WrapParamSet hashPs = BuildFixedParamSet({ { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 } });
    (void)HksHash(hashPs.s, &srcData, &hash);
    free(hash.data);

    uint8_t nBuf[64] = {0};
    uint8_t aBuf[64] = {0};
    uint8_t eBuf[4] = {1, 0, 0, 0};
    uint8_t xBuf[64] = {0};
    struct HksBlob n = { 64, nBuf };
    struct HksBlob a = { 64, aBuf };
    struct HksBlob e = { 4, eBuf };
    struct HksBlob x = { 64, xBuf };
    n.data[63] = 3;
    a.data[0] = 2;
    (void)HksBnExpMod(&x, &a, &e, &n);

    struct HksBlob random = { 32, static_cast<uint8_t *>(calloc(32, 1)) };
    WrapParamSet randomPs = BuildFixedParamSet({});
    (void)HksGenerateRandom(randomPs.s, &random);
    free(random.data);
}

static void FuzzGoldenPathIpc()
{
    struct HksBlob rsaAlias = { 7, reinterpret_cast<uint8_t *>(const_cast<char *>("fuz_rsa")) };
    struct HksBlob eccAlias = { 7, reinterpret_cast<uint8_t *>(const_cast<char *>("fuz_ecc")) };
    struct HksBlob aesAlias = { 7, reinterpret_cast<uint8_t *>(const_cast<char *>("fuz_aes")) };
    struct HksBlob hmacAlias = { 8, reinterpret_cast<uint8_t *>(const_cast<char *>("fuz_hmac")) };

    WrapParamSet rsaPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS } });
    (void)HksGenerateKey(&rsaAlias, rsaPs.s, nullptr);

    WrapParamSet eccPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 } });
    (void)HksGenerateKey(&eccAlias, eccPs.s, nullptr);

    WrapParamSet aesPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    (void)HksGenerateKey(&aesAlias, aesPs.s, nullptr);

    WrapParamSet hmacPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = 256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    (void)HksGenerateKey(&hmacAlias, hmacPs.s, nullptr);

    struct HksBlob sigData = { 512, static_cast<uint8_t *>(calloc(512, 1)) };
    struct HksBlob srcData = { 4, reinterpret_cast<uint8_t *>(const_cast<char *>("test")) };
    WrapParamSet signPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS } });
    (void)HksSign(&rsaAlias, signPs.s, &srcData, &sigData);

    WrapParamSet verifyPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS } });
    (void)HksVerify(&rsaAlias, verifyPs.s, &srcData, &sigData);
    free(sigData.data);

    uint8_t pubKeyBuf[512] = {0};
    struct HksBlob pubKey = { 512, pubKeyBuf };
    WrapParamSet exportPs = BuildFixedParamSet({});
    (void)HksExportPublicKey(&rsaAlias, exportPs.s, &pubKey);

    (void)HksKeyExist(&rsaAlias, nullptr);

    uint8_t paramSetOutBuf[512] = {0};
    struct HksParamSet *paramSetOut = reinterpret_cast<struct HksParamSet *>(paramSetOutBuf);
    paramSetOut->paramSetSize = 512;
    WrapParamSet getKeyParamPs = BuildFixedParamSet({});
    (void)HksGetKeyParamSet(&rsaAlias, getKeyParamPs.s, paramSetOut);

    struct HksBlob cipherText = { 512, static_cast<uint8_t *>(calloc(512, 1)) };
    WrapParamSet encPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    (void)HksEncrypt(&aesAlias, encPs.s, &srcData, &cipherText);

    struct HksBlob plainText = { 512, static_cast<uint8_t *>(calloc(512, 1)) };
    WrapParamSet decPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    (void)HksDecrypt(&aesAlias, decPs.s, &cipherText, &plainText);
    free(cipherText.data);
    free(plainText.data);

    struct HksBlob macData = { 64, static_cast<uint8_t *>(calloc(64, 1)) };
    WrapParamSet macPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    (void)HksMac(&hmacAlias, macPs.s, &srcData, &macData);
    free(macData.data);
}

int HksFuzzInitWithGoldenPath()
{
    FuzzGoldenPathLocalEngine();
    FuzzGoldenPathIpc();
    return 0;
}
}}}