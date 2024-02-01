/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_CHIPSET_PLATFORM_TEST_H
#define HKS_CHIPSET_PLATFORM_TEST_H

#include <vector>
#include <cstdint>
#include <cstdio>
#include "hks_type.h"
#include "hks_param.h"

namespace OHOS {
namespace Security {
namespace Hks {
struct HksChipsetPlatformTestCase {
    std::vector<uint8_t> salt {};
    std::vector<uint8_t> tmpPk {};
    std::vector<uint8_t> hmacMsg {};
    std::vector<uint8_t> iv {};
    std::vector<uint8_t> aad {};
    std::vector<uint8_t> mac {};
    std::vector<uint8_t> cipher {};
    std::vector<uint8_t> expectPlain {};
};

struct HksCipsetPlatformEncryptInput {
    // the scene that the user will invoke decrypt on.
    // currently only support ta2ta
    enum HksChipsetPlatformDecryptScene scene;
    // user info as derive salt, the salt will be used to derive a pair of platform keys.
    // the salt length MUST be 16 bytes, and the last byte will be ignored.
    // huks will fill the last byte according to different scene before deriving platform keys.
    std::vector<uint8_t> salt;
    // caller ta uuid.
    std::vector<uint8_t> uuid;
    // customInfo identifies the user's current business work.
    // uuid and customInfo will be concatenating together during encrypting and decrypting.
    std::vector<uint8_t> customInfo;
    std::vector<uint8_t> plainText;
    bool inputPlatformPubKeyManually;
    std::vector<uint8_t> platformPubKey;
};

inline std::vector<HksParam> CipherMaterialsToDecryptInputParams(struct HksChipsetPlatformTestCase &t)
{
    return {{ .tag = HKS_TAG_SALT, .blob = { .size = t.salt.size(), .data = t.salt.data() } },
            { .tag = HKS_TAG_PEER_PUBLIC_KEY, .blob = { .size = t.tmpPk.size(), .data = t.tmpPk.data() } },
            { .tag = HKS_TAG_INFO, .blob = { .size = t.hmacMsg.size(), .data = t.hmacMsg.data() } },
            { .tag = HKS_TAG_IV, .blob = { .size = t.iv.size(), .data = t.iv.data() } },
            { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = { .size = t.aad.size(), .data = t.aad.data() } },
            { .tag = HKS_TAG_AE_TAG, .blob = { .size = t.mac.size(), .data = t.mac.data() } },
            { .tag = HKS_TAG_CIPHER_TEXT, .blob = { .size = t.cipher.size(), .data = t.cipher.data() } }};
}

struct WrapParamSet {
    struct HksParamSet *s = nullptr;
    WrapParamSet() = default;
    WrapParamSet(WrapParamSet &&other)
    {
        s = other.s;
        other.s = nullptr;
    }
    WrapParamSet(WrapParamSet &other) = delete;
    ~WrapParamSet()
    {
        if (s == nullptr) {
            return;
        }
        HksFreeParamSet(&s);
    }
};
}}}

#endif // HKS_CHIPSET_PLATFORM_TEST_H
