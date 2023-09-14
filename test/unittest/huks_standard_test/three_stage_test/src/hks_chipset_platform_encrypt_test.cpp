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

#include <cstdint>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hks_api.h"
#include "hks_template.h"
#include "hks_test_log.h"
#include "hks_three_stage_test_common.h"
#include "hks_chipset_platform_decrypt.h"
#include "hks_client_service_adapter.h"
#include "hks_chipset_platform_test.h"

using namespace testing::ext;
namespace {
std::vector<HksCipsetPlatformEncryptInput> g_encryptInputs = {
    {
        .scene = HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA,
        .salt = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .uuid = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .customInfo = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .plainText = {
            0x11,
        },
    }, {
        .scene = HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA,
        .salt = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .uuid = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .customInfo = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .plainText = {
            0x11, 0x22, 0x33, 0x44,
        },
    }, {
        .scene = HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA,
        .salt = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .uuid = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .customInfo = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .plainText = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        },
    }, {
        .scene = HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA,
        .salt = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .uuid = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .customInfo = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .plainText = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        },
    }, {
        .scene = HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA,
        .salt = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .uuid = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .customInfo = {
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        },
        .plainText = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        },
    },
};

void PrintOne(const std::vector<uint8_t> one)
{
    enum { NEW_LINE = 16 };
    for (std::size_t i = 0; i < one.size(); ++i) {
        if (i % NEW_LINE == 0) {
            printf("        0x%02X, ", one[i]);
        } else if (i % NEW_LINE == NEW_LINE - 1) {
            printf("0x%02X,\n", one[i]);
        } else {
            printf("0x%02X, ", one[i]);
        }
    }
    if (one.size() % NEW_LINE != 0) {
        printf("\n");
    }
}

void PrintResult(const HksChipsetPlatformTestCase &res)
{
    printf("{\n");

    printf("    .salt = {\n");
    PrintOne(res.salt);
    printf("    },\n");

    printf("    .tmpPk = {\n");
    PrintOne(res.tmpPk);
    printf("    },\n");

    printf("    .hmacMsg = {\n");
    PrintOne(res.hmacMsg);
    printf("    },\n");

    printf("    .iv = {\n");
    PrintOne(res.iv);
    printf("    },\n");

    printf("    .aad = {\n");
    PrintOne(res.aad);
    printf("    },\n");

    printf("    .mac = {\n");
    PrintOne(res.mac);
    printf("    },\n");

    printf("    .cipher = {\n");
    PrintOne(res.cipher);
    printf("    },\n");

    printf("    .expectPlain = {\n");
    PrintOne(res.expectPlain);
    printf("    },\n");

    printf("},\n");
}

uint8_t g_tmpKeyPairAliasStr[] = "tmpKeyPair";
struct HksBlob g_tmpKeyPairAlias = { sizeof(g_tmpKeyPairAliasStr), g_tmpKeyPairAliasStr };

// Notice: you need to pass an empty HksBlob for x509PubKey, and you MUST free x509PubKey after using
int32_t ExportX509ChipsetPlatformPubKey(const struct HksBlob &salt,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob &x509PubKey)
{
    std::vector<uint8_t> rawPk(PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE);
    HksBlob publicKeyBlob = { .size = PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE, .data = rawPk.data() };
    int32_t ret = HksExportChipsetPlatformPublicKey(&salt, scene, &publicKeyBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksPubKeyInfo publicKeyInfo = {
        .keyAlg = HKS_ALG_ECC,
        .keySize = HKS_ECC_KEY_SIZE_256,
        .nOrXSize = HKS_ECC_KEY_SIZE_256 / HKS_BITS_PER_BYTE,
        .eOrYSize = HKS_ECC_KEY_SIZE_256 / HKS_BITS_PER_BYTE,
        .placeHolder = 0,
    };
    std::vector<uint8_t> huksPk(sizeof(publicKeyInfo) + publicKeyBlob.size);
    struct HksBlob HksFullPubKey = { .size = static_cast<uint32_t>(huksPk.size()), .data = huksPk.data() };
    EXPECT_EQ(memcpy_s(HksFullPubKey.data, HksFullPubKey.size, &publicKeyInfo, sizeof(publicKeyInfo)), EOK);
    EXPECT_EQ(memcpy_s(HksFullPubKey.data + sizeof(publicKeyInfo), HksFullPubKey.size - sizeof(publicKeyInfo),
        publicKeyBlob.data, publicKeyBlob.size), EOK);
    ret = TranslateToX509PublicKey(&HksFullPubKey, &x509PubKey);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HKS_LOG_I("import platform public key success");

    return ret;
}

int32_t GenerateTmpKeyPairAndExportPublicKey(std::vector<uint8_t> &resTmpPk)
{
    WrapParamSet genParamSet {};
    struct HksParam genParams[] = {
        {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_ECC
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_AGREE
        }, {
            .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = HKS_ECC_KEY_SIZE_256
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_NONE
        }, {
            .tag = HKS_TAG_PADDING,
            .uint32Param = HKS_PADDING_NONE
        }
    };
    int32_t ret = InitParamSet(&genParamSet.s, genParams, HKS_ARRAY_SIZE(genParams));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    HksGenerateKey(&g_tmpKeyPairAlias, genParamSet.s, nullptr);

    enum { TMP_PK_BUFFER_SIZE = 4096, };
    resTmpPk.resize(TMP_PK_BUFFER_SIZE);
    struct HksBlob tmpPk = { .size = TMP_PK_BUFFER_SIZE, .data = resTmpPk.data() };
    ret = HksExportPublicKey(&g_tmpKeyPairAlias, nullptr, &tmpPk);
    EXPECT_EQ(ret, HKS_SUCCESS) << "export tmp ecc pub key failed";
    // the exported key is in X.509 format, and the last part is the raw key
    resTmpPk = std::vector<uint8_t> {
        resTmpPk.begin() + tmpPk.size - PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE,
        resTmpPk.begin() + tmpPk.size
    };
    return ret;
}

int32_t AgreeSharedKey(struct HksBlob &x509PubKey, struct HksBlob &sharedKey)
{
    WrapParamSet agreeParamSet {};
    static struct HksParam agreeParams[] = {
        {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_ECDH
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_AGREE
        }, {
            .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = HKS_ECC_KEY_SIZE_224
        }
    };
    int32_t ret = InitParamSet(&agreeParamSet.s, agreeParams, HKS_ARRAY_SIZE(agreeParams));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(agree) failed.";

    ret = HksAgreeKey(agreeParamSet.s, &g_tmpKeyPairAlias, &x509PubKey, &sharedKey);
    EXPECT_EQ(ret, HKS_SUCCESS);

    return ret;
}

int32_t HmacWrapKey(const struct HksBlob &sharedKey, const struct HksBlob &hmacMsg, struct HksBlob wrapKey)
{
    uint8_t sharedKeyAliasStr[] = "sharedKey";
    struct HksBlob sharedKeyAlias = { sizeof(sharedKeyAliasStr), sharedKeyAliasStr };

    // first, import sharedKey into huks
    std::vector<HksParam> importParams = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    };
    WrapParamSet importParamSet {};
    int32_t ret = InitParamSet(&importParamSet.s, importParams.data(), importParams.size());
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksImportKey(&sharedKeyAlias, importParamSet.s, &sharedKey);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // second, do hmac-sha256
    static struct HksParam hmacParams[] = {
        {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_HMAC
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_MAC
        }, {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SHA256
        }, {
            .tag = HKS_TAG_KEY_SIZE,
            .uint32Param = PLATFORM_KEY_WRAPPED_KEY_SIZE,
        }
    };

    WrapParamSet hmacParamSet {};
    EXPECT_EQ(InitParamSet(&hmacParamSet.s, hmacParams, HKS_ARRAY_SIZE(hmacParams)), HKS_SUCCESS);

    ret = HksMac(&sharedKeyAlias, hmacParamSet.s, &hmacMsg, &wrapKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    static_cast<void>(HksDeleteKey(&sharedKeyAlias, nullptr));
    return ret;
}

int32_t AesGcmEncrypt(const struct HksBlob &wrapKey, const struct HksBlob &plainText,
    struct HksBlob iv, struct HksBlob aad, struct HksBlob cipherText)
{
    uint8_t wrapKeyAliasStr[] = "wrapKey";
    struct HksBlob wrapKeyAlias = { sizeof(wrapKeyAliasStr), wrapKeyAliasStr };
    // first, import wrapKey into huks
    std::vector<HksParam> importParams = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
    };
    WrapParamSet importParamSet {};
    int32_t ret = InitParamSet(&importParamSet.s, importParams.data(), importParams.size());
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksImportKey(&wrapKeyAlias, importParamSet.s, &wrapKey);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // second, generate random IV and aad
    ret = HksGenerateRandom(nullptr, &iv);
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksGenerateRandom(nullptr, &aad);
    EXPECT_EQ(ret, HKS_SUCCESS);

    // third, encrypt with aes gcm
    struct HksParam encryptParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_NONCE, .blob = iv },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = aad },
    };
    WrapParamSet encryptParamSet {};
    ret = InitParamSet(&encryptParamSet.s, encryptParams, HKS_ARRAY_SIZE(encryptParams));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    ret = HksEncrypt(&wrapKeyAlias, encryptParamSet.s, &plainText, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS);

    (void)HksDeleteKey(&wrapKeyAlias, nullptr);
    return ret;
}

HksChipsetPlatformTestCase Encrypt(HksCipsetPlatformEncryptInput &input)
{
    HksChipsetPlatformTestCase res {
        .salt = std::vector<uint8_t>(input.salt),
        .expectPlain = std::vector<uint8_t>(input.plainText),
    };
    HksBlob saltBlob = { .size = static_cast<uint32_t>(input.salt.size()), .data = input.salt.data() };
    HksBlob plainText = { .size = static_cast<uint32_t>(input.plainText.size()), .data = input.plainText.data() };

    struct HksBlob x509PubKey {};
    int32_t ret = ExportX509ChipsetPlatformPubKey(saltBlob, input.scene, x509PubKey);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<uint8_t> sharedKeyBuffer(PLATFORM_KEY_SHARED_KEY_SIZE);
    struct HksBlob sharedKey = { .size = PLATFORM_KEY_SHARED_KEY_SIZE, .data = sharedKeyBuffer.data() };

    // concatenating uuid and customData
    res.hmacMsg = std::vector<uint8_t>(input.uuid);
    res.hmacMsg.insert(res.hmacMsg.end(), input.customInfo.begin(), input.customInfo.end());
    struct HksBlob hmacMsg = { .size = static_cast<uint32_t>(res.hmacMsg.size()), .data = res.hmacMsg.data() };

    std::vector<uint8_t> wrapKeyBuffer(PLATFORM_KEY_WRAPPED_KEY_SIZE);
    struct HksBlob wrapKey = { .size = PLATFORM_KEY_WRAPPED_KEY_SIZE, .data = wrapKeyBuffer.data() };

    res.iv.resize(PLATFORM_KEY_IV_SIZE);
    struct HksBlob iv = { .size = PLATFORM_KEY_IV_SIZE, .data = res.iv.data() };

    // notice: cipher length = plain length + tag length
    res.cipher.resize(plainText.size + PLATFORM_KEY_TAG_SIZE);
    struct HksBlob cipherText = { .size = static_cast<uint32_t>(res.cipher.size()), .data = res.cipher.data() };

    res.aad.resize(PLATFORM_KEY_AAD_SIZE);
    struct HksBlob aad = { .size = PLATFORM_KEY_AAD_SIZE, .data = res.aad.data() };

    ret = GenerateTmpKeyPairAndExportPublicKey(res.tmpPk);
    EXPECT_EQ(ret, HKS_SUCCESS) << "generate tmp ecc key pair failed";

    ret = AgreeSharedKey(x509PubKey, sharedKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "agree shared key failed";

    ret = HmacWrapKey(sharedKey, hmacMsg, wrapKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "hmac wrap key failed";

    ret = AesGcmEncrypt(wrapKey, plainText, iv, aad, cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS);
    // extract cipher and tag from cipher
    res.mac = std::vector<uint8_t> { res.cipher.end() - PLATFORM_KEY_TAG_SIZE, res.cipher.end() };
    res.cipher = std::vector<uint8_t> { res.cipher.begin(), res.cipher.end() - PLATFORM_KEY_TAG_SIZE };

    (void)HksDeleteKey(&g_tmpKeyPairAlias, nullptr);
    HKS_FREE_BLOB(x509PubKey);
    return res;
}

std::vector<uint8_t> VectorStrToVectorUint8(const std::vector<std::string> &str)
{
    enum { HEX_BASE = 16 };
    std::vector<uint8_t> res(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        res[i] = (uint8_t)strtol(str[i].c_str(), nullptr, HEX_BASE);
    }
    return res;
}

int32_t ReadInputFile(const char *path, HksCipsetPlatformEncryptInput &input)
{
    #define MAP_SCENE_ENUM_KEY_VALUE(a) { (#a), (a) }
    std::map<std::string, enum HksChipsetPlatformDecryptScene> scenes = {
        MAP_SCENE_ENUM_KEY_VALUE(HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA),
    };
    #undef MAP_SCENE_ENUM_KEY_VALUE
    std::ifstream f(path, std::ios::binary | std::ios::in);
    if (!f) {
        HKS_TEST_LOG_I("open file \"%s\" failed", path);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    nlohmann::json data = nlohmann::json::parse(f);
    std::string scene = data["scene"];
    auto sceneValue = scenes.find(scene);
    if (sceneValue == scenes.end()) {
        HKS_TEST_LOG_I("invalid scene \"%s\"", scene.c_str());
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    input.scene = sceneValue->second;
    input.salt = VectorStrToVectorUint8(data["salt"]);
    input.uuid = VectorStrToVectorUint8(data["uuid"]);
    input.customInfo = VectorStrToVectorUint8(data["customInfo"]);
    input.plainText = VectorStrToVectorUint8(data["plainText"]);
    HKS_TEST_LOG_I("read scene = %s", scene.c_str());
    HKS_TEST_LOG_I("read salt size = %zu, data = ", input.salt.size());
    PrintOne(input.salt);
    HKS_TEST_LOG_I("read uuid size = %zu, data = ", input.uuid.size());
    PrintOne(input.uuid);
    HKS_TEST_LOG_I("read customInfo size = %zu, data = ", input.customInfo.size());
    PrintOne(input.customInfo);
    HKS_TEST_LOG_I("read plainText size = %zu, data = ", input.plainText.size());
    PrintOne(input.plainText);
    return HKS_SUCCESS;
}

void PrintTaToTaParams(HksChipsetPlatformTestCase &t)
{
    // Notice: the customInfo in ta to ta input params do not contains uuid
    t.hmacMsg = std::vector<uint8_t> { t.hmacMsg.begin() + PLATFORM_KEY_BUSINESS_ID_SIZE, t.hmacMsg.end() };
    WrapParamSet decryptParamSet {};
    auto decryptParams = CipherMaterialsToDecryptInputParams(t);
    int32_t ret = InitParamSet(&decryptParamSet.s, decryptParams.data(), decryptParams.size());
    EXPECT_EQ(ret, HKS_SUCCESS) << "decryptParamSet failed.";
    HKS_TEST_LOG_I("params[0] size = %d, data =", decryptParamSet.s->paramSetSize);
    PrintOne(std::vector<uint8_t>{reinterpret_cast<uint8_t*>(decryptParamSet.s),
        reinterpret_cast<uint8_t*>(decryptParamSet.s) + decryptParamSet.s->paramSetSize});
    HKS_TEST_LOG_I("params[1] size = %zu, data are all zeros", t.cipher.size());
}
}
namespace Unittest::HksChipsetPlatformEncryptTest {

class HksChipsetPlatformEncryptTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksChipsetPlatformEncryptTest::SetUpTestCase(void)
{
    HKS_LOG_E("set up cases");
    int32_t ret = HksInitialize();
    EXPECT_EQ(ret, HKS_SUCCESS);
}

void HksChipsetPlatformEncryptTest::TearDownTestCase(void)
{
}

void HksChipsetPlatformEncryptTest::SetUp()
{
}

void HksChipsetPlatformEncryptTest::TearDown()
{
}

/**
 * @tc.name: HksChipsetPlatformEncryptTest.EncryptTool
 * @tc.desc: encrypt tool
 * @tc.type: FUNC
 */
HWTEST_F(HksChipsetPlatformEncryptTest, EncryptTool, TestSize.Level0)
{
    HKS_TEST_LOG_I("begin EncryptTool");
    constexpr const char envInputPath[] = "HUKS_CHIPSET_PLATFORM_INPUT_PATH";
    constexpr const char defaultPath[] = "/data/input.json";
    HKS_TEST_LOG_I(
        "the encrypt tool will read the environment variable $%s or %s if the environment variable is not set",
        envInputPath, defaultPath);
    const char *inputPath = std::getenv(envInputPath);
    HKS_TEST_LOG_I("the environment variable $%s = \"%s\"", envInputPath, inputPath);
    if (inputPath == nullptr) {
        inputPath = defaultPath;
    }
    HKS_TEST_LOG_I("read \"%s\" now", inputPath);
    HksCipsetPlatformEncryptInput input {};
    int32_t ret = ReadInputFile(inputPath, input);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("read input file failed, do not test encrypt tool");
        return;
    }
    EXPECT_EQ(ret, HKS_SUCCESS);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_I("read input failed, please check input file format!");
        return;
    }
    HKS_TEST_LOG_I("begin encrypt");
    HksChipsetPlatformTestCase cipherMaterials = Encrypt(input);
    HKS_TEST_LOG_I("done encrypt, cipherMaterials =");
    PrintResult(cipherMaterials);
    if (input.scene == HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA) {
        HKS_TEST_LOG_I("TA TO TA input params =");
        PrintTaToTaParams(cipherMaterials);
    }
    HKS_TEST_LOG_I("end EncryptTool");
}

/**
 * @tc.name: HksChipsetPlatformEncryptTest.HksChipsetPlatformEncryptTest001
 * @tc.desc: tdd Normal process of chipset platform encrypt, expect ret == HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksChipsetPlatformEncryptTest, HksChipsetPlatformEncryptTest001, TestSize.Level0)
{
    HKS_LOG_E("enter HksChipsetPlatformEncryptTest");
    HksChipsetPlatformTestCase cipherMaterials {};
    for (auto &input : g_encryptInputs) {
        cipherMaterials = Encrypt(input);
        PrintResult(cipherMaterials);
    }
}

/**
 * @tc.name: HksChipsetPlatformEncryptTest.HksChipsetPlatformEncryptTest002
 * @tc.desc: tdd HksExportChipsetPlatformPublicKey normal case
 * @tc.type: FUNC
 */
HWTEST_F(HksChipsetPlatformEncryptTest, HksChipsetPlatformEncryptTest002, TestSize.Level0)
{
    HKS_LOG_E("enter HksChipsetPlatformEncryptTest");
    std::vector<uint8_t> saltData = std::vector<uint8_t>(PLATFORM_KEY_SALT_SIZE);
    HksBlob salt = { .size = static_cast<uint32_t>(saltData.size()), .data = saltData.data() };
    std::vector<uint8_t> pubKey = std::vector<uint8_t>(PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE);
    HksBlob pk = { .size = static_cast<uint32_t>(pubKey.size()), .data = pubKey.data() };
    int32_t ret = HksExportChipsetPlatformPublicKey(&salt, HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA, &pk);
    EXPECT_EQ(ret, HKS_SUCCESS);
    std::vector<uint8_t> allZero(PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE);
    EXPECT_NE(memcmp(pubKey.data(), allZero.data(), PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE), 0);
}

/**
 * @tc.name: HksChipsetPlatformEncryptTest.HksChipsetPlatformEncryptTest003
 * @tc.desc: tdd HksExportChipsetPlatformPublicKey bad case, nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HksChipsetPlatformEncryptTest, HksChipsetPlatformEncryptTest003, TestSize.Level0)
{
    HKS_LOG_E("enter HksChipsetPlatformEncryptTest");
    // bad case, nullptr
    int32_t ret = HksExportChipsetPlatformPublicKey(nullptr, HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA, nullptr);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksChipsetPlatformEncryptTest.HksChipsetPlatformEncryptTest004
 * @tc.desc: tdd HksExportChipsetPlatformPublicKey bad case, salt too long, pubKey too long
 * @tc.type: FUNC
 */
HWTEST_F(HksChipsetPlatformEncryptTest, HksChipsetPlatformEncryptTest004, TestSize.Level0)
{
    HKS_LOG_E("enter HksChipsetPlatformEncryptTest");
    // bad case, salt too long, pubKey too long
    std::vector<uint8_t> saltData(PLATFORM_KEY_SALT_SIZE + 1);
    HksBlob salt = { .size = static_cast<uint32_t>(saltData.size()), .data = saltData.data() };
    std::vector<uint8_t> pubKey(PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE + 1);
    HksBlob pk = { .size = static_cast<uint32_t>(pubKey.size()), .data = pubKey.data() };
    int32_t ret = HksExportChipsetPlatformPublicKey(&salt, HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA, &pk);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksChipsetPlatformEncryptTest.HksChipsetPlatformEncryptTest005
 * @tc.desc: tdd HksExportChipsetPlatformPublicKey bad case, salt too short
 * @tc.type: FUNC
 */
HWTEST_F(HksChipsetPlatformEncryptTest, HksChipsetPlatformEncryptTest005, TestSize.Level0)
{
    HKS_LOG_E("enter HksChipsetPlatformEncryptTest");
    // bad case, salt too short
    std::vector<uint8_t> saltData = std::vector<uint8_t>(PLATFORM_KEY_SALT_SIZE - 1);
    HksBlob salt = { .size = static_cast<uint32_t>(saltData.size()), .data = saltData.data() };
    std::vector<uint8_t> pubKey = std::vector<uint8_t>(PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE);
    HksBlob pk = { .size = static_cast<uint32_t>(pubKey.size()), .data = pubKey.data() };
    int32_t ret = HksExportChipsetPlatformPublicKey(&salt, HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA, &pk);
    EXPECT_NE(ret, HKS_SUCCESS);
}
}
