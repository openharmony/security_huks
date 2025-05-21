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
#include <memory>
#include <string>
#include <vector>
#include <cJSON.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_api.h"
#include "hks_chipset_platform_test.h"
#include "hks_client_service_adapter.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_test_adapt_for_de.h"
#include "hks_test_log.h"
#include "hks_three_stage_test_common.h"
#include "hks_type.h"

// HKS_OPENSSL_SUCCESS
#include "base/security/huks/frameworks/huks_standard/main/crypto_engine/openssl/include/hks_openssl_engine.h"
#include "base/security/huks/services/huks_standard/huks_engine/main/core/include/hks_chipset_platform_decrypt.h"
#include "base/security/huks/test/unittest/huks_standard_test/three_stage_test/include/hks_chipset_platform_test.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/types.h>
#include <openssl/x509.h>

using namespace testing::ext;
using namespace OHOS::Security::Hks;
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

struct HksChipsetPlatformEncryptJson {
    cJSON *scene;
    cJSON *salt;
    cJSON *uuid;
    cJSON *customInfo;
    cJSON *plainText;
    cJSON *inputPlatformPubKeyManually;
    cJSON *platformPubKey;

    HksChipsetPlatformEncryptJson()
    {
        scene = nullptr;
        salt  = nullptr;
        uuid  = nullptr;
        customInfo = nullptr;
        plainText  = nullptr;
        inputPlatformPubKeyManually = nullptr;
        platformPubKey = nullptr;
    }
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

void ConvertRawEcPubKeyToX509Key(const std::vector<uint8_t> &rawPk, std::vector<uint8_t> &x509PubKey)
{
    EXPECT_EQ(rawPk.size(), PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE);
    auto ecKey = std::unique_ptr<EC_KEY, void(*)(EC_KEY *&)>(
        EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), [](EC_KEY *&ecKey) {
        SELF_FREE_PTR(ecKey, EC_KEY_free)
    });
    EXPECT_NE(ecKey, nullptr);
    auto bigNumFree = [](BIGNUM *&bigNum) {
        SELF_FREE_PTR(bigNum, BN_free)
    };
    auto ecX = std::unique_ptr<BIGNUM, void(*)(BIGNUM *&)>(
        BN_bin2bn(rawPk.data(), PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE, nullptr), bigNumFree);
    EXPECT_NE(ecX, nullptr);
    auto ecY =  std::unique_ptr<BIGNUM, void(*)(BIGNUM *&)>(BN_bin2bn(rawPk.data() +
        PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE, PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE, nullptr), bigNumFree);
    EXPECT_NE(ecY, nullptr);
    EXPECT_EQ(EC_KEY_set_public_key_affine_coordinates(ecKey.get(), ecX.get(), ecY.get()), HKS_OPENSSL_SUCCESS);
    EC_KEY_set_conv_form(ecKey.get(), POINT_CONVERSION_UNCOMPRESSED);
    auto pkey = std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY *&)>(EVP_PKEY_new(), [](EVP_PKEY *&pkey) {
        SELF_FREE_PTR(pkey, EVP_PKEY_free)
    });
    EXPECT_NE(pkey, nullptr);
    EXPECT_EQ(EVP_PKEY_set1_EC_KEY(pkey.get(), ecKey.get()), HKS_OPENSSL_SUCCESS);
    int32_t length = i2d_PUBKEY(pkey.get(), nullptr);
    EXPECT_GT(length, 0);
    EXPECT_LT(length, HKS_MAX_KEY_LEN);
    x509PubKey.resize(length);
    std::fill(x509PubKey.begin(), x509PubKey.end(), 0);
    uint8_t *tmp = x509PubKey.data();
    EXPECT_EQ(i2d_PUBKEY(pkey.get(), &tmp), length);
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

    HksGenerateKeyForDe(&g_tmpKeyPairAlias, genParamSet.s, nullptr);

    enum { TMP_PK_BUFFER_SIZE = 4096, };
    resTmpPk.resize(TMP_PK_BUFFER_SIZE);
    struct HksBlob tmpPk = { .size = TMP_PK_BUFFER_SIZE, .data = resTmpPk.data() };
    ret = HksExportPublicKeyForDe(&g_tmpKeyPairAlias, nullptr, &tmpPk);
    EXPECT_EQ(ret, HKS_SUCCESS) << "export tmp ecc pub key failed";
    // the exported key is in X.509 format, and the last part is the raw key.
    // we have verified that the length of public key will always be PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE bytes.
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
            .uint32Param = HKS_ECC_KEY_SIZE_256
        }
    };
    int32_t ret = InitParamSet(&agreeParamSet.s, agreeParams, HKS_ARRAY_SIZE(agreeParams));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(agree) failed.";

    ret = HksAgreeKeyForDe(agreeParamSet.s, &g_tmpKeyPairAlias, &x509PubKey, &sharedKey);
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

    ret = HksImportKeyForDe(&sharedKeyAlias, importParamSet.s, &sharedKey);
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

    ret = HksMacForDe(&sharedKeyAlias, hmacParamSet.s, &hmacMsg, &wrapKey);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    static_cast<void>(HksDeleteKeyForDe(&sharedKeyAlias, nullptr));
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

    ret = HksImportKeyForDe(&wrapKeyAlias, importParamSet.s, &wrapKey);
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

    ret = HksEncryptForDe(&wrapKeyAlias, encryptParamSet.s, &plainText, &cipherText);
    EXPECT_EQ(ret, HKS_SUCCESS);

    (void)HksDeleteKeyForDe(&wrapKeyAlias, nullptr);
    return ret;
}

HksChipsetPlatformTestCase Encrypt(HksCipsetPlatformEncryptInput &input)
{
    HksChipsetPlatformTestCase res {
        .salt = std::vector<uint8_t>(input.salt),
        .expectPlain = std::vector<uint8_t>(input.plainText),
    };
    HksBlob plainText = { .size = static_cast<uint32_t>(input.plainText.size()), .data = input.plainText.data() };

    std::vector<uint8_t> rawPubKey{};
    if (input.inputPlatformPubKeyManually) {
        rawPubKey = input.platformPubKey;
    } else {
        EXPECT_EQ(input.inputPlatformPubKeyManually, true);
        return {};
    }
    EXPECT_EQ(rawPubKey.size(), PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE);
    std::vector<uint8_t> x509PubKeyData{};
    ConvertRawEcPubKeyToX509Key(rawPubKey, x509PubKeyData);
    HksBlob x509PubKey = { .size = x509PubKeyData.size(), .data = x509PubKeyData.data() };

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

    int32_t ret = GenerateTmpKeyPairAndExportPublicKey(res.tmpPk);
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

    (void)HksDeleteKeyForDe(&g_tmpKeyPairAlias, nullptr);
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

int32_t FileRead(const char *filePath, uint8_t *blob, size_t size)
{
    FILE *fp = fopen(filePath, "rb");
    HKS_IF_NULL_LOGE_RETURN(fp, HKS_ERROR_OPEN_FILE_FAIL, "open file fail");
    size_t len = fread(blob, 1, size, fp);
    HKS_IF_TRUE_LOGE_RETURN(fclose(fp) < 0, HKS_ERROR_CLOSE_FILE_FAIL, "close file fail");
    return len;
}

int32_t CJsonArrayToVectorUint8(cJSON *jsonArrayObj, std::vector<uint8_t> &res)
{
    std::vector<std::string> str;
    for (int i = 0; i < cJSON_GetArraySize(jsonArrayObj); ++i) {
        cJSON *arrayItem = cJSON_GetArrayItem(jsonArrayObj, i);
        HKS_IF_NULL_LOGE_RETURN(arrayItem, HKS_FAILURE, "get array item failed");
        HKS_IF_NOT_TRUE_LOGE_RETURN(cJSON_IsString(arrayItem), HKS_FAILURE, "arrayItem not a string type");
        str.push_back(arrayItem->valuestring);
    }
    res = VectorStrToVectorUint8(str);
    return HKS_SUCCESS;
}

bool GetCJsonBoolValue(cJSON *jsonObj)
{
    HKS_IF_NULL_LOGE_RETURN(jsonObj, false, "bool obj is nullptr");
    HKS_IF_NOT_TRUE_LOGE_RETURN(cJSON_IsBool(jsonObj), false, "obj is not a bool type");
    return cJSON_IsTrue(jsonObj) ? true : false;
}

int32_t ParseEncryptJson(cJSON **json, char *data, HksChipsetPlatformEncryptJson &jsonInfo)
{
    bool allCorrect = false;
    do {
        *json = cJSON_Parse(data);
        HKS_IF_NULL_LOGE_BREAK(*json, "can not parse json string");

        jsonInfo.scene = cJSON_GetObjectItem(*json, "scene");
        HKS_IF_NULL_LOGE_BREAK(jsonInfo.scene, "get object scene failed");
        HKS_IF_NOT_TRUE_LOGE_BREAK(cJSON_IsString(jsonInfo.scene), "scene not a string type");

        jsonInfo.salt = cJSON_GetObjectItem(*json, "salt");
        HKS_IF_NULL_LOGE_BREAK(jsonInfo.salt, "get object salt failed");
        HKS_IF_NOT_TRUE_LOGE_BREAK(cJSON_IsArray(jsonInfo.salt), "salt not a array type");

        jsonInfo.uuid = cJSON_GetObjectItem(*json, "uuid");
        HKS_IF_NULL_LOGE_BREAK(jsonInfo.uuid, "get object uuid failed");
        HKS_IF_NOT_TRUE_LOGE_BREAK(cJSON_IsArray(jsonInfo.uuid), "uuid not a array type");

        jsonInfo.customInfo = cJSON_GetObjectItem(*json, "customInfo");
        HKS_IF_NULL_LOGE_BREAK(jsonInfo.customInfo, "get object customInfo failed");
        HKS_IF_NOT_TRUE_LOGE_BREAK(cJSON_IsArray(jsonInfo.customInfo), "customInfo not a array type");

        jsonInfo.plainText = cJSON_GetObjectItem(*json, "plainText");
        HKS_IF_NULL_LOGE_BREAK(jsonInfo.plainText, "get object plainText failed");
        HKS_IF_NOT_TRUE_LOGE_BREAK(cJSON_IsArray(jsonInfo.plainText), "plainText not a array type");

        jsonInfo.inputPlatformPubKeyManually = cJSON_GetObjectItem(*json, "inputPlatformPubKeyManually");
        HKS_IF_NULL_LOGE_BREAK(jsonInfo.inputPlatformPubKeyManually, "get object inputPlatformPubKeyManually failed");
        HKS_IF_NOT_TRUE_LOGE_BREAK(cJSON_IsBool(jsonInfo.inputPlatformPubKeyManually),
            "inputPlatformPubKeyManually not a bool type");
        
        if (cJSON_IsTrue(jsonInfo.inputPlatformPubKeyManually)) {
            jsonInfo.platformPubKey = cJSON_GetObjectItem(*json, "platformPubKey");
            HKS_IF_NULL_LOGE_BREAK(jsonInfo.platformPubKey, "get object platformPubKey failed");
            HKS_IF_NOT_TRUE_LOGE_BREAK(cJSON_IsArray(jsonInfo.platformPubKey), "platformPubKey not a array type");
        }
        allCorrect = true;
    } while (0);
    if (allCorrect == false) {
        HKS_LOG_E("get object failed");
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}
#define HKS_FILE_CACHE 1024 * 10
int32_t ReadInputFile(const char *path, HksCipsetPlatformEncryptInput &input)
{
    #define MAP_SCENE_ENUM_KEY_VALUE(a) { (#a), (a) }
    std::map<std::string, enum HksChipsetPlatformDecryptScene> scenes = {
        MAP_SCENE_ENUM_KEY_VALUE(HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA),
    };
    #undef MAP_SCENE_ENUM_KEY_VALUE
    
    cJSON *json = nullptr;
    std::unique_ptr<cJSON, void(*)(cJSON *)> jsonData(json, cJSON_Delete);
    std::unique_ptr<uint8_t> fileData(new uint8_t[HKS_FILE_CACHE]);
    struct HksChipsetPlatformEncryptJson encryptJson;
    int32_t ret = FileRead(path, fileData.get(), HKS_FILE_CACHE);
    HKS_IF_TRUE_LOGE_RETURN(ret < 0, ret, "can not read info from file");
    
    ret = ParseEncryptJson(&json, reinterpret_cast<char *>(fileData.get()), encryptJson);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_FAILURE, "ParseEncryptJson failed");
    auto sceneValue = scenes.find(encryptJson.scene->valuestring);
    HKS_IF_TRUE_LOGE_RETURN(sceneValue == scenes.end(), HKS_ERROR_INVALID_ARGUMENT,
        "invalid scene %" LOG_PUBLIC "s", encryptJson.scene->valuestring);
    ret = CJsonArrayToVectorUint8(encryptJson.salt, input.salt);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get array info from salt failed");
    ret = CJsonArrayToVectorUint8(encryptJson.uuid, input.uuid);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get array info from uuid failed");
    ret = CJsonArrayToVectorUint8(encryptJson.customInfo, input.customInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get array info from customInfo failed");
    ret = CJsonArrayToVectorUint8(encryptJson.plainText, input.plainText);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get array info from plainText failed");
    input.inputPlatformPubKeyManually = GetCJsonBoolValue(encryptJson.inputPlatformPubKeyManually);
    if (input.inputPlatformPubKeyManually) {
        ret = CJsonArrayToVectorUint8(encryptJson.platformPubKey, input.platformPubKey);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get array info from platformPubKey failed");
    }
    HKS_LOG_E("get object SUCCESS");

    HKS_TEST_LOG_I("read scene = %s", encryptJson.scene->valuestring);
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
}
