/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <iostream>

#include "file_ex.h"
#include "hks_ability.h"
#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"
#include "hks_params_key_data_01.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
namespace {
struct TestCaseParams {
    HksUsageSpec usageSpec = {0};
    std::string keyData;
    std::string hexData;

    HksErrorCode decryptResult = HksErrorCode::HKS_SUCCESS;
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_001_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_001_PARAMS_KEY_DATA
    .hexData = "4af9454165afd9ad50635a7f18858dd3693a9713604971572824fff91cee16fb80169977eb1a91afe8e2ad401e1"
                          "bcdec93f8c6c5f1398432ee35bd5865a70a1d",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_002_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData =
        "0100000000030000600000006000000060000000bb715e35d0c13b8c2a283017fe1adc3b38d74e8c1870a2ee3c04a25ba9d4ee332f3210"
        "8eb7d7c46cf78f88080b64703ba7732592433e8598f4e693d16461ab58284a72a0a9a2df470514369f19fbc7b6a4f0c14e5d2dd289f630"
        "e263d4907c3500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001269b10e6509a9be3"
        "2083aa742697eda81ceaeb789b4807a6bda1ceb6c661deb59810ddac275d3f4d9a276bc30c65a15fad040d4a41991680ccbf5127548bb6"
        "153ef468283ba702d8a13655ab5a6c73b6d3dd5accf567a3231900e138af224641",
    .hexData =
        "ab3c8dfe0cc42bf5176514913a146fe5466bc317344e073de2c5af055961f04d1cefb563a0c478121f74a23b561a7d6f2bca77a59b5e03"
        "669955ce3d320925aee431712eeeac08b96e346d0a59ca94f3780768915fb885e09ce81dd7b5490527",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_003_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_003_PARAMS_KEY_DATA
    .hexData = "88455132d720d77b04128a201f6c1fa234568c368cc4f57d1381316c80e32d3874f5a30f2be6cebbb960ef2a526"
                          "3801b9c2b98261018b3bbe93e97908739f65be688432a89d1851c45c1d7b02d881db53750795450811f28ce538c"
                          "f80729ce6f455fc059705e5d120d48280fbbe331226c53fb14293f92351aff3dae32b05d64",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_004_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_004_PARAMS_KEY_DATA
    .hexData =
        "1b0e0e20bdc554668442cd2c319ff6141c40a33ad6fb84faa9d464f489260b0ea97618c3bd5c7a83aed8d8b7943f32fccb66ddeccfdcd6"
        "7890efe8a1eb68a45d8b0750c6512aeb2d5ff4d146ed343f8b13def65ac7cc9c7f5ec3b6deaf7f393ece7b29de191dbabfcc1f7ad7e77a"
        "8a199668eef72cf46b54a443804f3cccda2864edc45d899070fc9227368ec73195cb4822509653c822a73d0200b0470b9b70aa549c16a5"
        "2d43e5ed3975f5762762949590e7d27849939590febed7c0e39ac57b2bfdcb982cec8048de669d2c00095ca8aea66388f8be1403fcba33"
        "754df4343ce0b7cbab26f5b43f595c9abe50c79a6876167fe652bc632cc1f341e1e21f8d",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_005_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_005_PARAMS_KEY_DATA
    .hexData =
        "51873b08dde7e0c840d341d0785a26d4f7fc5c4c8cfedb2fd8e0537720a8b680205d8068d37d0fccb8e3825e73aa33bd0daa911a1a1bf1"
        "5fa4d87cb900600fb5914d2dc8f6b7e00497abc3308657b00fee8505a3340011f46817f8111bdb839888ed1fa2e9a9f8fad9480557a8fd"
        "8d49d255e3b01e5fad00233a65605fda776909338fa3f806513ce02d535ded88170721d4635c03c7e2907fae9227991abbcaffc28cc462"
        "4918571861aaf53796f7716aebb946051b312364fe358a6849685b87bc0a5373cbb95760001a958fbfa089df9157b66721fab189df5308"
        "28292409494909a8b3f3aca7d909c88bce75c1a41cc3a639f7ed4cd018b6187faefa4b1c8362e754b2571b0b7f8d208ce81305dcb35d89"
        "e5ec2eb8e3a5690c26c8eb9b84ebd9b1cb3c652f2e70c5a3d7621925feed1441d88a31b4e2f927c9825409ad4396ed81bdfbb67bd2892a"
        "5246e915663e0210c0abdc0ede5f6021d37561893e7342a30c0609c04708be29f13737b98d1969b7b56c48d84ab6d854731bf299379e",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_006_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_006_PARAMS_KEY_DATA
    .hexData =
        "8b8c55416c4fb052ead30f042c39e66c512b002c0b38a4fb08f0ebd7c78b2f231b16793e857738b0b1a6d6d198a95aa1acf8c85e997ab1"
        "2e1c6cf1fdaf2016adea6d6b54b972452154566b1ac786c71ef199f9e50ae35dbe5196a12b0bcfd746cb72d93eda34418f3cd73189acb6"
        "03a4ab6f05d0f08318c8b48128e23cdfff529eb1fd9c6a3a64171711981d568bb93166f68d9a8eed44a8040bf0f703853c337dcbaddfb4"
        "b48ccf4a2a0358574182ecf4eb3d9a04a0e3c64409be0b60dd4165bad4fa7750197201c5dbaba642e713f0c776ab57ce4788f4f7b8ea7a"
        "0e0a562894dd7624bef236ec805ed0be81dc4e0cace17e00a6afca23364d2e1f868c8c7daf70b66ed646a889f9ed1880b3fbd8d4a1b33d"
        "325c76f83b16e7594597e38ffeec60013456d433eabfc0cfdf0f863d90559c9214f84aa60d947850858940606a1d9982c9d5dc0f3952ef"
        "d28b3d49e3b2dbfa117dde77382ac541f0a1e5156a528a393ce4554875216bc254fe9ee1d5b5cb693440eaf00adb4a1e1537376480b448"
        "9a8e717a5d565fcadc561e14e1a74fbf779a6348ba1ff4548c35cddc49829b9dd4611fc38ac80b840fb94411982124d8ffa270825c3ab8"
        "63c732cd4b81db68fcb901370b8ebf0075fc8f64c8faa17ca19ac7fc0fef63510ff2dbebb0954649ac380bdce1657b4ee32470c3077129"
        "afdd319c966fa39b05bd8faa05a16a87f1",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_007_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_007_PARAMS_KEY_DATA
    .hexData = "0716c17114c78dc6000d72b612174e6ac6b42cc2b7aeeb3651dffc92741a6396360368cc8a3f43629a78ef56231"
                          "89708b4cc75a244c46235793c2d6bfe1dbc06",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_008_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_008_PARAMS_KEY_DATA
    .hexData =
        "3d6968c44be17c9379d982a739429424e24c30dda87732d9858efd0ed43a43d2e5abad0bb2a84254700b6d2c3f41a7fb6d9b726439dc6c"
        "735cbb8fda5061051e5f2012f7960919de7a4e7e4b8c53aa39584ae1df649e33a951e6e1c5089aa251",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_009_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_009_PARAMS_KEY_DATA
    .hexData = "29bbe6754eba61b5b2907a73f03d4c3d21ec3b15296f78cc12bc870eaea302e2f1f0703c53d9a8ead057079affc"
                          "0e1bf7b740593f826f8b2e78c7f580bb311c04bae6005576a0df747c7353b827719ba551fdbc40209733b2b4049"
                          "de1fbae809ff6d548b53338bb9259699caed4281e2a5f10ae9247436ef9b892ba2d4be4fd7",

    .decryptResult = HKS_SUCCESS,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_010_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_0010_PARAMS_KEY_DATA
    .hexData =
        "ab325c28d67e141d0af060d14d6f51858b7ef237756d41fb26d3ee4d64992fe2dc47028a7295da19b751fe3023399ac2b6fc368b479735"
        "e24812ac24e4c35831d556718378b502832ad8aff79eaf1790fbf2f173f6eea2f330fcc3b6463737a63c443ab9ced5f4bd0d07bd230579"
        "27c14d45cef42b7f4c73e92d61ba4006974259c6b47d236ed7076267f8d02204d793b89f360bb890578392ce23baed87998c1f7db074cf"
        "4a781ee4f7d273f44b67e541d1b79f50ed9be0315c64cfd6636e07fc02285435b765d612fa6d608a3e29f2c943ae2e13823021439c4b5a"
        "647f8db556b41d3590983fea6dbb05ca140ce16ccf209978050ff670ecb0c1227b04820e",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_011_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_0011_PARAMS_KEY_DATA
    .hexData =
        "06f006e44c76a83944663b77495304ed3cdbe478aa2132eaa1fcdf0b690a791b240ca9f4771a901c9ac5f1fedb9547260d20037e339331"
        "21f99b022c465f9fcea0c3b5789c79c57d5ae884104a914cf7f0d44aa37e5602d029b6c7ad3c714fce96b229eed0aa51aedf7c79351ec6"
        "9025cf32ea4d32f7e04b59530a4241cf823bf7a9cb1e6ce877970b0bcd016b1db78d82c8ab53c114177d5ee184cd193d59244a6e575353"
        "9f25e7058b1deb48c0af84ae2402cef58c454575eb07c5be0516881c0699d7870a00d8d0acb6fc8775bed70be9ca0d040ff82017e22ffd"
        "38571988659480cc29a41163940d7fa74f57dac386a55334d4cc7be312f499cb55c19389f92bbe2b7200ef1218323efe2793981695e527"
        "3253ac14139b9dcd27c2c216b7a284fab2b7f4fb91ec97bf9974b214af1f718efd2973af9cc1ce4349614e6131b1c39a5e6be4b273a268"
        "4c706f054c87a4afc64c1f80293143772e010482b61dd028612d1935d7c372bf6236a4863faef090fe10597bf91fe2464bb60b0c18e2",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_012_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_0012_PARAMS_KEY_DATA
    .hexData =
        "2769734972944c17d96fadc2c2ac2295a0b0fbbeec6bbc866ec2f4b49af477de0be17ce35d5568780ec74400dfccc7dfcd53a5ce84c758"
        "02bb3e20e66dfd2e9f35df0e94efab95e5e946bd203865abebd8280f0ec2a072e307a40ef7828d0c5c9149a1c292bbf25f1e5682e78a1c"
        "f13301b830131c487463d04def399b5d04add2c145293c5903424bdbca2ae7c7010383e81c7b1371bbcd481e19a4234074fcd1d369de0d"
        "c0b9302577f4187fc067901cd0d01c479aac5817ba0bbf49da87e8dd9b0e3d5a188a4614f4129084b3712c7a76434fe947dc24388a8094"
        "3202c125ca2095378d7cb6ab17767387acf8dd83aad89bfc538bd09e69e010b9e568dc361301bbfba1d38a69691b0b8e8dfb0fd6704779"
        "5d32239295496ccf9a0d397ef294a96a4665cef6206f20ac400039b2217e16c8ad9497509bfb506724d4d6d1564e45defb035a488428ea"
        "9748400c97e169bc1aee1833f628e37c42ed840d2845fd5dc7217316eb7225ac64b6b97a487448f3aa2a5b2d3a9a484bd0aa9eaef58e00"
        "04b83610089129f8d7a66507643a5d99a5188e2bd0bdf2caa1b0b93d198401f5ca2859b5286a351e41fa1ebefc64d0213e957387cbd8f6"
        "8fce198134a27a3ee691efdd9ac83eb870ade586b28f9ca9e2758c21cd8d2fa18a8316e78bdf0cbe9de48416beb60be675662429e7ef0d"
        "4ee157e6fd03dc292c7d4cc39b6cef7b09",

    .decryptResult = HKS_SUCCESS,
};
}  // namespace

class HksCryptoHalRsaDecrypt : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        uint32_t keyLenTest = testCaseParams.keyData.length() / HKS_COUNT_OF_HALF;
        HksBlob key = { .size = keyLenTest, .data = (uint8_t *)HksMalloc(keyLenTest) };
        ASSERT_EQ(key.data == nullptr, false) << "key malloc failed.";
        for (uint32_t ii = 0; ii < keyLenTest; ii++) {
            key.data[ii] = ReadHex((const uint8_t *)&testCaseParams.keyData[HKS_COUNT_OF_HALF * ii]);
        }

        uint32_t inLen = testCaseParams.hexData.length() / HKS_COUNT_OF_HALF;
        uint32_t outLenTest = inLen;

        HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        ASSERT_EQ(message.data == nullptr, false) << "message malloc failed.";
        for (uint32_t ii = 0; ii < inLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[HKS_COUNT_OF_HALF * ii]);
        }

        HksBlob cipherText = { .size = outLenTest, .data = (uint8_t *)HksMalloc(outLenTest + HKS_PADDING_SUPPLENMENT) };
        ASSERT_EQ(cipherText.data == nullptr, false) << "cipherText malloc failed.";

        EXPECT_EQ(
            HksCryptoHalDecrypt(&key, &testCaseParams.usageSpec, &message, &cipherText), testCaseParams.decryptResult);
        HKS_FREE(key.data);
        HKS_FREE(message.data);
        HKS_FREE(cipherText.data);
    }
};

void HksCryptoHalRsaDecrypt::SetUpTestCase(void)
{
}

void HksCryptoHalRsaDecrypt::TearDownTestCase(void)
{
}

void HksCryptoHalRsaDecrypt::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalRsaDecrypt::TearDown()
{
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaDecrypt_001
 * @tc.name      : HksCryptoHalRsaDecrypt_001
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-512-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_001, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaDecrypt_002
 * @tc.name      : HksCryptoHalRsaDecrypt_002
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-768-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_002, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaDecrypt_003
 * @tc.name      : HksCryptoHalRsaDecrypt_003
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-1024-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_003, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_003_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaDecrypt_004
 * @tc.name      : HksCryptoHalRsaDecrypt_004
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-2048-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_004, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_004_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaDecrypt_005
 * @tc.name      : HksCryptoHalRsaDecrypt_005
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-3072-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_005, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_005_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaDecrypt_006
 * @tc.name      : HksCryptoHalRsaDecrypt_006
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-4096-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_006, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_006_PARAMS);
}
#endif

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaDecrypt_007
 * @tc.name      : HksCryptoHalRsaDecrypt_007
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-512-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_007, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_007_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaDecrypt_008
 * @tc.name      : HksCryptoHalRsaDecrypt_008
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-768-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_008, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_008_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaDecrypt_009
 * @tc.name      : HksCryptoHalRsaDecrypt_009
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-1024-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_009, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_009_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaDecrypt_010
 * @tc.name      : HksCryptoHalRsaDecrypt_010
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-2048-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_010, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_010_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaDecrypt_011
 * @tc.name      : HksCryptoHalRsaDecrypt_011
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-3072-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_011, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_011_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaDecrypt_012
 * @tc.name      : HksCryptoHalRsaDecrypt_012
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-4096-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaDecrypt, HksCryptoHalRsaDecrypt_012, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_DECRYPT_012_PARAMS);
}
#endif
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS