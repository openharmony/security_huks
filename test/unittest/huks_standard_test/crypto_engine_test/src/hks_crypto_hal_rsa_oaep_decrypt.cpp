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
#include "hks_params_key_data_02.h"
#include "hks_params_key_data_01.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
namespace {
struct TestCaseParams {
    HksUsageSpec usageSpec = {0};
    std::string hexData;
    std::string keyData;

    HksErrorCode decryptResult = HksErrorCode::HKS_SUCCESS;
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_013_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_013_PARAMS_KEY_DATA
    .hexData = "070bd81030f33310b12f3a83894c16ab23ebc6d9843a71988807874a465eb29f06042a5e9b27f16e998815e1bf8"
        "a5f55b48750632202693fde21264c21dedd33",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_014_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_014_PARAMS_KEY_DATA
    .hexData =
        "35249280c4a155024e0f64c0c26ab980d1ddd9fa05ee8c4ad8122f70647c0c608b63c3efe68dde3e07cacd89398ec1660f858bfb1082e6"
        "ed82ce54c14a7c6927a229c0b619d0e909c09daab2dae24a809139496217307fb02a5d4dea9b2e0074",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_015_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_015_PARAMS_KEY_DATA
    .hexData = "752b367cad05c09718da9077ada4062a3aca68a63c92af640cdfcb6c409cd857df9092bfd1dd14f894fde120434"
        "f2007e67d10acf835c4767be6b596840faf88a706e95f085d63b46694a5ed492ca36c251636af3839eaba1a7714"
        "d796a686cd94afdb96893f04fe276d681afe036708dcf3a8bd7516255dd8042eb9517e9584",

    .decryptResult = HKS_SUCCESS,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_016_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_016_PARAMS_KEY_DATA
    .hexData =
        "c303489c1204761cf6e3ea1d4ebbdd77933dce5acff16594564a9b1c41a5690a04777814c531ff8f0a0112182b0f96c627e3756d4b2756"
        "d7d1f8a2ec8c7cba4e0cb29d9cb8edf343e5633715297a882f4a864e4543b30063018ce01358639fdd9ad452152fd4d938f9e680b23e7b"
        "27fa85a23c027c7ca95498c3ee2f8ac0bbeec11c0c8455584f2f583027054b39b92326f018d2d68093b99cf741a2985e8af712548eff72"
        "5b5c707172458ed73b6fcc98143fd1bf6ede2885a9ebe10e76b215d4554d6cc9b04cc10c76b6a3c4f8d0dd1b67fb439b9dcf4fa2cc59b3"
        "786a4f57f328645d20d8a3da2e301f42783f453ae93c622173d643516c8484d024d6b5d8",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_017_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_017_PARAMS_KEY_DATA
    .hexData =
        "444665d129abd103992a5953066d4e7a6bbe9f6132d2a783db39c665980b5b89c9bb06de04fabf8aa1d7d2a5ef34d55a336200632a933f"
        "73f3f9f84ca1cfbb6e69986c128919dcacb16f741b2e0c90562ed3f410e4419411d49650b73be9e910705cb69824286640debf3be88e5a"
        "c5cc300b38575933df66b9c51907e2e997b531a486bd320becba1992fad8b099f6b110c125c3559431f45cf0ad9ede5c33087e4b464905"
        "8a9e87bddc647eb02bdc39fb86f5498dbd3a317bbf29d02460a0991f9cfd615f0efffc1a66e5d48af9aeba2702ec7c3c0dd48a1987f333"
        "5c06208ebdf0c0817604137f9c67718faf301059a2be8da7ac43663410e44362e28fcc0f17de1af251c7145c944c1e4bf29d7989d5805b"
        "f971ebf021ca7e139f0a1f946636b17e2638f3b59e04ff613c20fe58f9b07bf2c039a27aaf3da4cc788effbc4214f7d3034e1f32ac0361"
        "e5a7f88871be506b43aa5ed24e42ffdf3174e89d3a3e7337389d3e017ee76005154afae1230993ed1dda61194ef4fb9ade757d5b27af",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_018_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_018_PARAMS_KEY_DATA
    .hexData =
        "193b8cc1eb7736b40ceb90c48a184a2bd7b02759e0ba6f167dfeccdbc09e40ab1ab7e7940b073951892696e5dea1325da7662d61e4b888"
        "b395067dbe3db7e2fae21c8da725b841e7d05306a44a69736d4003ee18eb3013e9df01b78205e9b8d789f670f51d7e425c0f63355c615f"
        "460d066d52fc747eaa23f8ec411bd22ea75db5236035b2805d9e356cb8f694a4788dc549db357cb7e914f55ebd9d1b76f272544adb71e6"
        "6d285c8cbe6bd6b2f835ccc8f5c80f24c19d0e5a50f7c7d158fe354a5d267bdd217359035cc1f0dc38b0c5f40359528314a5129b709a9a"
        "9b4d3291002aea22da98eda77e096128854f7664572a61fe1f6615fd0c1df1e3cdefef189642bb23fab3450f6d4bae77e9a3df43e08c62"
        "ebcfb1d2d6f10d8bd6b2f4ddfb3bd4a143d61cc1d065ccf45de5e330fa1ab2f8c6fbd3753549a7cd8bd8e26c88ac21fa277a106f7f9e49"
        "45b87374f04e73214e4c6ce61e4d77643e1fd8c13ac0e1b93e55ad2b574e9185b0f490dc0cf8858125b505edc330f91bd44bc14f74bdb6"
        "66e6df9d26bf4c45e414ba569461f3f53915a5b80edb59254e6b786fb24728b4c08180bd912b037a20ac9a4d795121eb7bdbf38cd36aff"
        "4adc1c693b51ef6d5d85395ba16f35eca51317c9ecbe67b7b583cb8006c79f51e20efc2c2187b529aef5fdd7cfbd2c9cb1798f43883e83"
        "70bf2e4c27a89d718536c06e449b934b41",

    .decryptResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_019_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_019_PARAMS_KEY_DATA
    .hexData = "aa7b5d9919b61a4d1a7e7b3651c17a758e995ec9583e9d2b5ef4121b45d8f9dec009fc03b19e4527105ee1d0cbd"
        "1b3bd66123c12899f1e425ea63e69958e6dc5",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_020_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_020_PARAMS_KEY_DATA
    .hexData =
        "8e5129736a8e1986fcdfadd0393f8aabe080823a7b4275d0dfa4d9fa32b9e05720d957130acf4c8cd512688d447b8f84cfe7f1b4cb4371"
        "e2f988ee2774b280de4461f40467d2e03e86389547b5066e43f81e2da8e5cfbd9aa0c2f16fdfb618dd",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_021_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_021_PARAMS_KEY_DATA
    .hexData = "7d18be21fa944e51759c94e1b276d5051059e2b759a12090c6d22b264d46f00e9d52d3ddd5878c381c00c675ddf"
        "e08f48dc47b6c8e01a759dfc2ead5bdc72afcec8f8cd939dd256b619cbb98b5cd3e387f048b7ccef09c5c1c8004"
        "0e59760f64300ef08739e22fa7e272fa3c5ced217b6a7371b435cf9c169ecc1a1d551fc05e",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_022_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_022_PARAMS_KEY_DATA
    .hexData =
        "a3f9244077328f00ed6921234d6d9ede1c1d580a8ba7a5f3748880d29011e50e26e1f84106674d07e20c4ea5ff0d6821979f01d86f4a16"
        "4e5cc3c3af9fc8bb627beada5686f3281b105f2c5da0453cd75f5ec13d1543dd84dc7a14da3aeb55dca29aa0466f78d0d8e6e223ff5534"
        "ad1d638f7f4cab4d8fc3a8b68a83df50102302f1445bf5c7782fc787b6e95ad21bb4dd3b2460dd17447296fa898af7e5b8ef99b43d2eb5"
        "9e7b1142cce5e9bbb2181a3a5241572c194df23f2f4242d825bf6ab6d943db161ec879566d0c3b845c57586109a9f408e4ccb6f79ecc71"
        "2c18dad3476d283fac34d6513e34e01f9688afe2fca84e00976fd624292aa128b6518dbd",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_023_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_023_PARAMS_KEY_DATA
    .hexData =
        "5e9f606bffcfb96cd8905ccaf2aef45b6c78bb1ff81907c849fc10cbdafed6309df895697051e5c7ff473d65aaa0fcc79ee7c4b1e5f1cd"
        "3f8b269230303a5d838e93b9a0f8cf12b8bf459faa0653c7a0f9ca94fad2e789bf89b8515dc9e9e3ff3c4fcf86c426f2557a7467005f28"
        "ab978c3cc4a06faa102d8fa3ad9299d3891bcf50f926e3722075ff89cfc9061a3ea498e37e8202bcb4eedede8541c1425a4e278fa7a821"
        "202ebb5e64c7052aae99fce16ae14371fa94614c87a62cd1576e0ddc93faf4af81d84cc65d003fc6eed7a9310005c05f5ce7284be77cce"
        "dc287da88c9ae840ebbc6ef3abc440f089f93b06da4b7b4122c0b9a6f120ce0167aba1551082d93df8e6edacaf442b200c9ad4d5e6aa50"
        "9245f955d7b3126e8b7edcd294cb8a8e9c52c660c2059d536b6c8c5f9364d86a45f501b0f944207bcd631f9a6b69e3b508946f539f7fa8"
        "0c877b80522d08bb3f41a7a442894567aac96ecb929cb9c1fc5972172845b2859c094836a0b1755b3c8c50e54a51b93b4aa6958d646a",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_024_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_024_PARAMS_KEY_DATA
    .hexData =
        "8687202d898e1a5cef2f34dc0ab0c57f1ac8e9c0b4e1c2b76362a8bfc427dc2cddee16722b748a521bae5a5013f94bbc2587654ab42fa2"
        "3d8026c91dfeac05e5adecdc230943a5f4c711cf745f81a852c63823fdbbccf10f5455cec93575d4164a21e07fa9102fb63843aa95f6bc"
        "0cc299f4a8e9e2b32163485e893aff386c5d573054c63bd56842111b61323335501f858b5e71a566931f7c6f5ea3db1beb29bbdf095eba"
        "b66477b666e7c74fbc3759319fd25f7f584d6bd556cf067313918e8cdfd8b96857b8c1e50ed1a7159e13ef7296352bea25c802ca0a8d22"
        "9b96fa66a6c497b7ee5dcb3baf69152050e9c3873e2891c13dea277bfdf5af46f91c406472e96a5e5ffe2f326777c59b9b5926b2db0961"
        "cd6764cd3bfc7b09af75ce79a34247bf860a502fde341f6e736adb6579fde5b56f8adae621580a6872ad1493ed21f57dd8b2547e0f52f4"
        "ab21950c8e77a9d15caa5799cf517581f072632acff9309dfd3467ee6e9f3e72b0e9e7cde6dc96d979a8be167337d4689da8d84b46ce53"
        "14b90ecdb15c84af1b57b906d53bb9d751928a02cae04dc07e752d422c8b91fb9ae26e3c3f034cc488a98719f70146a62fd4999a4716cb"
        "52ca1212fe0c5fe504fbebe7457253f7993eb5955c440d1d918f873126e6d2c07a613b56137ec4086e9f8dbff10b2333be22203b2e8e48"
        "de68a475b9453c38ee89a4ccfd895ae851",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_025_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_025_PARAMS_KEY_DATA
    .hexData = "50389b5555550000000000000000000050e79855555500000000000010000000000000000000000000000000200"
        "0000000000000000000000000000000000000",
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_026_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_026_PARAMS_KEY_DATA
    .hexData =
        "5f9be2e65ccb8b571ccdf77b0735d47acd7f0525d465039ad0876ddaf68045d04e84250a35dc3a4facfd7560306cd00894fea152a70124"
        "6f08df381814ee1552ea9b0735846e9c458653b780d6cda5a042d3eb9ec532faafd3bb47d718b23c10",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_027_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_027_PARAMS_KEY_DATA
    .hexData = "9e70d407bae1443ed93a186b966ee760505748026759887955bee36be9960a244e210d7a29d7b7e014dc248d3d5"
        "5170bdcb89721ce71172db79ccf0f13dc7bb273e913fe92a314aa5b591fdabbf19f45fcc307b88ca3bab20e1a83"
        "c80bd249d414c6e2c4cda407e52233ff13b527dcd127713e48d9006e62b2bc885a59586347",

    .decryptResult = HKS_SUCCESS,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_028_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_028_PARAMS_KEY_DATA
    .hexData =
        "0ee884e4926c704ee96a07d8727fbcd4452bb17d65533a735665493befca50dcee93f2c5a331042f30254e78de7f2d6067f8513d56f157"
        "9b1945f2a3e312c59dcdbc1393765a02a6ff6ee9086e186a97684909a15512c92c22465ce9671b534975b8aa1904a2f06e23e29d8a438e"
        "9b15bbbb9ea6182479e7823c0ebb27394b9fbe4c167b8ab82f9637c9a28d6f09cf5c8029460ae649407a893b1e68b18940ee77cd8a3439"
        "6b7d8fff53ce1674e3d58f9c66af1ac858d0cd520b578e0b3a855a7f76755a2c9a2bc205b6541b9ef8ac546aeebd881ccf134c29316053"
        "7b0aa8f17a02a8fd6681bbfc62edc56991c9042d3bfc66844182a8e36a9edd35ad149668",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_029_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_029_PARAMS_KEY_DATA
    .hexData =
        "0a8424bd6c97912903cd8f5acd83c99474ca3bc9d793393394bcb5b1e651a9b576e77dd3cbe3914181d2052fa20fc118c25e24188f9e33"
        "85d322a33eae700ca4bcac74f9bf0acbc230c54bb8961cfa76f46b4250b661596995335e627d458aea2491ebccd99312c4ae5b05f2f28e"
        "020dc80d96120a901cc1b35a8bd00a0a539c63c673b5bc73567e0fbe791ade0285eca2b6d6c1ca9fbb1a7a25e986061941294740197563"
        "7f30d813d19c554f46c823318ac8d1c7b2db8a3225950b265ec072e42c46f1cdb58a2bb537ab31b3935e772a5ab06535570f328b2c6cc2"
        "b967a0cb3f37629e6c6e072493b5ca6b6694eb992a9146c469e3b1d24f82cc13ae0465a0a03c8506872b08994b51a30e9d48e2ddc0fcb8"
        "b5f525be9622edeba13fbc922276710e4809cf83e9a46c4889b2d01b23bf164db06b8e84b52ac7d50614a053837d071e711c0792867ea5"
        "12208bf9626c41ed53a25090c817dd6c329c9a029e836689b13d9c8a694dd51e4db4311b5f68b56c2b1feebea8ba39e9073b371ad4b9",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_030_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_030_PARAMS_KEY_DATA
    .hexData =
        "042295390fbf8589571e1adc47b7ed8fcae6118ae762581b2890cfa83fec4662488037a690501b84e037e51ca9e4d9f1cad8e9f937d014"
        "729bf9ec630c357f94dfafdf5dc3c335f93483b8df99d13f88461620269c9aeb6ca68275e47a374d60d6c22d632aa286de179dc1ac90d5"
        "b5ba87539f292a083244d8bc66e68d17469c9b88c9e26f66f68d39ed56567ebfe865866120d905826852561e1af79e12dd4831ea843841"
        "bf18eaa62d3fb5ac9fab8f8d3e271035dbdc3086bce5a201f4ecf32d0cf8279826cf1d4167c1cf066aff055ca0ca197f9319c065c22029"
        "968c76d16bfaf6634ee28bbfbb053dbe558e4c41c4fb1682dcb1d2449c1c86ad9cfbd9f6635103064ca1501133e4cd05f13248f108bfe9"
        "0393d31369f12bcc4f98f285e6cb9481cededabb1619d6b92ad74bfa824af9290e6ab98a29e7aaa992aaa193b7474b05b526778140d99d"
        "150c154ca7caa6c9be0a8d362d8c7ebbfab5ec707f8eb7d52b86a3d8ebc7e7909533a19ab83b6b0cd432eae2400f23761b2379bea8055e"
        "a456b636839dee074b079032a70a65ebe89696502a6796160fa51dbce095d50d5f4a7159d64c3e1f84eac2e22b7ff8a1873a075d1f7fb7"
        "adecce73a5b226316be1fd24586a08467a1fdfa9a2b47f25f5764d1263b5b121be4e1fe383d9c9491319883f9b618eb7a2359482118eb8"
        "848d6b6a53a3e851a1c70832cb1123e99f",

    .decryptResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_031_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_031_PARAMS_KEY_DATA
    .hexData = "0000000000000000000000000000000050e79855555500000000000010000000000000000000000000000000200"
        "0000000000000000000000000000000000000",
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_032_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_032_PARAMS_KEY_DATA
    .hexData =
        "005e9b55555500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_033_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_033_PARAMS_KEY_DATA
    .hexData = "72102aa4fd30d438cfe0fcb04d4d5b491efa17b4f75f636648169fc5730b29bbeb781ceef25ad7cceca3e653a84"
        "31fafb19713ddb566d7618d881aa693248d7bf2d8ff6c1cc7ea2aa1f242227507ec248b412fcbe75aba812578dc"
        "7e8871f8ef19784c21970236be43656feec81bae8577aff26937cdcf924dc8624f7e6a03fe",

    .decryptResult = HKS_SUCCESS,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_034_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_034_PARAMS_KEY_DATA
    .hexData =
        "1c0731b85707b5a67dec0bdc291b8a7c00a6fa2f494e573b47a8c8445eee2b49aa6c6b015b0d4f8be60074a8ee01e914a8c7964d05596d"
        "776c5cdcb826db4574bf579c7d0c204fdeb61f6525f2927adddc0434d48c560206c5a4e95260531aaedfd3ad05a6afa2423aca600ce084"
        "4be4c0dd5c89ee5b5e58dceb92817751880108bdea99acca257893ca0c407fff41f2b3eb8a4c54b06df07d04aa26ba8e349062e0b6f022"
        "6e788c2c57a89a00bf1b5411ea3195d0118385a6bae7efcc2257648c4c5a001c6bb7405439adda7f9c449b6802b6fa9166c448d50b7383"
        "b4b0fc0d0f043a1ec42599e31591be49a344cfed1a0cea16d99f45bbf296fc7a11f2c380",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_035_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_035_PARAMS_KEY_DATA
    .hexData =
        "1a4a913074a6942fae678aa174fba8e958ed838d9720db2a434c1ab80e97ad60cfd0ff14c46c9d76a5d3389d5952a82ae40c25aede5b2c"
        "23cac516b0927dc8740ce199be8f67e034493c4be5a7b5781444f0bef04af35c8de8f11a833645969b460ee730154df3e86f2f92e98295"
        "b10ae10e6cd2544bc02081f987951af012bdf9ed2ad49869891e178b2fffdf10b6babbbebe92f48c342fd0306491e5aa52783f525e6e81"
        "5b598042444cb703e775e4c79faf89a27ee2cfd319db3af4ff30dee3225830a304e35252e9c9b170be90b98d3f5f2bef85ccc9b4892005"
        "e3bfb8ddf42c3dd4f4d53fd87ff2a8e6a8442328389962680960dbf12d85c92bbdb65a10b4cd51e3195bfbc5ce0bcf0073818ff18eabbe"
        "29c441ae15a0fce82d1fd7370bbc9209e15ae994311da9399701fc67e2c19b0875898deb21aa446c87f7c91b611dc95e84a7cfe5c900b3"
        "6c086a173d79cb36981a814bd8a0ca770323371f085935f04417cbad6484e58332e107c5fc9bd21b8c7d12e855849c7cf2be7fac5f3f",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_036_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_036_PARAMS_KEY_DATA
    .hexData =
        "3f8f6c4d7a4a5f2a52d652198476cb4b7936378c0815fbcc5e646b3c60e3495fa4d0ff4bec76b008d7460df745b21656d34bc3bcb45a7f"
        "ae2a5bfe1b227f88d9bc78381e3f2ade35372ecfa34e4195127572ab77096899c0d74eb0c444424884183f1725fd5068c600706b94b3e5"
        "af61fd705e3cd5cbdc6b60496f34f3035939a9942c6bf724a6b68183078e8e9c66c216bf89df0c4c27f92c4719e7760db16d6e0b41f1df"
        "b1897ddb1348d5f70e29649f2a060f2ba93b2f01f6374ca1c53648d12d8c74b063e3abcdaf5f5a4cc329a04c7a2ba5e694dfa5287e7ab4"
        "2565dc533e9f4e7feec7d81519e7743f46e6a6093e1d58a3726024375df22644591bb2f40d4c4fb56832f0e697094a8727c151cba311a7"
        "012e003703a4c0f8197b385fbeafa06adde6aeaedd1a4be6079dd29ccdababf5b166db8d501f673d9d7cf4bcee53bfc1c89e9dc9faf490"
        "ee0a2d409d5a4cc9b164d847fae31977cf6ca597d4bfafadbd8f944aac5620e9e2225327aace2231fc66d4fb45a66dd4e9c156c1aef053"
        "7d53243abe91f7a4993759f86ec692e962ba64d4efd3bbd928d4c921d44f54761e12a506a4a020ff7efb8ea629bc904aebadecd0cd6351"
        "b0ef04b9650737b40e3be064aba627b1d175bf16448e50af4710e7413efe1c45b6e087af7a6e00bcc2e37411a17b9c2323e04da7d42f3f"
        "f24807a3f8f488216af206cf5e109b27dd",

    .decryptResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_037_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_037_PARAMS_KEY_DATA
    .hexData = "0000000000000000000000000000000050e79855555500000000000010000000000000000000000000000000200"
        "0000000000000000000000000000000000000",
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_038_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_038_PARAMS_KEY_DATA
    .hexData =
        "a03c3df7ff7f0000a03c3df7ff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_039_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_039_PARAMS_KEY_DATA
    .hexData = "c0789b555555000000000000000000001efa17b4f75f636648169fc5730b29bbeb781ceef25ad7cceca3e653a84"
        "31fafb19713ddb566d7618d881aa693248d7bf2d8ff6c1cc7ea2aa1f242227507ec248b412fcbe75aba812578dc"
        "7e8871f8ef19784c21970236be43656feec81bae8577aff26937cdcf924dc8624f7e6a03fe",
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_040_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_040_PARAMS_KEY_DATA
    .hexData =
        "0a2b55577fab07262b26f974237ef1b3b55d4d8f6f26672144f12958738d2ef52fa64460ac9d48fddad78f778faf650f10c25185a30b3a"
        "6b0b112a8107b99f54189ec1d3297c76f4677197f536f9917813c735380a0a1d7ef3f1839a2a88e3adb8e9a56e7842573b80b76afb3e32"
        "a360d42efbce9fe874e4ae1e012fee87f5db1820e78e1d428b452a0103825355389980dc6d40289caa8c90bb9c7f4e69fd8154230717e6"
        "0c1a1cdc1c52725ed8329d641a5f3dcd5f4774020082eba94137f4cef5a5f8917a221b53e3311ea3b21059d6d680d8ebb2dd21ceb32e40"
        "bb384da3f37d29b44d95ef6cd8c2de66658326b73eea8785010ef4e8513ae575376f2795",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_041_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_041_PARAMS_KEY_DATA
    .hexData =
        "84807a24502876d729e545f2c07a4eb7df7e15782d3d3a5ec29bce1dc2bacbf03dff90b39442a3b5a3228864ba80af4d27524cdfaa40f6"
        "9f4f34671566a6c8f127ce39c66e7a35425db127f56f8ea79647e7a6edbc2ff6067f93efdc7077fa1dd16354a3f26c3effab326be32dfa"
        "69f48ec15f9d7b58ad026ff7f8606d91b69474d740170bb48a32c4e6131181eb34872f6e0343ab91b2d182e59e614a078cb772020a170e"
        "5e1c925dc84cde890376a632faf61da99033a9040e253d9f69c353e286e7d071e46c1c04633e651d147e57907e20269202d4a6b2855be5"
        "0301578410419f9e40bca573d8b66bf0313dabc375a8b06f878b84a8e9571c86fd8f80b833f8910351ff2d06052ebf50c8d314d84dcdc5"
        "3d576a61219ae99b00af82890349632e5d60055a2d68b9887759c1173c9683f2fbe2b88a57c709994e18dd7813aa2f35a4587b753737e0"
        "3e94e17865dd8a6daf89c34cb1e9d512af5331daf1fe072e8ba5f66db6006ec406c7df4d70142c706c30124a4c5d084522f404e74438",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_042_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_042_PARAMS_KEY_DATA
    .hexData =
        "afca445e73fede94488a5d9b000589a244bd2c27446d26f32e55de317b15b2ca2e8738dc0662db53a472f5a4ab7a8906a9e7bd001066f5"
        "467cc235a0f335942e57def499c5b7f4a0dcbccfc2814cb2daa59410f035fd474447efee395665063ac2c44ac407ea8bffdd8bc7ac2515"
        "dff7cda5ec6cb711038e54b2705fff90b2f64e9961d10b784c2ff71d4b5f1b558f406fa768ce11c0017abd24462cb206047dcb5c90876b"
        "9dfac79cb2093509b9c82a21f9b984342ca80c8559629ef11c08efa543f7d63049c719d7a40770680ab426633f1d34e149124e7cb1cd8b"
        "f49df625517ae55fb5cd7b4a9c7bfb33d426b1d383cc677a41a8b095c57a48f59a1460af92ab8b09c0e7e90dbf4c9d236bc3f5e785c9db"
        "25511a546cfaf4c9595ad1f2a1d65432e9e675b22beff63d7131e6068aeac55c15ca9b4c747d0233db32d0d6208ab5e039beb56042c437"
        "e891a2646042d59e419c82c7dfe207c3a629f071f2bde9caf876fa61d3c3f5b8407376896db682586dc99a1f895466c2808b4953131d4d"
        "020d8f45bac5ccb7b42357bf14a3e50eaef9d6e105c35822e090355a0e13ba21d64beec5d186e1131ed90bdcfb5e9efa40dc0fd1b3bc8f"
        "7a05a4863fe74b3c19c8c561adcb3dc3f62542fc8a7ed645a3d47f7d044e4420ce762656e863b559f57f7540f984d49744f7b2a17e037a"
        "8f6aa6489016f5a36a912f59bf27abbc12",

    .decryptResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_043_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_043_PARAMS_KEY_DATA
    .hexData = "0000000000000000000000000000000050e79855555500000000000010000000000000000000000000000000200"
        "0000000000000000000000000000000000000",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_044_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_044_PARAMS_KEY_DATA
    .hexData =
        "d28a725fbe4b240aba0b2d8c9bf4d024c3044bdb3c505905ebeff937f628b3f1c8d236b411592f4d32f0f8575293db2d3cdc6a35ca14af"
        "029a1d6204ff8c804d5621f5732e2d70fd80c714568592b38bcffb875dc7cf428033121a16838f80c0",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_045_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_045_PARAMS_KEY_DATA
    .hexData = "1e3401e969b112a4a7df26a6aaedf3ff16a7dff41af6edc23490a27dedeea873db62d8b1ef22bb94a7d5c7116fa"
        "aedc5b51ff16dbc2f5b4e064fccb345c8ee7f64cb87015d5e753e399d6f891f7f79d3b017f237a08837795c4744"
        "4d3ec649a636e5968f217e524a9fc1a47eb5da4f18c8dbcdcaa3a3cefd6b4ef09eb15d805f",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_046_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_046_PARAMS_KEY_DATA
    .hexData =
        "8d0cbf0efc5ff64680b435e48977355279a8083567db3ad50208b3ce94103f1794049d7549f968850a81e10504015cde2c433b5285bdbb"
        "cf3dc2f65d2041fea52c767210a4060861027ab88316d43ce78c37cf56f1a4689bb1dd3cb28f049ec63af250bea3b3387f2ce7b3779e8d"
        "a8ea425b1d1313f7f1316f5b52768209c085b847d498a71c0e7356c05243a6c61975b64d9354993b0d289ffec94161e58872c0f47c275d"
        "23f082f27239ce509e4434e555b61b4bc4be22834cd8e9164d86dd20f06e3fab308ca19f33a8b3fc4c931f208c4bf28548e5346014bbfb"
        "afda034a173ef3523302ee1605ab6a9e50e1514d780a8791f2c9afaa4f7701017bacc665",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_047_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_047_PARAMS_KEY_DATA
    .hexData =
        "1d4f65c5a56ae7d3c7eac6da9f60cca30c4ba05e62a0dbf2e5f0fe2f12d359f2cddce668ea4294726790da3ae941bb1186e5fa1197999d"
        "37a0413e1694dd534f9466b7bed275feee9137358448d3a6d3a0d22501b14f1e8bc68ab80feb63500b8b19c4b27d2f64abe448bc4bba74"
        "a8ddebb089f3d0c2cd56ffe169d9e4f3c77df534089ae814d1e6d0064546282043b4fdfbaf3d4b866155fb6f727bab1687132ca4ef9967"
        "ddcbf78ae8d1407b9f1450112bc141f35fbeb57240e99f5ea40a256a6e11b1549b908d66d379a5b744eef01672b891c492b89ed95c7437"
        "f6039d56de1434dc78b9b037e574421f583cf282af3c326b53e816b0a54f931eddc918a6e6b86d66f949080d64cf3d03cafe6de46da8d1"
        "818a104fd4a1791957c14b345d53ca1e22e387ac33c7b8b3e457b1ed92642280c9ad712a55a5fa1f621726ece801b97fc1c53c18c4894f"
        "0c5c34d4fb4322570f29a0d35ad3870d33605e07536d80f51c6e2a2862198c01ff84ed985f109865817c4f8937dd44cdf36e9623a6cd",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_048_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_048_PARAMS_KEY_DATA
    .hexData =
        "8577cf3e564f07d0f9457fd6f9e974dba0e7aa86ad20260db31eafc0ce30aeba1bc23324151bdd6cb8b5f251cb40589bd72b896e4da771"
        "c7b78ce7fb2999c2eaf5ca060feb616967097cfb69ff734f65c43691525ac2d3c36962c2bca15b041641024fe0ff37c487fff44c2fbb7d"
        "7b58203b1203c2adce58c9c4768ab9f1ac07d76aa86a0d857d62a9d9649ebd5242f50753a2d75c893eb8fa3b6a48a600f699004e8e958e"
        "874e6a012e4c45b32c3a5706bb00c32924fc50c6d63606ea7a5fe598bdce3c460dcc48949441384b1505e3b94f191cdce10947d8736c46"
        "4db32a303fb5e61e29dfe69bd185563d3dcf5a7f86412bc450ee160919169f9d87e40257cb48c626bfc1e696cc4a4c0c6e947a308cd60c"
        "dfb6801c2ccc4a5ec25c2caafd0115f8f9fde3eb8d63be36ff31de8347bcc5da2b3202576adcf0280ecefc9e8f83cbcb60684ae5ddf915"
        "232a4a204aa98516d6b6fbb6a6b841b52c786f3755577693efb8ef5eeced7a3bbd186adb9458daadae80d28769c79a95041a64ebad9388"
        "4bbb36e5387fe4264b92c0b0173f690ae39d6d73facb3877f898a60ef4894b52e1c8de3a8e47b69320d2fd412debf80b6569fe185ba89f"
        "a731a5b2cc0231b4189b9c2780256568cd166cf88dc8a67e7980e2ea29871f078ebd92b1ef1570f28171ef61ed1ea7b69abb3aa8abf6f7"
        "a8f600f191e2edbaf8d21785903f47cd19",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};
}  // namespace

class HksCryptoHalRsaOaepDecrypt : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void TearDown();
    void SetUp();
protected:
    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        uint32_t keyLen = testCaseParams.keyData.length() / HKS_COUNT_OF_HALF;
        HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
        ASSERT_EQ(key.data == nullptr, false) << "key malloc failed.";
        for (uint32_t ii = 0; ii < keyLen; ii++) {
            key.data[ii] = ReadHex((const uint8_t *)&testCaseParams.keyData[HKS_COUNT_OF_HALF * ii]);
        }

        uint32_t inLen = testCaseParams.hexData.length() / HKS_COUNT_OF_HALF;
        uint32_t outLen = inLen;

        HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        ASSERT_EQ(message.data == nullptr, false) << "message malloc failed.";
        for (uint32_t ii = 0; ii < inLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[HKS_COUNT_OF_HALF * ii]);
        }

        HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen + HKS_PADDING_SUPPLENMENT) };
        ASSERT_EQ(cipherText.data == nullptr, false) << "cipherText malloc failed.";

        EXPECT_EQ(
            HksCryptoHalDecrypt(&key, &testCaseParams.usageSpec, &message, &cipherText), testCaseParams.decryptResult);
        HKS_FREE(key.data);
        HKS_FREE(message.data);
        HKS_FREE(cipherText.data);
    }
};

void HksCryptoHalRsaOaepDecrypt::SetUpTestCase(void)
{
}

void HksCryptoHalRsaOaepDecrypt::TearDownTestCase(void)
{
}

void HksCryptoHalRsaOaepDecrypt::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalRsaOaepDecrypt::TearDown()
{
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_013
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_013
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-512-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_013, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_013_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_014
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_014
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-768-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_014, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_014_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_015
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_015
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-1024-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_015, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_015_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_016
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_016
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-2048-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_016, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_016_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_017
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_017
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-3072-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_017, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_017_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_018
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_018
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-4096-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_018, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_018_PARAMS);
}
#endif

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_019
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_019
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-512-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_019, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_019_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_020
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_020
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-768-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_020, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_020_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_021
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_021
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-1024-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_021, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_021_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_022
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_022
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-2048-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_022, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_022_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_023
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_023
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-3072-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_023, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_023_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_024
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_024
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-4096-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_024, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_024_PARAMS);
}
#endif //CUT_RSA_4096_TEST

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_025
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_025
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-512-OAEP_SHA256 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_025, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_025_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_026
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_026
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-768-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_026, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_026_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_027
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_027
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-1024-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_027, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_027_PARAMS);
}
#endif //HKS_UNTRUSTED_RUNNING_ENV

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_028
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_028
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-2048-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_028, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_028_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_029
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_029
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-3072-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_029, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_029_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_030
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_030
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-4096-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_030, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_030_PARAMS);
}
#endif

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_031
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_031
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-512-OAEP_SHA384 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_031, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_031_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_032
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_032
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-768-OAEP_SHA384 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_032, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_032_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_033
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_033
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-1024-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_033, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_033_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_034
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_034
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-2048-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_034, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_034_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_035
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_035
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-3072-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_035, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_035_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_036
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_036
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-4096-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_036, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_036_PARAMS);
}
#endif

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_037
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_037
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-512-OAEP_SHA512 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_037, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_037_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_038
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_038
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-768-OAEP_SHA512 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_038, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_038_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_039
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_039
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-1024-OAEP_SHA512 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_039, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_039_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_040
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_040
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-2048-OAEP_SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_040, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_040_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_041
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_041
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-3072-OAEP_SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_041, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_041_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_042
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_042
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-4096-OAEP_SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_042, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_042_PARAMS);
}
#endif

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_043
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_043
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-512-OAEP failed: wrong digest.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_043, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_043_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_044
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_044
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-768-OAEP key failed: wrong digest.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_044, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_044_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_045
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_045
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-1024-OAEP key failed: wrong digest.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_045, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_045_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_046
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_046
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-2048-OAEP key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_046, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_046_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_047
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_047
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-3072-OAEP key.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_047, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_047_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepDecrypt_048
 * @tc.name      : HksCryptoHalRsaOaepDecrypt_048
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt RSA-4096-OAEP key failed: wrong digest.
 */
HWTEST_F(HksCryptoHalRsaOaepDecrypt, HksCryptoHalRsaOaepDecrypt_048, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_DECRYPT_048_PARAMS);
}
#endif
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS