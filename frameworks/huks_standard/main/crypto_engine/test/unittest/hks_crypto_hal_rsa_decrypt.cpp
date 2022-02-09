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

#include "hks_ability.h"
#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"

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
    HksStageType runStage = HksStageType::HKS_STAGE_THREE;

    HksErrorCode decryptResult = HksErrorCode::HKS_SUCCESS;
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_001_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData =
        "0100000000020000400000004000000040000000ba5395c32972cdd04061fc45ac6d501555110a32300d44f57d6d7d9b478888361d815b"
        "45c30aedce3674cf440c455552ba05ea9ef4659f37077c9498541f79d10000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000010001355e09702ba801411b9fb514f3ad1f99ec"
        "9283dc1a1d42da1981c9cf36eee92c3154e0b65cd6653c01a0568dec5f969bf6581ca2aa3c572138cfc9a0b2b3535d",
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
    .keyData =
        "0100000000040000800000008000000080000000a51514cb129c6e19e50eaf764e08067e5720ba300a9031a5a40509d210b0e5a072b7dc"
        "6e0b9da82b59bb5c41b0baabbd4b534eb6a8fd50c25a7d9b7b1c7d9e808c5de65a0658fbb353b635dce78ab6d09478257b7e8b5b508cd7"
        "5a735ca3944aba2bc8f443cd9ed6b0096cfda268e2fda1462182b313b25f27ecdc4510fc87770000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100"
        "016671c4ab98eb16b05f2353e3d8dcc61ad53aec10301df791514e0720235783c8a4285154c1449f3df7bb7baf105b67845b2061b29d00"
        "4683b5e049028755b56c15879f4b5dc76e57fd0296c1286b347f7387b2f9e8cee0fbd6cf034cd16dffa6cc2f5c1101c1f430c265ea0d5b"
        "c27a01672405d4f670baf194ccb4ba87a3c5b1",
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

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_004_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData =
        "0100000000080000000100000001000000010000a0286e22fea334e1ec2f48a955d91d44992e2fda06d23ff00bbfdd70f0f961bed02781"
        "e345ad866f63c217ae82f84db6f3ef2d5937fe9684f2c1e1ac091e81eb7dc1da7bb4a2ad7e3bb2911cfbfa8c0244527b91259b5b7ac1e4"
        "32701ac4e5c87186b59340ae0b67e4d2805ad01431121d907181aaac1d7a26e4703b1812c711fa3d056a8f4709a923193895f2657e66b0"
        "b109dbc65c9703bc08d79696f35f63e790aff9cf4323320288d5bc9360f08dc9576d7cba0792bc56864a844b72c49041340b8b3487dba1"
        "f724bac429e7d40c99d752d4be9cca352b59a7594ddae02784c3b8e137f141e2a77e098524aec3b96d989fe09e28578fabeb6e6976bba3"
        "77000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000100010490024b36ebd956d24eaa88406cd5fb9d4d"
        "868974864ad200d3af70473d237eb7195906eb763d0d314f57335e81ca5cfae80667b343aa7011265ad276d40aa975c4aeffb52ea9389e"
        "64c0e38d7e1ebcf5cb4fbfdbcd6836c00d4b2e8c64ad931f40d22d66bb4e91e01feb0e2b3d580487191552b754fde5fbf3a80ad6edba04"
        "0a8d0c30fa413ce7cb7d1bdd5960cb6d9c68285cf7ca8abde4c2a5aa2f7ef875e66094b9a263e529f38651f405ee9410ae45f3f272effb"
        "d318c23eb112bb295b79cfff9f5df4ed2a91c590c03fdb304e74dd7758916b91e4716a6b4f5703516aaad8a8cb9f2b603f11ac90b0e941"
        "ffdf7059c7ba1a74c5bf6435a8040f175ae1",
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
    .keyData =
        "01000000000c0000800100008001000080010000b3c325e9339d6cc17db61da704dc05364320f4ca208467ddbf3d44a625a5dc3a6cd134"
        "27cce14a3f0a2f7a50a6e377b52f73bb824254d8bed785b91303f30211c20d1bef9ddd5e4ee88b7425ef2846f41e791d5a9670682553be"
        "ce2dbf41d88abbfde7dc3f450572290daabb55a1a56b28b282de9576249de95d0075d47914943f52d9a559ddcec9b5f610eeee9bf10cd3"
        "d807d00abdf94e7f63a50d01ddb8cff95e0452e56e614115031fe5ddb91d46c13358c1f42685fc19e09a2cf3170fa0bf0e0a380400fc8c"
        "c3e2f287c68d48ae04ecd3448273198744f37187eee774cc2dcc28fd3b037af7f4c54e30dd254c12b6f482c32e2de7014fb48f5badfea3"
        "91531b6a58c1c95f84ded943cc8fe113ff21e3c5f5625d88c77ee24ecad6b22e0013831af764c2a87c7db71062b922c136402a102391c4"
        "911bb286e8d96efa8e1c629d8818fd02de45bcdb8352cf16af7f282e5676a4b07c74a7e52b94726963fb79f433991114415474f90b10e3"
        "fea5d24043ce964298a938aa79014ae98da4b3000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000010001546d4714ebc4f81b382b9c69a102a500032f2b48f354bc638d39fd4ffb4696d469df279bb9"
        "c1e5d90db396c2e25edb0e21a73d5dc4418d3ab4867d91ccbd092fc5efda3b03edc029575687ca7934757e9a015024079beb8dfc7314ea"
        "af75017ac7284d09483de67ce38323b8b0532719d9175e17a422c4b7d5ae7454e2e1ab24a54908277cb98c317860853b729d92ecef61fa"
        "e95ee23281079b891d3ecf1fc9add8d63708c27ab2d2679147a8871494f290671350d3f7019c35bcb377c850f1e87dcc174873ecd98d0c"
        "f6ed9dd83118142d9f9cef1301b221a047440609ac3be88bf69e8e50843f75c855f974dc00e18168c8000a9a4ca65247560a5187ffed04"
        "4eb4da9e4e517870ab2dcbf6574c63676f8a3620852940c6b185186d21a53bdb20e7bf7d16288a3d9e0d47844d2b605f8ba879e87ce348"
        "033667577d6c91645f30f2720e9f9229ccc7a270215b124677650e94e5c181cdac04e2b2dfb8c3165f3a4a556c78684f60e602fb79f911"
        "68a938c5f0c4254265ae72f54938268021",
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
    .keyData =
        "0100000000100000000200000002000000020000e5a087382ce37175f66f6e4ebc00c0cb7d9b0486425eed1bf831cb43566031894221a1"
        "f1b0c7275318d82b186640256c3f1325f32a740e2c9ab3f7ca866d02b982f9caaa59eb49d7e3268f6b902e589ec65c91164d1e370ec407"
        "b06f9687b059835574ce9a541607b08e18a33fc74ec9ae0bb7e2a3c1fd73eeffb493e2e939b9ab7501dd0692ac63d262cb4130fae6be54"
        "42964a80f3e7474c0fee48dce2940e7fae7a8a8aec30a8d71dab54b1d42b1a364fc60a837f2533ca79dec02796cc00202db34dfb674641"
        "d20aa00c1d748aae18f5219ff5232a479e4e61a653c54b84ec1fbbd16624d595af1bb831508af96f02494312e46bcccca9e8c6f471c082"
        "c7a2e742a239cb908279b63f29385d53172ece4a85272acca9e52b9599c244a6ee786b7ddb599c198362bd5697c522f667457c11503286"
        "4e4364325873652f9e69b27aae8b1c8c385164c8edcdf401dc306ade1907449bd1c58593681b5f8e8cb536c9e60390152ce648ada0f091"
        "d3b11ca660f44421257434b69f4f60a6159cb86c8911559319e765550d142d58e844896259f0e8eb471a2150a79221c31d0b2032b3d716"
        "b3c00255eb300fbb2fba4bec0d4041d7b010939fd339e8080d52c7ded936af229358a580ac87518bbd785fb103534b9ad3f19501125b5a"
        "9467d4b76e5e571d2b1393454e92711be52d1f9482f7997f4e65102995874febc087792b77000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000198"
        "f34d3e40c01ac22d2cd9f7bdc86ea2dc7e560c2bc758fe695a997eb7d90905d933d7cfca254d6f4f3c25b071e3464a0cd56f50c2355d7f"
        "9e6843a3f5d8449956c19599d49d21a9985705eeeab1c43bb5fad0755f56c1eba6ed4c3b77b3d7e637d1c3251eace5a3a7996e95c694b6"
        "4926120e20fb5ceababf36398ccbf6f78951c8753e48f387ba51d796754cefc2a482317c341222e4299c637c1fb269859f06b32c527de8"
        "871cdf7496bbaa5b9d7e2f3101c3dd04e2bdd59f499d0a81aa4e6720a9af46c6ea884b24e2a84f3262714694791a37c97d8f08c642caec"
        "3f9d66e374dbc0c5ddc11a9bf1c5c5ab557681d7aefeeb6594dc6c72bc67514937a6a399d80094486382538c330569a3a944375751d9eb"
        "ed82c39bf81cf27f88c211070960d781719fb64d3c7a507c955e015cd3c4e968fea4d999d57245b30bcffae2c44ab6bfe4d2c3d7457a68"
        "3f0580cdc0d4910e071ef624888db604f110eb6aa2a454cd9b74d4b9b857994452c092c20df2a0110ed81c8275aa745971e900c9485f67"
        "82fbf666215762f2f971e4d213be05cb1760e4c7bfc3fb17ae1409039568ba3d9e2d34e282cc43c9db4ed8286a0a504022cbd23cd68cc7"
        "94685dd6daddf1054673cb9b517495e0c39569e0627e4b8ef80bb196f58f53627af0a4142fb2b469cc767a348ce74ea8dbdc647386e485"
        "62a124488021988f9d71ff68f2028a19",
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

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_007_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData =
        "0100000000020000400000004000000040000000a6a29490a5a6b309192f7571daa7cacce05dc5a5af6e4c0648ffc3dd72704651c806ee"
        "0cb61afc2f118bb24075a2f303cc548bfd9fea2c3dc945d5d976457ae10000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000100012a295cb9b4901720a834afdc9cdc739d9e"
        "ef5b00ef0053500bcc5afc7ee6158457279c58942bafa28d436be509cd30b841e40cb769efffe8723b70c6f464f599",
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
    .keyData =
        "0100000000030000600000006000000060000000d056e8b387700c781feb01097ecd9868c32af0cea33292634b2b0027117b75af0ebdb9"
        "6172c776ef95bb7c3dcfa6126858e6fe69c87e0ed69dcf81e15ebef50f03fbaffaee527c291f3740e521730271eb3b63f4057cba780c6a"
        "c8520816d79300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001acbf7361f12a5a5c"
        "7c72bac069d105cfd00c59f1ace630f57e0d60aa0457ef63c10055a754a9c997acfaf170bb2dc3d21b8e26541ba01ff0b99788b13a553b"
        "f97c8c71cd149dcb421fb96affc55a6588adb642251bd991ef7d54890950e5b719",
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
    .keyData =
        "0100000000040000800000008000000080000000bc294482ddb7abe39a04a31b8410e9115691e8cdedc7aa060a63977d55a6f924f8387d"
        "93bba101ad7351ad244baf25d19a840dc975409801fe634a603cce8fec3f2c40db3d2b6f0053e4ae0c073f5d21c9632e4d3a61f4afac89"
        "5367e58eb6fc9a723e75f14a8dcd7dd210644427d9d26da3cb88aa085e9d3fb74bdeb16d4d250000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100"
        "014fc97801be1eba46a2f2c06f548b0f2988fa0a2bf85e281cb39f1387d4201f99ab9fd8b02269dd9a3d422f172af8b422b350b7bfeb76"
        "5e7ec9ee3485a68338c78cc6cd9ceb514aa6b7cce5811306d6d256b3a1d6f6e1a2c309b0d721a0a32566c8e030794c90d984af31685a99"
        "70960dc0698a51f3e03211fa43b3a4f9336141",
    .hexData = "29bbe6754eba61b5b2907a73f03d4c3d21ec3b15296f78cc12bc870eaea302e2f1f0703c53d9a8ead057079affc"
                          "0e1bf7b740593f826f8b2e78c7f580bb311c04bae6005576a0df747c7353b827719ba551fdbc40209733b2b4049"
                          "de1fbae809ff6d548b53338bb9259699caed4281e2a5f10ae9247436ef9b892ba2d4be4fd7",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_DECRYPT_010_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData =
        "0100000000080000000100000001000000010000ddf3e9c6589658e5c124a49d473db529e8eb08b99c351cf7c5d502f64def9752d4ee88"
        "d942cbdbc7fb46eac9d9b9f9b309fbffa99c9fe05363b2d5e71c2d132bc83d74f0b8441266fc2f6f0462b54fa0ffaef92bb93cec2d1805"
        "9db40ff9d579f7980c08cb9a30d076d6ebf50f4166514bd00cdf20ca042ddf13581feddd32b15e8508f2b185f4e6c77217c5096a9dfecd"
        "5132ee4ce41bccd3faa75abcf1014e5e27328d3a1b08e56c33d5f5f2fe8b8f232db6953a337bca29e2726165732c8d1aae10a6e9c60ce5"
        "4b2423868e6d024dfdfab45fbb3d589d06fb8f55564bdc2bb07c1c84cf8c076045706b36e6715c4dc8cd1f4fe751de77b031b5bcf7cde7"
        "41000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000001000151ac53b5fd1b361335837a5fb5bb6b52c4b6"
        "d83b14d42698b65faffb5aaa7390b37223416f66fcb5162dfe6fd082b2f3c314cbfb69fb1add14aed62f791acd172b54121812765a1f33"
        "657100b821e7ef62a6cc61de842094676689a59ccb5e56c75957f45497a4a6d1543cf7ac69707131e89913f248e448ccf19d58027b870f"
        "361c57bc60e75da62e75d94b7e42c544e7ef183fd1935f0ca8d637e18cc4acae0e99f8aabbf83c968460b5237eac3271f214fd10580166"
        "c836e067948438f8a3c5edded4871baf6acab762e501db5fde6f2ec201072532c109d0a55cdf0e275322ccf326c9a2a6b235d5742067b6"
        "f7912bf772c9039385ab0a81c0186bf91001",
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
    .keyData =
        "01000000000c0000800100008001000080010000b6267a0a854bc91d6a7f469ea9212dc3fb2a5a2e6626ec1f41e3f6436361b0c8141bcc"
        "77e3e568dfee0068e0c863681ba0383b22046e6ef166274cbe19893e8a0ad4fdf86475998b0b00af04ccb0d1e1b42f89a20f56dccbfe14"
        "45e794a8123434a252eab9e386a35d663669d219b34ad92f7a64a90a91f25ffa002ccc589843fde8cb3111d566b4a665c51d801f290ceb"
        "be980ae71fad125e851c426d240fa361414c34a037d2a0840a25e4af4355931a6efc7c9faf11a5e8d225387965ea51f81f910786b9dfa9"
        "8459678db6a0670b14b64a2be05ebd2db0f25fcab225f719b5cd97a0f38c490d38a710d594d50ba75ab0ebc04456fe12514f96351cdc9a"
        "8a868389c932b3572726ce2303ab1e7f85c43c18e52ae14efcad4e0f65bffbf3254e10ad616ce169594373dcf1d44016c4fd77023bb0a8"
        "302ce72de9ce1aba9d885c05aefa935492592afaae543c8c99e997dff2c1125a3931f5897b5ce2c6217d69be0d74612dea66347c076c44"
        "5849c786e36a0c285e0f3b838d630b3347a96b000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000100013f242b5e0642f51e6b525f6a947a59e0fbe9fc84e5084d05b0d393045d28fa1d014b799f7d"
        "b2829e4d647af6a0c044d07ec3bf4bd5796a9fe7a76be4e1f93f629ecaa2973e4bbdc40336637528778ae9d08a420d997fa4de59df3134"
        "4bc5cf39a59d375d02bf2a66eaf3899d39258b8f40a642a92e27e9dbb905729614e80930588e20118c7b0b35481133393cb69086581a23"
        "9e73ebf914cb0b1d76b15ab4c90fe790c1156104747c11007dbb7b7de8965b2ecf0c93a56c7bbe8d047ca0a58edaa75649497e7a4c1b69"
        "90a9d6fda6dcbf9732d517a01a3818287c8717949fa4820d88f3a5918bc0d629d88ae63e1b9ba0a52bd8cefdf30e4b273e9ead163dad87"
        "bafb456b7af8b8e5dc353eda84195190b994e447758f082c1d9700d83655f1956f1c75dd5cde9880169b7f7720cc39761411a3c98cb25d"
        "ce939c5c1724c07f31a1bfb59771d06cee3c6057e04489ceec6a122866d67d19923c7c5cbf598e48ab4fede639807b9d3d6f83aa821411"
        "94019bc2c4fd028ccca7dc4e56e657f931",
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
    .keyData =
        "0100000000100000000200000002000000020000c214a594a87457faccdfa9e466160af3a292f93003783fa46feeae2d84c0c41704d01a"
        "2eb9874b59fcd217d7394e01e20a9fd162ef4de6c87adc11d423bc13c1f2b609e73c5ff20251a7e9e940fdb2fed3e8d04a2dc5fd33708e"
        "aeea6b85ea021487daa0d8cc52b1ee0299915a5dc5b469792908aa05bad12d4c1af13c5ab552849c480ac6bec9fd4256d2b2b8f4f48583"
        "f471c8f9e3c099c170e4863f5935ae11475d45bf4a1c5022937c31cdb23379f3bdbbfc8f59cce6dff3b02f201f660640605c9cf9f489da"
        "74d378f9a97cc1284662346fd78f621c7b36b15b60cc5d645b5217a5aaee9f4c5f0cd1a3ba6d4fcfc49e472951e300af124106f38fc10f"
        "3e40812997b93c35e44e8267e5d88bb0fba1e941801ee360317d1b4be71e40332d2a44c8727f7ae36eefe83906b4bc44214f126882f03a"
        "9856e08268784c39fa351a7a00fbe916c2279ca679d7fa39a386e7ad50a08511031a480ffb449928b8e6b729921671f882f85dffbea3b6"
        "93c362c311cba5ab909f06c7e2e333d11ca9ed0a821f4029101788071471236bd7af5a6e84ee6f5b7010a35ecd4abc894db5e5283322e7"
        "5ef6f539d8a1524f155a7d2da825f42b11b80358d806d28934ef73014e863eeca74156d4b1b066ae11a875b746164095ed815b10478a37"
        "cae6fa96fe16e9833397270fd531f7c1a9cfae0caad254e3b659e37e3fa9a1dcf07b48e101000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100012f"
        "99f4cab34e65cdc3b60feb4f0695051098cfb971006b4b9f9080f3f51d7a7ad2d95fb29a1a8ee6b155ae37417cda856069b667779e39be"
        "6e33cfc3a2481ce872e92720a9f4365d4f3dc9e745e373a580c017663a37d7546884f66dd49571c1b4db654a12227b1ddcec9251ce4235"
        "9d7c49154164c22701eb04418f6d682a14e525979ddd052a718d75d213b7bd8cc3ba8b97e4dd357925bd063d6697deff85840366e31679"
        "ccdbf2bf0db5016875abb19695a6ea59f221a64814ac5a4a99316b54b722614413139b97ca922179d1be5914f91b7d59538cfcc37b5898"
        "3347acb7a138df8f3f1b9f15a9053a0d1d8677c517b508736723e1ccae5a501eb011569bd1d1dc71f75681c5871497a149bdd4c0cfe7ca"
        "acca439faba11526aee5f280345555c81f09213e6d6699511cece3dcb1ef47694c3d2eada01653d565dd0f85a56b9bf35ed63f1dcffdec"
        "73939a2bd962f67feb49aeca0395214d7d2430b6a9c43a93f49386ee99579a46ad9848138ca08c0c02c4036f538f41b708bd1ce3be00c6"
        "4caff64bfbeafe65d19b245f3547b999d84163e51c200b91b762728e43d5eace6ebec90119be092ae6f131ea7b5d5901eda3b8cbca01f0"
        "df7f98dc3aab37712c3b223d03510ce241cb81e5719fb8ee161a1346d8323397d2ab673695d5d08816f1c0fc61073eb33471d29d7ecdcd"
        "083678709efd4b63e5f0a699ec19e949",
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
    void RunTestCase(const TestCaseParams &testCaseParams)
    {
        uint32_t keyLen = testCaseParams.keyData.length() / HKS_COUNT_OF_HALF;
        HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
        for (uint32_t ii = 0; ii < keyLen; ii++) {
            key.data[ii] = ReadHex((const uint8_t *)&testCaseParams.keyData[2 * ii]);
        }

        uint32_t inLen = testCaseParams.hexData.length() / HKS_COUNT_OF_HALF;
        uint32_t outLen = inLen;

        HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        for (uint32_t ii = 0; ii < inLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[2 * ii]);
        }

        HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen + HKS_PADDING_SUPPLENMENT) };

        if (testCaseParams.runStage == HksStageType::HKS_STAGE_THREE) {
            void* context = (void *)HksMalloc(HKS_CONTEXT_DATA_MAX);
            EXPECT_EQ(HksCryptoHalDecryptInit(&key, &testCaseParams.usageSpec, &context), HKS_SUCCESS);

            uint32_t point = 0;
            if (inLen > HKS_UPDATE_DATA_MAX) {
                HksBlob messageUpdate = {
                    .size = HKS_UPDATE_DATA_MAX,
                    .data = (uint8_t *)HksMalloc(HKS_UPDATE_DATA_MAX)
                };
                HksBlob out = { .size = HKS_UPDATE_DATA_MAX, .data = (uint8_t *)HksMalloc(HKS_UPDATE_DATA_MAX) };
                while (point < inLen - HKS_UPDATE_DATA_MAX) {
                    memcpy_s(messageUpdate.data, messageUpdate.size, &message.data[point], HKS_UPDATE_DATA_MAX);
                    EXPECT_EQ(HksCryptoHalDecryptUpdate(&messageUpdate, context, &out,
                        testCaseParams.usageSpec.algType), HKS_SUCCESS);
                    point = point + HKS_UPDATE_DATA_MAX;
                }

                HksFree(out.data);
                HksFree(messageUpdate.data);
            }

            uint32_t lastLen = inLen - point;
            HksBlob messageLast = { .size = lastLen, .data = (uint8_t *)HksMalloc(lastLen) };
            memcpy_s(messageLast.data, lastLen, &message.data[point], lastLen);
            HksBlob tagAead = { .size = 0, .data = nullptr };
            EXPECT_EQ(HksCryptoHalDecryptFinal(&messageLast, &context, &cipherText, &tagAead,
                testCaseParams.usageSpec.algType), HKS_SUCCESS);

            HksFree(messageLast.data);
        } else {
            EXPECT_EQ(HksCryptoHalDecrypt(&key, &testCaseParams.usageSpec, &message, &cipherText),
                testCaseParams.decryptResult);
        }

        HksFree(key.data);
        HksFree(message.data);
        HksFree(cipherText.data);
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