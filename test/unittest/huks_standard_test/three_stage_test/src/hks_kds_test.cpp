/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_kds_test.h"
#include "hks_client_ipc.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

// #include "hks_log.h"
// #include "hks_mem.h"
// #include "hks_param.h"
// #include "hks_type_inner.h"
#include "hks_ability.h"
#include "hks_client_service.h"
#include "hks_three_stage_test_common.h"
// #include "huks_access.h"
#include "base/security/huks/services/huks_standard/huks_engine/main/core/src/hks_kds.c"

using namespace testing::ext;
namespace Unittest::HksKdsTest {
namespace {
constexpr uint32_t KDS_CIPHER_TEST_SIZE = 16;
constexpr uint32_t KDS_PLAIN_TEST_SIZE = 16;
// constexpr uint32_t KDS_ABNORMAL_CHANGE_SIZE = 1;
constexpr uint32_t KDS_CUSTOM_INFO_CUR_SIZE = 32;
const uint8_t SALT[KDS_SALT_SIZE] = {0};
const uint8_t TMP_PK[KDS_TMP_PK_SIZE] = {
    2,0,0,0,0,1,0,0,32,0,0,0,32,0,0,0,
    0,0,0,0,148,39,21,198,217,171,244,149,90,91,243,89,
    57,166,224,91,107,222,34,69,255,35,44,95,218,234,249,116,
    178,225,223,74,170,50,97,75,67,143,96,89,52,45,105,13,
    16,35,99,138,84,130,151,15,190,243,143,142,219,109,1,1,
    199,207,18,182
};
const uint8_t CUSTOM_INFO[KDS_CUSTOM_INFO_CUR_SIZE] = {
    17, 34, 51, 68, 85, 102, 119, 136,
    17, 34, 51, 68, 85, 102, 119, 136,
    17, 34, 51, 68, 85, 102, 119, 136,
    17, 34, 51, 68, 85, 102, 119, 136
};
const uint8_t IV[KDS_IV_SIZE] = {
    139, 120, 59, 99, 233, 204, 159, 105,
    24, 216, 237, 17
};
const uint8_t AAD[KDS_AAD_SIZE] = {
    107, 160, 191, 184, 106, 120, 254, 205,
    60, 22, 212, 235, 80, 223, 99, 57
};
const uint8_t MAC[KDS_MAC_SIZE] = {0};
const uint8_t CIPHER_TEXT[KDS_CIPHER_TEST_SIZE] = {
    44, 186, 189, 208, 215, 9, 86, 138,
    5, 10, 58, 236, 171, 76, 194, 163
};
const uint8_t PLAIN_TEXT_EXPECTED[KDS_PLAIN_TEST_SIZE] = {
    17, 34, 51, 68, 85, 102, 119, 136,
    17, 34, 51, 68, 85, 102, 119, 136
};
struct TestCaseParams {
    std::vector<HksParam> params;
    uint32_t plainTextSize;
    uint32_t saltType;
    HksErrorCode kdsResult = HksErrorCode::HKS_SUCCESS;
};

const struct HksParam kds_Paramas001[] = {
    {
        .tag = HKS_TAG_SALT,
        .blob = {
            .size = KDS_SALT_SIZE,
            .data = const_cast<uint8_t *>(SALT)
        }
    }, {
        .tag = HKS_TAG_AGREE_PUBLIC_KEY,
        .blob = {
            .size = KDS_TMP_PK_SIZE,
            .data = const_cast<uint8_t *>(TMP_PK)
        }
    }, {
        .tag = HKS_TAG_INFO,
        .blob = {
            .size = KDS_CUSTOM_INFO_SIZE,
            .data = const_cast<uint8_t *>(CUSTOM_INFO)
        }
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = KDS_IV_SIZE,
            .data = const_cast<uint8_t *>(IV)
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = KDS_AAD_SIZE,
            .data = const_cast<uint8_t *>(AAD)
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = KDS_MAC_SIZE,
            .data = const_cast<uint8_t *>(MAC)
        }
    }, {
        .tag = HKS_TAG_CRYPTO_CTX,
        .blob = {
            .size = KDS_CIPHER_TEST_SIZE,
            .data = const_cast<uint8_t *>(CIPHER_TEXT)
        }
    }
};

const TestCaseParams HKS_KDS_001_PARAMS = {
    .params = vector<HksParam> (kds_Paramas001, kds_Paramas001 + KDS_INPUT_PARAMS_NUMBER),
    .plainTextSize = KDS_PLAIN_TEST_SIZE,
    .saltType = KDS_SALT_TYPE_TA,
    .kdsResult = HKS_SUCCESS,
};

// 异常1：传入空的paramSet指针

// 异常2：paramSet数量不符合

// 异常3：paramSet符合tag的数量不对（如出现重复）

// 异常4：paramSet中的blob == null， size == 0

// 异常5：saltType不符合要求

// ecdh异常6： pubKey长度不符合规范

// ecdh异常7: salt长度不符合规范

// hmac异常8： 定制信息长度不符合规范

// aes异常9： 密文明文长度不匹配

// aes异常10： 密文、明文不为16整数倍

// aes异常11： 密文、明文长度不符合规范

// aes异常12：AAD长度错误

// aes异常13：IV长度错误

// aes异常14： MAC长度错误
} // 匿名类namespace
class HksKdsTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
protected:
    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        std::cout << "begin \n";
        HKS_LOG_E("enter run test case");
        HksBlob plainText = { .size = 0, .data = nullptr };
        if (testCaseParams.plainTextSize != 0) {
            plainText = { .size = testCaseParams.plainTextSize,
                .data = reinterpret_cast<uint8_t *> (HksMalloc(testCaseParams.plainTextSize)) };
        }
        ASSERT_NE(plainText.data, nullptr) << "malloc failed";
        std::cout << "malloc blob success \n";
        HKS_LOG_E("malloc blob success");
        struct HksParamSet *kdsParamSet = nullptr;
        int32_t ret = InitParamSet(&kdsParamSet, testCaseParams.params.data(),
            testCaseParams.params.size());
        EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(kdsParams) failed";
        std::cout << "malloc param set success \n";
        HKS_LOG_E("malloc param set success");

        ret = HuksCoreChipsetPlatformDecrypt(kdsParamSet, &plainText, testCaseParams.saltType);
        std::cout << "kds done \n";
        HKS_LOG_E("kds done");
        EXPECT_EQ(ret, testCaseParams.kdsResult) << "not expected result";
        if (testCaseParams.kdsResult == HKS_SUCCESS) {
            bool equalBytes = false;
            do {
                if (plainText.size != KDS_PLAIN_TEST_SIZE) {
                    break;
                }
                bool eachEqual = true;
                for (uint32_t i = 0; i < KDS_PLAIN_TEST_SIZE; i++) {
                    if (plainText.data[i] != PLAIN_TEXT_EXPECTED[i]) {
                        eachEqual = false;
                        break;
                    }
                }
                if (!eachEqual) {
                    break;
                }
                equalBytes = true;
            } while(0);
            // HksMemCmp(const void *ptr1, const void *ptr2, uint32_t size)
            EXPECT_EQ(equalBytes, true) << "plainText not equal!";
        }
        HKS_LOG_E("free begin");
        HksFreeParamSet(&kdsParamSet);
        HksFree(plainText.data);
        std::cout << "end '\n";
        HKS_LOG_E("free done");
    }
};

void HksKdsTest::SetUpTestCase(void)
{
    HKS_LOG_E("set up cases");
}

void HksKdsTest::TearDownTestCase(void)
{
}

void HksKdsTest::SetUp()
{
    HKS_LOG_E("enter HksServiceInitialize");
    // HksCryptoAbilityInit();
    HksServiceInitialize();
    // HksClientInitialize();
    HKS_LOG_E("init end");
}

void HksKdsTest::TearDown()
{
}

/**
 * @tc.name: HksKdsTest.HksKdsTest001
 * @tc.desc: tdd Normal process of KDS, expect ret == HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksKdsTest, HksKdsTest001, TestSize.Level0)
{
    HKS_LOG_E("enter HksKdsTest001");
    // uint8_t huksPlatFormPubKey[84] = {2,0,0,0,0,1,0,0,32,0,0,0,32,0,0,0,0,0,0,0,40,34,254,220,207,35,20,25,22,166,190,152,29,122,17,25,37,170,188,207,1,151,147,51,181,134,108,183,230,9,154,147,185,70,213,187,107,142,3,83,192,166,45,153,61,90,16,207,141,138,236,156,57,254,213,132,55,231,68,12,244,252,173,178};
    // uint32_t algName = HKS_ALG_ECC;
    // uint8_t transedPubKey[91] = {0};
    // uint8_t huksTmpPkData[84] = {0};
    // struct HksBlob huksPK = { .size = 84, .data = huksPlatFormPubKey };
    // struct HksBlob transedPK = { .size = 91, .data = transedPubKey };
    // int32_t ret = TranslateToX509PublicKey(&huksPK, &transedPK);
    // EXPECT_EQ(ret, 0);
    // std::cout << "X509 platform pub key" << std::endl;
    // for (uint32_t i = 0; i < transedPK.size; i++) {
    //     std::cout << (int)transedPK.data[i] << ",";
    // }
    // uint8_t X509tmpPK[91] = {
    //     48,89,48,19,6,7,42,134,72,206,61,2,1,6,8,42,134,72,206,61,
    //     3,1,7,3,66,0,4,148,39,21,198,217,171,244,149,90,91,243,89,57,166,224,91,107,222,34,69,255,35,44,95,218,234,249,116,178,225,223,74,
    //     170,50,97,75,67,143,96,89,52,45,105,13,16,35,99,138,84,130,151,15,190,243,143,142,219,109,1,1,199,207,18,182
    // };
    // struct HksBlob X509tmpPk = {
    //     .size = 91,
    //     .data = X509tmpPK
    // };
    // struct HksBlob huksTmpPK =
    // {
    //     .size = 84,
    //     .data = huksTmpPkData
    // };
    // ret = TranslateFromX509PublicKey(algName, &X509tmpPk, &huksTmpPK);
    // EXPECT_EQ(ret, 0);
    // std::cout << "Huks tmpPK" << std::endl;
    // for (uint32_t i = 0; i < huksTmpPK.size; i++) {
    //     std::cout << (int)huksTmpPK.data[i] << ",";
    // }
    RunTestCase(HKS_KDS_001_PARAMS);
}

}
