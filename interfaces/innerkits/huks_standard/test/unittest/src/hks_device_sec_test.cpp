/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "hks_device_sec_test.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_api_performance.h"
#include "hks_test_common.h"
#include "hks_test_log.h"
#include "hks_test_mem.h"
#include "hks_type.h"

using namespace testing::ext;
namespace {
class HksDeviceSecTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksDeviceSecTest::SetUpTestCase(void)
{
}

void HksDeviceSecTest::TearDownTestCase(void)
{
}

void HksDeviceSecTest::SetUp()
{
}

void HksDeviceSecTest::TearDown()
{
}

char g_secInfoData[] = "hi_security_level_info";
char g_challengeData[] = "hi_security_level_info";
const int g_size = 128;

static int32_t IdAttestTest()
{
    HKS_TEST_LOG_E("id attest test start");
    struct HksBlob challenge = { sizeof(g_challengeData), (uint8_t *)g_challengeData };
    uint8_t *cert = (uint8_t *)HksTestMalloc(g_size);
    if (cert == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    const struct HksBlob keyAlias = { sizeof(g_secInfoData), (uint8_t *)g_secInfoData };
    struct HksBlob certChainBlob = { g_size, cert };
    struct HksCertChain certChain = { &certChainBlob, 1 }; // 1 is the cert count
    int32_t ret = HKS_ERROR_MALLOC_FAIL;
    struct HksParamSet *paramSet = nullptr;
    do {
        ret = HksInitParamSet(&paramSet);
        if (ret != HKS_SUCCESS) {
            break;
        }
        struct HksParam tmpParam[] = {
            { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = challenge },
        };
        ret = HksAddParams(paramSet, tmpParam, sizeof(tmpParam) / sizeof(tmpParam[0]));
        if (ret != HKS_SUCCESS) {
            break;
        }
        ret = HksBuildParamSet(&paramSet);
        if (ret != HKS_SUCCESS) {
            break;
        }
        ret = HksAttestKey(&keyAlias, paramSet, &certChain);
    } while (0);

    HKS_TEST_LOG_E("id attest test result is %x", ret);
    printf("cert chain is %s\n", (char *)certChainBlob.data);
    HksFreeParamSet(&paramSet);
    HksTestFree(cert);
    return ret;
}

static void FreeBuf(uint8_t *a, uint8_t *b, uint8_t *c)
{
    if (a != nullptr) {
        HksTestFree(a);
    }
    if (b != nullptr) {
        HksTestFree(b);
    }
    if (c != nullptr) {
        HksTestFree(c);
    }
}
static int32_t ValidateCertChainTest()
{
    HKS_TEST_LOG_E("validate cert chain test start");
    uint8_t *challengeData = (uint8_t *)HksTestMalloc(g_size);
    uint8_t *sec = (uint8_t *)HksTestMalloc(g_size);
    uint8_t *cert = (uint8_t *)HksTestMalloc(g_size);
    if (challengeData == nullptr || sec == nullptr || cert == nullptr) {
        FreeBuf(challengeData, sec, cert);
        return HKS_ERROR_MALLOC_FAIL;
    }

    struct HksBlob challenge = { g_size, challengeData };
    struct HksBlob secInfo = { g_size, sec };
    struct HksBlob certChain = { g_size, cert };
    int32_t ret = HKS_ERROR_MALLOC_FAIL;
    struct HksParamSet *paramSet = nullptr;
    do {
        ret = HksInitParamSet(&paramSet);
        if (ret != HKS_SUCCESS) {
            break;
        }
        struct HksParam tmpParam[] = {
            { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = challenge },
            { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = secInfo},
        };
        ret = HksAddParams(paramSet, tmpParam, sizeof(tmpParam) / sizeof(tmpParam[0]));
        if (ret != HKS_SUCCESS) {
            break;
        }
        ret = HksBuildParamSet(&paramSet);
        if (ret != HKS_SUCCESS) {
            break;
        }
        ret = HksValidateCertChain(&certChain, paramSet);
        HKS_TEST_LOG_E("validate cert chain result is %x", ret);
        printf("challenge is %s\n", (char *)paramSet->params[0].blob.data);
        printf("sec info is %s\n", (char *)paramSet->params[1].blob.data);
    } while (0);
    FreeBuf(challengeData, sec, cert);
    HksFreeParamSet(&paramSet);
    return ret;
}
/**
 * @tc.name: HksDeleteTest.HksDeleteTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksDeviceSecTest, HksDeviceSecTest001, TestSize.Level0)
{
    HKS_TEST_LOG_E("import id test start");
    struct HksBlob secInfo = { sizeof(g_secInfoData), (uint8_t *)g_secInfoData };
    int32_t ret = HksImportId(HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, &secInfo);
    HKS_TEST_LOG_E("import id test result is %x", ret);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: HksDeleteTest.HksDeleteTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksDeviceSecTest, HksDeviceSecTest002, TestSize.Level0)
{
    int32_t ret = IdAttestTest();

    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: HksDeleteTest.HksDeleteTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksDeviceSecTest, HksDeviceSecTest003, TestSize.Level0)
{
    int32_t ret = ValidateCertChainTest();
    ASSERT_TRUE(ret == 0);
}
}
