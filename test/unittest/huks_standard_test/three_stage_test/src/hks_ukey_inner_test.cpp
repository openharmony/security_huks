/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include <string>
#include <vector>
#include "hks_error_code.h"
#include "hks_mock_common.h"
#include "hks_template.h"
#include "hks_log.h"
#include "token_setproc.h"
#include "hks_plugin_def.h"
#include "hks_type.h"
#include "hks_ukey_test.h"
#include "securec.h"
#include "file_ex.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_tag.h"
#include "hks_mem.h"
#include "hks_test_log.h"
#include "hks_api.h"
#include "hks_test_common_h.h"
#include "nativetoken_kit.h"

using namespace testing::ext;
namespace {
class HksUKeyInnerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    static struct HksBlob StringToHuksBlob(const char *str)
    {
        struct HksBlob blob;
        if (!str) {
            blob.size = 0;
            blob.data = nullptr;
            return blob;
        }
        blob.size = strlen(str);
        blob.data = (uint8_t *)str;
        return blob;
    }

    static int32_t ConstructTestParamSet(struct HksParamSet **paramSet)
    {
        HksParam params[] = {
            {
                .tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME,
                .blob = { 18, (uint8_t *)"ability_name_value" }
            },
            {
                .tag = HKS_EXT_CRYPTO_TAG_UKEY_PIN,
                .blob = { .size = 6, .data = (uint8_t *)"123789" }
            }
        };

        uint32_t paramsCnt = sizeof(params) / sizeof(params[0]);
        uint32_t totalSize = sizeof(struct HksParamSet) + sizeof(struct HksParam) * paramsCnt;

        *paramSet = (struct HksParamSet *)HksMalloc(totalSize);
        if (*paramSet == nullptr) {
            return HKS_ERROR_MALLOC_FAIL;
        }
        (*paramSet)->paramSetSize = totalSize;
        (*paramSet)->paramsCnt = paramsCnt;

        for (uint32_t i = 0; i < paramsCnt; i++) {
            (*paramSet)->params[i] = params[i];
        }

        return 0;
    }

    static int32_t ConstructTestParamSet(struct HksParamSet **paramSet, HksParam params[], uint32_t paramsCnt)
    {
        uint32_t totalSize = sizeof(struct HksParamSet) + sizeof(struct HksParam) * paramsCnt;

        *paramSet = (struct HksParamSet *)HksMalloc(totalSize);
        if (*paramSet == nullptr) {
            return HKS_ERROR_MALLOC_FAIL;
        }
        (*paramSet)->paramSetSize = totalSize;
        (*paramSet)->paramsCnt = paramsCnt;

        for (uint32_t i = 0; i < paramsCnt; i++) {
            (*paramSet)->params[i] = params[i];
        }

        return 0;
    }
};

static uint64_t g_shellTokenId = 0;

void HksUKeyInnerTest::SetUpTestCase(void)
{
    g_shellTokenId = GetSelfTokenID();
    HksMockCommon::SetTestEvironment(g_shellTokenId);
}

void HksUKeyInnerTest::TearDownTestCase(void)
{
    SetSelfTokenID(g_shellTokenId);
    HksMockCommon::ResetTestEvironment();
}

void HksUKeyInnerTest::SetUp()
{
}

void HksUKeyInnerTest::TearDown()
{
}

HWTEST_F(HksUKeyInnerTest, HksUKeyInnerTest001, TestSize.Level0)
{
    //mock
    std::string bundleName = "com.homs.hukstest.ukey";
    std::vector<std::string> reqPerm{};
    reqPerm.emplace_back("ohos.permission.CRYPTO_EXTENSION_REGISTER");
    auto mockProccess = std::make_shared<HksMockHapToken>(bundleName, reqPerm, true);
    EXPECT_NE(mockProccess, nullptr) << "mockProcess is null";

    HksProcessInfo processInfo{};
    HksGetProcessInfoForIPC(&processInfo);

    std::string resourceId = "{\"providerName\":\"P01\",\"abilityName\":\"CryptoAbility\","
        "\"bundleName\":\"com.hmos.hukstest.ukey\",\"index\":\"key1\"}";
    struct HksAbilityInfo tmp{};
    tmp.abilityName.data = (uint8_t*)HksMalloc(128);
    tmp.abilityName.size = 128;
    tmp.bundleName.data = (uint8_t*)HksMalloc(128);
    tmp.bundleName.size = 128;
    HksBlob resourceBlob = StringToHuksBlob(resourceId.data());
    int32_t ret = HksQueryAbilityInfo(&resourceBlob, &tmp);
    HKS_IF_NOT_SUCC_LOGE(ret, "query fail");

    HKS_LOG_I("bundleName:%" LOG_PUBLIC "s, uiAbilityName: %" LOG_PUBLIC "s, index: %" LOG_PUBLIC "s",
        tmp.bundleName.data, tmp.abilityName.data, resourceBlob.data);
    EXPECT_EQ(ret, HKS_SUCCESS);
}
}
