/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "hks_rename_test.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_common.h"
#include "hks_test_log.h"
#include "hks_type.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_file_operator.h"
using namespace testing::ext;
namespace {
static const uint32_t USER_ID_INT = 100;
class HksRenameKeyAliasPart2Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksRenameKeyAliasPart2Test::SetUpTestCase(void)
{
}

void HksRenameKeyAliasPart2Test::TearDownTestCase(void)
{
}

void HksRenameKeyAliasPart2Test::SetUp()
{
}

void HksRenameKeyAliasPart2Test::TearDown()
{
}

static int32_t BuildParamSetWithParam(struct HksParamSet **paramSet, struct HksParam *param, uint32_t paramCnt)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("BuildParamSetWithParam HksInitParamSet failed");
        return ret;
    }
    if (param != nullptr) {
        ret = HksAddParams(*paramSet, param, paramCnt);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("BuildParamSetWithParam HksAddParams failed");
            return ret;
        }
    }
    return HksBuildParamSet(paramSet);
}

/**
 * @tc.name: HksRenameKeyAliasPart2Test.HksRenameKeyAliasPart2Test020
 * @tc.desc: check no permission
 * @tc.type: FUNC
 */
HWTEST_F(HksRenameKeyAliasPart2Test, HksRenameKeyAliasPart2Test020, TestSize.Level0)
{
    const char *alias = "oldKeyAlias020";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    int32_t ret = BuildParamSetWithParam(&paramSet, storageLevel, sizeof(storageLevel) / sizeof(storageLevel[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION) << "Hks get generate key failed, ret is " << ret;;

    struct HksParamSet *renameParamSet = NULL;
    struct HksParam paramArr[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = USER_ID_INT },
        {.tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
        {.tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = true},
    };
    ret = BuildParamSetWithParam(&renameParamSet, paramArr, sizeof(paramArr) / sizeof(paramArr[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);
    const char *alias2 = "newKeyAlias020";
    struct HksBlob newKeyAlias = { strlen(alias2), (uint8_t *)alias2 };
    ret = HksDeleteKey(&newKeyAlias, renameParamSet);
    ret = HksRenameKeyAlias(&keyAlias, renameParamSet, &newKeyAlias);
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION) << "HksRenameKeyAlias ret is " << ret;

    ret = HksKeyExist(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION) << "old key is not exit, ret is " << ret;

    ret = HksDeleteKey(&keyAlias, paramSet);
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&renameParamSet);
}
}