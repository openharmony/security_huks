/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_storage_utils.h"
#include "hks_type_inner.h"

#include "base/security/huks/services/huks_standard/huks_service/main/upgrade/file_transfer/src/hks_file_transfer.c"

using namespace testing::ext;
using namespace OHOS;
namespace Unittest::HksServiceUpgradeFileTransferTest {
class HksServiceUpgradeFileTransferTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksServiceUpgradeFileTransferTest::SetUpTestCase(void)
{
}

void HksServiceUpgradeFileTransferTest::TearDownTestCase(void)
{
}

void HksServiceUpgradeFileTransferTest::SetUp()
{
}

void HksServiceUpgradeFileTransferTest::TearDown()
{
}

/**
 * @tc.name: HksServiceUpgradeFileTransferTest.HksServiceUpgradeFileTransferTest001
 * @tc.desc: test HksUpgradeFileTransfer, with de key file to ce
 * @tc.type: FUNC
 */
HWTEST_F(HksServiceUpgradeFileTransferTest, HksServiceUpgradeFileTransferTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksServiceUpgradeFileTransferTest001");
    const char *alias = "HksServiceUpgradeFileTransferTest001";
    uint32_t uid = 0;
    struct HksProcessInfo processInfo = {
        .processName = { .data = reinterpret_cast<uint8_t *>(&uid), .size = sizeof(uid) },
        .uidInt = uid,
        .userIdInt = uid,
        .userId = { .data = reinterpret_cast<uint8_t *>(&uid), .size = sizeof(uid) },
        .accessTokenId = static_cast<uint64_t>(IPCSkeleton::GetCallingTokenID())
    };
    struct HksBlob aliasBlob = {
        .data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(alias)), .size = strlen(alias)
    };
    struct HksParamSet *paramset = nullptr;
    struct HksParam params001[] = {
        {
            .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES
        }, {
            .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128
        }
    };
    ASSERT_EQ(HKS_SUCCESS, HksInitParamSet(&paramset));
    ASSERT_EQ(HKS_SUCCESS, HksAddParams(paramset, params001, HKS_ARRAY_SIZE(params001)));
    ASSERT_EQ(HKS_SUCCESS, HksBuildParamSet(&paramset));

    ASSERT_EQ(HKS_SUCCESS, HksServiceGenerateKey(&processInfo, &aliasBlob, paramset, nullptr));

    uint32_t fileSize = 4096;
    struct HksBlob fileBlob = { .data = (uint8_t *)HksMalloc(fileSize), .size = fileSize };
    ASSERT_NE(nullptr, fileBlob.data);
    ASSERT_EQ(HKS_SUCCESS, HksFileRead(HKS_KEY_STORE_PATH "/0/0/key", alias,
        0, &fileBlob, &fileBlob.size));

    HksMakeFullDir(HKS_KEY_STORE_TMP_PATH "/0/0/key");
    ASSERT_EQ(HKS_SUCCESS, HksFileWrite(HKS_KEY_STORE_TMP_PATH "/0/0/key", alias, 0, fileBlob.data, fileBlob.size));
    ASSERT_EQ(HKS_SUCCESS, HksFileRemove(HKS_KEY_STORE_PATH "/0/0/key", alias));
    ASSERT_EQ(HKS_SUCCESS, HksUpgradeFileTransferOnPowerOn());
    ASSERT_EQ(HKS_SUCCESS, HksIsFileExist(HKS_CE_ROOT_PATH "/0/" HKS_STORE_SERVICE_PATH "/0/key", alias));

    ASSERT_EQ(HKS_SUCCESS, HksFileRemove(HKS_CE_ROOT_PATH "/0/" HKS_STORE_SERVICE_PATH "/0/key", alias));
    HksFreeParamSet(&paramset);
    HKS_FREE_BLOB(aliasBlob);
    HKS_FREE_BLOB(fileBlob);
}
}
