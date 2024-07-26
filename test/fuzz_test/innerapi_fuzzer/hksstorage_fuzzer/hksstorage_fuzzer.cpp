/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "hksstorage_fuzzer.h"

#include <string>

#include "hks_api.h"
#include "hks_config.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_storage_manager.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_inner.h"

const std::string TEST_PROCESS_NAME = "test_process";
const std::string TEST_USER_ID = "123465";
const std::string TEST_KEY_ALIAS = "key_alias";
constexpr uint32_t TEST_BLOB_SIZE = 16;
constexpr uint8_t TEST_BLOB[TEST_BLOB_SIZE] = {0};

namespace OHOS {
namespace Security {
namespace Hks {

static int32_t BuildParamSet(const struct HksParam *param, uint32_t paramCnt, struct HksParamSet **paramSetOut)
{
    int32_t ret;
    struct HksParamSet *paramSet = nullptr;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        if (param != nullptr && paramCnt > 0) {
            ret = HksAddParams(paramSet, param, paramCnt);
            HKS_IF_NOT_SUCC_BREAK(ret)
        }

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
    }
    *paramSetOut = paramSet;
    return HKS_SUCCESS;
}

static const struct HksParam g_genParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

static void PrepareBlob()
{
    HksBlob processName = {
        .size = TEST_PROCESS_NAME.size() + 1,
        .data = (uint8_t *)&TEST_PROCESS_NAME[0],
    };
    HksBlob userId = {
        .size = TEST_USER_ID.size() + 1,
        .data = (uint8_t *)&TEST_USER_ID[0]
    };
    HksBlob keyAlias = {
        .size = TEST_KEY_ALIAS.size() + 1,
        .data = (uint8_t *)&TEST_KEY_ALIAS[0],
    };
    HksBlob keyBlob = {
        .size = TEST_BLOB_SIZE,
        .data = (uint8_t *)TEST_BLOB,
    };
    HksProcessInfo hksProcessInfo = {
        .userId = userId,
        .processName = processName
    };

    struct HksParamSet *paramSet = nullptr;
    BuildParamSet(g_genParams, HKS_ARRAY_SIZE(g_genParams), &paramSet);
    HksManageStoreKeyBlob(&hksProcessInfo, paramSet, &keyAlias,
        &keyBlob, HksStorageType::HKS_STORAGE_TYPE_KEY);
    HksFreeParamSet(&paramSet);
}

static void HksStorageTest001()
{
    HksBlob processName = {
        .size = TEST_PROCESS_NAME.size() + 1,
        .data = (uint8_t *)&TEST_PROCESS_NAME[0],
    };
    HksBlob userId = {
        .size = TEST_USER_ID.size() + 1,
        .data = (uint8_t *)&TEST_USER_ID[0]
    };
    HksBlob keyBlob = {
        .size = TEST_BLOB_SIZE,
        .data = (uint8_t *)TEST_BLOB,
    };
    HksBlob keyAlias = {
        .size = TEST_KEY_ALIAS.size() + 1,
        .data = (uint8_t *)&TEST_KEY_ALIAS[0],
    };
    HksProcessInfo hksProcessInfo = {
        .userId = userId,
        .processName = processName
    };

    struct HksParamSet *paramSet = nullptr;
    BuildParamSet(g_genParams, HKS_ARRAY_SIZE(g_genParams), &paramSet);
    HksManageStoreKeyBlob(&hksProcessInfo, paramSet, &keyAlias,
        &keyBlob, HksStorageType::HKS_STORAGE_TYPE_KEY);
    HksFreeParamSet(&paramSet);
}

static void HksStorageTest002()
{
    PrepareBlob();

    HksBlob processName = {
        .size = TEST_PROCESS_NAME.size() + 1,
        .data = (uint8_t *)&TEST_PROCESS_NAME[0],
    };
    HksBlob userId = {
        .size = TEST_USER_ID.size() + 1,
        .data = (uint8_t *)&TEST_USER_ID[0]
    };
    HksBlob keyAlias = {
        .size = TEST_KEY_ALIAS.size() + 1,
        .data = (uint8_t *)&TEST_KEY_ALIAS[0],
    };
    uint8_t buff[TEST_BLOB_SIZE] = {0};
    HksBlob keyBlob = {
        .size = TEST_BLOB_SIZE,
        .data = buff,
    };
    HksProcessInfo hksProcessInfo = {
        .userId = userId,
        .processName = processName
    };

    struct HksParamSet *paramSet = nullptr;
    BuildParamSet(g_genParams, HKS_ARRAY_SIZE(g_genParams), &paramSet);
    HksManageStoreGetKeyBlob(&hksProcessInfo, paramSet,
        &keyAlias, &keyBlob, HksStorageType::HKS_STORAGE_TYPE_KEY);
    HksFreeParamSet(&paramSet);
}

static void HksStorageTest003()
{
    PrepareBlob();

    HksBlob processName = {
        .size = TEST_PROCESS_NAME.size() + 1,
        .data = (uint8_t *)&TEST_PROCESS_NAME[0],
    };
    HksBlob userId = {
        .size = TEST_USER_ID.size() + 1,
        .data = (uint8_t *)&TEST_USER_ID[0]
    };
    HksBlob keyAlias = {
        .size = TEST_KEY_ALIAS.size() + 1,
        .data = (uint8_t *)&TEST_KEY_ALIAS[0],
    };
    HksProcessInfo hksProcessInfo = {
        .userId = userId,
        .processName = processName
    };
    struct HksParamSet *paramSet = nullptr;
    BuildParamSet(g_genParams, HKS_ARRAY_SIZE(g_genParams), &paramSet);
    HksManageStoreDeleteKeyBlob(&hksProcessInfo, paramSet, &keyAlias,
        HksStorageType::HKS_STORAGE_TYPE_KEY);
    HksFreeParamSet(&paramSet);
}
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    OHOS::Security::Hks::HksStorageTest001();
    OHOS::Security::Hks::HksStorageTest002();
    OHOS::Security::Hks::HksStorageTest003();
    return 0;
}
