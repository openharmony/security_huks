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
#include "hks_storage_file_lock.h"
#include "hks_storage_manager.c"
#include "hks_storage_utils.c"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_inner.h"

const std::string TEST_PROCESS_NAME = "test_process";
const std::string TEST_USER_ID = "123465";
const std::string TEST_KEY_ALIAS = "key_alias";
constexpr uint32_t TEST_BLOB_SIZE = 16;
constexpr uint32_t PARAM_INDEX = 2;
constexpr uint8_t TEST_BLOB[TEST_BLOB_SIZE] = {0};
constexpr size_t MAX_TEST_COUNT = 1024;

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

static void HksStorageMultithreadTest001()
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

static void HksStorageMultithreadTest002()
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

static void HksStorageMultithreadTest003()
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

static void HksStorageFileLockTest001()
{
    std::string path = "/test/test";
    HksStorageFileLock *lock = HksStorageFileLockCreate(&path[0]);
    HksStorageFileLockRead(lock);
    HksStorageFileUnlockRead(lock);
    HksStorageFileLockWrite(lock);
    HksStorageFileUnlockWrite(lock);
    HksStorageFileLockRelease(lock);
}

static void HksStorageFileLockTest002()
{
    std::string pathBase = "/test/test";
    std::vector<HksStorageFileLock *> locks;
    for (size_t i = 0; i < MAX_TEST_COUNT; i++) {
        std::string path = pathBase + std::to_string(i);
        HksStorageFileLock *lock = HksStorageFileLockCreate(&path[0]);
        if (lock != nullptr) {
            locks.push_back(lock);
        }
    }
    locks.size();
    for (auto lock : locks) {
        HksStorageFileLockRelease(lock);
    }
}

static void HksStorageFileLockTest003()
{
    std::string path = "/test/test";
    std::vector<HksStorageFileLock *> locks;
    for (size_t i = 0; i < MAX_TEST_COUNT; i++) {
        HksStorageFileLock *lock = HksStorageFileLockCreate(&path[0]);
        if (lock != nullptr) {
            locks.push_back(lock);
        }
    }

    for (auto lock : locks) {
        HksStorageFileLockRelease(lock);
    }
}

static void HksStorageFileLockTest004()
{
    std::string path = "/test/test";
    HksStorageFileLock *lock1 = HksStorageFileLockCreate(&path[0]);
    HksStorageFileLock *lock2 = HksStorageFileLockCreate(&path[0]);

    HksStorageFileLockRead(lock1);
    HksStorageFileUnlockRead(lock1);
    HksStorageFileLockRead(lock2);
    HksStorageFileUnlockRead(lock2);

    HksStorageFileLockWrite(lock1);
    HksStorageFileUnlockWrite(lock1);
    HksStorageFileLockWrite(lock2);
    HksStorageFileUnlockWrite(lock2);

    HksStorageFileLockRelease(lock1);
    HksStorageFileLockRelease(lock2);
}

static void HksStorageTest001()
{
    HKS_LOG_I("enter HksStorageTest001");
    const char input = '#';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
}

static void HksStorageTest002()
{
    HKS_LOG_I("enter HksStorageTest002");
    const char input = '$';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
}

static void HksStorageTest003()
{
    HKS_LOG_I("enter HksStorageTest003");
    const char input = '%';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
}

static void HksStorageTest004()
{
    HKS_LOG_I("enter HksStorageTest004");
    const char input = '&';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
}

static void HksStorageTest005()
{
    HKS_LOG_I("enter HksStorageTest005");
    const char input = '(';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
}

static void HksStorageTest006()
{
    HKS_LOG_I("enter HksStorageTest006");
    const char input = ')';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
}

static void HksStorageManagerTest001()
{
    HKS_LOG_I("enter HksStorageManagerTest001");
    uint32_t userId = 1;
    uint32_t uid = 1;
    struct HksProcessInfo processInfo001 = {
        .processName = {
            .data = (uint8_t *)&uid,
            .size = sizeof(uid)
        },
        .userIdInt = userId, .userId = { .data = (uint8_t *)&userId, .size = sizeof(userId) }, .uidInt = uid,
        .accessTokenId = 1
    };
    struct HksBlob alias = {
        .data = (uint8_t *)"HksStorageManagerTest001", .size = strlen("HksStorageManagerTest001")
    };
    struct HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE
        }, {
            .tag = HKS_TAG_SPECIFIC_USER_ID,
            .uint32Param = 1
        }
    };
    HksAddParams(paramSet, params, PARAM_INDEX);
    HksBuildParamSet(&paramSet);

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    InitStorageMaterial(&processInfo001, paramSet, &alias, HKS_STORAGE_TYPE_KEY, &material);

    HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath));
    HksMemCmp(HKS_KEY_STORE_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath));

    HksMemCmp("1", material.uidPath, strlen(material.uidPath));
    HksMemCmp("1", material.userIdPath, strlen(material.userIdPath));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}

static void HksStorageManagerTest002()
{
    HKS_LOG_I("enter HksStorageManagerTest002");
    uint32_t userId = 2;
    uint32_t uid = 2;
    struct HksProcessInfo processInfo002 = {
        .processName = {
            .data = (uint8_t *)&uid,
            .size = sizeof(uid)
        },
        .userIdInt = userId, .userId = { .data = (uint8_t *)&userId, .size = sizeof(userId) }, .uidInt = uid,
        .accessTokenId = 2
    };
    struct HksBlob alias = {
        .data = (uint8_t *)"HksStorageManagerTest002", .size = strlen("HksStorageManagerTest002")
    };
    struct HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE
        }
    };
    HksAddParams(paramSet, params, PARAM_INDEX);
    HksBuildParamSet(&paramSet);

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    InitStorageMaterial(&processInfo002, paramSet, &alias, HKS_STORAGE_TYPE_KEY, &material);

    HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath));
    HksMemCmp(HKS_KEY_STORE_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath));

    HksMemCmp("2", material.uidPath, strlen(material.uidPath));
    HksMemCmp("2", material.userIdPath, strlen(material.userIdPath));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}

static void HksStorageManagerTest003()
{
    HKS_LOG_I("enter HksStorageManagerTest003");
    uint32_t userId = 3;
    uint32_t uid = 3;
    struct HksProcessInfo processInfo003 = {
        .processName = {
            .data = (uint8_t *)&uid,
            .size = sizeof(uid)
        },
        .userIdInt = userId, .userId = { .data = (uint8_t *)&userId, .size = sizeof(userId) }, .uidInt = uid,
        .accessTokenId = 3
    };
    struct HksBlob alias = {
        .data = (uint8_t *)"HksStorageManagerTest003", .size = strlen("HksStorageManagerTest003")
    };
    struct HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE
        }
    };
    HksAddParams(paramSet, params, PARAM_INDEX);
    HksBuildParamSet(&paramSet);

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    InitStorageMaterial(&processInfo003, paramSet, &alias, HKS_STORAGE_TYPE_KEY, &material);

    HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath));
    HksMemCmp(HKS_KEY_STORE_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath));

    HksMemCmp("3", material.uidPath, strlen(material.uidPath));
    HksMemCmp("3", material.userIdPath, strlen(material.userIdPath));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}

#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
static void HksStorageManagerTest004()
{
    HKS_LOG_I("enter HksStorageManagerTest004");
    uint32_t userId = 0;
    uint32_t uid = 0;
    struct HksProcessInfo processInfo004 = {
        .processName = {
            .data = (uint8_t *)&uid,
            .size = sizeof(uid)
        },
        .userIdInt = userId, .userId = { .data = (uint8_t *)&userId, .size = sizeof(userId) }, .uidInt = uid,
        .accessTokenId = 4
    };
    struct HksBlob alias = {
        .data = (uint8_t *)"HksStorageManagerTest004", .size = strlen("HksStorageManagerTest004")
    };
    struct HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_OLD_DE_TMP
        }
    };
    HksAddParams(paramSet, params, PARAM_INDEX);
    HksBuildParamSet(&paramSet);

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    InitStorageMaterial(&processInfo004, paramSet, &alias, HKS_STORAGE_TYPE_KEY, &material);

    HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath));
    HksMemCmp(HKS_KEY_STORE_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath));

    HksMemCmp("+0+0+0+0", material.uidPath, strlen(material.uidPath));
    HksMemCmp("", material.userIdPath, strlen(material.userIdPath));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}

static void HksStorageManagerTest005()
{
    HKS_LOG_I("enter HksStorageManagerTest005");
    uint32_t userId = 100;
    uint32_t uid = 0;
    struct HksProcessInfo processInfo005 = {
        .processName = {
            .data = (uint8_t *)&uid,
            .size = sizeof(uid)
        },
        .userIdInt = userId, .userId = { .data = (uint8_t *)&userId, .size = sizeof(userId) }, .uidInt = uid,
        .accessTokenId = 5
    };
    struct HksBlob alias = {
        .data = (uint8_t *)"HksStorageManagerTest005", .size = strlen("HksStorageManagerTest005")
    };
    struct HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_OLD_DE_TMP
        }
    };
    HksAddParams(paramSet, params, PARAM_INDEX);
    HksBuildParamSet(&paramSet);

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    InitStorageMaterial(&processInfo005, paramSet, &alias, HKS_STORAGE_TYPE_KEY, &material);

    HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath));
    HksMemCmp(HKS_KEY_STORE_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath));

    HksMemCmp("+0+0+0+0", material.uidPath, strlen(material.uidPath));
    HksMemCmp("d+0+0+0", material.userIdPath, strlen(material.userIdPath));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}
#endif

static void HksStorageManagerTest006()
{
    HKS_LOG_I("enter HksStorageManagerTest006");
    uint32_t userId = 6;
    uint32_t uid = 6;
    struct HksProcessInfo processInfo006 = {
        .processName = {
            .data = (uint8_t *)&uid,
            .size = sizeof(uid)
        },
        .userIdInt = userId, .userId = { .data = (uint8_t *)&userId, .size = sizeof(userId) }, .uidInt = uid,
        .accessTokenId = 6
    };
    struct HksBlob alias = {
        .data = (uint8_t *)"HksStorageManagerTest006", .size = strlen("HksStorageManagerTest006")
    };
    struct HksParamSet *paramSet = nullptr;
    HksInitParamSet(&paramSet);
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE
        }
    };
    HksAddParams(paramSet, params, PARAM_INDEX);
    HksBuildParamSet(&paramSet);

    struct HksStoreMaterial material = { ECE_PATH, 0 };
    InitStorageMaterial(&processInfo006, paramSet, &alias, HKS_STORAGE_TYPE_ROOT_KEY, &material);

    HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath));
    HksMemCmp(HKS_KEY_STORE_ROOT_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath));

    HksMemCmp("6", material.uidPath, strlen(material.uidPath));
    HksMemCmp("6", material.userIdPath, strlen(material.userIdPath));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    OHOS::Security::Hks::HksStorageMultithreadTest001();
    OHOS::Security::Hks::HksStorageMultithreadTest002();
    OHOS::Security::Hks::HksStorageMultithreadTest003();
    OHOS::Security::Hks::HksStorageFileLockTest001();
    OHOS::Security::Hks::HksStorageFileLockTest002();
    OHOS::Security::Hks::HksStorageFileLockTest003();
    OHOS::Security::Hks::HksStorageFileLockTest004();
    OHOS::Security::Hks::HksStorageTest001();
    OHOS::Security::Hks::HksStorageTest002();
    OHOS::Security::Hks::HksStorageTest003();
    OHOS::Security::Hks::HksStorageTest004();
    OHOS::Security::Hks::HksStorageTest005();
    OHOS::Security::Hks::HksStorageTest006();
    OHOS::Security::Hks::HksStorageManagerTest001();
    OHOS::Security::Hks::HksStorageManagerTest002();
    OHOS::Security::Hks::HksStorageManagerTest003();
#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    OHOS::Security::Hks::HksStorageManagerTest004();
    OHOS::Security::Hks::HksStorageManagerTest005();
#endif
    OHOS::Security::Hks::HksStorageManagerTest006();
    return 0;
}
