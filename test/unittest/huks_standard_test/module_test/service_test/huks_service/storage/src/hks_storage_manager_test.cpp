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

#undef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#define HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL

#undef HKS_ENABLE_LITE_HAP

#undef HKS_USE_RKC_IN_STANDARD
#define HKS_USE_RKC_IN_STANDARD

#undef HKS_KEY_STORE_LITE_HAP
#define HKS_KEY_STORE_LITE_HAP "/lite/hap"

#undef HKS_CONFIG_RKC_STORE_PATH
#define HKS_CONFIG_RKC_STORE_PATH ""

#include <gtest/gtest.h>
#include <cstring>

#include "file_ex.h"
#include "hks_log.h"
#include "hks_type_inner.h"
#include "hks_param.h"

#include "hks_storage_manager.h"
#include "hks_storage_utils.h"

#include "base/security/huks/services/huks_standard/huks_service/main/core/src/hks_storage_manager.c"

using namespace testing::ext;
namespace Unittest::HksStorageManagerTest {
class HksStorageManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksStorageManagerTest::SetUpTestCase(void)
{
}

void HksStorageManagerTest::TearDownTestCase(void)
{
}

void HksStorageManagerTest::SetUp()
{
}

void HksStorageManagerTest::TearDown()
{
}

/**
 * @tc.name: HksStorageManagerTest.HksStorageManagerTest001
 * @tc.desc: test InitStorageMaterial with full DE_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageManagerTest, HksStorageManagerTest001, TestSize.Level0)
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
    ASSERT_EQ(HKS_SUCCESS, HksInitParamSet(&paramSet)) << "HksStorageManagerTest001 init paramset failed.";
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE
        }, {
            .tag = HKS_TAG_SPECIFIC_USER_ID,
            .uint32Param = 1
        }
    };
    ASSERT_EQ(HKS_SUCCESS, HksAddParams(paramSet, params, 2));
    ASSERT_EQ(HKS_SUCCESS, HksBuildParamSet(&paramSet)) << "HksStorageManagerTest001 build paramset failed.";

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    ASSERT_EQ(HKS_SUCCESS, InitStorageMaterial(&processInfo001, paramSet, &alias, HKS_STORAGE_TYPE_KEY, &material));

    ASSERT_EQ(strlen((char *)alias.data), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath)));

    ASSERT_EQ(strlen(HKS_KEY_STORE_KEY_PATH), strlen(material.storageTypePath));
    ASSERT_EQ(EOK, HksMemCmp(HKS_KEY_STORE_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath)));

    ASSERT_EQ(strlen("1"), strlen(material.uidPath)) << "uid path is " << material.uidPath;
    ASSERT_EQ(EOK, HksMemCmp("1", material.uidPath, strlen(material.uidPath))) << "uid path is " << material.uidPath;

    ASSERT_EQ(strlen("1"), strlen(material.userIdPath)) << "userId path is " << material.userIdPath;
    ASSERT_EQ(EOK, HksMemCmp("1", material.userIdPath, strlen(material.userIdPath)));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksStorageManagerTest.HksStorageManagerTest002
 * @tc.desc: test InitStorageMaterial with full CE_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageManagerTest, HksStorageManagerTest002, TestSize.Level0)
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
    ASSERT_EQ(HKS_SUCCESS, HksInitParamSet(&paramSet)) << "HksStorageManagerTest002 init paramset failed.";
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE
        }
    };
    ASSERT_EQ(HKS_SUCCESS, HksAddParams(paramSet, params, 2));
    ASSERT_EQ(HKS_SUCCESS, HksBuildParamSet(&paramSet)) << "HksStorageManagerTest002 build paramset failed.";

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    ASSERT_EQ(HKS_SUCCESS, InitStorageMaterial(&processInfo002, paramSet, &alias, HKS_STORAGE_TYPE_KEY, &material));

    ASSERT_EQ(strlen((char *)alias.data), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath)));

    ASSERT_EQ(strlen(HKS_KEY_STORE_KEY_PATH), strlen(material.storageTypePath));
    ASSERT_EQ(EOK, HksMemCmp(HKS_KEY_STORE_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath)));

    ASSERT_EQ(strlen("2"), strlen(material.uidPath)) << "uid path is " << material.uidPath;
    ASSERT_EQ(EOK, HksMemCmp("2", material.uidPath, strlen(material.uidPath))) << "uid path is " << material.uidPath;

    ASSERT_EQ(strlen("2"), strlen(material.userIdPath)) << "userId path is " << material.userIdPath;
    ASSERT_EQ(EOK, HksMemCmp("2", material.userIdPath, strlen(material.userIdPath)));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksStorageManagerTest.HksStorageManagerTest003
 * @tc.desc: test InitStorageMaterial with full ECE_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageManagerTest, HksStorageManagerTest003, TestSize.Level0)
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
    ASSERT_EQ(HKS_SUCCESS, HksInitParamSet(&paramSet)) << "HksStorageManagerTest003 init paramset failed.";
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_ECE
        }
    };
    ASSERT_EQ(HKS_SUCCESS, HksAddParams(paramSet, params, 2));
    ASSERT_EQ(HKS_SUCCESS, HksBuildParamSet(&paramSet)) << "HksStorageManagerTest003 build paramset failed.";

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    ASSERT_EQ(HKS_SUCCESS, InitStorageMaterial(&processInfo003, paramSet, &alias, HKS_STORAGE_TYPE_KEY, &material));

    ASSERT_EQ(strlen((char *)alias.data), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath)));

    ASSERT_EQ(strlen(HKS_KEY_STORE_KEY_PATH), strlen(material.storageTypePath));
    ASSERT_EQ(EOK, HksMemCmp(HKS_KEY_STORE_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath)));

    ASSERT_EQ(strlen("3"), strlen(material.uidPath)) << "uid path is " << material.uidPath;
    ASSERT_EQ(EOK, HksMemCmp("3", material.uidPath, strlen(material.uidPath))) << "uid path is " << material.uidPath;

    ASSERT_EQ(strlen("3"), strlen(material.userIdPath)) << "userId path is " << material.userIdPath;
    ASSERT_EQ(EOK, HksMemCmp("3", material.userIdPath, strlen(material.userIdPath)));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}

#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
/**
 * @tc.name: HksStorageManagerTest.HksStorageManagerTest004
 * @tc.desc: test InitStorageMaterial with full HKS_AUTH_STORAGE_LEVEL_OLD_DE_TMP with user id 0
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageManagerTest, HksStorageManagerTest004, TestSize.Level0)
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
    ASSERT_EQ(HKS_SUCCESS, HksInitParamSet(&paramSet)) << "HksStorageManagerTest004 init paramset failed.";
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_OLD_DE_TMP
        }
    };
    ASSERT_EQ(HKS_SUCCESS, HksAddParams(paramSet, params, 2));
    ASSERT_EQ(HKS_SUCCESS, HksBuildParamSet(&paramSet)) << "HksStorageManagerTest004 build paramset failed.";

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    ASSERT_EQ(HKS_SUCCESS, InitStorageMaterial(&processInfo004, paramSet, &alias, HKS_STORAGE_TYPE_KEY, &material));

    ASSERT_EQ(strlen((char *)alias.data), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath)));

    ASSERT_EQ(strlen(HKS_KEY_STORE_KEY_PATH), strlen(material.storageTypePath));
    ASSERT_EQ(EOK, HksMemCmp(HKS_KEY_STORE_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath)));

    ASSERT_EQ(strlen("+0+0+0+0"), strlen(material.uidPath)) << "uid path is " << material.uidPath;
    ASSERT_EQ(EOK, HksMemCmp("+0+0+0+0", material.uidPath, strlen(material.uidPath)));

    ASSERT_EQ(strlen(""), strlen(material.userIdPath)) << "userId path is " << material.userIdPath;
    ASSERT_EQ(EOK, HksMemCmp("", material.userIdPath, strlen(material.userIdPath)));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksStorageManagerTest.HksStorageManagerTest005
 * @tc.desc: test InitStorageMaterial with full HKS_AUTH_STORAGE_LEVEL_OLD_DE_TMP with user id 100
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageManagerTest, HksStorageManagerTest005, TestSize.Level0)
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
    ASSERT_EQ(HKS_SUCCESS, HksInitParamSet(&paramSet)) << "HksStorageManagerTest005 init paramset failed.";
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_OLD_DE_TMP
        }
    };
    ASSERT_EQ(HKS_SUCCESS, HksAddParams(paramSet, params, 2));
    ASSERT_EQ(HKS_SUCCESS, HksBuildParamSet(&paramSet)) << "HksStorageManagerTest005 build paramset failed.";

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    ASSERT_EQ(HKS_SUCCESS, InitStorageMaterial(&processInfo005, paramSet, &alias, HKS_STORAGE_TYPE_KEY, &material));

    ASSERT_EQ(strlen((char *)alias.data), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath)));

    ASSERT_EQ(strlen(HKS_KEY_STORE_KEY_PATH), strlen(material.storageTypePath));
    ASSERT_EQ(EOK, HksMemCmp(HKS_KEY_STORE_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath)));

    ASSERT_EQ(strlen("+0+0+0+0"), strlen(material.uidPath)) << "uid path is " << material.uidPath;
    ASSERT_EQ(EOK, HksMemCmp("+0+0+0+0", material.uidPath, strlen(material.uidPath)));

    ASSERT_EQ(strlen("d+0+0+0"), strlen(material.userIdPath)) << "userId path is " << material.userIdPath;
    ASSERT_EQ(EOK, HksMemCmp("d+0+0+0", material.userIdPath, strlen(material.userIdPath)));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}
#endif

/**
 * @tc.name: HksStorageManagerTest.HksStorageManagerTest006
 * @tc.desc: test InitStorageMaterial with full DE_PATH, with storage type as info
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageManagerTest, HksStorageManagerTest006, TestSize.Level0)
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
    ASSERT_EQ(HKS_SUCCESS, HksInitParamSet(&paramSet)) << "HksStorageManagerTest006 init paramset failed.";
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
            .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE
        }
    };
    ASSERT_EQ(HKS_SUCCESS, HksAddParams(paramSet, params, 2));
    ASSERT_EQ(HKS_SUCCESS, HksBuildParamSet(&paramSet));

    struct HksStoreMaterial material = { ECE_PATH, 0 };
    ASSERT_EQ(HKS_SUCCESS,
        InitStorageMaterial(&processInfo006, paramSet, &alias, HKS_STORAGE_TYPE_ROOT_KEY, &material));

    ASSERT_EQ(strlen((char *)alias.data), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(alias.data, material.keyAliasPath, strlen(material.keyAliasPath)));

    ASSERT_EQ(strlen(HKS_KEY_STORE_ROOT_KEY_PATH), strlen(material.storageTypePath));
    ASSERT_EQ(EOK, HksMemCmp(HKS_KEY_STORE_ROOT_KEY_PATH, material.storageTypePath, strlen(material.storageTypePath)));

    ASSERT_EQ(strlen("6"), strlen(material.uidPath)) << "uid path is " << material.uidPath;
    ASSERT_EQ(EOK, HksMemCmp("6", material.uidPath, strlen(material.uidPath)));

    ASSERT_EQ(strlen("6"), strlen(material.userIdPath)) << "userId path is " << material.userIdPath;
    ASSERT_EQ(EOK, HksMemCmp("6", material.userIdPath, strlen(material.userIdPath)));

    FreeStorageMaterial(&material);
    HksFreeParamSet(&paramSet);
}
}
