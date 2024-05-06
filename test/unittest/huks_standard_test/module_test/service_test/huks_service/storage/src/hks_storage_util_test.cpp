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
#define HKS_ENABLE_LITE_HAP

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

#include "hks_storage_utils.h"

#include "base/security/huks/services/huks_standard/huks_service/main/core/src/hks_storage_utils.c"

using namespace testing::ext;
namespace Unittest::HksStorageUtilTest {
class HksStorageUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksStorageUtilTest::SetUpTestCase(void)
{
}

void HksStorageUtilTest::TearDownTestCase(void)
{
}

void HksStorageUtilTest::SetUp()
{
}

void HksStorageUtilTest::TearDown()
{
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest001
 * @tc.desc: test HksGetFileInfo with full DE_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest001");
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("123");
    material.userIdPath = const_cast<char *>("999");
    struct HksStoreFileInfo fileInfo = { 0 };
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_KEY_STORE_PATH "/999/123/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest002
 * @tc.desc: test HksGetFileInfo with DE_PATH without user id
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest002");
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("222");
    material.userIdPath = const_cast<char *>("");
    struct HksStoreFileInfo fileInfo = { 0 };
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_KEY_STORE_PATH "/222/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest003
 * @tc.desc: test HksGetFileInfo with CE_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest003");
    struct HksStoreMaterial material = { CE_PATH, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("333");
    material.userIdPath = const_cast<char *>("100");
    struct HksStoreFileInfo fileInfo = { 0 };
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_CE_ROOT_PATH "/100/" HKS_STORE_SERVICE_PATH "/333/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest004
 * @tc.desc: test HksGetFileInfo with ECE_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest004");
    struct HksStoreMaterial material = { ECE_PATH, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("444");
    material.userIdPath = const_cast<char *>("100");
    struct HksStoreFileInfo fileInfo = { 0 };
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_ECE_ROOT_PATH "/100/" HKS_STORE_SERVICE_PATH "/444/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));
}

#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest005
 * @tc.desc: test HksGetFileInfo with TMP_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest005");
    struct HksStoreMaterial material = { TMP_PATH, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("555");
    material.userIdPath = const_cast<char *>("555");
    struct HksStoreFileInfo fileInfo = { 0 };
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_KEY_STORE_TMP_PATH "/555/555/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));
}
#endif

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest006
 * @tc.desc: test HksGetFileInfo with LITE_HAP_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest006");
    struct HksStoreMaterial material = { LITE_HAP_PATH, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("hks_client");
    material.userIdPath = const_cast<char *>("");
    struct HksStoreFileInfo fileInfo = { 0 };
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_KEY_STORE_LITE_HAP "/hks_client/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));
}

/**
 * @tc.name: HksStorageUtilTest.HksStorageUtilTest007
 * @tc.desc: test HksGetFileInfo with RKC_IN_STANDARD_PATH
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageUtilTest, HksStorageUtilTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageUtilTest007");
    struct HksStoreMaterial material = { RKC_IN_STANDARD_PATH, 0 };
    material.keyAliasPath = const_cast<char *>("alias");
    material.storageTypePath = const_cast<char *>("key");
    material.uidPath = const_cast<char *>("hks_client");
    material.userIdPath = const_cast<char *>("0");
    struct HksStoreFileInfo fileInfo = { 0 };
    int32_t ret = HksGetFileInfo(&material, &fileInfo);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ASSERT_EQ(strlen(fileInfo.mainPath.fileName), strlen(material.keyAliasPath));
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.fileName, material.keyAliasPath, strlen(material.keyAliasPath)));

    const char *expectPath =
        HKS_KEY_RKC_PATH "/hks_client/key";
    ASSERT_EQ(strlen(fileInfo.mainPath.path), strlen(expectPath)) << fileInfo.mainPath.path;
    ASSERT_EQ(EOK, HksMemCmp(fileInfo.mainPath.path, expectPath, strlen(expectPath)));
}
}
