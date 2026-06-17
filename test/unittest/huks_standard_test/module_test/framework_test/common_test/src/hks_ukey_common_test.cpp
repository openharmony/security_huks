/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hks_ukey_common_test.h"

#include <gtest/gtest.h>
#include <cstring>

#include "base/security/huks/frameworks/huks_standard/main/common/src/hks_external_error_info.c"
#include "base/security/huks/frameworks/huks_standard/main/common/src/hks_ukey_global_errInfo.c"
#include "base/security/huks/frameworks/huks_standard/main/common/src/hks_ukey_check.cpp"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

using namespace testing::ext;
namespace Unittest::HksUkeyCommonTest {

class HksUkeyCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksUkeyCommonTest::SetUpTestCase(void) {}
void HksUkeyCommonTest::TearDownTestCase(void) {}
void HksUkeyCommonTest::SetUp() {}
void HksUkeyCommonTest::TearDown() {}

/**
 * @tc.name: HksUkeyCommonTest.HksUkeyCommonTest001
 * @tc.desc: tdd HksCheckIsUkeyOperation branches (lines 36-44)
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyCommonTest, HksUkeyCommonTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksUkeyCommonTest001");

    /* invalid key class value -> INVALID_ARGUMENT */
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam classParam = { .tag = HKS_TAG_KEY_CLASS, .uint32Param = 99 };
    ret = HksAddParams(paramSet, &classParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    int32_t outRet = HKS_SUCCESS;
    ret = HksCheckIsUkeyOperation(paramSet, &outRet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(outRet, HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);

    /* KEY_CLASS_EXTENSION -> SUCCESS */
    ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam extParam = { .tag = HKS_TAG_KEY_CLASS, .uint32Param = HKS_KEY_CLASS_EXTENSION };
    ret = HksAddParams(paramSet, &extParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    outRet = HKS_SUCCESS;
    ret = HksCheckIsUkeyOperation(paramSet, &outRet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksUkeyCommonTest.HksUkeyCommonTest002
 * @tc.desc: tdd HksSetUkeyGlobalInfo, HksGetUkeyGlobalInfo, HksClearUkeyGlobalInfo
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyCommonTest, HksUkeyCommonTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksUkeyCommonTest002");

    int32_t errVal = 0;
    char buf[256] = {0};

    /* set with desc and get */
    HksSetUkeyGlobalInfo(-100, "test error desc");
    HksGetUkeyGlobalInfo(&errVal, buf, sizeof(buf));
    EXPECT_EQ(errVal, -100);
    EXPECT_STREQ(buf, "CryptoExtensionError: test error desc");

    /* set with null desc -> only prefix */
    HksSetUkeyGlobalInfo(-200, NULL);
    HksGetUkeyGlobalInfo(&errVal, buf, sizeof(buf));
    EXPECT_EQ(errVal, 0);
    EXPECT_STREQ(buf, "CryptoExtensionError: ");

    /* set with empty desc -> only prefix */
    HksSetUkeyGlobalInfo(-300, "");
    HksGetUkeyGlobalInfo(&errVal, buf, sizeof(buf));
    EXPECT_EQ(errVal, 0);
    EXPECT_STREQ(buf, "CryptoExtensionError: ");

    /* null params -> early return, no crash */
    HksGetUkeyGlobalInfo(NULL, buf, sizeof(buf));
    HksGetUkeyGlobalInfo(&errVal, NULL, sizeof(buf));
    HksGetUkeyGlobalInfo(&errVal, buf, 0);

    /* bufLen smaller than prefix -> empty string */
    char smallBuf[10] = {0};
    HksSetUkeyGlobalInfo(-400, "long error description");
    HksGetUkeyGlobalInfo(&errVal, smallBuf, sizeof(smallBuf));
    EXPECT_EQ(strlen(smallBuf), 9u);

    /* clear */
    HksClearUkeyGlobalInfo();
    HksGetUkeyGlobalInfo(&errVal, buf, sizeof(buf));
    EXPECT_EQ(errVal, 0);
    EXPECT_STREQ(buf, "");
}

/**
 * @tc.name: HksUkeyCommonTest.HksUkeyCommonTest003
 * @tc.desc: tdd HksAppendThreadExtErrMsg, HksGetAndClearThreadExtErrMsg,
 *           HksCreateExternalErrorInfo, HksFreeExternalErrorInfo (lines 40-43, 51-56, 85-91, 99-102)
 * @tc.type: FUNC
 */
HWTEST_F(HksUkeyCommonTest, HksUkeyCommonTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksUkeyCommonTest003");

    /* HksCreateExternalErrorInfo with normal desc */
    struct HksExternalErrorInfo *info = HksCreateExternalErrorInfo(-1, "normal error");
    ASSERT_NE(info, nullptr);
    EXPECT_EQ(info->errVal, -1);
    EXPECT_STREQ(info->errorDesc, "normal error");
    EXPECT_EQ(info->errorDescLen, 12u);
    HksFreeExternalErrorInfo(info);

    /* HksCreateExternalErrorInfo with NULL desc */
    info = HksCreateExternalErrorInfo(-2, NULL);
    ASSERT_NE(info, nullptr);
    EXPECT_STREQ(info->errorDesc, "");
    HksFreeExternalErrorInfo(info);

    /* HksCreateExternalErrorInfo with empty desc */
    info = HksCreateExternalErrorInfo(-3, "");
    ASSERT_NE(info, nullptr);
    EXPECT_STREQ(info->errorDesc, "");
    HksFreeExternalErrorInfo(info);

    /* HksFreeExternalErrorInfo with NULL -> no crash */
    HksFreeExternalErrorInfo(NULL);

    /* HksAppendThreadExtErrMsg + HksGetThreadExtErrMsg */
    HksAppendThreadExtErrMsg(-10, "thread error");
    const struct HksExternalErrorInfo *threadInfo = HksGetThreadExtErrMsg();
    ASSERT_NE(threadInfo, nullptr);
    EXPECT_EQ(threadInfo->errVal, -10);
    EXPECT_STREQ(threadInfo->errorDesc, "thread error");

    /* HksAppendThreadExtErrMsg with NULL desc -> uses empty string */
    HksAppendThreadExtErrMsg(-20, NULL);
    threadInfo = HksGetThreadExtErrMsg();
    ASSERT_NE(threadInfo, nullptr);
    EXPECT_EQ(threadInfo->errVal, -20);

    /* HksGetAndClearThreadExtErrMsg -> returns and clears */
    struct HksExternalErrorInfo *cleared = HksGetAndClearThreadExtErrMsg();
    ASSERT_NE(cleared, nullptr);
    EXPECT_EQ(cleared->errVal, -20);
    EXPECT_EQ(HksGetThreadExtErrMsg(), nullptr);
    HksFreeExternalErrorInfo(cleared);

    /* HksClearThreadExtErrMsg */
    HksAppendThreadExtErrMsg(-30, "to clear");
    HksClearThreadExtErrMsg();
    EXPECT_EQ(HksGetThreadExtErrMsg(), nullptr);

    /* HksClearThreadExtErrMsg when already NULL -> no crash */
    HksClearThreadExtErrMsg();
}

}
