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

#include "hctest.h"
#include "hi_watchdog.h"
#include "hks_bn_exp_mod_test_c.h"

/*
 * @tc.register: register a test suit named "CalcMultiTest"
 * @param: test subsystem name
 * @param: c_example module name
 * @param: CalcMultiTest test suit name
 */
LITE_TEST_SUIT(husk, huks_lite, HksBnExpModTest);

/**
 * @tc.setup: define a setup for test suit, format:"CalcMultiTest + SetUp"
 * @return: true——setup success
 */
static BOOL HksBnExpModTestSetUp()
{
    LiteTestPrint("setup\n");
    hi_watchdog_disable();
    TEST_ASSERT_TRUE(HksInitialize() == 0);
    return TRUE;
}

/**
 * @tc.teardown: define a setup for test suit, format:"CalcMultiTest + TearDown"
 * @return: true——teardown success
 */
static BOOL HksBnExpModTestTearDown()
{
    LiteTestPrint("tearDown\n");
    hi_watchdog_enable();
    return TRUE;
}

/**
 * @tc.name: HksBnExpModTest.HksBnExpModTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
LITE_TEST_CASE(HksBnExpModTest, HksBnExpModTest001, Level1)
{
    int32_t ret;
    if (g_testBnExpModParams[0].isTestValue) {
        ret = TestValue();
        TEST_ASSERT_TRUE(ret == 0);
    } else {
        struct HksBlob *x = NULL;
        struct HksBlob *a = NULL;
        struct HksBlob *e = NULL;
        struct HksBlob *n = NULL;
        ret = TestConstuctBlob(&x, g_testBnExpModParams[0].xParams.blobExist,
            g_testBnExpModParams[0].xParams.blobSize, g_testBnExpModParams[0].xParams.blobDataExist,
            g_testBnExpModParams[0].xParams.blobDataSize);
        TEST_ASSERT_TRUE(ret == 0);

        ret = TestConstructBlobOut(&a, g_testBnExpModParams[0].aParams.blobExist,
            g_testBnExpModParams[0].aParams.blobSize,  g_testBnExpModParams[0].aParams.blobDataExist,
            g_testBnExpModParams[0].aParams.blobDataSize);
        TEST_ASSERT_TRUE(ret == 0);

        ret = TestConstuctBlob(&e, g_testBnExpModParams[0].eParams.blobExist,
            g_testBnExpModParams[0].eParams.blobSize, g_testBnExpModParams[0].eParams.blobDataExist,
            g_testBnExpModParams[0].eParams.blobDataSize);
        TEST_ASSERT_TRUE(ret == 0);

        ret = TestConstuctBlob(&n, g_testBnExpModParams[0].nParams.blobExist,
            g_testBnExpModParams[0].nParams.blobSize, g_testBnExpModParams[0].nParams.blobDataExist,
            g_testBnExpModParams[0].nParams.blobDataSize);
        TEST_ASSERT_TRUE(ret == 0);
        if ((n != NULL) && (n->data != NULL) && (n->size != 0)) {
            n->data[n->size - 1] = n->data[n->size - 1] | 0x00000001; /* make sure n is odd */
        }

        ret = HksBnExpModRun(x, a, e, n, 1);

        TEST_ASSERT_TRUE(ret == g_testBnExpModParams[0].expectResult);

        TestFreeBlob(&x);
        TestFreeBlob(&a);
        TestFreeBlob(&e);
        TestFreeBlob(&n);
        TEST_ASSERT_TRUE(ret == 0);
    }
}

RUN_TEST_SUITE(HksBnExpModTest);
