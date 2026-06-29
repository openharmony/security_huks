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

#include <gtest/gtest.h>
#include <securec.h>
#include <cstdint>
#include <cstring>

#include "hks_event_info.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_report_three_stage_get.h"
#include "hks_se_session_manager.h"
#include "hks_session_manager.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksReportThreeStageTest {

class HksReportThreeStageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksReportThreeStageTest::SetUpTestCase(void) {}
void HksReportThreeStageTest::TearDownTestCase(void) {}
void HksReportThreeStageTest::SetUp() {}
void HksReportThreeStageTest::TearDown() {}

static int32_t BuildParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    if (params != nullptr && paramCount > 0) {
        ret = HksAddParams(*paramSet, params, paramCount);
        if (ret != HKS_SUCCESS) {
            HksFreeParamSet(paramSet);
            return ret;
        }
    }
    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(paramSet);
        return ret;
    }
    return HKS_SUCCESS;
}

static void BuildProcessInfo(struct HksProcessInfo *processInfo, uint32_t userIdInt, uint32_t uidInt)
{
    uint8_t userIdData[] = "test_user";
    uint8_t processNameData[] = "test_proc_r3s";
    processInfo->userIdInt = userIdInt;
    processInfo->uidInt = uidInt;
    processInfo->userId.size = sizeof(userIdData);
    processInfo->userId.data = (uint8_t *)HksMalloc(sizeof(userIdData));
    if (processInfo->userId.data != nullptr) {
        (void)memcpy_s(processInfo->userId.data, sizeof(userIdData), userIdData, sizeof(userIdData));
    } else {
        processInfo->userId.size = 0;
    }
    processInfo->processName.size = sizeof(processNameData);
    processInfo->processName.data = (uint8_t *)HksMalloc(sizeof(processNameData));
    if (processInfo->processName.data != nullptr) {
        (void)memcpy_s(processInfo->processName.data, sizeof(processNameData), processNameData, sizeof(processNameData));
    } else {
        processInfo->processName.size = 0;
    }
    processInfo->accessTokenId = 0;
    processInfo->pid = 0;
}

static void FreeProcessInfo(struct HksProcessInfo *processInfo)
{
    if (processInfo != nullptr) {
        HKS_FREE_BLOB(processInfo->userId);
        HKS_FREE_BLOB(processInfo->processName);
    }
}

static uint64_t BuildSeHandle(uint64_t baseHandle)
{
    return baseHandle | (1ULL << HKS_SE_HANDLE_MASK_BIT);
}

static void InitNormalOpErrMsgBlob(struct HksOperation *operation)
{
    operation->errMsgBlob = { 0, nullptr };
}

/**
 * @tc.name: HksReportThreeStageTest.HksReportThreeStageTest001
 * @tc.desc: tdd HksGetInitEventInfo, purpose mapping and keySecurityLevel
 * @tc.type: FUNC
 */
HWTEST_F(HksReportThreeStageTest, HksReportThreeStageTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportThreeStageTest001");
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);
    uint8_t aliasData[] = "test_alias";
    struct HksBlob keyAlias = { sizeof(aliasData), aliasData };

    struct HksParam paramsWithTag[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_TEE },
    };
    struct HksParamSet *psWithTag = nullptr;
    int32_t ret = BuildParamSet(&psWithTag, paramsWithTag, sizeof(paramsWithTag) / sizeof(paramsWithTag[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    HksEventInfo evWithTag = {};
    ret = HksGetInitEventInfo(&keyAlias, nullptr, psWithTag, &processInfo, &evWithTag);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(evWithTag.common.eventId, HKS_EVENT_CRYPTO);
    EXPECT_EQ(evWithTag.cryptoInfo.keyInfo.keySecurityLevel, HKS_KEY_SECURITY_LEVEL_TEE);

    struct HksParam paramsNoTag[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    };
    struct HksParamSet *psNoTag = nullptr;
    ret = BuildParamSet(&psNoTag, paramsNoTag, sizeof(paramsNoTag) / sizeof(paramsNoTag[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    HksEventInfo evNoTag = {};
    ret = HksGetInitEventInfo(&keyAlias, nullptr, psNoTag, &processInfo, &evNoTag);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(evNoTag.keyInfo.keySecurityLevel, HKS_KEY_SECURITY_LEVEL_DEFAULT);

    struct HksParam paramsSign[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
    };
    struct HksParamSet *psSign = nullptr;
    ret = BuildParamSet(&psSign, paramsSign, sizeof(paramsSign) / sizeof(paramsSign[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    HksEventInfo evSign = {};
    ret = HksGetInitEventInfo(&keyAlias, nullptr, psSign, &processInfo, &evSign);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(evSign.common.eventId, HKS_EVENT_SIGN_VERIFY);

    struct HksParam paramsMac[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
    };
    struct HksParamSet *psMac = nullptr;
    ret = BuildParamSet(&psMac, paramsMac, sizeof(paramsMac) / sizeof(paramsMac[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    HksEventInfo evMac = {};
    ret = HksGetInitEventInfo(&keyAlias, nullptr, psMac, &processInfo, &evMac);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(evMac.common.eventId, HKS_EVENT_MAC);

    struct HksParam paramsBad[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = 9999 },
    };
    struct HksParamSet *psBad = nullptr;
    ret = BuildParamSet(&psBad, paramsBad, sizeof(paramsBad) / sizeof(paramsBad[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    HksEventInfo evBad = {};
    ret = HksGetInitEventInfo(&keyAlias, nullptr, psBad, &processInfo, &evBad);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);

    HksFreeParamSet(&psWithTag);
    HksFreeParamSet(&psNoTag);
    HksFreeParamSet(&psSign);
    HksFreeParamSet(&psMac);
    HksFreeParamSet(&psBad);
    FreeProcessInfo(&processInfo);
}

/**
 * @tc.name: HksReportThreeStageTest.HksReportThreeStageTest002
 * @tc.desc: tdd null pointer checks for public report functions
 * @tc.type: FUNC
 */
HWTEST_F(HksReportThreeStageTest, HksReportThreeStageTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportThreeStageTest002");

    EXPECT_EQ(HksGetInitEventInfo(nullptr, nullptr, nullptr, nullptr, nullptr), HKS_ERROR_NULL_POINTER);

    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);
    EXPECT_EQ(HksGetInitEventInfo(nullptr, nullptr, nullptr, &processInfo, nullptr), HKS_ERROR_NULL_POINTER);

    EXPECT_EQ(HksThreeStageReport("test", nullptr, nullptr, nullptr), HKS_ERROR_NULL_POINTER);

    EXPECT_EQ(HksServiceInitReport("test", nullptr, nullptr, nullptr, nullptr), HKS_ERROR_NULL_POINTER);

    FreeProcessInfo(&processInfo);
}

/**
 * @tc.name: HksReportThreeStageTest.HksReportThreeStageTest003
 * @tc.desc: tdd HksOperationUnion, isSe flag controls union member access
 * @tc.type: FUNC
 */
HWTEST_F(HksReportThreeStageTest, HksReportThreeStageTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportThreeStageTest003");

    struct HksOperation normalOp = {};
    HksThreeStageReportInfo infoNormal = {};
    infoNormal.unionOp.isSe = false;
    infoNormal.unionOp.op.operation = &normalOp;
    EXPECT_EQ(infoNormal.unionOp.isSe, false);
    EXPECT_EQ(infoNormal.unionOp.op.operation, &normalOp);

    struct HksSeOperation seOp = {};
    HksThreeStageReportInfo infoSe = {};
    infoSe.unionOp.isSe = true;
    infoSe.unionOp.op.seOperation = &seOp;
    EXPECT_EQ(infoSe.unionOp.isSe, true);
    EXPECT_EQ(infoSe.unionOp.op.seOperation, &seOp);
}

/**
 * @tc.name: HksReportThreeStageTest.HksReportThreeStageTest004
 * @tc.desc: tdd normal operation, HksServiceInitReport success path
 * @tc.type: FUNC
 */
HWTEST_F(HksReportThreeStageTest, HksReportThreeStageTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportThreeStageTest004");
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *emptyPs = nullptr;
    int32_t ret = BuildParamSet(&emptyPs, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = 10001;
    struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handleValue };
    ret = HksCreateOperation(&processInfo, emptyPs, &handleBlob, true);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksOperation *operation = QueryOperationAndMarkInUse(&processInfo, &handleBlob);
    ASSERT_NE(operation, nullptr);
    InitNormalOpErrMsgBlob(operation);
    MarkOperationUnUse(operation);

    struct HksParam purposeParams[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_TEE },
    };
    struct HksParamSet *purposePs = nullptr;
    ret = BuildParamSet(&purposePs, purposeParams, sizeof(purposeParams) / sizeof(purposeParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksEventInfo eventInfo = {};
    eventInfo.keyInfo.keySecurityLevel = HKS_KEY_SECURITY_LEVEL_TEE;
    eventInfo.common.eventId = HKS_EVENT_CRYPTO;
    eventInfo.cryptoInfo.keyInfo.purpose = HKS_KEY_PURPOSE_ENCRYPT;
    eventInfo.common.callerInfo.uid = processInfo.uidInt;

    HksThreeStageReportInfo reportInfo = {};
    reportInfo.errCode = HKS_SUCCESS;
    reportInfo.stage = HKS_INIT;
    reportInfo.startTime = 0;
    reportInfo.inDataSize = 0;
    reportInfo.traceId = 0;
    reportInfo.handle = &handleBlob;
    reportInfo.unionOp = { false, { nullptr } };

    ret = HksServiceInitReport("HksServiceInit", &processInfo, purposePs, &reportInfo, &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    operation = QueryOperationAndMarkInUse(&processInfo, &handleBlob);
    EXPECT_NE(operation, nullptr);
    if (operation != nullptr) {
        EXPECT_EQ(operation->eventInfo.cryptoInfo.keyInfo.keySecurityLevel, HKS_KEY_SECURITY_LEVEL_TEE);
        EXPECT_NE(operation->errMsgBlob.data, nullptr);
        EXPECT_GT(operation->errMsgBlob.size, 0u);
        MarkOperationUnUse(operation);
    }

    DeleteOperation(&handleBlob);
    HksFreeParamSet(&emptyPs);
    HksFreeParamSet(&purposePs);
    FreeProcessInfo(&processInfo);
}

/**
 * @tc.name: HksReportThreeStageTest.HksReportThreeStageTest005
 * @tc.desc: tdd SE operation, HksServiceInitReport success path
 * @tc.type: FUNC
 */
HWTEST_F(HksReportThreeStageTest, HksReportThreeStageTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportThreeStageTest005");
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *emptyPs = nullptr;
    int32_t ret = BuildParamSet(&emptyPs, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t seHandleValue = BuildSeHandle(20001);
    struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&seHandleValue };
    ret = HksCreateSeOperation(&processInfo, emptyPs, &handleBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam purposeParams[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = HKS_KEY_SECURITY_LEVEL_TEE },
    };
    struct HksParamSet *purposePs = nullptr;
    ret = BuildParamSet(&purposePs, purposeParams, sizeof(purposeParams) / sizeof(purposeParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksEventInfo eventInfo = {};
    eventInfo.keyInfo.keySecurityLevel = HKS_KEY_SECURITY_LEVEL_TEE;
    eventInfo.common.eventId = HKS_EVENT_CRYPTO;
    eventInfo.cryptoInfo.keyInfo.purpose = HKS_KEY_PURPOSE_ENCRYPT;
    eventInfo.common.callerInfo.uid = processInfo.uidInt;

    HksThreeStageReportInfo reportInfo = {};
    reportInfo.errCode = HKS_SUCCESS;
    reportInfo.stage = HKS_INIT;
    reportInfo.startTime = 0;
    reportInfo.inDataSize = 0;
    reportInfo.traceId = 0;
    reportInfo.handle = &handleBlob;
    reportInfo.unionOp = { true, { nullptr } };

    ret = HksServiceInitReport("HksServiceInit", &processInfo, purposePs, &reportInfo, &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *seOp = HksQuerySeOperationAndMarkInUse(&processInfo, &handleBlob);
    EXPECT_NE(seOp, nullptr);
    if (seOp != nullptr) {
        EXPECT_EQ(seOp->eventInfo.cryptoInfo.keyInfo.keySecurityLevel, HKS_KEY_SECURITY_LEVEL_TEE);
        EXPECT_NE(seOp->errMsgBlob.data, nullptr);
        EXPECT_GT(seOp->errMsgBlob.size, 0u);
        HksMarkSeOperationUnUse(seOp);
    }

    HksDeleteSeOperation(&handleBlob);
    HksFreeParamSet(&emptyPs);
    HksFreeParamSet(&purposePs);
    FreeProcessInfo(&processInfo);
}

/**
 * @tc.name: HksReportThreeStageTest.HksReportThreeStageTest006
 * @tc.desc: tdd normal op, HksThreeStageReport Finish failure preserves keySecurityLevel
 * @tc.type: FUNC
 */
HWTEST_F(HksReportThreeStageTest, HksReportThreeStageTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportThreeStageTest006");
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *emptyPs = nullptr;
    int32_t ret = BuildParamSet(&emptyPs, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = 10002;
    struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&handleValue };
    ret = HksCreateOperation(&processInfo, emptyPs, &handleBlob, true);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksOperation *operation = QueryOperationAndMarkInUse(&processInfo, &handleBlob);
    ASSERT_NE(operation, nullptr);
    operation->eventInfo = {};
    operation->eventInfo.common.eventId = HKS_EVENT_CRYPTO;
    operation->eventInfo.cryptoInfo.keyInfo.purpose = HKS_KEY_PURPOSE_ENCRYPT;
    operation->eventInfo.cryptoInfo.keyInfo.keySecurityLevel = HKS_KEY_SECURITY_LEVEL_TEE;
    operation->eventInfo.common.callerInfo.uid = processInfo.uidInt;
    InitNormalOpErrMsgBlob(operation);
    MarkOperationUnUse(operation);

    struct HksParam freshParams[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    };
    struct HksParamSet *freshPs = nullptr;
    ret = BuildParamSet(&freshPs, freshParams, sizeof(freshParams) / sizeof(freshParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksThreeStageReportInfo reportInfo = {};
    reportInfo.errCode = HKS_FAILURE;
    reportInfo.stage = HKS_FINISH;
    reportInfo.startTime = 0;
    reportInfo.inDataSize = 0;
    reportInfo.traceId = 0;
    reportInfo.handle = &handleBlob;
    reportInfo.unionOp.isSe = false;
    reportInfo.unionOp.op.operation = operation;

    (void)HksThreeStageReport("HksServiceFinish", &processInfo, freshPs, &reportInfo);

    EXPECT_EQ(operation->eventInfo.cryptoInfo.keyInfo.keySecurityLevel, HKS_KEY_SECURITY_LEVEL_TEE);

    DeleteOperation(&handleBlob);
    HksFreeParamSet(&emptyPs);
    HksFreeParamSet(&freshPs);
    FreeProcessInfo(&processInfo);
}

/**
 * @tc.name: HksReportThreeStageTest.HksReportThreeStageTest007
 * @tc.desc: tdd SE op, HksThreeStageReport Finish failure preserves keySecurityLevel
 * @tc.type: FUNC
 */
HWTEST_F(HksReportThreeStageTest, HksReportThreeStageTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportThreeStageTest007");
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *emptyPs = nullptr;
    int32_t ret = BuildParamSet(&emptyPs, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t seHandleValue = BuildSeHandle(20002);
    struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&seHandleValue };
    ret = HksCreateSeOperation(&processInfo, emptyPs, &handleBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *seOp = HksQuerySeOperationAndMarkInUse(&processInfo, &handleBlob);
    ASSERT_NE(seOp, nullptr);
    seOp->eventInfo = {};
    seOp->eventInfo.common.eventId = HKS_EVENT_CRYPTO;
    seOp->eventInfo.cryptoInfo.keyInfo.purpose = HKS_KEY_PURPOSE_ENCRYPT;
    seOp->eventInfo.cryptoInfo.keyInfo.keySecurityLevel = HKS_KEY_SECURITY_LEVEL_TEE;
    seOp->eventInfo.common.callerInfo.uid = processInfo.uidInt;
    HksMarkSeOperationUnUse(seOp);

    struct HksParam freshParams[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    };
    struct HksParamSet *freshPs = nullptr;
    ret = BuildParamSet(&freshPs, freshParams, sizeof(freshParams) / sizeof(freshParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksThreeStageReportInfo reportInfo = {};
    reportInfo.errCode = HKS_FAILURE;
    reportInfo.stage = HKS_FINISH;
    reportInfo.startTime = 0;
    reportInfo.inDataSize = 0;
    reportInfo.traceId = 0;
    reportInfo.handle = &handleBlob;
    reportInfo.unionOp.isSe = true;
    reportInfo.unionOp.op.seOperation = seOp;

    (void)HksThreeStageReport("HksServiceFinish", &processInfo, freshPs, &reportInfo);

    EXPECT_EQ(seOp->eventInfo.cryptoInfo.keyInfo.keySecurityLevel, HKS_KEY_SECURITY_LEVEL_TEE);

    HksDeleteSeOperation(&handleBlob);
    HksFreeParamSet(&emptyPs);
    HksFreeParamSet(&freshPs);
    FreeProcessInfo(&processInfo);
}

/**
 * @tc.name: HksReportThreeStageTest.HksReportThreeStageTest008
 * @tc.desc: tdd SE op, HksThreeStageReport Init success calls HandleSeSuccessStage
 * @tc.type: FUNC
 */
HWTEST_F(HksReportThreeStageTest, HksReportThreeStageTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportThreeStageTest008");
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *emptyPs = nullptr;
    int32_t ret = BuildParamSet(&emptyPs, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t seHandleValue = BuildSeHandle(20003);
    struct HksBlob handleBlob = { sizeof(uint64_t), (uint8_t *)&seHandleValue };
    ret = HksCreateSeOperation(&processInfo, emptyPs, &handleBlob);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *seOp = HksQuerySeOperationAndMarkInUse(&processInfo, &handleBlob);
    ASSERT_NE(seOp, nullptr);
    seOp->eventInfo = {};
    seOp->eventInfo.common.eventId = HKS_EVENT_CRYPTO;
    seOp->eventInfo.cryptoInfo.keyInfo.purpose = HKS_KEY_PURPOSE_ENCRYPT;
    seOp->eventInfo.cryptoInfo.keyInfo.keySecurityLevel = HKS_KEY_SECURITY_LEVEL_TEE;
    HksMarkSeOperationUnUse(seOp);

    struct HksParam purposeParams[] = {
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    };
    struct HksParamSet *purposePs = nullptr;
    ret = BuildParamSet(&purposePs, purposeParams, sizeof(purposeParams) / sizeof(purposeParams[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksThreeStageReportInfo reportInfo = {};
    reportInfo.errCode = HKS_SUCCESS;
    reportInfo.stage = HKS_INIT;
    reportInfo.startTime = 0;
    reportInfo.inDataSize = 0;
    reportInfo.traceId = 0;
    reportInfo.handle = &handleBlob;
    reportInfo.unionOp.isSe = true;
    reportInfo.unionOp.op.seOperation = seOp;

    ret = HksThreeStageReport("HksServiceInit", &processInfo, purposePs, &reportInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    EXPECT_NE(seOp->errMsgBlob.data, nullptr);
    EXPECT_GT(seOp->errMsgBlob.size, 0u);
    EXPECT_EQ(seOp->eventInfo.cryptoInfo.keyInfo.keySecurityLevel, HKS_KEY_SECURITY_LEVEL_TEE);

    HksDeleteSeOperation(&handleBlob);
    HksFreeParamSet(&emptyPs);
    HksFreeParamSet(&purposePs);
    FreeProcessInfo(&processInfo);
}

}
