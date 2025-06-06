/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hks_samgr_server.h"

#include "hks_client_service.h"
#include "hks_template.h"

#define STACK_SIZE 0x800
#define QUEUE_SIZE 20

static const char *GetName(Service *service)
{
    (void)service;
    return HKS_SAMGR_SERVICE;
}
static BOOL Initialize(Service *service, Identity identity)
{
    HKS_IF_NULL_RETURN(service, false)

    HksMgrService *hksMgrService = (HksMgrService *)service;
    hksMgrService->identity = identity;
    return true;
}

static BOOL MessageHandle(Service *service, Request *request)
{
    (void)service;
    HKS_IF_NULL_RETURN(request, false)
    return true;
}

static TaskConfig GetTaskConfig(Service *service)
{
    (void)service;
    TaskConfig config = { LEVEL_HIGH, PRI_NORMAL, STACK_SIZE, QUEUE_SIZE, SINGLE_TASK };
    return config;
}

static HksMgrService g_hksMgrService = {
    .GetName = GetName,
    .Initialize = Initialize,
    .MessageHandle = MessageHandle,
    .GetTaskConfig = GetTaskConfig,
    .identity = { -1, -1, NULL }
};

static void Init(void)
{
    int32_t ret = HksServiceInitialize();
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("huks service initialaize failed!");
    }
    bool isRegistered = SAMGR_GetInstance()->RegisterService((Service *)&g_hksMgrService);
    if (!isRegistered) {
        HKS_LOG_E("register service failed!");
    }
    HKS_LOG_I("HUKS service init");
}
SYS_SERVICE_INIT(Init);
