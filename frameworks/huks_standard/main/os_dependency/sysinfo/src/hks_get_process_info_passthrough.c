/*
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
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

#include "hks_get_process_info.h"

#include "securec.h"

#include "hks_mem.h"

#define USER_ID_ROOT_DEFAULT          "0"
static char g_processName[] = "hks_client";
int32_t HksGetProcessName(char **processName)
{
    *processName = g_processName;
    return HKS_SUCCESS;
}

int32_t GetUserIDWithProcessName(struct HksBlob *processName, struct HksBlob *userID)
{
    (void)processName;
    userID->data = (uint8_t *)malloc(sizeof(USER_ID_ROOT_DEFAULT));
    userID->size = sizeof(USER_ID_ROOT_DEFAULT);
    if (memcpy_s(userID->data, userID->size, USER_ID_ROOT_DEFAULT, sizeof(USER_ID_ROOT_DEFAULT)) != EOK) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    return HKS_SUCCESS;
}
