/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "log_utils.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "hilog/log_c.h"
#include "securec.h"
#include "hilog/log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002F06

#undef LOG_TAG
#define LOG_TAG "[HUKS]"

#define LOG_DEBUG(buf) HILOG_DEBUG(LOG_CORE, "%{public}s", buf)
#define LOG_INFO(buf) HILOG_INFO(LOG_CORE, "%{public}s", buf)
#define LOG_WARN(buf) HILOG_WARN(LOG_CORE, "%{public}s", buf)
#define LOG_ERROR(buf) HILOG_ERROR(LOG_CORE, "%{public}s", buf)

#define CRYPTO_PRINT_MAX_LEN 1024

static void OutPrint(const char * buf, CryptogLevel level)
{
    switch (level){
        case LOG_LEVEL_DEBUG:
            LOG_DEBUG(buf);
            break;
        case LOG_LEVEL_INFO:
            LOG_INFO(buf);
            break;
        case LOG_LEVEL_WARN:
            LOG_WARN(buf);
            break;
        case LOG_LEVEL_ERROR:
            LOG_ERROR(buf);
            break;
        default:
            break;
    }
}

void LogPrint(CryptogLevel level, const char *funName, const char *fmt, ...)
{
    int32_t ulPos = 0;
    char outStr[CRYPTO_PRINT_MAX_LEN] = { 0 };
    int32_t ret = sprintf_s(outStr, sizeof(outStr), "%s: ", funName);
    if (ret < 0) {
        return;
    }
    ulPos = strlen(outStr);
    va_list arg;
    va_start(arg, fmt);
    ret = vsprintf_s(&outStr[ulPos], sizeof(outStr) - ulPos, fmt, arg);
    va_end(arg);
    if (ret < 0) {
        return;
    }
    OutPrint(outStr, level);
}