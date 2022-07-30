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

#include "hks_hitrace.h"

struct HksHitraceId HksHitraceBegin(const char *name, int flag)
{
#ifdef L2_STANDARD
    HiTraceIdStruct traceId = HiTraceBegin(name, flag);
    struct HksHitraceId hitraceId = {
        .traceId = traceId,
    };
    return hitraceId;
#else
    (void)name;
    (void)flag;
    struct HksHitraceId hitraceId = {};
    return hitraceId;
#endif
}

void HksHitraceEnd(struct HksHitraceId *hitraceId)
{
#ifdef L2_STANDARD
    HiTraceEnd(&hitraceId->traceId);
#else
    (void)hitraceId;
#endif
}