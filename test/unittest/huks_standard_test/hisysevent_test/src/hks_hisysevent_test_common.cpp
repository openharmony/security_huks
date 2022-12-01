/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "hks_hisysevent_test_common.h"

#include <cstdio>
#include <sys/time.h>
#include <unistd.h>

#include "hisysevent_manager.h"

using namespace std;

static const int MAX_QUERY_EVENT_COUNT = 1000;
static const int TIME_S_TO_MS = 1000;
static const int TIME_MS_TO_US = 1000;

static long long int g_beginTime = 0;
static long long int g_endTime = 0;
static volatile  bool g_queryResult = false;
static string g_queryStr;

namespace OHOS {
namespace HiviewDFX {
class HksHiSysEventCallBack : public OHOS::HiviewDFX::HiSysEventQueryCallback {
public:
    HksHiSysEventCallBack() {}
    virtual ~HksHiSysEventCallBack() {}
    void OnQuery(std::shared_ptr<std::vector<HiSysEventRecord>> sysEvents);
    void OnComplete(int32_t reason, int32_t total);
};

void HksHiSysEventCallBack::OnQuery(std::shared_ptr<std::vector<HiSysEventRecord>> sysEvents)
{
    if (g_queryStr.size() == 0 || sysEvents == nullptr) {
        return;
    }
    for_each((*sysEvents).cbegin(), (*sysEvents).cend(), [](const HiSysEventRecord& tmp) {
        string::size_type idx = tmp.AsJson().find(g_queryStr);
        if (idx != string::npos) {
            g_queryResult = true;
        }
    });
    return;
}

void HksHiSysEventCallBack::OnComplete(int32_t reason, int32_t total)
{
    return;
}
} // namespace HiviewDFX
} // namespace OHOS

using namespace OHOS::HiviewDFX;

static long long int GetCurrentTime(void)
{
    struct timeval tv;
    (void)gettimeofday(&tv, nullptr);
    long long int timeStamp = tv.tv_sec * TIME_S_TO_MS + tv.tv_usec / TIME_MS_TO_US;
    return timeStamp;
}

void HksHiSysEventQueryStart(void)
{
    g_beginTime = GetCurrentTime();
    g_endTime = 0;
}

int32_t HksHiSysEventQueryResult(const string funStr)
{
    if (g_beginTime == 0) {
        return HKS_HISYSEVENT_QUERY_FAILED;
    }

    g_queryResult = false;
    g_queryStr = funStr;
    
    sleep(1); // Waiting for hisysevent to upload

    // queryArg
    g_endTime = GetCurrentTime();
    struct QueryArg args(g_beginTime, g_endTime, MAX_QUERY_EVENT_COUNT);

    // queryRules
    string domain = "SECURITY_HUKS";
    vector<string> eventList;
    eventList.push_back("HUKS_FAULT");
    QueryRule rule(domain, eventList);
    vector<QueryRule> queryRules;
    queryRules.push_back(rule);

    // queryCallback
    auto queryCallBack = std::make_shared<HksHiSysEventCallBack>();
    if (HiSysEventManager::Query(args, queryRules, queryCallBack) == 0) {
        if (g_queryResult) {
            return HKS_HISYSEVENT_QUERY_SUCCESS;
        }
        return HKS_HISYSEVENT_QUERY_FAILED;
    }
    
    return HKS_HISYSEVENT_QUERY_FAILED;
}