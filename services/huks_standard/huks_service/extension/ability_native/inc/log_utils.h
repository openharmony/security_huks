/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef LOG_UTILS_H
#define LOG_UTILS_H

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3
} CryptogLevel;

#ifdef __cplusplus
extern "C" {
#endif

void LogPrint(CryptogLevel level, const char *funName, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

#ifdef __cplusplus
}
#endif

#define LOGD(fmt, ...) (LogPrint(LOG_LEVEL_DEBUG, __FUNCTION__, fmt, ##__VA_ARGS__))
#define LOGI(fmt, ...) (LogPrint(LOG_LEVEL_INFO, __FUNCTION__, fmt, ##__VA_ARGS__))
#define LOGW(fmt, ...) (LogPrint(LOG_LEVEL_WARN, __FUNCTION__, fmt, ##__VA_ARGS__))
#define LOGE(fmt, ...) (LogPrint(LOG_LEVEL_ERROR, __FUNCTION__, fmt, ##__VA_ARGS__))

#endif