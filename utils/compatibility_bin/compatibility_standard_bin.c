/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdbool.h>

#include <securec.h>

/**
 * This bin file is used in l2 device triggered when device initializing
*/

#include "hilog/log.h"
#define LOG_ENGINE LOG_CORE
#define LOG_PUBLIC "{public}"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002F00 /* Security subsystem's domain id */

#define HKS_LOG_E(fmt, arg...) HILOG_ERROR(LOG_ENGINE, "%" LOG_PUBLIC "s[%" LOG_PUBLIC "u]: " fmt "\n", \
                                                                                            __func__, __LINE__, ##arg)

#define HUKS_SERVICE_UID 3510
#define DIR_TYPE 4
#define DEFAULT_PATH_LEN 1024
#define DEFAULT_HUKS_PATH_PERMISSION 0700

#include <stdio.h>

#include <errno.h>

static void ChangeDirAndFilesPerm(const char *path)
{
    HKS_LOG_E("enter ChangeDirAndFilesPerm %" LOG_PUBLIC "s", path);
    DIR *dir;
    struct dirent *ptr;
    dir = opendir(path);
    if (dir == NULL) {
        return;
    }
    int ret = EOK;
    while ((ptr = readdir(dir)) != NULL) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        char curPath[DEFAULT_PATH_LEN] = { 0 };

        ret = strcpy_s(curPath, DEFAULT_PATH_LEN, path);
        if (ret != EOK) {
            break;
        }
        ret = strcat_s(curPath, DEFAULT_PATH_LEN, "/");
        if (ret != EOK) {
            break;
        }
        ret = strcat_s(curPath, DEFAULT_PATH_LEN, ptr->d_name);
        if (ret != EOK) {
            break;
        }

        ret = chown(curPath, HUKS_SERVICE_UID, HUKS_SERVICE_UID);
        if (ret != EOK) {
            break;
        }
        if ((ptr->d_type != DIR_TYPE)) {
            if (chmod(curPath, S_IRUSR | S_IWUSR) < 0) {
                break;
            }
        } else {
            if (chmod(curPath, S_IRWXU) < 0) {
                break;
            }
            ChangeDirAndFilesPerm(curPath);
        }
    }
    if (ret != EOK) {
        printf("chmod dir and file failed! errno = 0x%x \n", errno);
    }
    (void)closedir(dir);
}

int main(void)
{
    const char *path = "/data/data/huks_service";
    // change directories and files permission
    ChangeDirAndFilesPerm(path);
}
