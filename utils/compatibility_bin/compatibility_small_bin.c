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
 * This bin file is used in l1 device triggered when device initializing, in order to support the compatibility for old
 * keys with version 1.
*/

#define HUKS_SERVICE_UID 12
#define DIR_TYPE 4
#define DEFAULT_PATH_LEN 1024
#define DEFAULT_READ_BUFFER 4096
#define DEFAULT_HUKS_PATH_PERMISSION 0700

static void ChangeDirAndFilesPerm(const char *path)
{
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

static void MoveOldFileToNew(const char *srcPath, const char *tarPath)
{
    char buffer[DEFAULT_READ_BUFFER];
    FILE *in, *out;
    if ((in = fopen(srcPath, "r")) == NULL) {
        printf("open source file failed !\n");
        return;
    }
    if ((out = fopen(tarPath, "w")) == NULL) {
        printf("open target file failed !\n");
        (void)fclose(in);
        return;
    }
    int len;
    while ((len = fread(buffer, 1, DEFAULT_READ_BUFFER, in)) > 0) {
        int size = fwrite(buffer, 1, len, out);
        if (size != len) {
            printf("move old file to new path failed!");
            (void)fclose(out);
            (void)fclose(in);
            return;
        }
    }
    (void)fclose(out);
    (void)fclose(in);

    (void)remove(srcPath);
}

static int ConstructSrcAndTargetPath(char *curPath, char *desPath, struct dirent *ptr,
    const char *srcPath, const char *tarPath)
{
    int ret = strcpy_s(curPath, DEFAULT_PATH_LEN, srcPath);
    if (ret != EOK) {
        return ret;
    }
    ret = strcat_s(curPath, DEFAULT_PATH_LEN, "/");
    if (ret != EOK) {
        return ret;
    }

    ret = strcat_s(curPath, DEFAULT_PATH_LEN, ptr->d_name);
    if (ret != EOK) {
        return ret;
    }

    ret = strcpy_s(desPath, DEFAULT_PATH_LEN, tarPath);
    if (ret != EOK) {
        return ret;
    }
    ret = strcat_s(desPath, DEFAULT_PATH_LEN, "/");
    if (ret != EOK) {
        return ret;
    }

    ret = strcat_s(desPath, DEFAULT_PATH_LEN, ptr->d_name);
    if (ret != EOK) {
        return ret;
    }
    return EOK;
}

static void MoveOldFolderToNew(const char *srcPath, const char *tarPath)
{
    if (!opendir(tarPath)) {
        if (mkdir(tarPath, DEFAULT_HUKS_PATH_PERMISSION) != 0) {
            printf("mkdir failed! errno = 0x%x \n", errno);
            return;
        }
    }
    struct dirent *ptr;
    DIR *dir = opendir(srcPath);
    int ret = EOK;
    while ((ptr = readdir(dir)) != NULL) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        char curPath[DEFAULT_PATH_LEN] = { 0 };
        char desPath[DEFAULT_PATH_LEN] = { 0 };

        ret = ConstructSrcAndTargetPath(curPath, desPath, ptr, srcPath, tarPath);
        if (ret != EOK) {
            printf("construct src and target path failed!");
            break;
        }
        if (ptr->d_type == DIR_TYPE) {
            MoveOldFolderToNew(curPath, desPath);
        } else {
            MoveOldFileToNew(curPath, desPath);
        }
    }
    (void)closedir(dir);
    if (ret != EOK) {
        printf("chmod dir and file failed! errno = 0x%x \n", errno);
    }
    (void)rmdir(srcPath);
}

int main(void)
{
    const char *oldPath = "/storage/maindata";
    const char *newPath = "/storage/data/service/el1/public/huks_service/maindata";

    // move directories and files form old path to new path
    MoveOldFolderToNew(oldPath, newPath);

    // change directories and files permission
    ChangeDirAndFilesPerm(newPath);
}
