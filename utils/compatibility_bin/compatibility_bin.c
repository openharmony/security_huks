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

#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdbool.h>

void ChangeDirAndFilesPerm(const char *path)
{
    DIR *dir;
    struct dirent *ptr;
    dir = opendir(path);
    if (dir == NULL) {
        return;
    }
    int ret;
    while ((ptr = readdir(dir)) != NULL) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0)
        {
            continue;
        }
        char curPath[1000] = { 0 };

        strcpy(curPath, path);
        strcat(curPath, "/");
        strcat(curPath, ptr->d_name);

        ret = chown(curPath, 12, 12);
        if ((ptr->d_type != 4)) {
            if (chmod(curPath, S_IRUSR|S_IWUSR) < 0) {
                printf("chmod file failed! errno = 0x% x \n", errno);
            }
        } else {
            if (chmod(curPath, S_IRWXU) < 0) {
            printf("chmod dir failed! errno = 0x% x \n", errno);
            }
            ChangeDirAndFilesPerm(curPath);
        }
    }
    closedir(dir);
}

void MoveOldFileToNew(const char *srcPath, const char *tarPath)
{
    char buffer[1024];
    FILE *in, *out;
    if ((in = fopen(srcPath, "r")) == NULL) {
        printf("open source file failed !\n");
        return;
    }
    if ((out = fopen(tarPath, "w")) == NULL) {
        printf("open target file failed !\n");
        fclose(in);
        return;
    }
    int len;
    while ((len = fread(buffer, 1, 1024, in)) > 0) {
        fwrite(buffer, 1, len, out);
    }
    fclose(out);
    fclose(in);

    remove(srcPath);
}

void MoveOldFolderToNew(const char *srcPath, const char *tarPath)
{
    if(!opendir(tarPath)) {
        if (mkdir(tarPath, 0700) != 0) {
            printf("mkdir failed! errno = 0x% x \n", errno);
        }
    }
    struct dirent* ptr;
    DIR* dir=opendir(srcPath);
    while ((ptr = readdir(dir)) != NULL) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0)
        {
            continue;
        }

        char curPath[1000] = { 0 };
        strcpy(curPath, srcPath);
        strcat(curPath, "/");

        strcat(curPath, ptr->d_name);

        char desPath[1000]={ 0 };
        strcpy(desPath, tarPath);
        strcat(desPath, "/");

        strcat(desPath, ptr->d_name);
        if (ptr->d_type == 4) { // dir
            MoveOldFolderToNew(curPath, desPath);
        }
        else{
            MoveOldFileToNew(curPath, desPath);
        }
    }
    rmdir(srcPath);
}

int main()
{
    const char *oldPath = "/storage/maindata";
    const char *newPath = "/data/service/el1/public/huks_service/maindata";

    // move directories and files form old path to new path
    MoveOldFolderToNew(oldPath, newPath);

    // change directories and files permission
    ChangeDirAndFilesPerm(newPath);
}
