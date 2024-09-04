/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "hksfiletransfer_fuzzer.h"

#include "hks_config_parser.h"
#include "hks_file_transfer.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

#undef HUKS_SA_UPGRADE_CONFIG
#undef HUKS_HAP_UPGRADE_CONFIG
#undef HUKS_SA_SKIP_UPGRADE_CONFIG
#undef HUKS_HAP_SKIP_UPGRADE_CONFIG

#define HUKS_SA_UPGRADE_CONFIG { { 6, false, false }, { 7, false, true }, { 8, true, false }, { 9, true, true } }
#define HUKS_HAP_UPGRADE_CONFIG { { "com.example.demo1", true, true }, \
    { "com.example.demo2", true, false }, \
    { "com.example.demo3", false, true }, \
    { "com.example.demo4", false, false } }
#define HUKS_SA_SKIP_UPGRADE_CONFIG { 0, 10, 99 }
#define HUKS_HAP_SKIP_UPGRADE_CONFIG { "com.example.skip1", "com.example.skip2" }

#include "hks_config_parser.c"

namespace OHOS {
namespace Security {
namespace Hks {

enum HksAtType g_accessTokenType = HKS_TOKEN_HAP;
char *g_hapName = nullptr;

static void HksServiceUpgradeConfigParserTest001()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest001");
    g_hapName = const_cast<char *>("com.example.demo1");
    g_accessTokenType = HKS_TOKEN_HAP;
    struct HksParamSet *paramSet001 = nullptr;
    (void)HksInitParamSet(&paramSet001);
    uint32_t userId001 = 0;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&userId001),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId001
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet001, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet001);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet001),
        .size = paramSet001->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("", &fileContent, &info);

    HksFreeParamSet(&paramSet001);
}

static void HksServiceUpgradeConfigParserTest002()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest002");
    g_hapName = const_cast<char *>("com.example.demo2");
    g_accessTokenType = HKS_TOKEN_HAP;
    struct HksParamSet *paramSet002 = nullptr;
    (void)HksInitParamSet(&paramSet002);
    uint32_t userId002 = 100;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&userId002),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId002
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet002, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet002);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet002),
        .size = paramSet002->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("", &fileContent, &info);

    HksFreeParamSet(&paramSet002);
}

static void HksServiceUpgradeConfigParserTest003()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest003");
    g_hapName = const_cast<char *>("com.example.demo3");
    g_accessTokenType = HKS_TOKEN_HAP;
    struct HksParamSet *paramSet003 = nullptr;
    (void)HksInitParamSet(&paramSet003);
    uint32_t userId003 = 100;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&userId003),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId003
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet003, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet003);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet003),
        .size = paramSet003->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("", &fileContent, &info);

    HksFreeParamSet(&paramSet003);
}

static void HksServiceUpgradeConfigParserTest004()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest004");
    g_hapName = const_cast<char *>("com.example.demo4");
    g_accessTokenType = HKS_TOKEN_HAP;
    struct HksParamSet *paramSet004 = nullptr;
    (void)HksInitParamSet(&paramSet004);
    uint32_t userId004 = 100;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&userId004),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId004
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet004, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet004);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet004),
        .size = paramSet004->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("", &fileContent, &info);

    HksFreeParamSet(&paramSet004);
}

static void HksServiceUpgradeConfigParserTest005()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest005");
    g_hapName = const_cast<char *>("com.example.skip1");
    g_accessTokenType = HKS_TOKEN_HAP;
    struct HksParamSet *paramSet005 = nullptr;
    (void)HksInitParamSet(&paramSet005);
    uint32_t userId005 = 100;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&userId005),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId005
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet005, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet005);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet005),
        .size = paramSet005->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("", &fileContent, &info);

    HksFreeParamSet(&paramSet005);
}

static void HksServiceUpgradeConfigParserTest006()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest006");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet006 = nullptr;
    (void)HksInitParamSet(&paramSet006);
    uint32_t userId006 = 0;
    uint32_t uid006 = 6;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid006),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId006
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet006, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet006);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet006),
        .size = paramSet006->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("", &fileContent, &info);

    HksFreeParamSet(&paramSet006);
}

static void HksServiceUpgradeConfigParserTest007()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest007");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet007 = nullptr;
    (void)HksInitParamSet(&paramSet007);
    uint32_t userId007 = 0;
    uint32_t uid007 = 7;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid007),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId007
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet007, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet007);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet007),
        .size = paramSet007->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("", &fileContent, &info);

    HksFreeParamSet(&paramSet007);
}

static void HksServiceUpgradeConfigParserTest008()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest008");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet008 = nullptr;
    (void)HksInitParamSet(&paramSet008);
    uint32_t userId008 = 0;
    uint32_t uid008 = 8;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid008),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId008
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet008, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet008);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet008),
        .size = paramSet008->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("", &fileContent, &info);

    HksFreeParamSet(&paramSet008);
}

static void HksServiceUpgradeConfigParserTest009()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest009");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet009 = nullptr;
    (void)HksInitParamSet(&paramSet009);
    uint32_t userId009 = 0;
    uint32_t uid009 = 9;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid009),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId009
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet009, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet009);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet009),
        .size = paramSet009->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("", &fileContent, &info);

    HksFreeParamSet(&paramSet009);
}

static void HksServiceUpgradeConfigParserTest010()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest010");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet010 = nullptr;
    (void)HksInitParamSet(&paramSet010);
    uint32_t userId010 = 0;
    uint32_t uid010 = 10;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid010),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId010
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet010, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet010);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet010),
        .size = paramSet010->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("", &fileContent, &info);

    HksFreeParamSet(&paramSet010);
}

static void HksServiceUpgradeConfigParserTest011()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest011");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet011 = nullptr;
    (void)HksInitParamSet(&paramSet011);
    uint32_t userId011 = 0;
    uint32_t uid011 = 11;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid011),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId011
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet011, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet011);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet011),
        .size = paramSet011->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("DistributedDataRdb_test", &fileContent, &info);

    HksFreeParamSet(&paramSet011);
}

static void HksServiceUpgradeConfigParserTest012()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest012");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet012 = nullptr;
    (void)HksInitParamSet(&paramSet012);
    uint32_t userId012 = 0;
    uint32_t uid012 = 11;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid012),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId012
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet012, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet012);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet012),
        .size = paramSet012->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("distributeddb_client_root_key", &fileContent, &info);

    HksFreeParamSet(&paramSet012);
}

static void HksServiceUpgradeConfigParserTest013()
{
    HKS_LOG_I("enter HksServiceUpgradeConfigParserTest013");
    g_accessTokenType = HKS_TOKEN_NATIVE;
    struct HksParamSet *paramSet013 = nullptr;
    (void)HksInitParamSet(&paramSet013);
    uint32_t userId013 = 0;
    uint32_t uid013 = 11;
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .data = reinterpret_cast<uint8_t *>(&uid013),
                .size = sizeof(uint32_t)
            }
        }, {
            .tag = HKS_TAG_USER_ID,
            .uint32Param = userId013
        }, {
            .tag = HKS_TAG_ACCESS_TOKEN_ID,
            .uint64Param = 0
        }
    };
    (void)HksAddParams(paramSet013, params, HKS_ARRAY_SIZE(params));
    (void)HksBuildParamSet(&paramSet013);
    struct HksBlob fileContent = { .data = reinterpret_cast<uint8_t *>(paramSet013),
        .size = paramSet013->paramSetSize };
    struct HksUpgradeFileTransferInfo info = { 0 };
    (void)HksParseConfig("distributeddb_client_root_key_etc", &fileContent, &info);

    HksFreeParamSet(&paramSet013);
}

static void HksFileTransferTest001()
{
    HKS_LOG_I("enter HksFileTransferTest001");
    const uint32_t testUserId = 100;
    HksUpgradeFileTransferOnUserUnlock(testUserId);
}
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest001();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest002();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest003();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest004();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest005();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest006();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest007();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest008();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest009();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest010();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest011();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest012();
    OHOS::Security::Hks::HksServiceUpgradeConfigParserTest013();
    OHOS::Security::Hks::HksFileTransferTest001();
    return 0;
}
