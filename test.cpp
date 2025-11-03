#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define ALIGN_SIZE(size) ((((uint32_t)(size) + 3) >> 2) << 2)

struct HksBlob { uint32_t size; uint8_t *data; };

struct HksParam {
    uint32_t tag;
    union {
        uint32_t uint32Param;
        struct HksBlob blob;
        int32_t int32Param;
        uint8_t boolParam;
    };
};

struct HksParamSet {
    uint32_t paramSetSize;
    uint32_t paramsCnt;
    struct HksParam params[];
};

static void PrintHex(const uint8_t *buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

static void DumpLayoutGeneral(const struct HksBlob *name, const struct HksParamSet *ps)
{
    uint32_t total = 4 + ALIGN_SIZE(name->size) + ALIGN_SIZE(ps->paramSetSize);
    printf("GeneralPack total=%u\n", total);
}

static void DumpLayoutBlob2(const struct HksBlob *b1, const struct HksBlob *b2, const struct HksParamSet *ps)
{
    uint32_t total = 4 + ALIGN_SIZE(b1->size) + 4 + ALIGN_SIZE(b2->size) + ALIGN_SIZE(ps->paramSetSize);
    printf("Blob2ParamSetPack total=%u\n", total);
}

static void DumpLayoutClear(const struct HksBlob *idx)
{
    uint32_t total = 4 + ALIGN_SIZE(idx->size);
    printf("ClearPinAuthStatePack total=%u\n", total);
}

static int PackGeneral(const struct HksBlob *name, const struct HksParamSet *ps, struct HksBlob *out)
{
    uint32_t need = 4 + ALIGN_SIZE(name->size) + ALIGN_SIZE(ps->paramSetSize);
    out->size = need;
    out->data = (uint8_t*)malloc(need);
    if (!out->data) return -1;
    uint32_t off = 0;

    memcpy(out->data + off, &name->size, 4); off += 4;
    memcpy(out->data + off, name->data, name->size); off += ALIGN_SIZE(name->size);
    memcpy(out->data + off, ps, ps->paramSetSize); off += ALIGN_SIZE(ps->paramSetSize);
    return 0;
}

static int PackBlob2ParamSet(const struct HksBlob *b1, const struct HksBlob *b2,
                             const struct HksParamSet *ps, struct HksBlob *out)
{
    uint32_t need = 4 + ALIGN_SIZE(b1->size) + 4 + ALIGN_SIZE(b2->size) + ALIGN_SIZE(ps->paramSetSize);
    out->size = need;
    out->data = (uint8_t*)malloc(need);
    if (!out->data) return -1;
    uint32_t off = 0;
    memcpy(out->data + off, &b1->size, 4); off += 4;
    memcpy(out->data + off, b1->data, b1->size); off += ALIGN_SIZE(b1->size);

    memcpy(out->data + off, &b2->size, 4); off += 4;
    memcpy(out->data + off, b2->data, b2->size); off += ALIGN_SIZE(b2->size);

    memcpy(out->data + off, ps, ps->paramSetSize); off += ALIGN_SIZE(ps->paramSetSize);
    return 0;
}

static int PackClear(const struct HksBlob *idx, struct HksBlob *out)
{
    uint32_t need = 4 + ALIGN_SIZE(idx->size);
    out->size = need;
    out->data = (uint8_t*)malloc(need);
    if (!out->data) return -1;
    uint32_t off = 0;
    memcpy(out->data + off, &idx->size, 4); off += 4;
    memcpy(out->data + off, idx->data, idx->size); off += ALIGN_SIZE(idx->size);
    return 0;
}

// 构造与测试一致的 paramSet（两个 blob param）
static struct HksParamSet* BuildTestParamSet()
{
    uint32_t paramsCnt = 2;
    uint32_t psSize = sizeof(struct HksParamSet) + paramsCnt * sizeof(struct HksParam);
    struct HksParamSet *ps = (struct HksParamSet*)malloc(psSize);
    if (!ps) return NULL;
    ps->paramSetSize = psSize;
    ps->paramsCnt = paramsCnt;

    // 使用真实 tag 值；这里硬编码简化。如果包含 hks_tag.h，可直接写宏名称。
    const uint32_t HKS_EXT_CRYPTO_TAG_UKEY_PIN = (1u << 28) | 200001;       // HKS_TAG_TYPE_BYTES | 200001
    const uint32_t HKS_EXT_CRYPTO_TAG_ABILITY_NAME = (1u << 28) | 200002;   // HKS_TAG_TYPE_BYTES | 200002

    ps->params[0].tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME;
    ps->params[0].blob.size = 18;
    ps->params[0].blob.data = (uint8_t*)"ability_name_value";

    ps->params[1].tag = HKS_EXT_CRYPTO_TAG_UKEY_PIN;
    ps->params[1].blob.size = 6;
    ps->params[1].blob.data = (uint8_t*)"123789";

    return ps;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s [general|blob2|clear]\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];

    const char *nameStr = "testHap";
    struct HksBlob name = { (uint32_t)strlen(nameStr), (uint8_t*)nameStr };

    const char *indexStr =
        "{\"providerName\":\"testHap\",\"abilityName\":\"com.cryptoapplication\",\"bundleName\":\"CryptoExtension\","
        "\"index\":{\"key\":\"testkey1\"}}";
    struct HksBlob index = { (uint32_t)strlen(indexStr), (uint8_t*)indexStr };

    struct HksParamSet *ps = BuildTestParamSet();
    if (!ps) {
        printf("paramSet malloc fail\n");
        return 2;
    }

    struct HksBlob out = {0, NULL};

    if (strcmp(mode, "general") == 0) {
        DumpLayoutGeneral(&name, ps);
        if (PackGeneral(&name, ps, &out) != 0) { puts("PackGeneral fail"); return 3; }
    } else if (strcmp(mode, "blob2") == 0) {
        // 对应 GetRemoteProperty 的场景：资源 ID + propertyId（示例用同一个 indexStr）
        DumpLayoutBlob2(&index, &index, ps);
        if (PackBlob2ParamSet(&index, &index, ps, &out) != 0) { puts("PackBlob2ParamSet fail"); return 3; }
    } else if (strcmp(mode, "clear") == 0) {
        DumpLayoutClear(&index);
        if (PackClear(&index, &out) != 0) { puts("PackClear fail"); return 3; }
    } else {
        printf("Unknown mode %s\n", mode);
        return 1;
    }

    printf("inBlob size=%u\n", out.size);
    PrintHex(out.data, out.size);

    // 可选：打印字段解析
    uint32_t off = 0;
    if (strcmp(mode, "general") == 0) {
        uint32_t nameLen = *(uint32_t*)(out.data + off); off += 4;
        printf("NameLen=%u\n", nameLen);
        printf("Name='%.*s'\n", (int)nameLen, out.data + off);
        off += ALIGN_SIZE(nameLen);
        struct HksParamSet *psIn = (struct HksParamSet*)(out.data + off);
        printf("ParamSetSize=%u ParamsCnt=%u\n", psIn->paramSetSize, psIn->paramsCnt);
    }

    free(ps);
    free(out.data);
    return 0;
}