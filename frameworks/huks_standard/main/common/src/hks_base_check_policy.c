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

#include "hks_config.h"
#include "hks_type.h"

#ifdef _CUT_AUTHENTICATE_
#undef HKS_SUPPORT_RSA_C
#undef HKS_SUPPORT_ECC_C
#undef HKS_SUPPORT_ECDH_C
#undef HKS_SUPPORT_X25519_C
#undef HKS_SUPPORT_ED25519_C
#endif

#define HKS_BLOCK_CIPHER_CBC_IV_LEN 16
#define HKS_AES_CCM_AAD_LEN_MIN     4
#define HKS_AES_CCM_NONCE_LEN_MIN   7
#define HKS_AES_CCM_NONCE_LEN_MAX   13
#define HKS_AES_GCM_NONCE_LEN_MIN   12

#define HKS_RSA_OAEP_DIGEST_NUM 2
#define HKS_RSA_KEY_BLOCK_SIZE 8
#define HKS_BLOCK_CIPHER_CBC_BLOCK_SIZE 16

#define HKS_ECC_SIGN_MAX_TL_SIZE    8

#ifdef HKS_SUPPORT_RSA_C
static const uint32_t g_rsaKeySize[] = {
    HKS_RSA_KEY_SIZE_512,
    HKS_RSA_KEY_SIZE_768,
    HKS_RSA_KEY_SIZE_1024,
    HKS_RSA_KEY_SIZE_2048,
    HKS_RSA_KEY_SIZE_3072,
    HKS_RSA_KEY_SIZE_4096
};
static const uint32_t g_rsaPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_OAEP,
    HKS_PADDING_PSS,
    HKS_PADDING_PKCS1_V1_5,
    HKS_PADDING_ISO_IEC_9796_2
};
static const uint32_t g_rsaDigest[] = {
    HKS_DIGEST_MD5,
    HKS_DIGEST_NONE,
    HKS_DIGEST_SHA1,
    HKS_DIGEST_SHA224,
    HKS_DIGEST_SHA256,
    HKS_DIGEST_SHA384,
    HKS_DIGEST_SHA512
};
static const uint32_t g_rsaSignPadding[] = {
    HKS_PADDING_PSS,
    HKS_PADDING_PKCS1_V1_5,
    HKS_PADDING_ISO_IEC_9796_2
};
static const uint32_t g_rsaCipherPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_OAEP,
    HKS_PADDING_PKCS1_V1_5,
    HKS_PADDING_ISO_IEC_9796_2
};
#endif

#ifdef HKS_SUPPORT_AES_C
static const uint32_t g_aesKeySize[] = {
    HKS_AES_KEY_SIZE_128,
    HKS_AES_KEY_SIZE_192,
    HKS_AES_KEY_SIZE_256
};
static const uint32_t g_aesMacKeySize[] = {
    HKS_AES_KEY_SIZE_256,
};
static const uint32_t g_aesPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
static const uint32_t g_aesMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_CCM,
    HKS_MODE_CTR,
    HKS_MODE_ECB,
    HKS_MODE_GCM
};
static const uint32_t g_aesCbcPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
static const uint32_t g_aesAeadPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_aesCtrPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_aesEcbPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
#endif

#ifdef HKS_SUPPORT_DES_C
static const uint32_t g_desKeySize[] = {
    HKS_DES_KEY_SIZE_64
};
static const uint32_t g_desMacKeySize[] = {
    HKS_DES_KEY_SIZE_64
};
static const uint32_t g_desPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_desMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_ECB
};
static const uint32_t g_desCbcPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_desEcbPadding[] = {
    HKS_PADDING_NONE
};
#endif

#ifdef HKS_SUPPORT_3DES_C
static const uint32_t g_3desKeySize[] = {
    HKS_3DES_KEY_SIZE_128,
    HKS_3DES_KEY_SIZE_192
};
static const uint32_t g_3desMacKeySize[] = {
    HKS_3DES_KEY_SIZE_128,
    HKS_3DES_KEY_SIZE_192
};
static const uint32_t g_3desPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_3desMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_ECB
};
static const uint32_t g_3desCbcPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_3desEcbPadding[] = {
    HKS_PADDING_NONE
};
#endif

#ifdef HKS_SUPPORT_SM4_C
static const uint32_t g_sm4KeySize[] = {
    HKS_SM4_KEY_SIZE_128,
};
static const uint32_t g_sm4Padding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
static const uint32_t g_sm4Purpose[] = {
    HKS_KEY_PURPOSE_ENCRYPT,
    HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
};
static const uint32_t g_sm4Mode[] = {
    HKS_MODE_CBC,
    HKS_MODE_CTR,
    HKS_MODE_ECB,
    HKS_MODE_CFB,
    HKS_MODE_OFB,
};
static const uint32_t g_sm4CbcPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
static const uint32_t g_sm4CtrPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_sm4EcbPadding[] = {
    HKS_PADDING_NONE,
    HKS_PADDING_PKCS7
};
static const uint32_t g_sm4CfbPadding[] = {
    HKS_PADDING_NONE
};
static const uint32_t g_sm4OfbPadding[] = {
    HKS_PADDING_NONE
};
#endif

#ifdef HKS_SUPPORT_ECC_C
static const uint32_t g_eccKeySize[] = {
    HKS_ECC_KEY_SIZE_224,
    HKS_ECC_KEY_SIZE_256,
    HKS_ECC_KEY_SIZE_384,
    HKS_ECC_KEY_SIZE_521
};

static const uint32_t g_eccDigest[] = {
    HKS_DIGEST_NONE,
    HKS_DIGEST_SHA1,
    HKS_DIGEST_SHA224,
    HKS_DIGEST_SHA256,
    HKS_DIGEST_SHA384,
    HKS_DIGEST_SHA512
};
#endif

#ifdef HKS_SUPPORT_SM2_C
static const uint32_t g_sm2KeySize[] = {
    HKS_SM2_KEY_SIZE_256
};

static const uint32_t g_sm2Digest[] = {
    HKS_DIGEST_SM3,
    HKS_DIGEST_NONE
};

static const uint32_t g_sm2CipherPadding[] = {
    HKS_PADDING_NONE,
};
#endif

#ifdef HKS_SUPPORT_SM3_C
static const uint32_t g_sm3Digest[] = {
    HKS_DIGEST_SM3
};
#endif

static const uint32_t g_digest[] = {
    HKS_DIGEST_SHA256,
    HKS_DIGEST_SHA384,
    HKS_DIGEST_SHA512
};

static const uint32_t g_macDigest[] = {
    HKS_DIGEST_SHA256
};

#ifdef HKS_SUPPORT_ECDH_C
static const uint32_t g_ecdhKeySize[] = {
    HKS_ECC_KEY_SIZE_224,
    HKS_ECC_KEY_SIZE_256,
    HKS_ECC_KEY_SIZE_384,
    HKS_ECC_KEY_SIZE_521
};
#endif

#if defined(HKS_SUPPORT_X25519_C) || defined(HKS_SUPPORT_ED25519_C)
static const uint32_t g_curve25519KeySize[] = {
    HKS_CURVE25519_KEY_SIZE_256,
};
#endif
#ifdef HKS_SUPPORT_HMAC_C
static const uint32_t g_hmacDigest[] = {
    HKS_DIGEST_SHA1,
    HKS_DIGEST_SHA224,
    HKS_DIGEST_SHA256,
    HKS_DIGEST_SHA384,
    HKS_DIGEST_SHA512,
    HKS_DIGEST_SM3
};
#endif

#ifdef HKS_SUPPORT_DSA_C
static const uint32_t g_dsaDigest[] = {
    HKS_DIGEST_NONE,
    HKS_DIGEST_SHA1,
    HKS_DIGEST_SHA224,
    HKS_DIGEST_SHA256,
    HKS_DIGEST_SHA384,
    HKS_DIGEST_SHA512
};
#endif
#ifdef HKS_SUPPORT_DH_C
static const uint32_t g_dhKeySize[] = {
    HKS_DH_KEY_SIZE_2048,
    HKS_DH_KEY_SIZE_3072,
    HKS_DH_KEY_SIZE_4096
};
#endif

#ifdef HKS_SUPPORT_RSA_C
static const struct ParamsValuesChecker g_rsaParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectRsaParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_rsaKeySize, HKS_ARRAY_SIZE(g_rsaKeySize) },
        { true, g_rsaPadding, HKS_ARRAY_SIZE(g_rsaPadding) },
        { false, NULL, 0 },
        { true, g_rsaDigest, HKS_ARRAY_SIZE(g_rsaDigest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { true, g_rsaKeySize, HKS_ARRAY_SIZE(g_rsaKeySize) },
        { true, g_rsaPadding, HKS_ARRAY_SIZE(g_rsaPadding) },
        { false, NULL, 0 },
        { true, g_rsaDigest, HKS_ARRAY_SIZE(g_rsaDigest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_AES_C
static const struct ParamsValuesChecker g_aesParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
	{ HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } }
};

static const struct ExpectParamsValuesChecker g_expectAesParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_aesKeySize, HKS_ARRAY_SIZE(g_aesKeySize) },
        { true, g_aesPadding, HKS_ARRAY_SIZE(g_aesPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_aesMode, HKS_ARRAY_SIZE(g_aesMode) }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { true, g_aesPadding, HKS_ARRAY_SIZE(g_aesPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_aesMode, HKS_ARRAY_SIZE(g_aesMode) }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { true, g_aesMacKeySize, HKS_ARRAY_SIZE(g_aesMacKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_macDigest, HKS_ARRAY_SIZE(g_macDigest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, {
        { true, g_aesKeySize, HKS_ARRAY_SIZE(g_aesKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_digest, HKS_ARRAY_SIZE(g_digest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_DES_C
static const struct ParamsValuesChecker g_desParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } }
};

static const struct ExpectParamsValuesChecker g_expectDesParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_desKeySize, HKS_ARRAY_SIZE(g_desKeySize) },
        { true, g_desPadding, HKS_ARRAY_SIZE(g_desPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_desMode, HKS_ARRAY_SIZE(g_desMode) }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { true, g_desPadding, HKS_ARRAY_SIZE(g_desPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_desMode, HKS_ARRAY_SIZE(g_desMode) }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { true, g_desMacKeySize, HKS_ARRAY_SIZE(g_desMacKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_macDigest, HKS_ARRAY_SIZE(g_macDigest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, {
        { true, g_desKeySize, HKS_ARRAY_SIZE(g_desKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_digest, HKS_ARRAY_SIZE(g_digest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_3DES_C
static const struct ParamsValuesChecker g_3desParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } }
};

static const struct ExpectParamsValuesChecker g_expect3DesParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_3desKeySize, HKS_ARRAY_SIZE(g_3desKeySize) },
        { true, g_3desPadding, HKS_ARRAY_SIZE(g_3desPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_3desMode, HKS_ARRAY_SIZE(g_3desMode) }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { true, g_3desPadding, HKS_ARRAY_SIZE(g_3desPadding) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_3desMode, HKS_ARRAY_SIZE(g_3desMode) }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { true, g_3desMacKeySize, HKS_ARRAY_SIZE(g_3desMacKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_macDigest, HKS_ARRAY_SIZE(g_macDigest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, {
        { true, g_3desKeySize, HKS_ARRAY_SIZE(g_3desKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_digest, HKS_ARRAY_SIZE(g_digest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_ECC_C
static const struct ParamsValuesChecker g_eccParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectEccParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_eccKeySize, HKS_ARRAY_SIZE(g_eccKeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_eccDigest, HKS_ARRAY_SIZE(g_eccDigest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_eccDigest, HKS_ARRAY_SIZE(g_eccDigest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_SM2_C
static const struct ParamsValuesChecker g_sm2ParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectSm2Params[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_sm2KeySize, HKS_ARRAY_SIZE(g_sm2KeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_sm2Digest, HKS_ARRAY_SIZE(g_sm2Digest) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { true, g_sm2KeySize, HKS_ARRAY_SIZE(g_sm2KeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_sm2Digest, HKS_ARRAY_SIZE(g_sm2Digest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_SM3_C
static const struct ParamsValuesChecker g_sm3ParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectSm3Params[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_sm3Digest, sizeof(g_sm3Digest) / sizeof(g_sm3Digest[0]) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_sm3Digest, sizeof(g_sm3Digest) / sizeof(g_sm3Digest[0]) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_SM4_C
static const struct ParamsValuesChecker g_sm4ParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { true, 0, false}, { true, 0, false}, { true, 0, false}, { false, 0, false},
        { true, 0, false} } },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, { { true, 0, false}, { false, 0, false}, { false, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectSm4Params[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_sm4KeySize, HKS_ARRAY_SIZE(g_sm4KeySize) },
        { true, g_sm4Padding, HKS_ARRAY_SIZE(g_sm4Padding) },
        { true, g_sm4Purpose, HKS_ARRAY_SIZE(g_sm4Purpose) },
        { false, NULL, 0 },
        { true, g_sm4Mode, HKS_ARRAY_SIZE(g_sm4Mode) }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { true, g_sm4KeySize, HKS_ARRAY_SIZE(g_sm4KeySize) },
        { true, g_sm4Padding, HKS_ARRAY_SIZE(g_sm4Padding) },
        { true, g_sm4Purpose, HKS_ARRAY_SIZE(g_sm4Purpose) },
        { false, NULL, 0 },
        { true, g_sm4Mode, HKS_ARRAY_SIZE(g_sm4Mode) }
        }
    },
    { HKS_CHECK_TYPE_GEN_DERIVE_KEY, {
        { true, g_sm4KeySize, HKS_ARRAY_SIZE(g_sm4KeySize) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_sm3Digest, HKS_ARRAY_SIZE(g_sm3Digest) },
        { false, NULL, 0 }
        }
    }
};
#endif

#if defined(HKS_SUPPORT_X25519_C) || defined(HKS_SUPPORT_ED25519_C)
static const struct ParamsValuesChecker g_curve25519ParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectCurve25519Params[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_curve25519KeySize, sizeof(g_curve25519KeySize) / sizeof(g_curve25519KeySize[0]) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_HMAC_C
static const struct ParamsValuesChecker g_hmacParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectHmacParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_hmacDigest, sizeof(g_hmacDigest) / sizeof(g_hmacDigest[0]) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_hmacDigest, sizeof(g_hmacDigest) / sizeof(g_hmacDigest[0]) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_hmacDigest, sizeof(g_hmacDigest) / sizeof(g_hmacDigest[0]) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_CMAC_C
static const struct ParamsValuesChecker g_cmacParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectCmacParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_GEN_MAC_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_DSA_C
static const struct ParamsValuesChecker g_dsaParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { false, 0, false}, { false, 0, false}, { true, 0, false}, { true, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectDsaParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_dsaDigest, sizeof(g_dsaDigest) / sizeof(g_dsaDigest[0]) },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { true, g_dsaDigest, sizeof(g_dsaDigest) / sizeof(g_dsaDigest[0]) },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_DH_C
static const struct ParamsValuesChecker g_dhParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectDhParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_dhKeySize, sizeof(g_dhKeySize) / sizeof(g_dhKeySize[0]) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { true, g_dhKeySize, sizeof(g_dhKeySize) / sizeof(g_dhKeySize[0]) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    }
};
#endif

#ifdef HKS_SUPPORT_ECDH_C
static const struct ParamsValuesChecker g_ecdhParamSet[] = {
    { HKS_CHECK_TYPE_GEN_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } },
    { HKS_CHECK_TYPE_USE_KEY, { { true, 0, false}, { false, 0, false}, { true, 0, false}, { false, 0, false},
        { false, 0, false} } }
};
static const struct ExpectParamsValuesChecker g_expectEcdhParams[] = {
    { HKS_CHECK_TYPE_GEN_KEY, {
        { true, g_ecdhKeySize, sizeof(g_ecdhKeySize) / sizeof(g_ecdhKeySize[0]) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    },
    { HKS_CHECK_TYPE_USE_KEY, {
        { true, g_ecdhKeySize, sizeof(g_ecdhKeySize) / sizeof(g_ecdhKeySize[0]) },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 },
        { false, NULL, 0 }
        }
    }
};
#endif

static struct HksAlgParamSetHandler g_hksAlgParamSetHandlerPart1[] = {
#ifdef HKS_SUPPORT_RSA_C
    { HKS_ALG_RSA, g_rsaParamSet, HKS_ARRAY_SIZE(g_rsaParamSet), g_expectRsaParams, HKS_ARRAY_SIZE(g_expectRsaParams) },
#endif
#ifdef HKS_SUPPORT_AES_C
    { HKS_ALG_AES, g_aesParamSet, HKS_ARRAY_SIZE(g_aesParamSet), g_expectAesParams, HKS_ARRAY_SIZE(g_expectAesParams) },
#endif
#ifdef HKS_SUPPORT_DES_C
    { HKS_ALG_DES, g_desParamSet, HKS_ARRAY_SIZE(g_desParamSet), g_expectDesParams, HKS_ARRAY_SIZE(g_expectDesParams) },
#endif
#ifdef HKS_SUPPORT_3DES_C
    { HKS_ALG_3DES, g_3desParamSet, HKS_ARRAY_SIZE(g_3desParamSet), g_expect3DesParams,
        HKS_ARRAY_SIZE(g_expect3DesParams) },
#endif
#ifdef HKS_SUPPORT_ECC_C
    { HKS_ALG_ECC, g_eccParamSet, HKS_ARRAY_SIZE(g_eccParamSet), g_expectEccParams, HKS_ARRAY_SIZE(g_expectEccParams) },
#endif
#ifdef HKS_SUPPORT_SM2_C
    { HKS_ALG_SM2, g_sm2ParamSet, HKS_ARRAY_SIZE(g_sm2ParamSet), g_expectSm2Params, HKS_ARRAY_SIZE(g_expectSm2Params) },
#endif
#ifdef HKS_SUPPORT_SM3_C
    { HKS_ALG_SM3, g_sm3ParamSet, HKS_ARRAY_SIZE(g_sm3ParamSet), g_expectSm3Params, HKS_ARRAY_SIZE(g_expectSm3Params) },
#endif
#ifdef HKS_SUPPORT_SM4_C
    { HKS_ALG_SM4, g_sm4ParamSet, HKS_ARRAY_SIZE(g_sm4ParamSet), g_expectSm4Params, HKS_ARRAY_SIZE(g_expectSm4Params) },
#endif
};

static struct HksAlgParamSetHandler g_hksAlgParamSetHandlerPart2[] = {
#ifdef HKS_SUPPORT_X25519_C
    { HKS_ALG_X25519, g_curve25519ParamSet, HKS_ARRAY_SIZE(g_curve25519ParamSet), g_expectCurve25519Params,
        HKS_ARRAY_SIZE(g_expectCurve25519Params) },
#endif
#ifdef HKS_SUPPORT_ED25519_C
    { HKS_ALG_ED25519, g_curve25519ParamSet, HKS_ARRAY_SIZE(g_curve25519ParamSet), g_expectCurve25519Params,
        HKS_ARRAY_SIZE(g_expectCurve25519Params) },
#endif
#ifdef HKS_SUPPORT_HMAC_C
    { HKS_ALG_HMAC, g_hmacParamSet, HKS_ARRAY_SIZE(g_hmacParamSet), g_expectHmacParams,
        HKS_ARRAY_SIZE(g_expectHmacParams) },
#endif
#ifdef HKS_SUPPORT_CMAC_C
    { HKS_ALG_CMAC, g_cmacParamSet, HKS_ARRAY_SIZE(g_cmacParamSet), g_expectCmacParams,
        HKS_ARRAY_SIZE(g_expectCmacParams) },
#endif
#ifdef HKS_SUPPORT_DSA_C
    { HKS_ALG_DSA, g_dsaParamSet, HKS_ARRAY_SIZE(g_dsaParamSet), g_expectDsaParams, HKS_ARRAY_SIZE(g_expectDsaParams) },
#endif
#ifdef HKS_SUPPORT_DH_C
    { HKS_ALG_DH, g_dhParamSet, HKS_ARRAY_SIZE(g_dhParamSet), g_expectDhParams, HKS_ARRAY_SIZE(g_expectDhParams) },
#endif
#ifdef HKS_SUPPORT_ECDH_C
    { HKS_ALG_ECDH, g_ecdhParamSet, HKS_ARRAY_SIZE(g_ecdhParamSet), g_expectEcdhParams,
        HKS_ARRAY_SIZE(g_expectEcdhParams) },
#endif
};

#ifndef _CUT_AUTHENTICATE_
static const uint32_t g_invalidPurpose[][2] = {
#ifdef HKS_SUPPORT_RSA_C
    {
        HKS_ALG_RSA,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP |
            HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_ECC_C
    {
        HKS_ALG_ECC,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    },
#endif
#ifdef HKS_SUPPORT_SM2_C
    {
        HKS_ALG_SM2,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP,
    },
#endif
#ifdef HKS_SUPPORT_SM3_C
    {
        HKS_ALG_SM3,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP | HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_SM4_C
    {
        HKS_ALG_SM4,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_AES_C
    {
        HKS_ALG_AES,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_AGREE | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
#ifdef HKS_SUPPORT_DES_C
    {
        HKS_ALG_DES,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_AGREE | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
#ifdef HKS_SUPPORT_3DES_C
    {
        HKS_ALG_3DES,
        HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_AGREE | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
#ifdef HKS_SUPPORT_ED25519_C
    {
        HKS_ALG_ED25519,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP |
            HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    },
#endif
#ifdef HKS_SUPPORT_X25519_C
    {
        HKS_ALG_X25519,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT |
            HKS_KEY_PURPOSE_WRAP,
    },
#endif
#ifdef HKS_SUPPORT_HMAC_C
    {
        HKS_ALG_HMAC,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP | HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_CMAC_C
    {
        HKS_ALG_CMAC,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY | HKS_KEY_PURPOSE_WRAP |
            HKS_KEY_PURPOSE_UNWRAP | HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_DSA_C
    {
        HKS_ALG_DSA,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP |
            HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_AGREE,
    },
#endif
#ifdef HKS_SUPPORT_DH_C
    {
        HKS_ALG_DH,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP |
            HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
#endif
#ifdef HKS_SUPPORT_ECDH_C
    {
        HKS_ALG_ECDH,
        HKS_KEY_PURPOSE_DERIVE | HKS_KEY_PURPOSE_MAC | HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP |
            HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
#endif
};

static const uint32_t g_invalidImportKeyPurpose[][2] = {
#ifdef HKS_SUPPORT_ECC_C
    {
        HKS_ALG_ECC,
        HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
#ifdef HKS_SUPPORT_X25519_C
    {
        HKS_ALG_X25519,
        HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
#ifdef HKS_SUPPORT_SM2_C
    {
        HKS_ALG_SM2,
        HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP,
    },
#endif
};
#endif

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
static const uint32_t g_userAuthChallengeType[] = {
    HKS_CHALLENGE_TYPE_NORMAL,
    HKS_CHALLENGE_TYPE_CUSTOM,
    HKS_CHALLENGE_TYPE_NONE,
};

static const uint32_t g_validBiometricAuthAccessType[] = {
    HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL,
    HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD,
    HKS_AUTH_ACCESS_ALWAYS_VALID
};

static const uint32_t g_validPinAuthAccessType[] = {
    HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD,
    HKS_AUTH_ACCESS_ALWAYS_VALID
};

static const uint32_t g_validTuiPinAuthAccessType[] = {
    HKS_AUTH_ACCESS_ALWAYS_VALID
};

static const struct AuthAccessTypeChecker g_expectAuthAccessParams[] = {
    { HKS_USER_AUTH_TYPE_FACE,
        { true, g_validBiometricAuthAccessType, HKS_ARRAY_SIZE(g_validBiometricAuthAccessType) }
    },
    { HKS_USER_AUTH_TYPE_FINGERPRINT,
        { true, g_validBiometricAuthAccessType, HKS_ARRAY_SIZE(g_validBiometricAuthAccessType) }
    },
    { HKS_USER_AUTH_TYPE_PIN,
        { true, g_validPinAuthAccessType, HKS_ARRAY_SIZE(g_validPinAuthAccessType) }
    },
    { HKS_USER_AUTH_TYPE_TUI_PIN,
        { true, g_validTuiPinAuthAccessType, HKS_ARRAY_SIZE(g_validTuiPinAuthAccessType) }
    }
};

static const uint32_t g_supportUserAuthTypes[] = {
    HKS_USER_AUTH_TYPE_PIN,
    HKS_USER_AUTH_TYPE_FINGERPRINT,
    HKS_USER_AUTH_TYPE_FACE,
    HKS_USER_AUTH_TYPE_PIN | HKS_USER_AUTH_TYPE_FINGERPRINT,
    HKS_USER_AUTH_TYPE_PIN | HKS_USER_AUTH_TYPE_FACE,
    HKS_USER_AUTH_TYPE_FACE | HKS_USER_AUTH_TYPE_FINGERPRINT,
    HKS_USER_AUTH_TYPE_PIN | HKS_USER_AUTH_TYPE_FACE | HKS_USER_AUTH_TYPE_FINGERPRINT,
    HKS_USER_AUTH_TYPE_TUI_PIN,
    HKS_USER_AUTH_TYPE_TUI_PIN | HKS_USER_AUTH_TYPE_FINGERPRINT,
    HKS_USER_AUTH_TYPE_TUI_PIN | HKS_USER_AUTH_TYPE_FACE,
    HKS_USER_AUTH_TYPE_TUI_PIN | HKS_USER_AUTH_TYPE_FACE | HKS_USER_AUTH_TYPE_FINGERPRINT
};

static const uint32_t g_supportSecureSignType[] = {
    HKS_SECURE_SIGN_WITH_AUTHINFO
};

#ifdef HKS_SUPPORT_AES_C
static const uint32_t g_supportAesPurpose[] = {
    HKS_KEY_PURPOSE_ENCRYPT,
    HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_DERIVE,
    HKS_KEY_PURPOSE_MAC
};

static const uint32_t g_supportAesCipherMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_GCM,
    HKS_MODE_CCM
};

static const struct KeyInfoParams g_validAesKeyInfo[] = {
    { true, HKS_TAG_PURPOSE, g_supportAesPurpose, HKS_ARRAY_SIZE(g_supportAesPurpose) },
    { true, HKS_TAG_BLOCK_MODE, g_supportAesCipherMode, HKS_ARRAY_SIZE(g_supportAesCipherMode) }
};
#endif

#ifdef HKS_SUPPORT_DES_C
static const uint32_t g_supportDesPurpose[] = {
    HKS_KEY_PURPOSE_ENCRYPT,
    HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_DERIVE,
    HKS_KEY_PURPOSE_MAC
};

static const uint32_t g_supportDesCipherMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_ECB
};

static const struct KeyInfoParams g_validDesKeyInfo[] = {
    { true, HKS_TAG_PURPOSE, g_supportDesPurpose, HKS_ARRAY_SIZE(g_supportDesPurpose) },
    { true, HKS_TAG_BLOCK_MODE, g_supportDesCipherMode, HKS_ARRAY_SIZE(g_supportDesCipherMode) }
};
#endif

#ifdef HKS_SUPPORT_3DES_C
static const uint32_t g_support3DesPurpose[] = {
    HKS_KEY_PURPOSE_ENCRYPT,
    HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_DERIVE,
    HKS_KEY_PURPOSE_MAC
};

static const uint32_t g_support3DesCipherMode[] = {
    HKS_MODE_CBC,
    HKS_MODE_ECB
};

static const struct KeyInfoParams g_valid3DesKeyInfo[] = {
    { true, HKS_TAG_PURPOSE, g_support3DesPurpose, HKS_ARRAY_SIZE(g_support3DesPurpose) },
    { true, HKS_TAG_BLOCK_MODE, g_support3DesCipherMode, HKS_ARRAY_SIZE(g_support3DesCipherMode) }
};
#endif

#ifdef HKS_SUPPORT_SM4_C
static const uint32_t g_supportSm4Purpose[] = {
    HKS_KEY_PURPOSE_ENCRYPT,
    HKS_KEY_PURPOSE_DECRYPT,
    HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
};

static const uint32_t g_supportSm4CipherMode[] = {
    HKS_MODE_CBC
};

static const struct KeyInfoParams g_validSm4KeyInfo[] = {
    { true, HKS_TAG_PURPOSE, g_supportSm4Purpose, HKS_ARRAY_SIZE(g_supportSm4Purpose) },
    { true, HKS_TAG_BLOCK_MODE, g_supportSm4CipherMode, HKS_ARRAY_SIZE(g_supportSm4CipherMode) }
};
#endif

static const struct AuthAcceessKeyInfoChecker g_validKeyInfo[] = {
#ifdef HKS_SUPPORT_AES_C
    { HKS_ALG_AES, g_validAesKeyInfo, HKS_ARRAY_SIZE(g_validAesKeyInfo) },
#endif
#ifdef HKS_SUPPORT_DES_C
    { HKS_ALG_DES, g_validDesKeyInfo, HKS_ARRAY_SIZE(g_validDesKeyInfo) },
#endif
#ifdef HKS_SUPPORT_3DES_C
    { HKS_ALG_3DES, g_valid3DesKeyInfo, HKS_ARRAY_SIZE(g_valid3DesKeyInfo) },
#endif
#ifdef HKS_SUPPORT_SM4_C
    { HKS_ALG_SM4, g_validSm4KeyInfo, HKS_ARRAY_SIZE(g_validSm4KeyInfo) }
#endif
};
#endif
