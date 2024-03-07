/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_batch_test.h"
#include "hks_aes_cipher_test_common.h"
#include "hks_access_control_test_common.h"

#include <gtest/gtest.h>
#ifdef L2_STANDARD
#include "file_ex.h"
#endif
#include "hks_log.h"

using namespace testing::ext;
namespace Unittest::BatchTest {
class HksBatchTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksBatchTest::SetUpTestCase(void)
{
}

void HksBatchTest::TearDownTestCase(void)
{
}

void HksBatchTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksBatchTest::TearDown()
{
}

static struct HksParam g_genParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_KEY_AUTH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};
static struct HksParam g_encryptParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = AesCipher::IV_SIZE,
            .data = (uint8_t *)AesCipher::IV
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }
};
static struct HksParam g_decryptParams001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = AesCipher::NONCE_SIZE,
            .data = (uint8_t *)AesCipher::NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }, {
        .tag = HKS_TAG_IS_BATCH_OPERATION,
        .boolParam = true
    }, {
        .tag = HKS_TAG_BATCH_OPERATION_TIMEOUT,
        .uint32Param = 600
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};

static struct HksParam g_genParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_KEY_AUTH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};
static struct HksParam g_encryptParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = AesCipher::IV_SIZE,
            .data = (uint8_t *)AesCipher::IV
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }
};
static struct HksParam g_decryptParams002[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = AesCipher::NONCE_SIZE,
            .data = (uint8_t *)AesCipher::NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }, {
        .tag = HKS_TAG_IS_BATCH_OPERATION,
        .boolParam = true
    }, {
        .tag = HKS_TAG_BATCH_OPERATION_TIMEOUT,
        .uint32Param = 0
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};

static struct HksParam g_genParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_KEY_AUTH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};

static struct HksParam g_encryptParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = AesCipher::IV_SIZE,
            .data = (uint8_t *)AesCipher::IV
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }
};

static struct HksParam g_decryptNormalParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = AesCipher::NONCE_SIZE,
            .data = (uint8_t *)AesCipher::NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }
};

static struct HksParam g_decryptBatchParams003[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = AesCipher::NONCE_SIZE,
            .data = (uint8_t *)AesCipher::NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }, {
        .tag = HKS_TAG_IS_BATCH_OPERATION,
        .boolParam = true
    }, {
        .tag = HKS_TAG_BATCH_OPERATION_TIMEOUT,
        .uint32Param = 600
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};

static struct HksParam g_genParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_KEY_AUTH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
    }
};
static struct HksParam g_encryptParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = AesCipher::IV_SIZE,
            .data = (uint8_t *)AesCipher::IV
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }
};
static struct HksParam g_decryptParams004[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = AesCipher::NONCE_SIZE,
            .data = (uint8_t *)AesCipher::NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }, {
        .tag = HKS_TAG_IS_BATCH_OPERATION,
        .boolParam = true
    }, {
        .tag = HKS_TAG_BATCH_OPERATION_TIMEOUT,
        .uint32Param = 600
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};

static struct HksParam g_genParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_KEY_AUTH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};
static struct HksParam g_encryptParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = AesCipher::IV_SIZE,
            .data = (uint8_t *)AesCipher::IV
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }
};
static struct HksParam g_decryptParams005[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = AesCipher::NONCE_SIZE,
            .data = (uint8_t *)AesCipher::NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }, {
        .tag = HKS_TAG_IS_BATCH_OPERATION,
        .boolParam = true
    }, {
        .tag = HKS_TAG_BATCH_OPERATION_TIMEOUT,
        .uint32Param = 600
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }
};

static struct HksParam g_genParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_KEY_AUTH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};
static struct HksParam g_encryptParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = AesCipher::IV_SIZE,
            .data = (uint8_t *)AesCipher::IV
        }
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }
};
static struct HksParam g_decryptParams006[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = AesCipher::AAD_SIZE,
            .data = (uint8_t *)AesCipher::AAD
        }
    }, {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = AesCipher::NONCE_SIZE,
            .data = (uint8_t *)AesCipher::NONCE
        }
    }, {
        .tag = HKS_TAG_AE_TAG,
        .blob = {
            .size = AesCipher::AEAD_SIZE,
            .data = (uint8_t *)AesCipher::AEAD
        }
    }, {
        .tag = HKS_TAG_BATCH_OPERATION_TIMEOUT,
        .uint32Param = 600
    }, {
        .tag = HKS_TAG_BATCH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }
};


#ifdef L2_STANDARD
/**
 * @tc.name: HksBatchTest.HksBatchTest001
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksBatchTest, HksBatchTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksBatchTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams001, sizeof(g_encryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams001, sizeof(g_decryptParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = AesCipher::HksAesCipherTestCaseGcm4(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, false);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksBatchTest.HksBatchTest002
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksBatchTest, HksBatchTest002, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksBatchTest002";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams002, sizeof(g_encryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams002, sizeof(g_decryptParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = AesCipher::HksAesCipherTestCaseGcm4(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, true);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_TIME_OUT) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

static int32_t InitParamSetForHksBatchTest003(struct HksParamSet **genParamSet, struct HksParamSet **encryptParamSet,
    struct HksParamSet **decNormaLParamSet, struct HksParamSet **decryptBatchParamSet)
{
    int32_t ret = InitParamSet(genParamSet, g_genParams003,
        sizeof(g_genParams003) / sizeof(HksParam));
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = InitParamSet(encryptParamSet, g_encryptParams003,
        sizeof(g_encryptParams003) / sizeof(HksParam));
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = InitParamSet(decNormaLParamSet, g_decryptNormalParams003,
        sizeof(g_decryptNormalParams003) / sizeof(HksParam));
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = InitParamSet(decryptBatchParamSet, g_decryptBatchParams003,
        sizeof(g_decryptBatchParams003) / sizeof(HksParam));
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    return HKS_SUCCESS;
}

/**
 * @tc.name: HksBatchTest.HksBatchTest003
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksBatchTest, HksBatchTest003, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksBatchTest003";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *encryptParamSet = nullptr;
    struct HksParamSet *decNormaLParamSet = nullptr;
    struct HksParamSet *decryptBatchParamSet = nullptr;
    int32_t ret = InitParamSetForHksBatchTest003(&genParamSet, &encryptParamSet, &decNormaLParamSet,
        &decryptBatchParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /* 1. Generate Key */
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey failed.";

    static const std::string tmp_inData1 = "Hks_string1";
    struct HksBlob inData1 = { tmp_inData1.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(tmp_inData1.c_str())) };

    static const std::string tmp_inData2 = "Hks_string2";
    struct HksBlob inData2 = { tmp_inData2.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(tmp_inData2.c_str())) };

    uint8_t cipher1[AesCipher::AES_COMMON_SIZE] = {0};
    struct HksBlob cipherText1 = { AesCipher::AES_COMMON_SIZE, cipher1 };

    uint8_t cipher2[AesCipher::AES_COMMON_SIZE] = {0};
    struct HksBlob cipherText2 = { AesCipher::AES_COMMON_SIZE, cipher2 };

    ret = AesCipher::HksAesEncryptThreeStage(&keyAlias, encryptParamSet, &inData1, &cipherText1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    ret = AesCipher::HksAesEncryptThreeStage(&keyAlias, encryptParamSet, &inData2, &cipherText2);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    uint8_t plainNormal1[AesCipher::AES_COMMON_SIZE] = {0};
    struct HksBlob plainTextNormal1 = { AesCipher::AES_COMMON_SIZE, plainNormal1 };

    uint8_t plainNormal2[AesCipher::AES_COMMON_SIZE] = {0};
    struct HksBlob plainTextNormal2 = { AesCipher::AES_COMMON_SIZE, plainNormal2 };

    ret = AesCipher::HksAesDecryptThreeStage(&keyAlias, decNormaLParamSet, &inData1, &cipherText1, &plainTextNormal1);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    ret = AesCipher::HksAesDecryptThreeStage(&keyAlias, decNormaLParamSet, &inData2, &cipherText2, &plainTextNormal2);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    uint8_t plainBathc1[AesCipher::AES_COMMON_SIZE] = {0};
    struct HksBlob plainTextBatch1 = { AesCipher::AES_COMMON_SIZE, plainBathc1 };

    uint8_t plainBatch2[AesCipher::AES_COMMON_SIZE] = {0};
    struct HksBlob plainTextBatch2 = { AesCipher::AES_COMMON_SIZE, plainBatch2 };

    ret = AesCipher::HksAesDecryptForBatch(&keyAlias, decryptBatchParamSet, &inData1, &cipherText1, &plainTextBatch1,
        &inData2, &cipherText2, &plainTextBatch2);
    EXPECT_EQ(ret, HKS_SUCCESS) << "this case failed.";

    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decNormaLParamSet);
    HksFreeParamSet(&decryptBatchParamSet);
}

/**
 * @tc.name: HksBatchTest.HksBatchTest004
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksBatchTest, HksBatchTest004, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksBatchTest004";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams004, sizeof(g_genParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams004, sizeof(g_encryptParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams004, sizeof(g_decryptParams004) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = AesCipher::HksAesCipherTestCaseGcm4(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, false);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksBatchTest.HksBatchTest005
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksBatchTest, HksBatchTest005, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksBatchTest005";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams005, sizeof(g_genParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams005, sizeof(g_encryptParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams005, sizeof(g_decryptParams005) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = AesCipher::HksAesCipherTestCaseGcm4(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, false);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_PURPOSE) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksBatchTest.HksBatchTest006
 * @tc.desc: alg-AES pur-ENCRYPT&DECRYPT mod-GCM pad-NONE size-128.
 * @tc.type: FUNC
 */
HWTEST_F(HksBatchTest, HksBatchTest006, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksBatchTest006";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams006, sizeof(g_genParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_encryptParams006, sizeof(g_encryptParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_decryptParams006, sizeof(g_decryptParams006) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = AesCipher::HksAesCipherTestCaseGcm4(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, false);
    EXPECT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "this case failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}
#endif

} // namespace Unittest::BatchTest