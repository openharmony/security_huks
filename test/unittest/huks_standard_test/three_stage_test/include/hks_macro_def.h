#define HKS_PARAM_ARR \
{.tag = HKS_TAG_ALGORITHM,.uint32Param = HKS_ALG_ECDH},\
{.tag = HKS_TAG_PURPOSE,.uint32Param = HKS_KEY_PURPOSE_AGREE},\
{.tag = HKS_TAG_KEY_SIZE,.uint32Param = HKS_ECC_KEY_SIZE_256}

#define HKS_PARAM_ARR_01 \
{.tag = HKS_TAG_KEY_STORAGE_FLAG,.uint32Param = HKS_STORAGE_PERSISTENT}, \
{.tag = HKS_TAG_IS_KEY_ALIAS,.boolParam = true}, \
{.tag = HKS_TAG_ALGORITHM,.uint32Param = HKS_ALG_AES}, \
{.tag = HKS_TAG_KEY_SIZE,.uint32Param = HKS_AES_KEY_SIZE_256}, \
{.tag = HKS_TAG_PURPOSE,.uint32Param = HKS_KEY_PURPOSE_DERIVE}, \
{.tag = HKS_TAG_DIGEST,.uint32Param = HKS_DIGEST_SHA256}, 

#define HKS_PARAM_ARR_02 \
{.tag = HKS_TAG_ALGORITHM,.uint32Param = HKS_ALG_AES}, \
{.tag = HKS_TAG_KEY_SIZE,.uint32Param = HKS_AES_KEY_SIZE_256}, \
{.tag = HKS_TAG_PURPOSE,.uint32Param = HKS_KEY_PURPOSE_DERIVE}, \
{.tag = HKS_TAG_DIGEST,.uint32Param = HKS_DIGEST_SHA256}, 

#define HKS_PARAM_ARR_03 \
{.tag = HKS_TAG_IS_KEY_ALIAS,.boolParam = true}, \
{.tag = HKS_TAG_ALGORITHM,.uint32Param = HKS_ALG_AES}, \
{.tag = HKS_TAG_KEY_SIZE,.uint32Param = HKS_AES_KEY_SIZE_256}, \
{.tag = HKS_TAG_PURPOSE,.uint32Param = HKS_KEY_PURPOSE_DERIVE}, \
{.tag = HKS_TAG_DIGEST,.uint32Param = HKS_DIGEST_SHA256}, 
