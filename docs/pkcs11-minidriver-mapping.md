# PKCS#11 ↔ Windows Smart Card Minidriver 实现指南

> **规范版本**
> - PKCS#11：**OASIS PKCS #11 Cryptographic Token Interface Base Specification Version 2.40 Plus Errata 01**（2016-05-13）
>   参考：https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html
> - Minidriver：**Windows Smart Card Minidriver Specification Version 7.07**（2016-02-25）
>   参考：https://msdn.microsoft.com/en-us/library/windows/hardware/gg487500.aspx

---

## 目录

1. [架构概述](#1-架构概述)
2. [PKCS#11 最小 API 集合](#2-pkcs11-最小-api-集合)
3. [Minidriver 最小 API 集合](#3-minidriver-最小-api-集合)
4. [函数映射表](#4-函数映射表)
5. [虚拟文件系统构建](#5-虚拟文件系统构建)
6. [数据格式转换](#6-数据格式转换)
7. [实现注意事项](#7-实现注意事项)

---

## 1. 架构概述

### 调用链

```
Windows Application
        │ CAPI / CNG
        ▼
Base CSP / KSP  (Microsoft, msbasecsp.dll / mscng.dll)
        │ Minidriver API (CARD_DATA function table)
        ▼
Card Minidriver  ← 你实现（本文档描述的内容）
        │ PKCS#11 C API
        ▼
PKCS#11 Library  ← 你实现（跨平台）
        │ PC/SC (WinSCard)
        ▼
Smart Card
```

### 设计原则

- PKCS#11 library 是**跨平台的加密核心**，负责与卡通信、执行密码学操作。
- Minidriver 是**薄的翻译层**，负责将 Base CSP/KSP 的调用翻译成 PKCS#11 调用，并虚拟化 Windows 期望的文件系统接口。
- Minidriver 不做验签——验签由 Base CSP/KSP 层用公钥在软件中完成，minidriver 只需要提供公钥。
- 所有不支持的 minidriver 函数指针须置 `NULL` 或返回 `SCARD_E_UNSUPPORTED_FEATURE`，不可崩溃。
- 所有不支持的 PKCS#11 函数须返回 `CKR_FUNCTION_NOT_SUPPORTED`。

---

## 2. PKCS#11 最小 API 集合

### 2.1 所有场景都必须实现

```c
// 初始化
C_Initialize
C_Finalize
C_GetFunctionList
C_GetInfo

// Slot / Token 查询
C_GetSlotList
C_GetSlotInfo
C_GetTokenInfo
C_GetMechanismList
C_GetMechanismInfo

// Session
C_OpenSession
C_CloseSession
C_GetSessionInfo

// 对象查询
C_FindObjectsInit
C_FindObjects
C_FindObjectsFinal
C_GetAttributeValue

// Legacy parallel（必须存在，固定返回 CKR_FUNCTION_NOT_PARALLEL）
C_GetFunctionStatus
C_CancelFunction
```

合计：**19 个函数**。

### 2.2 读写卡额外需要

```c
// 认证（读写卡需要创建容器，通常需要 User PIN）
C_Login
C_Logout
```

### 2.3 签名能力（只读卡和读写卡都需要）

```c
C_SignInit
C_Sign
```

### 2.4 RSA 解密能力（若卡支持 key exchange 密钥）

```c
C_DecryptInit
C_Decrypt
```

### 2.5 ECC DH 能力（若卡支持 ECDH）

```c
// 仅当需要 CardConstructDHAgreement 时
C_DeriveKey   // 用 CKM_ECDH1_DERIVE 派生共享密钥
```

### 2.6 读写卡额外需要（密钥生成 / 导入）

```c
C_GenerateKeyPair     // 卡上生成密钥对
C_CreateObject        // 导入密钥（key import 场景）
C_DestroyObject       // 删除容器
C_SetAttributeValue   // 修改对象属性（可选，用于更新 label 等）
```

### 2.7 明确不需要实现的函数

下列函数对 minidriver 场景不需要，可以返回 `CKR_FUNCTION_NOT_SUPPORTED`：

```
C_EncryptInit / C_Encrypt / C_EncryptUpdate / C_EncryptFinal
C_DecryptUpdate / C_DecryptFinal
C_DigestInit / C_Digest / C_DigestUpdate / C_DigestKey / C_DigestFinal
C_VerifyInit / C_Verify / C_VerifyUpdate / C_VerifyFinal
C_SignRecoverInit / C_SignRecover
C_VerifyRecoverInit / C_VerifyRecover
C_DigestEncryptUpdate / C_DecryptDigestUpdate
C_SignEncryptUpdate / C_DecryptVerifyUpdate
C_GenerateKey / C_WrapKey / C_UnwrapKey
C_SeedRandom / C_GenerateRandom
C_GetOperationState / C_SetOperationState
C_CopyObject / C_GetObjectSize
C_InitToken / C_InitPIN / C_SetPIN
C_WaitForSlotEvent
```

---

## 3. Minidriver 最小 API 集合

Minidriver 通过 `CardAcquireContext` 向 Base CSP/KSP 返回一张函数指针表（`CARD_DATA`）。

### 3.1 所有卡都必须实现（约 10 个）

```c
// 初始化
CardAcquireContext          // 建立上下文，填写 CARD_DATA 函数表
CardDeleteContext            // 释放上下文

// Session 管理
CardAuthenticatePin         // v4 认证接口，仍须实现
CardAuthenticateEx          // v6 认证接口，支持外部 PIN / session PIN
CardDeauthenticateEx        // v6，必须存在；无法高效实现时返回 SCARD_E_UNSUPPORTED_FEATURE
CardDeauthenticate          // 可置 NULL；若置 NULL，Base CSP 用卡复位代替

// 属性系统（v6）
CardGetProperty             // 必须响应所有标准属性（见 3.4）
CardSetProperty             // 只读卡仅需支持 CP_PARENT_WINDOW 和 CP_PIN_CONTEXT_STRING
```

### 3.2 只读卡必须实现（在 3.1 基础上再加约 9 个）

```c
// 文件系统（只读）
CardReadFile                // 需要虚拟化 cardid / cardcf / mscp\cmapfile
CardGetFileInfo
CardEnumFiles
CardQueryFreeSpace          // 返回 0 bytes available, 0 containers available

// 密钥容器查询
CardGetContainerInfo        // 返回公钥材料（BCRYPT 格式）
CardQueryKeySizes
CardQueryCapabilities       // 向后兼容 v5

// 密码学
CardSignData                // 所有卡都必须实现

// 容器属性（v6）
CardGetContainerProperty
```

只读卡最小集合计：**约 19 个函数**。

### 3.3 读写卡在只读最小集基础上额外需要

```c
// 文件系统（写）
CardCreateDirectory
CardDeleteDirectory
CardCreateFile
CardWriteFile
CardDeleteFile

// 密钥容器管理
CardCreateContainer         // 支持 KEY_GEN 或 KEY_IMPORT 至少之一
CardDeleteContainer
CardSetContainerProperty

// 认证管理
CardChangeAuthenticator     // v4，仍须实现
CardChangeAuthenticatorEx   // v6
CardGetChallenge            // 仅当卡有 admin key
CardAuthenticateChallenge   // 仅当卡有 admin key
CardGetChallengeEx          // v6，仅当卡有 admin key
CardUnblockPin              // admin 必须支持，user 不支持

// RSA 解密（若卡支持）
CardRSADecrypt
```

### 3.4 `CardGetProperty` 必须响应的属性

| 属性常量 | 类型 | 说明 |
|----------|------|------|
| `CP_CARD_FREE_SPACE` | `CARD_FREE_SPACE_INFO` | 只读卡返回全 0 |
| `CP_CARD_CAPABILITIES` | `CARD_CAPABILITIES` | `fKeyGen` 只读卡为 FALSE |
| `CP_CARD_KEYSIZES` | `CARD_KEY_SIZES` | 按 `dwFlags` 指定算法类型返回 |
| `CP_CARD_READ_ONLY` | `BOOL` | 只读卡返回 TRUE |
| `CP_CARD_CACHE_MODE` | `DWORD` | 只读卡建议返回 `CP_CACHE_MODE_SESSION_ONLY` |
| `CP_SUPPORTS_WIN_X509_ENROLLMENT` | `BOOL` | 只读卡返回 FALSE |
| `CP_CARD_GUID` | `BYTE[16]` | 必须与 `cardid` 文件内容完全一致 |
| `CP_CARD_PIN_INFO` | `PIN_INFO` | 按 `dwFlags` 指定的 PIN_ID 返回 |
| `CP_CARD_LIST_PINS` | `PIN_SET` | 返回卡上存在的 PIN 位掩码 |
| `CP_CARD_PIN_STRENGTH_VERIFY` | `DWORD` | 返回支持的 PIN 强度位掩码 |
| `CP_CARD_SERIAL_NO` | `BYTE[]` | 可选 |
| `CP_CARD_AUTHENTICATED_STATE` | `PIN_SET` | 可选 |

### 3.5 ECC 相关（若卡支持）

```c
CardConstructDHAgreement    // RSA-only 卡置 NULL
CardDeriveKey               // RSA-only 卡置 NULL（v5）
CardDestroyDHAgreement      // RSA-only 卡置 NULL（v5）
```

### 3.6 安全密钥注入（Secure Key Injection，v7，全部可选）

```c
MDImportSessionKey          // 服务器端
MDEncryptData               // 服务器端
CardGetSharedKeyHandle
CardImportSessionKey
CardGetAlgorithmProperty
CardGetKeyProperty
CardSetKeyProperty
CardDestroyKey
CardProcessEncryptedData
```

仅在需要加密导入密钥到卡的场景（如 CA 密钥归档）时实现，一般只读卡不需要。

---

## 4. 函数映射表

### 4.1 认证

| Minidriver 函数 | PKCS#11 调用 | 说明 |
|-----------------|--------------|------|
| `CardAuthenticatePin(ROLE_USER)` | `C_Login(CKU_USER, PIN, pinLen)` | |
| `CardAuthenticatePin(ROLE_ADMIN)` | `C_Login(CKU_SO, PIN, pinLen)` | SO 对应 admin |
| `CardAuthenticateEx(ROLE_USER)` | `C_Login(CKU_USER, ...)` | 需处理 `CARD_AUTHENTICATE_GENERATE_SESSION_PIN` flag |
| `CardDeauthenticate` | `C_Logout` | |
| `CardDeauthenticateEx` | `C_Logout` | |

**注意**：PKCS#11 的 `CKU_USER` / `CKU_SO` 只有两级，minidriver 支持 ROLE 0–7。如果卡只有一个 user PIN，将 `ROLE_USER`(1) 映射到 `CKU_USER`，`ROLE_ADMIN`(2) 映射到 `CKU_SO`，roles 3–7 返回 `SCARD_E_UNSUPPORTED_FEATURE`。

### 4.2 密钥容器枚举

```
CardAcquireContext 时执行：
  C_OpenSession(slotId, CKF_SERIAL_SESSION, ...)
  C_FindObjectsInit(template=[CKA_CLASS=CKO_PRIVATE_KEY])
  C_FindObjects(...)  → 得到 CK_OBJECT_HANDLE 列表
  C_FindObjectsFinal()

  对每个 handle：
    C_GetAttributeValue([CKA_ID, CKA_LABEL, CKA_KEY_TYPE, CKA_MODULUS_BITS])
    → 分配容器索引 bContainerIndex（0,1,2,...）
    → 建立映射表：bContainerIndex ↔ CK_OBJECT_HANDLE

  同时枚举对应的公钥对象（CKA_CLASS=CKO_PUBLIC_KEY，匹配 CKA_ID）
  同时枚举证书对象（CKA_CLASS=CKO_CERTIFICATE，匹配 CKA_ID）
```

内存中维护结构体数组（生命周期与 CARD_DATA 上下文相同）：

```c
typedef struct {
    BYTE             bContainerIndex;
    CK_OBJECT_HANDLE hPrivKey;
    CK_OBJECT_HANDLE hPubKey;       // 可能为 CK_INVALID_HANDLE
    CK_OBJECT_HANDLE hCert;         // 可能为 CK_INVALID_HANDLE
    CK_KEY_TYPE      keyType;       // CKK_RSA / CKK_EC
    DWORD            dwKeyBitLen;
    WCHAR            wszGuid[MAX_CONTAINER_NAME_LEN]; // 用于 cmapfile
} CONTAINER_MAPPING;
```

### 4.3 `CardGetContainerInfo`

```
输入：bContainerIndex
  → 查映射表，得到 hPubKey

  C_GetAttributeValue(hPubKey, [CKA_KEY_TYPE])

  若 CKK_RSA：
    C_GetAttributeValue(hPubKey, [CKA_MODULUS, CKA_PUBLIC_EXPONENT])
    → 组装 BCRYPT_RSAKEY_BLOB（见 6.1）
    → 填入 CONTAINER_INFO.pbKeyExPublicKey（AT_KEYEXCHANGE）
       或   CONTAINER_INFO.pbSigPublicKey（AT_SIGNATURE）

  若 CKK_EC：
    C_GetAttributeValue(hPubKey, [CKA_EC_POINT, CKA_EC_PARAMS])
    → 解析 DER 编码的 ECPoint
    → 组装 BCRYPT_ECCKEY_BLOB（见 6.2）
```

### 4.4 `CardSignData`

```
输入：CARD_SIGNING_INFO（bContainerIndex, dwKeySpec, dwSigningFlags, pbData, cbData）

  → 查映射表，得到 hPrivKey

  确定 PKCS#11 机制：
    若 CARD_PADDING_PKCS1 → CKM_RSA_PKCS
    若 CARD_PADDING_PSS   → CKM_RSA_PKCS_PSS（需构造 CK_RSA_PKCS_PSS_PARAMS）
    若 CARD_PADDING_NONE  → CKM_RSA_X_509（原始 RSA）
    若 ECC 签名           → CKM_ECDSA

  C_SignInit(session, &mechanism, hPrivKey)
  C_Sign(session, pbData, cbData, pbSignedData, &cbSignedData)

  → 将 pbSignedData 写入 CARD_SIGNING_INFO.pbSignedData（用 PFN_CSP_ALLOC 分配）
```

**PSS 参数转换**（`BCRYPT_PSS_PADDING_INFO` → `CK_RSA_PKCS_PSS_PARAMS`）：

```c
// Windows 侧
typedef struct _BCRYPT_PSS_PADDING_INFO {
    LPCWSTR pszAlgId;   // e.g., BCRYPT_SHA256_ALGORITHM
    ULONG   cbSalt;
} BCRYPT_PSS_PADDING_INFO;

// PKCS#11 侧
typedef struct CK_RSA_PKCS_PSS_PARAMS {
    CK_MECHANISM_TYPE hashAlg;   // e.g., CKM_SHA256
    CK_RSA_PKCS_MGF_TYPE mgf;   // e.g., CKG_MGF1_SHA256
    CK_ULONG sLen;               // = cbSalt
} CK_RSA_PKCS_PSS_PARAMS;

// pszAlgId 到 hashAlg / mgf 的映射：
// BCRYPT_SHA1_ALGORITHM   → CKM_SHA_1    / CKG_MGF1_SHA1
// BCRYPT_SHA256_ALGORITHM → CKM_SHA256   / CKG_MGF1_SHA256
// BCRYPT_SHA384_ALGORITHM → CKM_SHA384   / CKG_MGF1_SHA384
// BCRYPT_SHA512_ALGORITHM → CKM_SHA512   / CKG_MGF1_SHA512
```

### 4.5 `CardRSADecrypt`

```
输入：CARD_RSA_DECRYPT_INFO（bContainerIndex, dwPaddingType, pPaddingInfo, pbData, cbData）

  → 查映射表，得到 hPrivKey

  确定 PKCS#11 机制：
    若 CARD_PADDING_PKCS1 → CKM_RSA_PKCS
    若 CARD_PADDING_OAEP  → CKM_RSA_PKCS_OAEP（需构造 CK_RSA_PKCS_OAEP_PARAMS）
    若 CARD_PADDING_NONE  → CKM_RSA_X_509

  C_DecryptInit(session, &mechanism, hPrivKey)
  C_Decrypt(session, pbData, cbData, pbPlain, &cbPlain)

  → 若卡不做 padding removal，调用 pfnCspUnpadData 在软件中去 padding
```

### 4.6 `CardQueryKeySizes`

```
输入：dwKeySpec（AT_SIGNATURE / AT_KEYEXCHANGE / AT_ECDSA_P256 等）

  dwKeySpec → PKCS#11 mechanism：
    AT_SIGNATURE   → CKM_RSA_PKCS_PSS 或 CKM_RSA_PKCS
    AT_KEYEXCHANGE → CKM_RSA_PKCS
    AT_ECDSA_P256  → CKM_ECDSA（keyBitLen = 256）
    AT_ECDSA_P384  → CKM_ECDSA（keyBitLen = 384）
    AT_ECDSA_P521  → CKM_ECDSA（keyBitLen = 521）

  C_GetMechanismInfo(slotId, mechanism, &info)
  → info.ulMinKeySize / ulMaxKeySize → CARD_KEY_SIZES
```

### 4.7 `CardGetProperty` 映射

| 属性 | 来源 |
|------|------|
| `CP_CARD_GUID` | token `serialNumber`（16 字节）或其 SHA-1 截断，**必须与 `cardid` 文件保持一致** |
| `CP_CARD_CAPABILITIES.fKeyGen` | `CKF_GENERATE_KEY_PAIR` in `CK_TOKEN_INFO.flags` |
| `CP_CARD_KEYSIZES` | `C_GetMechanismInfo` |
| `CP_CARD_PIN_INFO` | 静态构造，结合 `CK_TOKEN_INFO.flags`（`CKF_LOGIN_REQUIRED` 等） |
| `CP_CARD_LIST_PINS` | 静态：只读卡通常只有 `ROLE_USER`（bit 1） |
| `CP_CARD_READ_ONLY` | 静态 TRUE（只读卡） |
| `CP_CARD_CACHE_MODE` | 静态 `CP_CACHE_MODE_SESSION_ONLY`（只读卡） |
| `CP_SUPPORTS_WIN_X509_ENROLLMENT` | 静态 FALSE（只读卡） |

---

## 5. 虚拟文件系统构建

Base CSP/KSP 在初始化时会通过 `CardReadFile` 读取以下几个文件，minidriver **必须能返回正确内容**。这些文件在 PKCS#11 里没有对应概念，需要在内存中构建。

### 5.1 `cardid` 文件

- 内容：16 字节，与 `CP_CARD_GUID` 完全一致
- 推荐做法：取 PKCS#11 token 的 `serialNumber`（32 字节 ASCII，hex-decode 取前 16 字节），或对 label+serial 做 SHA-1 截断到 16 字节
- **必须在卡不变的情况下每次返回相同的值**，否则 Base CSP 缓存失效

```c
// 示例：从 CK_TOKEN_INFO.serialNumber 派生
CK_TOKEN_INFO info;
C_GetTokenInfo(slotId, &info);
// serialNumber 是 32 字节 space-padded ASCII
// 可直接取前 16 字节作为 cardid（需确保唯一性）
memcpy(cardid, info.serialNumber, 16);
```

### 5.2 `cardcf` 文件（Cache Freshness Counter）

- 只读卡：Base CSP/KSP 不会写此文件，但初次读取时需要返回一个合法的结构
- 内容：`CARD_CACHE_FILE_FORMAT` 结构体（定义在 cardmod.h）
- 只读卡可以在内存中维护，初始值全零

```c
typedef struct _CARD_CACHE_FILE_FORMAT {
    BYTE bVersion;          // = 0
    BYTE bPinsFreshness;    // = 0
    WORD wContainersFreshness;   // = 0
    WORD wFilesFreshness;        // = 0
} CARD_CACHE_FILE_FORMAT;
```

### 5.3 `mscp\cmapfile`（Container Map File）

这是最复杂的一个。Base CSP/KSP 用它来了解卡上有哪些容器、每个容器的 GUID 是什么。

```c
// 每个容器对应一条记录
#define MAX_CONTAINER_NAME_LEN  40

typedef struct _CONTAINER_MAP_RECORD {
    WCHAR wszGuid[MAX_CONTAINER_NAME_LEN]; // CAPI container GUID，space-padded
    BYTE  bFlags;                          // CONTAINER_MAP_VALID_CONTAINER | CONTAINER_MAP_DEFAULT_CONTAINER
    BYTE  bReserved;
    WORD  wSigKeySizeBits;                 // 签名密钥大小，无则为 0
    WORD  wKeyExchangeKeySizeBits;         // 加密密钥大小，无则为 0
} CONTAINER_MAP_RECORD;

// cmapfile = CONTAINER_MAP_RECORD 数组（所有容器连续排列）
```

**构建流程**（在 `CardAcquireContext` 时执行）：

```
1. 枚举所有私钥对象（见 4.2）
2. 对每个私钥，取 CKA_LABEL 作为 wszGuid（若为空则从 CKA_ID 生成一个稳定的 GUID 字符串）
3. 根据 CKA_KEY_TYPE 和 dwKeySpec 推断 wSigKeySizeBits / wKeyExchangeKeySizeBits
4. 第一个有效容器设置 CONTAINER_MAP_DEFAULT_CONTAINER flag
5. 序列化成字节数组，存入内存
```

**CKA_ID → GUID 字符串的稳定生成建议**：

```c
// 取 CKA_ID 的 SHA-1，格式化成 GUID 字符串
// {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
// 这样只要 CKA_ID 不变，GUID 就不变
```

### 5.4 `CardEnumFiles` 返回的文件列表

根目录：

```
cardid
cardcf
```

`mscp` 目录：

```
cmapfile
kxc00       // 第 0 个容器的 key exchange 证书（如有）
kxc01       // 第 1 个容器的 key exchange 证书（如有）
...
ksc00       // 第 0 个容器的 signature 证书（如有）
...
```

证书文件从 PKCS#11 的 `CKO_CERTIFICATE` 对象（匹配 `CKA_ID`）的 `CKA_VALUE` 属性读取，DER 编码直接返回。

---

## 6. 数据格式转换

### 6.1 RSA 公钥：`CKA_MODULUS` + `CKA_PUBLIC_EXPONENT` → `BCRYPT_RSAKEY_BLOB`

```c
typedef struct _BCRYPT_RSAKEY_BLOB {
    ULONG Magic;          // BCRYPT_RSAPUBLIC_MAGIC = 0x31415352
    ULONG BitLength;      // key bit length
    ULONG cbPublicExp;    // byte length of exponent
    ULONG cbModulus;      // byte length of modulus
    ULONG cbPrime1;       // = 0 for public key
    ULONG cbPrime2;       // = 0 for public key
    // followed by: PublicExponent[cbPublicExp] | Modulus[cbModulus]
    // all in big-endian
} BCRYPT_RSAKEY_BLOB;
```

注意：PKCS#11 返回的 `CKA_MODULUS` 是 big-endian 字节数组，与 BCRYPT 格式一致，直接拷贝。

### 6.2 ECC 公钥：`CKA_EC_POINT` → `BCRYPT_ECCKEY_BLOB`

```c
typedef struct _BCRYPT_ECCKEY_BLOB {
    ULONG dwMagic;   // BCRYPT_ECDSA_PUBLIC_P256_MAGIC 等
    ULONG cbKey;     // byte length of X (= Y = cbKey)
    // followed by: X[cbKey] | Y[cbKey]
    // all big-endian
} BCRYPT_ECCKEY_BLOB;
```

`CKA_EC_POINT` 是 DER 编码的 `ECPoint`（OCTET STRING 包裹 `04 || X || Y`），需要：

```
1. 解析 DER OCTET STRING（跳过 tag 04 和长度字节）
2. 确认首字节 = 0x04（uncompressed point）
3. 分离 X、Y 各 cbKey 字节
4. 填入 BCRYPT_ECCKEY_BLOB
```

`dwMagic` 根据曲线选择：
- P-256：`BCRYPT_ECDSA_PUBLIC_P256_MAGIC` = 0x31534345
- P-384：`BCRYPT_ECDSA_PUBLIC_P384_MAGIC` = 0x33534345
- P-521：`BCRYPT_ECDSA_PUBLIC_P521_MAGIC` = 0x35534345

### 6.3 `dwKeySpec` 与 PKCS#11 机制的对应

| `dwKeySpec` | PKCS#11 Key Type | 签名机制 | 解密机制 |
|-------------|------------------|----------|----------|
| `AT_SIGNATURE` | `CKK_RSA` | `CKM_RSA_PKCS` / `CKM_RSA_PKCS_PSS` | N/A |
| `AT_KEYEXCHANGE` | `CKK_RSA` | `CKM_RSA_PKCS` | `CKM_RSA_PKCS` / `CKM_RSA_PKCS_OAEP` |
| `AT_ECDSA_P256` | `CKK_EC`（P-256） | `CKM_ECDSA` | N/A |
| `AT_ECDSA_P384` | `CKK_EC`（P-384） | `CKM_ECDSA` | N/A |
| `AT_ECDSA_P521` | `CKK_EC`（P-521） | `CKM_ECDSA` | N/A |
| `AT_ECDHE_P256` | `CKK_EC`（P-256） | N/A | `CKM_ECDH1_DERIVE` |
| `AT_ECDHE_P384` | `CKK_EC`（P-384） | N/A | `CKM_ECDH1_DERIVE` |
| `AT_ECDHE_P521` | `CKK_EC`（P-521） | N/A | `CKM_ECDH1_DERIVE` |

区分 `AT_ECDSA_*` 和 `AT_ECDHE_*` 的方法：通过 `CKA_DERIVE`（TRUE 为 ECDHE）和 `CKA_SIGN`（TRUE 为 ECDSA）属性区分。

---

## 7. 实现注意事项

### 7.1 PKCS#11 Session 管理

- `CardAcquireContext` 时打开一个 session，存入上下文；`CardDeleteContext` 时关闭。
- 认证状态（`C_Login`）绑定在 session 上，若有多个进程/上下文并发，各自独立。
- `CardDeleteContext` 可能在无事务状态下调用（卡被拔出时），`C_CloseSession` 需要 graceful 处理错误。

### 7.2 只读卡文件系统不变性

- `cardid` 内容必须与 `CP_CARD_GUID` 的返回值**逐字节相同**，否则 Base CSP 缓存校验失败。
- 只要 PKCS#11 token 没有被重新个人化，`cardid` 和 `cmapfile` 必须每次返回相同的内容。建议在 `CardAcquireContext` 时一次性生成并缓存。
- 不要使用 `SCARD_E_FILE_NOT_FOUND` 作为通用错误码从 `CardReadFile` 返回，Base CSP/KSP 会缓存这个结果，导致后续访问被阻断。

### 7.3 内存管理

- Minidriver 分配的返回缓冲区（如 `CardReadFile` 返回的数据、`CardGetContainerInfo` 返回的公钥）必须用 `pfnCspAlloc` 分配，由 Base CSP/KSP 用 `pfnCspFree` 释放。
- 映射表等内部状态用普通堆内存，在 `CardDeleteContext` 中释放。

### 7.4 版本协商

```c
// CardAcquireContext 中
#define MINIDRIVER_MIN_VERSION 4  // 支持的最低版本
#define MINIDRIVER_CUR_VERSION 7  // 当前支持的最高版本

if (pCardData->dwVersion < MINIDRIVER_MIN_VERSION)
    return ERROR_REVISION_MISMATCH;

pCardData->dwVersion = min(pCardData->dwVersion, MINIDRIVER_CUR_VERSION);
```

低于 version 6 的调用者不会使用 `CardAuthenticateEx`、`CardGetProperty` 等 v6 函数，但函数指针仍需填写（调用者通过版本号决定是否调用）。

### 7.5 只读卡不支持的函数处理方式

函数指针**必须**填写（不能留 NULL，除非规范明确说可以置 NULL），实现体返回 `SCARD_E_UNSUPPORTED_FEATURE`：

```c
// 例：只读卡的 CardCreateContainer
DWORD WINAPI MyCardCreateContainer(...) {
    return SCARD_E_UNSUPPORTED_FEATURE;
}
```

可以置 NULL 的例外（规范明确说明）：
- `CardDeauthenticate`：置 NULL 时 Base CSP 用卡复位代替
- `CardRSADecrypt`：ECC-only 卡置 NULL
- `CardConstructDHAgreement` / `CardDeriveKey` / `CardDestroyDHAgreement`：RSA-only 卡置 NULL

### 7.6 `CardSignData` 中 padding 的处理

若卡**不支持**在卡内做 padding（大多数情况），流程如下：

```
1. 调用 pfnCspPadData（Base CSP 提供的 callback）对 pbData 补 padding
2. 将补好 padding 的数据用 CKM_RSA_X_509（原始 RSA）发给卡做私钥运算
3. 返回结果
```

若卡**支持**在卡内做 padding（较少见），直接传原始 hash 数据和机制参数。
