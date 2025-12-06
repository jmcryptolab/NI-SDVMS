#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "d_randombytes.h"
#include "d_sign.h"
#include "k_kem.h"           // KEM加密库
#include <openssl/sha.h>
#include <chrono>
#include <string>  // 为了用 std::string
#include <direct.h>         // 放到头文件区
#include <cstdio>
#define OUTDIR "D:\\DATA1\\k-d\\k-d\\x64\\Debug\\"

int main(void) {
    char cwd[MAX_PATH];
    _getcwd(cwd, MAX_PATH);
    printf("当前工作目录: %s D:\DATA1\k-d\k-d\x64\Debug\", cwd);   // 文件会写到这里


using namespace std::chrono;
   // SHA-256哈希库

#define CTXLEN 10
#define NUM_SIGNERS 3
#define MAX_MSG_LENGTH 50
#define MAX_SIGNED_MSG_LENGTH (MAX_MSG_LENGTH + CRYPTO_SIGN_BYTES) 
#define HASH_SIZE 32 // SHA-256哈希值大小
//=== 组合签名消息的SHA-256哈希 ===
//SHA - 256哈希值: adf75a2188f6f617a3ee8567e29c141ed04b69231c540761d4272dee35b328a9
//解密后的哈希值:  adf75a2188f6f617a3ee8567e29c141ed04b69231c540761d4272dee35b328a9
#define MAX_KEM_MESSAGE HASH_SIZE   // KEM处理的最大消息长度

// 辅助函数：以十六进制形式打印字节数组
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n        ");
    }
    printf("\n");
}

typedef struct {
    const char* name;
    const char* message;
    uint8_t pk[CRYPTO_SIGN_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SIGN_SECRETKEYBYTES];
    uint8_t signed_msg[MAX_SIGNED_MSG_LENGTH];
    size_t signed_msg_len;
} Signer;

// 把字节数组转成 0x 开头的十六进制字符串
std::string to_hex0x(const uint8_t* p, size_t n) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n + 2);
    s += "0x";
    for (size_t i = 0; i < n; i++) {
        s += hex[p[i] >> 4];
        s += hex[p[i] & 15];
    }
    return s;
}

// 带日志的保存函数：失败会 perror，成功会 [OK]
static void save_txt(const char* path, const std::string& s) {
    FILE* f = fopen(path, "wb");
    if (!f) { perror(path); return; }
    size_t n = fwrite(s.data(), 1, s.size(), f);
    fclose(f);
    printf("[OK] 写出: %s (%zu 字节)\n", path, n);
}

// 保存字符串到 txt 文件
void save_txt(const char* fname, const std::string& s) {
    FILE* f = fopen(fname, "wb");
    if (f) {
        fwrite(s.data(), 1, s.size(), f);
        fclose(f);
    }
}


int main(void) {
    char cwd[MAX_PATH]{ 0 };
    _getcwd(cwd, MAX_PATH);
    printf("当前工作目录: %s\n", cwd);
    int ret;
    uint8_t ctx[CTXLEN] = "zeshui";
    uint8_t hash_result[HASH_SIZE];  // 存储SHA-256哈希结果

    // KEM相关变量
    uint8_t kem_pk[CRYPTO_KEM_PUBLICKEYBYTES];  // KEM公钥
    uint8_t kem_sk[CRYPTO_KEM_SECRETKEYBYTES];  // KEM私钥
    uint8_t ct[CRYPTO_KEM_CIPHERTEXTBYTES];     // 密文
    uint8_t shared_alice[CRYPTO_KEM_BYTES];      // Alice的共享密钥
    uint8_t shared_bob[CRYPTO_KEM_BYTES];        // Bob的共享密钥
    uint8_t encrypted_hash[HASH_SIZE];       // 加密后的哈希值
    uint8_t decrypted_hash[HASH_SIZE];       // 解密后的哈希值

    // 用于存储连接后的签名消息
    uint8_t combined_signed_msgs[MAX_SIGNED_MSG_LENGTH * NUM_SIGNERS];
    size_t combined_length = 0;

    Signer signers[NUM_SIGNERS] = {
        {"xiandianuniversity", "xiandianuniversitydongdongyaojmzhang", {0}, {0}, {0}, 0},
        {"dongdongyao", "xiandianuniversitydongdongyaojmzhang", {0}, {0}, {0}, 0},
        {"jmzhang", "xiandianuniversitydongdongyaojmzhang", {0}, {0}, {0}, 0}
    };

    // 1. 生成数字签名密钥对
    for (int i = 0; i < NUM_SIGNERS; i++) {
        auto t1 = high_resolution_clock::now();
        int keygen_result = crypto_sign_keypair(signers[i].pk, signers[i].sk);
        auto t2 = high_resolution_clock::now();
        double keygen_time = duration_cast<microseconds>(t2 - t1).count() / 1000.0;
        printf("KeyGen Time for %%s: %%0.3f ms\n", signers[i].name, keygen_time);
        if (keygen_result != 0) {
            fprintf(stderr, "生成密钥对失败: %s\n", signers[i].name);
            return -1;
        }
        auto t4 = high_resolution_clock::now();
        double sign_time = duration_cast<microseconds>(t4 - t3).count() / 1000.0;
        printf("Signing Time for %%s: %%0.3f ms\n", signers[i].name, sign_time);
    }

    // 2. 生成签名并合并
    for (int i = 0; i < NUM_SIGNERS; i++) {
        size_t msg_len = strlen(signers[i].message);

        auto t3 = high_resolution_clock::now();
        int sign_result = crypto_sign(
            signers[i].signed_msg,
            &signers[i].signed_msg_len,
            (const uint8_t*)signers[i].message,
            msg_len,
            ctx,
            CTXLEN,
            signers[i].sk
        ) != 0) {
            fprintf(stderr, "签名失败: %s\n", signers[i].name);
            return -1;
        }

        printf("\n=== %s 的签名结果 ===\n", signers[i].name);
        printf("消息: %s\n", signers[i].message);
        printf("签名消息长度: %zu 字节\n", signers[i].signed_msg_len);

        // 将签名后的消息添加到组合缓冲区
        memcpy(combined_signed_msgs + combined_length,
            signers[i].signed_msg,
            signers[i].signed_msg_len);
        combined_length += signers[i].signed_msg_len;
    }

    auto t5 = high_resolution_clock::now();

// 3. 输出组合后的签名消息
    printf("\n=== 组合后的签名消息 ===\n");
    printf("总长度: %zu 字节\n", combined_length);
    print_hex("组合签名消息", combined_signed_msgs, combined_length);
auto t6 = high_resolution_clock::now();
double aggregation_time = duration_cast<microseconds>(t6 - t5).count() / 1000.0;
printf("Aggregation Time: %.3f ms\n", aggregation_time);
printf("Aggregated Signature Size: %.2f KB\n", combined_length / 1024.0);

    // 4. 计算SHA-256哈希
    printf("\n=== 组合签名消息的SHA-256哈希 ===\n");
    if (SHA256(combined_signed_msgs, combined_length, hash_result) == NULL) {
        fprintf(stderr, "SHA-256计算失败\n");
        return -1;
    }
    print_hex("SHA-256哈希值", hash_result, HASH_SIZE);

    // 5. KEM密钥生成 (Alice)
    printf("\n=== KEM密钥生成 ===\n");
    if (crypto_kem_keypair(kem_pk, kem_sk) != 0) {
        fprintf(stderr, "KEM密钥对生成失败\n");
        return -1;
    }
    printf("KEM公钥生成成功\n");

    // 6. KEM封装 (Bob使用Alice的公钥)
    printf("\n=== KEM封装阶段 ===\n");
    if (crypto_kem_enc(ct, shared_bob, kem_pk) != 0) {
        fprintf(stderr, "KEM封装失败\n");
        return -1;
    }
    printf("KEM封装成功\n");
    print_hex("KEM密文", ct, CRYPTO_KEM_CIPHERTEXTBYTES);
    print_hex("Bob的共享密钥", shared_bob, CRYPTO_KEM_BYTES);

    // 7. KEM解封装 (Alice使用自己的私钥)
    printf("\n=== KEM解封装阶段 ===\n");
    if (crypto_kem_dec(shared_alice, ct, kem_sk) != 0) {
        fprintf(stderr, "KEM解封装失败\n");
        return -1;
    }
    printf("KEM解封装成功\n");
    print_hex("Alice的共享密钥", shared_alice, CRYPTO_KEM_BYTES);

    // 8. 验证共享密钥是否匹配
    if (memcmp(shared_alice, shared_bob, CRYPTO_KEM_BYTES) != 0) {
        fprintf(stderr, "共享密钥不匹配！\n");
        return -1;
    }
    printf("双方共享密钥匹配\n");

    // 9. 使用共享密钥加密哈希值 (简化的一次性密码本)
    printf("\n=== 使用共享密钥加密SHA-256哈希 ===\n");
    for (size_t i = 0; i < HASH_SIZE; i++) {
        encrypted_hash[i] = hash_result[i] ^ shared_bob[i % CRYPTO_KEM_BYTES];
    }
    print_hex("加密后的哈希值", encrypted_hash, HASH_SIZE);

    // 10. 使用共享密钥解密哈希值
    printf("\n=== 使用共享密钥解密 ===\n");
    for (size_t i = 0; i < HASH_SIZE; i++) {
        decrypted_hash[i] = encrypted_hash[i] ^ shared_alice[i % CRYPTO_KEM_BYTES];
    }
    print_hex("解密后的哈希值", decrypted_hash, HASH_SIZE);

    // 11. 验证解密结果
    if (memcmp(decrypted_hash, hash_result, HASH_SIZE) != 0) {
        fprintf(stderr, "哈希解密失败！\n");
        return -1;
    }
    printf("哈希解密成功，与原始哈希值匹配\n");

    // === 保存关键数据到指定目录（OUTDIR） ===
    save_txt(OUTDIR "kem_pk.txt", to_hex0x(kem_pk, CRYPTO_KEM_PUBLICKEYBYTES));
    save_txt(OUTDIR "kem_sk_DO_NOT_SHARE.txt", to_hex0x(kem_sk, CRYPTO_KEM_SECRETKEYBYTES));
    save_txt(OUTDIR "messageDigest.txt", to_hex0x(hash_result, HASH_SIZE));

    for (size_t i = 0; i < NUM_SIGNERS; ++i) {
        std::string fct = std::string(OUTDIR) + "signer" + std::to_string(i) + "_ct.txt";
        std::string feh = std::string(OUTDIR) + "signer" + std::to_string(i) + "_encHash.txt";
        std::string fmsg = std::string(OUTDIR) + "signer" + std::to_string(i) + "_signedMsg.txt";
        save_txt(fct.c_str(), to_hex0x(ct, CRYPTO_KEM_CIPHERTEXTBYTES));
        save_txt(feh.c_str(), to_hex0x(encrypted_hash, HASH_SIZE));
        save_txt(fmsg.c_str(), to_hex0x(signers[i].signed_msg, signers[i].signed_msg_len));
    }

    printf("\n所有文件已保存到：%s\n", OUTDIR);

    // 列出该目录的文件清单
    system("cmd /C dir " OUTDIR);

    // 防止窗口立刻关闭
    system("pause");  // 需要 <cstdlib>；若未包含，改用 getchar();
    // getchar();

    return 0;
}


