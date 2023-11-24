#include <stdio.h>
#include <string.h>
#include "esp32s3/rom/sha.h"

#define HASH_SIZE 32
#define TRUNC_SIZE 16 // 截斷後的位元組數，可以根據需求修改

void print_hash(uint8_t *hash) {
    for (int i = 0; i < TRUNC_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void app_main() {
    uint8_t hash[HASH_SIZE];
    const char *data = "Hello, world!";

    // 使用截斷的技巧來減少SHA-256的輸出長度
    // 只保留前128位元的雜湊值，減少記
