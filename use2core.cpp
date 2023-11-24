#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "esp32s3/rom/sha.h"

#define HASH_SIZE 32
#define NUM_THREADS 2

void print_hash(uint8_t *hash) {
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// 定義一個結構體，用於傳遞參數給子執行緒
typedef struct {
    int id; // 子執行緒的編號
    const char *data; // 要雜湊的數據
    size_t data_len; // 數據的長度
    uint8_t *hash; // 雜湊值的指標
} sha_param_t;

// 定義一個函數，用於子執行緒執行SHA-256的計算
void *sha_worker(void *arg) {
    sha_param_t *param = (sha_param_t *)arg; // 取得參數
    printf("Thread %d is running\n", param->id); // 顯示子執行緒的編號
    esp_sha(SHA2_256, (const uint8_t *)param->data, param->data_len, param->hash); // 執行SHA-256的計算
    printf("Thread %d is done\n", param->id); // 顯示子執行緒的結束
    return NULL;
}

void app_main() {
    uint8_t hash[NUM_THREADS][HASH_SIZE]; // 定義一個二維陣列，用於存放每個子執行緒的雜湊值
    const char *data[NUM_THREADS] = {"Hello, world!", "Goodbye, world!"}; // 定義一個一維陣列，用於存放每個子執行緒要雜湊的數據
    pthread_t threads[NUM_THREADS]; // 定義一個一維陣列，用於存放每個子執行緒的識別碼
    sha_param_t params[NUM_THREADS]; // 定義一個一維陣列，用於存放每個子執行緒的參數

    // 使用平行化的方法來加速SHA-256的計算
    // 利用ESP32-S3的雙核心處理器來同時處理兩個SHA-256的計算
    // 參考這個網址中的第三節
    for (int i = 0; i < NUM_THREADS; i++) {
        // 初始化每個子執行緒的參數
        params[i].id = i;
        params[i].data = data[i];
        params[i].data_len = strlen(data[i]);
        params[i].hash = hash[i];
        // 創建每個子執行緒，並傳遞參數
        pthread_create(&threads[i], NULL, sha_worker, &params[i]);
    }

    // 等待每個子執行緒結束
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Print hash value
    for (int i = 0; i < NUM_THREADS; i++) {
        print_hash(hash[i]);
    }
}
