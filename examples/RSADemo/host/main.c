/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include "enclave.h"
#include "RSADemo_u.h"
#include "string.h"

#define BUF_LEN 32

int main()
{
    int  retval = 0;
    char *path = PATH;
    //char buf[BUF_LEN];
    cc_enclave_t *context = NULL;
    context = (cc_enclave_t *)malloc(sizeof(cc_enclave_t));
    if (!context) {
        return CC_ERROR_OUT_OF_MEMORY;
    }
    cc_enclave_result_t res = CC_FAIL;

    printf("Create secgear enclave\n");

    char real_p[PATH_MAX];
    /* check file exists, if not exist then use absolute path */
    if (realpath(path, real_p) == NULL) {
        if (getcwd(real_p, sizeof(real_p)) == NULL) {
            printf("Cannot find enclave.sign.so");
            goto end;
        }
        if (PATH_MAX - strlen(real_p) <= strlen("/enclave.signed.so")) {
            printf("Failed to strcat enclave.sign.so path");
            goto end;
        }
        (void)strcat(real_p, "/enclave.signed.so");
    }

    res = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, context);
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        goto end; 
    }

    //res = get_string(context, &retval, buf);
    char * plain_text="test rsa demo!";
    char result[1024];
    res = my_encrypt(context, &retval, plain_text, result);

    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Ecall enclave error\n");
    } else {
        printf("%s encrypt result:%s\n", plain_text, result);
    }

    char * cipher_text="test rsa demo!";
    char result2[1024];
    res = my_decrypt(context, &retval, cipher_text, result2);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Ecall enclave error\n");
    } else {
        printf("%s decrypt result:%s\n", cipher_text, result2);
    }

    res = cc_enclave_destroy(context);
    if(res != CC_SUCCESS) {
        printf("Destroy enclave error\n");
    }
end:
    free(context);
    return res;
}
