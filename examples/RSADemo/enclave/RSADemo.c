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
#include <string.h>
#include "RSADemo_t.h"
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

char * pub_key="-----BEGIN PUBLIC KEY-----\n"
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCU8heg6WcPKT3nXf8ABmpbsMK+\n"
"M9devMeDFLGy2c+AgJWrG2vWMIT2xVq6/LQpdoG45xwU5p/a7fWJhqC+w/1H+epb\n"
"u1IFGr6QzmKhz2ksq/54Uax7LM9mD7LVwisp9EqO1/0rnk8vUEXeSzEAKr14DaJE\n"
"PE3t2FDamb8YXp1xRwIDAQAB\n"
"-----END PUBLIC KEY-----";
char * pri_key="-----BEGIN RSA PRIVATE KEY-----\n"
"MIICXQIBAAKBgQCU8heg6WcPKT3nXf8ABmpbsMK+M9devMeDFLGy2c+AgJWrG2vW\n"
"MIT2xVq6/LQpdoG45xwU5p/a7fWJhqC+w/1H+epbu1IFGr6QzmKhz2ksq/54Uax7\n"
"LM9mD7LVwisp9EqO1/0rnk8vUEXeSzEAKr14DaJEPE3t2FDamb8YXp1xRwIDAQAB\n"
"AoGAD9fMcZ5CCxfM8N5LsHn+ODCOFmM3Rml4I1ZBLJAEhVuoD+JDzy2sBv+pDfix\n"
"RTPIyp0ynHqHiGcFVhKO6Ju6RhMhbAlXOTy7J8dv96hayjdlrigFS0Tf1nvqz4qp\n"
"ayTJukIpbncgmbQOtjiBjHuNc32/gSaIaIONOcihji/Q+yECQQDEqp9R/eeJxDTD\n"
"pN1UeVYjumaC2PgKtNbJWAdpz/9omD7AjasAyhWCiFKlu7Ev4cyGkkqNPFs8nYw8\n"
"mSYBV9bXAkEAweHKfDtOTNdhRYuGswi3M0EvTtP6oCKWxoJXKOkliy/n38YloWkD\n"
"c5sD3wycK0yFG3/NZNRtHWrpYRoXemybEQJBAL8SqpHlpuQhvcXrUqJ09KznuBse\n"
"o/b69cdPAHzceeBsMmOwAFlW/YkB25JsBd1oeuawEUChSF9fDlX90X/ykKcCQQCf\n"
"duXDHkg9fVydBbBpar67ol6VuFZIBYr7hNLJbFGb1HAjpmbnBmd3W0Vo3IdKOaq1\n"
"Pn2h8/I3IusHGZ277L3xAkBBAbIENcKEoMiRAHM8jco427J9TmMJISfDepz16Qou\n"
"lh/xASzBoM48S9FXwwV5BbLALhBIUfJNKpZ55i4JA8mC\n"
"-----END RSA PRIVATE KEY-----";

int my_encrypt(char * plain_text, char * cipher_text){
    
    char * en;
    int rsa_len;
    RSA *p_rsa = RSA_new();
    BIO *keybio = BIO_new_mem_buf((unsigned char*)pub_key, -1);

    p_rsa=PEM_read_bio_RSA_PUBKEY(keybio, &p_rsa, NULL, NULL);
    rsa_len=RSA_size(p_rsa);
    en=malloc(rsa_len+1);
    memset(en,0,rsa_len+1);
    if(RSA_public_encrypt(rsa_len,(unsigned char *)plain_text,(unsigned char*)en,p_rsa,RSA_NO_PADDING)<0){
        return 1;
    }

    BIO_free_all(keybio);
    RSA_free(p_rsa);
    
    strncpy(cipher_text, en, strlen(en) + 1);
    return 0;
}

int my_decrypt(char * cipher_text, char * plain_text){

    char * de;
    int rsa_len;
    RSA* p_rsa = RSA_new();
    BIO *keybio = BIO_new_mem_buf((unsigned char*)pri_key, -1);

    p_rsa = PEM_read_bio_RSAPrivateKey(keybio, &p_rsa, NULL, NULL);
    rsa_len=RSA_size(p_rsa);
    de=malloc(rsa_len+1);
    memset(de,0,rsa_len+1);
    if(RSA_private_decrypt(rsa_len,(unsigned char *)cipher_text,(unsigned char*)de,p_rsa,RSA_NO_PADDING)<0){
        return 1;
    }

    BIO_free_all(keybio);
    RSA_free(p_rsa);

    strncpy(plain_text, de, strlen(de) + 1);
    return 0;
}
