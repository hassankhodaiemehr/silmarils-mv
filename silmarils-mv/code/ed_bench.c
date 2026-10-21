#include <stdio.h>
#include <time.h>
#include <openssl/evp.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+1e-9*t.tv_nsec;}
int main(){EVP_PKEY*k=NULL;EVP_PKEY_CTX*pc=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);EVP_PKEY_keygen_init(pc);EVP_PKEY_keygen(pc,&k);
unsigned char m[128]={1},sig[64];size_t sl=64;EVP_MD_CTX*c=EVP_MD_CTX_new();
int R=5000;double t0=now();for(int i=0;i<R;i++){EVP_DigestSignInit(c,NULL,NULL,NULL,k);sl=64;EVP_DigestSign(c,sig,&sl,m,128);}double t1=now();
int ok=0;for(int i=0;i<R;i++){EVP_DigestVerifyInit(c,NULL,NULL,NULL,k);ok+=EVP_DigestVerify(c,sig,sl,m,128);}double t2=now();
printf("{\"scheme\":\"Ed25519 (OpenSSL, native C)\",\"sign_us\":%.1f,\"verify_us\":%.1f,\"ok\":%d}\n",(t1-t0)/R*1e6,(t2-t1)/R*1e6,ok==R);}
