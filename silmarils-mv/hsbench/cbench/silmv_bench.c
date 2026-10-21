/* SILMARILS-MV core: sign / verify benchmark over F_{2^255-19}. */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "fe25519.h"

static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+1e-9*t.tv_nsec; }
static void fe_rand(fe *h){ uint8_t b[32]; RAND_bytes(b,32); b[31]&=0x7f; fe_frombytes(h,b); }

/* m <- H(msg) mod p (SHA3-256, top bit cleared; bias 2^-250) */
static void hash_to_fe(fe *m,const uint8_t *msg,size_t len){
  uint8_t d[32]; unsigned int dl; EVP_Digest(msg,len,d,&dl,EVP_sha3_256(),NULL); d[31]&=0x7f; fe_frombytes(m,d);
}
/* powers e[0..psi] of m with log-depth dependency: e[2j]=e[j]^2, e[2j+1]=e[j]e[j+1] */
static void powers(fe *e,int psi,const fe *m){
  fe_0(&e[0]); e[0].v[0]=1; if(psi>=1) e[1]=*m;
  for(int k=2;k<=psi;k++){ int j=k>>1; if(k&1) fe_mul(&e[k],&e[j],&e[j+1]); else fe_mul(&e[k],&e[j],&e[j]); }
}
static void dotp(fe *out,const fe *x,const fe *y,int len){
  fe acc; fe_0(&acc);
  for(int i=0;i<len;i++){ fe t; fe_mul(&t,&x[i],&y[i]); fe_add(&acc,&acc,&t); if((i&7)==7) fe_carry(&acc);} 
  fe_carry(&acc); *out=acc;
}
/* alpha = A e(m); A row-major (w+1) x (psi+1) */
static void sign_core(fe *alpha,const fe *A,int w,int psi,const fe *m,fe *e){
  powers(e,psi,m);
  for(int i=0;i<=w;i++) dotp(&alpha[i],A+(size_t)i*(psi+1),e,psi+1);
}
/* accept iff <c,alpha> == <b,e(m)> */
static int verify_core(const fe *c,const fe *b,const fe *alpha,int w,int psi,const fe *m,fe *e){
  fe lhs,rhs; dotp(&lhs,c,alpha,w+1); powers(e,psi,m); dotp(&rhs,b,e,psi+1);
  return fe_eq(&lhs,&rhs);
}
static void keygen_verifier_row(fe *b,const fe *c,const fe *A,int w,int psi){ /* b = c^T A */
  for(int j=0;j<=psi;j++){ fe acc; fe_0(&acc);
    for(int i=0;i<=w;i++){ fe t; fe_mul(&t,&c[i],&A[(size_t)i*(psi+1)+j]); fe_add(&acc,&acc,&t); fe_carry(&acc);} b[j]=acc; }
}
int main(int argc,char**argv){
  int ws[]={1,2,3,5,10,20,33,66}; int psis[]={1,16,64,256};
  uint8_t msg[128]; RAND_bytes(msg,sizeof msg);
  /* hashing cost */
  { fe m; int R=200000; double t0=now(); for(int r=0;r<R;r++){ msg[0]=r; hash_to_fe(&m,msg,sizeof msg);} double t1=now();
    printf("{\"op\":\"hash_sha3_256_128B\",\"ns\":%.1f}\n",(t1-t0)/R*1e9); }
  for(unsigned a=0;a<sizeof ws/sizeof*ws;a++) for(unsigned b=0;b<sizeof psis/sizeof*psis;b++){
    int w=ws[a],psi=psis[b];
    fe *A=malloc(sizeof(fe)*(w+1)*(psi+1)),*c=malloc(sizeof(fe)*(w+1)),*bb=malloc(sizeof(fe)*(psi+1)),*al=malloc(sizeof(fe)*(w+1)),*e=malloc(sizeof(fe)*(psi+2));
    for(int i=0;i<(w+1)*(psi+1);i++) fe_rand(&A[i]);
    for(int i=0;i<=w;i++) fe_rand(&c[i]);
    keygen_verifier_row(bb,c,A,w,psi);
    fe m; hash_to_fe(&m,msg,sizeof msg);
    /* correctness + rejection sanity */
    sign_core(al,A,w,psi,&m,e); if(!verify_core(c,bb,al,w,psi,&m,e)){ printf("VERIFY FAIL\n"); return 1; }
    fe one; fe_0(&one); one.v[0]=1; fe_add(&al[0],&al[0],&one); if(verify_core(c,bb,al,w,psi,&m,e)){ printf("REJECT FAIL\n"); return 1; }
    sign_core(al,A,w,psi,&m,e);
    int R= 2000000/((w+1)*(psi+1)+psi+w+2); if(R<2000) R=2000;
    volatile int acc=0; double t0=now();
    for(int r=0;r<R;r++){ m.v[0]^=r&1; sign_core(al,A,w,psi,&m,e); acc+=al[0].v[0]&1; }
    double t1=now();
    for(int r=0;r<R;r++){ acc+=verify_core(c,bb,al,w,psi,&m,e); }
    double t2=now();
    printf("{\"omega\":%d,\"psi\":%d,\"sign_ns\":%.1f,\"verify_ns\":%.1f,\"sig_bytes\":%d,\"reps\":%d}\n",w,psi,(t1-t0)/R*1e9,(t2-t1)/R*1e9,32*(w+1),R);
    free(A);free(c);free(bb);free(al);free(e);
  }
  /* field mul latency */
  { fe x,y; fe_rand(&x); fe_rand(&y); int R=20000000; double t0=now(); for(int r=0;r<R;r++){ fe_mul(&x,&x,&y);} double t1=now();
    printf("{\"op\":\"fe_mul\",\"ns\":%.2f,\"chk\":%lu}\n",(t1-t0)/R*1e9,(unsigned long)x.v[0]&1); }
  return 0;
}
