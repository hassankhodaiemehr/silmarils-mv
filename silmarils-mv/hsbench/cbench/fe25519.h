/* Arithmetic in F_p, p = 2^255 - 19, radix 2^51 (5 limbs), donna-style. */
#ifndef FE25519_H
#define FE25519_H
#include <stdint.h>
#include <string.h>
typedef unsigned __int128 u128;
typedef struct { uint64_t v[5]; } fe;
#define MASK51 ((1ULL<<51)-1)

static inline void fe_0(fe *h){ memset(h,0,sizeof *h); }
static inline void fe_add(fe *h,const fe *f,const fe *g){ for(int i=0;i<5;i++) h->v[i]=f->v[i]+g->v[i]; }
/* h = f - g, adding 2p to stay positive (inputs limbs < 2^52) */
static inline void fe_sub(fe *h,const fe *f,const fe *g){
  h->v[0]=f->v[0]+0xFFFFFFFFFFFDAULL*2-g->v[0];
  for(int i=1;i<5;i++) h->v[i]=f->v[i]+0xFFFFFFFFFFFFEULL*2-g->v[i];
}
static inline void fe_carry(fe *h){
  uint64_t c;
  c=h->v[0]>>51; h->v[0]&=MASK51; h->v[1]+=c;
  c=h->v[1]>>51; h->v[1]&=MASK51; h->v[2]+=c;
  c=h->v[2]>>51; h->v[2]&=MASK51; h->v[3]+=c;
  c=h->v[3]>>51; h->v[3]&=MASK51; h->v[4]+=c;
  c=h->v[4]>>51; h->v[4]&=MASK51; h->v[0]+=c*19;
  c=h->v[0]>>51; h->v[0]&=MASK51; h->v[1]+=c;
}
static inline void fe_mul(fe *h,const fe *f,const fe *g){
  const uint64_t *a=f->v,*b=g->v;
  uint64_t b1=b[1]*19,b2=b[2]*19,b3=b[3]*19,b4=b[4]*19;
  u128 t0=(u128)a[0]*b[0]+(u128)a[1]*b4+(u128)a[2]*b3+(u128)a[3]*b2+(u128)a[4]*b1;
  u128 t1=(u128)a[0]*b[1]+(u128)a[1]*b[0]+(u128)a[2]*b4+(u128)a[3]*b3+(u128)a[4]*b2;
  u128 t2=(u128)a[0]*b[2]+(u128)a[1]*b[1]+(u128)a[2]*b[0]+(u128)a[3]*b4+(u128)a[4]*b3;
  u128 t3=(u128)a[0]*b[3]+(u128)a[1]*b[2]+(u128)a[2]*b[1]+(u128)a[3]*b[0]+(u128)a[4]*b4;
  u128 t4=(u128)a[0]*b[4]+(u128)a[1]*b[3]+(u128)a[2]*b[2]+(u128)a[3]*b[1]+(u128)a[4]*b[0];
  uint64_t r0,r1,r2,r3,r4,c;
  r0=(uint64_t)t0&MASK51; c=(uint64_t)(t0>>51); t1+=c;
  r1=(uint64_t)t1&MASK51; c=(uint64_t)(t1>>51); t2+=c;
  r2=(uint64_t)t2&MASK51; c=(uint64_t)(t2>>51); t3+=c;
  r3=(uint64_t)t3&MASK51; c=(uint64_t)(t3>>51); t4+=c;
  r4=(uint64_t)t4&MASK51; c=(uint64_t)(t4>>51);
  r0+=c*19; c=r0>>51; r0&=MASK51; r1+=c;
  h->v[0]=r0;h->v[1]=r1;h->v[2]=r2;h->v[3]=r3;h->v[4]=r4;
}
/* canonical form in [0,p) */
static inline void fe_freeze(fe *h){
  fe_carry(h); fe_carry(h);
  uint64_t q=(h->v[0]+19)>>51; q=(h->v[1]+q)>>51; q=(h->v[2]+q)>>51; q=(h->v[3]+q)>>51; q=(h->v[4]+q)>>51;
  h->v[0]+=19*q;
  uint64_t c;
  c=h->v[0]>>51; h->v[0]&=MASK51; h->v[1]+=c;
  c=h->v[1]>>51; h->v[1]&=MASK51; h->v[2]+=c;
  c=h->v[2]>>51; h->v[2]&=MASK51; h->v[3]+=c;
  c=h->v[3]>>51; h->v[3]&=MASK51; h->v[4]+=c;
  h->v[4]&=MASK51;
}
static inline int fe_eq(const fe *f,const fe *g){
  fe a=*f,b=*g; fe_freeze(&a); fe_freeze(&b);
  uint64_t d=0; for(int i=0;i<5;i++) d|=a.v[i]^b.v[i]; return d==0;
}
/* little-endian 32 bytes -> fe (top bit ignored) */
static inline void fe_frombytes(fe *h,const uint8_t s[32]){
  uint64_t w[4]; memcpy(w,s,32);
  h->v[0]=w[0]&MASK51;
  h->v[1]=((w[0]>>51)|(w[1]<<13))&MASK51;
  h->v[2]=((w[1]>>38)|(w[2]<<26))&MASK51;
  h->v[3]=((w[2]>>25)|(w[3]<<39))&MASK51;
  h->v[4]=(w[3]>>12)&MASK51;
}
static inline void fe_tobytes(uint8_t s[32],const fe *f){
  fe h=*f; fe_freeze(&h); uint64_t w[4];
  w[0]=h.v[0]|(h.v[1]<<51); w[1]=(h.v[1]>>13)|(h.v[2]<<38);
  w[2]=(h.v[2]>>26)|(h.v[3]<<25); w[3]=(h.v[3]>>39)|(h.v[4]<<12);
  memcpy(s,w,32);
}
#endif
