/* SILMARILS-MV threshold notarization (TN): per-member share, optimistic combine, certificate verification
   and robust fallback decoding (Gao's algorithm on one random combination of the coordinates, then erasure
   interpolation), over F_{2^255-19}. Committee n = 3t+1, member points y_j = j. */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rand.h>
#include "fe25519.h"

static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+1e-9*t.tv_nsec; }
static void fe_rand(fe *h){ uint8_t b[32]; RAND_bytes(b,32); b[31]&=0x7f; fe_frombytes(h,b); }
static void fe_set(fe *h,uint64_t x){ fe_0(h); h->v[0]=x; }
static void fadd(fe *h,const fe *f,const fe *g){ fe_add(h,f,g); fe_carry(h); }
static void fsub(fe *h,const fe *f,const fe *g){ fe a=*f,b=*g; fe_carry(&a); fe_carry(&b); fe_sub(h,&a,&b); fe_carry(h); }
static int fzero(const fe *f){ fe z; fe_0(&z); return fe_eq(f,&z); }
static void fsq(fe *h,const fe *f){ fe_mul(h,f,f); }
static void finv(fe *out,const fe *z){ /* z^(p-2), p-2 = 2^255-21 */
  fe r; fe_set(&r,1); fe b=*z;
  /* exponent bits: 2^255-21 = 0x7fff...ffeb */
  uint8_t e[32]; for(int i=0;i<32;i++) e[i]=0xff; e[0]=0xeb; e[31]=0x7f;
  for(int i=254;i>=0;i--){ fsq(&r,&r); if((e[i>>3]>>(i&7))&1) fe_mul(&r,&r,&b); }
  *out=r;
}
static void powers(fe *e,int psi,const fe *m){
  fe_set(&e[0],1); if(psi>=1) e[1]=*m;
  for(int k=2;k<=psi;k++){ int j=k>>1; if(k&1) fe_mul(&e[k],&e[j],&e[j+1]); else fe_mul(&e[k],&e[j],&e[j]); }
}
static void dotp(fe *out,const fe *x,const fe *y,int len){
  fe acc; fe_0(&acc);
  for(int i=0;i<len;i++){ fe t; fe_mul(&t,&x[i],&y[i]); fe_add(&acc,&acc,&t); if((i&7)==7) fe_carry(&acc);} fe_carry(&acc); *out=acc;
}
/* Lagrange coefficients at 0 for points xs[0..k-1]: L_i = prod_{j!=i} x_j/(x_j-x_i); batch inversion */
static void lag0(fe *L,const fe *xs,int k,fe *tmp){
  fe num; fe_set(&num,1); for(int j=0;j<k;j++) fe_mul(&num,&num,&xs[j]);
  for(int i=0;i<k;i++){ fe d; fe_set(&d,1); for(int j=0;j<k;j++) if(j!=i){ fe df; fsub(&df,&xs[j],&xs[i]); fe_mul(&d,&d,&df);} fe_mul(&tmp[i],&d,&xs[i]); }
  /* L_i = num / (x_i * prod (x_j-x_i)) ; batch invert tmp */
  fe *pre=malloc(sizeof(fe)*(k+1)); fe_set(&pre[0],1); for(int i=0;i<k;i++) fe_mul(&pre[i+1],&pre[i],&tmp[i]);
  fe iv; finv(&iv,&pre[k]);
  for(int i=k-1;i>=0;i--){ fe ti; fe_mul(&ti,&iv,&pre[i]); fe_mul(&iv,&iv,&tmp[i]); fe_mul(&L[i],&ti,&num); }
  free(pre);
}
/* polynomial helpers, coefficients low->high */
static int pdeg(const fe *a,int len){ for(int i=len-1;i>=0;i--) if(!fzero(&a[i])) return i; return -1; }
/* Gao decoding: points (xs[i], ys[i]), i<r, message length k (degree < k). Returns 1 and f (k coeffs) on success. */
static int gao(fe *f,const fe *xs,const fe *ys,int r,int k){
  fe *g0=calloc(r+1,sizeof(fe)), *g1=calloc(r+1,sizeof(fe)), *q=calloc(r+1,sizeof(fe)), *w=calloc(r,sizeof(fe)), *tmp=calloc(r+1,sizeof(fe));
  fe_set(&g0[0],1); int d0=0;
  for(int i=0;i<r;i++){ /* g0 *= (x - xs[i]) */
    for(int j=d0+1;j>=1;j--){ fe t; fe_mul(&t,&g0[j],&xs[i]); fsub(&g0[j],&g0[j-1],&t); }
    { fe t; fe_mul(&t,&g0[0],&xs[i]); fe z; fe_0(&z); fsub(&g0[0],&z,&t); }
    d0++;
  }
  /* weights w_i = 1/prod_{j!=i}(x_i-x_j) (batch inversion) */
  for(int i=0;i<r;i++){ fe d; fe_set(&d,1); for(int j=0;j<r;j++) if(j!=i){ fe df; fsub(&df,&xs[i],&xs[j]); fe_mul(&d,&d,&df);} w[i]=d; }
  { fe *pre=malloc(sizeof(fe)*(r+1)); fe_set(&pre[0],1); for(int i=0;i<r;i++) fe_mul(&pre[i+1],&pre[i],&w[i]);
    fe iv; finv(&iv,&pre[r]); for(int i=r-1;i>=0;i--){ fe ti; fe_mul(&ti,&iv,&pre[i]); fe_mul(&iv,&iv,&w[i]); w[i]=ti; } free(pre); }
  /* g1 = sum_i ys_i w_i g0(x)/(x-xs_i) (synthetic division) */
  for(int i=0;i<r;i++){ fe c; fe_mul(&c,&ys[i],&w[i]); fe acc=g0[r];
    for(int j=r-1;j>=0;j--){ fe t; fe_mul(&t,&acc,&c); fadd(&g1[j],&g1[j],&t); fe u; fe_mul(&u,&acc,&xs[i]); fadd(&acc,&g0[j],&u); } }
  /* partial extended Euclid on (g0, g1): stop when deg(remainder) < (r+k)/2 */
  fe *a=g0,*b=g1, *va=calloc(r+2,sizeof(fe)), *vb=calloc(r+2,sizeof(fe)); fe_set(&vb[0],1);
  int da=r, db=pdeg(b,r+1);
  int ok=0;
  while(2*db>=r+k){
    /* a = a - qq*b, va = va - qq*vb, with full division */
    fe ib; finv(&ib,&b[db]);
    for(int i=0;i<=r;i++) fe_0(&q[i]);
    while(da>=db && da>=0){ fe c; fe_mul(&c,&a[da],&ib); int s=da-db; q[s]=c;
      for(int j=0;j<=db;j++){ fe t; fe_mul(&t,&c,&b[j]); fsub(&a[j+s],&a[j+s],&t); } da=pdeg(a,da+1); }
    /* va -= q*vb */
    int dvb=pdeg(vb,r+2);
    for(int s=0;s<=r;s++) if(!fzero(&q[s])) for(int j=0;j<=dvb && j+s<r+2;j++){ fe t; fe_mul(&t,&q[s],&vb[j]); fsub(&va[j+s],&va[j+s],&t); }
    fe *x=a; a=b; b=x; int dx=da; da=db; db=dx; x=va; va=vb; vb=x;
  }
  /* now b = remainder (deg < stop), vb its cofactor: f = b / vb */
  int dv=pdeg(vb,r+2);
  if(dv>=0){
    fe iv; finv(&iv,&vb[dv]); int dbb=db; for(int i=0;i<k;i++) fe_0(&f[i]);
    int okdiv=1;
    while(dbb>=dv){ fe c; fe_mul(&c,&b[dbb],&iv); int s=dbb-dv; if(s>=k){ okdiv=0; break; } f[s]=c;
      for(int j=0;j<=dv;j++){ fe t; fe_mul(&t,&c,&vb[j]); fsub(&b[j+s],&b[j+s],&t);} dbb=pdeg(b,dbb+1); }
    ok = okdiv && dbb<0;
  }
  free(g0);free(g1);free(q);free(w);free(tmp);free(va);free(vb);
  return ok;
}
static void peval(fe *out,const fe *f,int k,const fe *x){ fe acc; fe_0(&acc); for(int i=k-1;i>=0;i--){ fe_mul(&acc,&acc,x); fadd(&acc,&acc,&f[i]); } *out=acc; }

int main(void){
  int ns[]={4,7,10,31,100,301,1000}; int ws[]={16,32}; int psi=64;
  for(unsigned wi=0;wi<2;wi++) for(unsigned ni=0;ni<sizeof ns/sizeof*ns;ni++){
    int n=ns[ni], t=(n-1)/3, w=ws[wi], W=w+1;
    /* committee sharing of A (degree t, coefficient matrices R_0=A, R_1..R_t) */
    fe *Rm=malloc(sizeof(fe)*(t+1)*W*(psi+1)); for(long i=0;i<(long)(t+1)*W*(psi+1);i++) fe_rand(&Rm[i]);
    fe *xs=malloc(sizeof(fe)*n); for(int j=0;j<n;j++) fe_set(&xs[j],j+1);
    fe m; fe_rand(&m); fe *e=malloc(sizeof(fe)*(psi+2)); powers(e,psi,&m);
    /* member shares A^{(j)} = sum_l R_l y_j^l, then share of alpha = A^{(j)} e(m) */
    fe *sh=malloc(sizeof(fe)*n*W), *Aj=malloc(sizeof(fe)*W*(psi+1));
    for(int j=0;j<n;j++){
      fe yp; fe_set(&yp,1);
      for(int i=0;i<W*(psi+1);i++) fe_0(&Aj[i]);
      for(int l=0;l<=t;l++){ for(int i=0;i<W*(psi+1);i++){ fe tt; fe_mul(&tt,&Rm[(long)l*W*(psi+1)+i],&yp); fadd(&Aj[i],&Aj[i],&tt);} fe_mul(&yp,&yp,&xs[j]); }
      for(int i=0;i<W;i++) dotp(&sh[j*W+i],Aj+(long)i*(psi+1),e,psi+1);
    }
    /* time: one member's share computation (A^{(j)} is stored; cost = (w+1)(psi+1) mults) */
    int R1=20000; double t0=now(); fe al[64]; volatile uint64_t sink=0;
    for(int r=0;r<R1;r++){ m.v[0]^=r&1; powers(e,psi,&m); for(int i=0;i<W;i++) dotp(&al[i],Aj+(long)i*(psi+1),e,psi+1); sink+=al[r%W].v[0]; }
    double share_ns=(now()-t0)/R1*1e9; powers(e,psi,&m);
    for(int j=0;j<n;j++){ /* recompute shares for the original m */ }
    /* reference alpha = A e(m) = R_0 e(m) */
    fe *alpha=malloc(sizeof(fe)*W); fe_rand(&m); powers(e,psi,&m);
    for(int j=0;j<n;j++){ fe yp; fe_set(&yp,1); for(int i=0;i<W*(psi+1);i++) fe_0(&Aj[i]);
      for(int l=0;l<=t;l++){ for(int i=0;i<W*(psi+1);i++){ fe tt; fe_mul(&tt,&Rm[(long)l*W*(psi+1)+i],&yp); fadd(&Aj[i],&Aj[i],&tt);} fe_mul(&yp,&yp,&xs[j]); }
      for(int i=0;i<W;i++) dotp(&sh[j*W+i],Aj+(long)i*(psi+1),e,psi+1); }
    for(int i=0;i<W;i++) dotp(&alpha[i],Rm+(long)i*(psi+1),e,psi+1);
    /* verifier key: c random, b = A^T c */
    fe *c=malloc(sizeof(fe)*W), *b=malloc(sizeof(fe)*(psi+1)); for(int i=0;i<W;i++) fe_rand(&c[i]);
    for(int jj=0;jj<=psi;jj++){ fe acc; fe_0(&acc); for(int i=0;i<W;i++){ fe tt; fe_mul(&tt,&c[i],&Rm[(long)i*(psi+1)+jj]); fadd(&acc,&acc,&tt);} b[jj]=acc; }
    /* optimistic combine: Lagrange on t+1 shares (coefficients recomputed each time), then verify */
    fe *L=malloc(sizeof(fe)*(t+1)), *tmp=malloc(sizeof(fe)*(t+1)), *pt=malloc(sizeof(fe)*(t+1)); int base=n-(t+1);
    for(int i=0;i<=t;i++) pt[i]=xs[base+i];
    int R2 = n<=31?2000:(n<=301?100:20); fe cand[64]; int okc=1; t0=now();
    for(int r=0;r<R2;r++){
      lag0(L,pt,t+1,tmp);
      for(int i=0;i<W;i++){ fe acc; fe_0(&acc); for(int j=0;j<=t;j++){ fe tt; fe_mul(&tt,&L[j],&sh[(base+j)*W+i]); fe_add(&acc,&acc,&tt); if((j&7)==7) fe_carry(&acc);} fe_carry(&acc); cand[i]=acc; }
      fe lhs,rhs; dotp(&lhs,c,cand,W); dotp(&rhs,b,e,psi+1); okc&=fe_eq(&lhs,&rhs);
    }
    double comb_ns=(now()-t0)/R2*1e9;
    for(int i=0;i<W;i++) okc&=fe_eq(&cand[i],&alpha[i]);
    /* verification of a certificate */
    int R3=20000; t0=now(); volatile int acc3=0;
    for(int r=0;r<R3;r++){ fe lhs,rhs; dotp(&lhs,c,alpha,W); powers(e,psi,&m); dotp(&rhs,b,e,psi+1); acc3+=fe_eq(&lhs,&rhs); }
    double ver_ns=(now()-t0)/R3*1e9;
    /* fallback: t members send garbage; random combination rho, Gao decode, locate errors, interpolate */
    fe *bad=malloc(sizeof(fe)*n*W); for(int i=0;i<n*W;i++) bad[i]=sh[i];
    for(int j=0;j<t;j++) for(int i=0;i<W;i++) fe_rand(&bad[(j*3%n)*W+i]); /* corrupt t distinct members (j*3 mod n distinct for n=3t+1) */
    fe *rho=malloc(sizeof(fe)*W); for(int i=0;i<W;i++) fe_rand(&rho[i]);
    fe *ys=malloc(sizeof(fe)*n), *f=malloc(sizeof(fe)*(t+1)); int R4 = n<=31?200:(n<=301?10:6); int okf=1;
    t0=now();
    for(int r=0;r<R4;r++){
      for(int j=0;j<n;j++) dotp(&ys[j],rho,&bad[j*W],W);
      int g=gao(f,xs,ys,n,t+1); okf&=g;
      /* error location and erasure interpolation from the first t+1 consistent members */
      int sel[2048], ns2=0; for(int j=0;j<n && ns2<=t;j++){ fe v; peval(&v,f,t+1,&xs[j]); if(fe_eq(&v,&ys[j])) sel[ns2++]=j; }
      for(int i=0;i<=t;i++) pt[i]=xs[sel[i]];
      lag0(L,pt,t+1,tmp);
      for(int i=0;i<W;i++){ fe acc; fe_0(&acc); for(int j=0;j<=t;j++){ fe tt; fe_mul(&tt,&L[j],&bad[sel[j]*W+i]); fe_add(&acc,&acc,&tt); if((j&7)==7) fe_carry(&acc);} fe_carry(&acc); cand[i]=acc; }
    }
    double fb_ns=(now()-t0)/R4*1e9;
    for(int i=0;i<W;i++) okf&=fe_eq(&cand[i],&alpha[i]);
    printf("{\"n\":%d,\"t\":%d,\"omega\":%d,\"psi\":%d,\"share_ns\":%.0f,\"combine_opt_ns\":%.0f,\"cert_verify_ns\":%.0f,\"fallback_ns\":%.0f,\"cert_bytes\":%d,\"ok_opt\":%d,\"ok_fallback\":%d}\n",
      n,t,w,psi,share_ns,comb_ns,ver_ns,fb_ns,32*W,okc,okf);
    fflush(stdout);
    free(Rm);free(xs);free(e);free(sh);free(Aj);free(alpha);free(c);free(b);free(L);free(tmp);free(pt);free(bad);free(rho);free(ys);free(f);
  }
  return 0;
}
