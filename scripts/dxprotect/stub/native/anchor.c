#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "generated_key.h"

__attribute__((used,section(".dxaseal"))) static const uint8_t DXA_SELF_SEAL[48]={DXP_ANCHOR_SELF_MARKER_BYTES};
__attribute__((used,section(".dxapeer"))) static const uint8_t DXA_PEER_SEAL[48]={DXP_ANCHOR_PEER_MARKER_BYTES};
static const uint8_t DXE_SELF_MARKER[16]={DXP_ENGINE_SELF_MARKER_BYTES};
static const uint8_t DXE_PEER_MARKER[16]={DXP_ENGINE_PEER_MARKER_BYTES};
static void reveal(char*out,const volatile uint8_t*in,size_t n,uint8_t mask){size_t i;for(i=0;i<n;i++)out[i]=(char)(in[i]^mask);out[n]=0;}
static int contains_bytes(const char*b,size_t n,const char*q,size_t m){size_t i;if(!m||m>n)return 0;for(i=0;i+m<=n;i++)if(!memcmp(b+i,q,m))return 1;return 0;}
static int runtime_clean(void){
    if(DXP_RUNTIME_GUARD==0)return 1;
    char path[DXP_RT_STATUS_PATH_LEN+1],key[DXP_RT_TRACER_KEY_LEN+1],status[4096];ssize_t n;int fd;
    reveal(path,DXP_RT_STATUS_PATH_X,DXP_RT_STATUS_PATH_LEN,DXP_RT_STATUS_PATH_MASK);reveal(key,DXP_RT_TRACER_KEY_X,DXP_RT_TRACER_KEY_LEN,DXP_RT_TRACER_KEY_MASK);
    fd=open(path,O_RDONLY|O_CLOEXEC);memset(path,0,sizeof(path));if(fd<0)return 0;n=read(fd,status,sizeof(status));close(fd);if(n<=0)return 0;
    char*p=0;size_t i;for(i=0;i+DXP_RT_TRACER_KEY_LEN<=(size_t)n;i++)if(!memcmp(status+i,key,DXP_RT_TRACER_KEY_LEN)){p=status+i+DXP_RT_TRACER_KEY_LEN;break;}memset(key,0,sizeof(key));if(!p)return 0;while(p<status+n&&(*p==' '||*p=='\t'))p++;if(p>=status+n||(*p>='1'&&*p<='9'))return 0;
    if(DXP_RUNTIME_GUARD<2)return 1;
    char maps_path[DXP_RT_MAPS_PATH_LEN+1];reveal(maps_path,DXP_RT_MAPS_PATH_X,DXP_RT_MAPS_PATH_LEN,DXP_RT_MAPS_PATH_MASK);fd=open(maps_path,O_RDONLY|O_CLOEXEC);memset(maps_path,0,sizeof(maps_path));if(fd<0)return 0;
    size_t cap=1048576,used=0;char*maps=malloc(cap);if(!maps){close(fd);return 0;}while(used<cap&&(n=read(fd,maps+used,cap-used))>0)used+=(size_t)n;close(fd);if(used==cap){free(maps);return 0;}
    const volatile uint8_t*xs[5]={DXP_RT_MARKER_1_X,DXP_RT_MARKER_2_X,DXP_RT_MARKER_3_X,DXP_RT_MARKER_4_X,DXP_RT_MARKER_5_X};const size_t ls[5]={DXP_RT_MARKER_1_LEN,DXP_RT_MARKER_2_LEN,DXP_RT_MARKER_3_LEN,DXP_RT_MARKER_4_LEN,DXP_RT_MARKER_5_LEN};const uint8_t ms[5]={DXP_RT_MARKER_1_MASK,DXP_RT_MARKER_2_MASK,DXP_RT_MARKER_3_MASK,DXP_RT_MARKER_4_MASK,DXP_RT_MARKER_5_MASK};
    int clean=1;for(i=0;i<5;i++){char marker[32];reveal(marker,xs[i],ls[i],ms[i]);if(contains_bytes(maps,used,marker,ls[i]))clean=0;memset(marker,0,sizeof(marker));if(!clean)break;}memset(maps,0,used);free(maps);return clean;
}

typedef struct{uint8_t data[64];uint32_t len;uint64_t bits;uint32_t state[8];}sha256_ctx;
static const uint32_t K[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define R(x,n)(((x)>>(n))|((x)<<(32-(n))))
static void tr(sha256_ctx*c,const uint8_t*d){uint32_t w[64],a,b,x,d0,e,f,g,h,t1,t2;int i;for(i=0;i<16;i++)w[i]=((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];for(i=16;i<64;i++){uint32_t s0=R(w[i-15],7)^R(w[i-15],18)^(w[i-15]>>3),s1=R(w[i-2],17)^R(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}a=c->state[0];b=c->state[1];x=c->state[2];d0=c->state[3];e=c->state[4];f=c->state[5];g=c->state[6];h=c->state[7];for(i=0;i<64;i++){uint32_t s1=R(e,6)^R(e,11)^R(e,25),ch=(e&f)^(~e&g),s0=R(a,2)^R(a,13)^R(a,22),maj=(a&b)^(a&x)^(b&x);t1=h+s1+ch+K[i]+w[i];t2=s0+maj;h=g;g=f;f=e;e=d0+t1;d0=x;x=b;b=a;a=t1+t2;}c->state[0]+=a;c->state[1]+=b;c->state[2]+=x;c->state[3]+=d0;c->state[4]+=e;c->state[5]+=f;c->state[6]+=g;c->state[7]+=h;}
static void si(sha256_ctx*c){c->len=0;c->bits=0;c->state[0]=0x6a09e667;c->state[1]=0xbb67ae85;c->state[2]=0x3c6ef372;c->state[3]=0xa54ff53a;c->state[4]=0x510e527f;c->state[5]=0x9b05688c;c->state[6]=0x1f83d9ab;c->state[7]=0x5be0cd19;}
static void su(sha256_ctx*c,const uint8_t*d,size_t n){size_t i;for(i=0;i<n;i++){c->data[c->len++]=d[i];if(c->len==64){tr(c,c->data);c->bits+=512;c->len=0;}}}
static void sf(sha256_ctx*c,uint8_t o[32]){uint32_t i=c->len;int j;c->data[i++]=0x80;if(i>56){while(i<64)c->data[i++]=0;tr(c,c->data);i=0;}while(i<56)c->data[i++]=0;c->bits+=(uint64_t)c->len*8;for(j=7;j>=0;j--)c->data[56+7-j]=(uint8_t)(c->bits>>(j*8));tr(c,c->data);for(i=0;i<4;i++)for(j=0;j<8;j++)o[i+4*j]=(uint8_t)(c->state[j]>>(24-i*8));}
static int eq(const uint8_t*a,const uint8_t*b){uint8_t x=0;int i;for(i=0;i<32;i++)x|=a[i]^b[i];return x==0;}
static int ra(int fd,uint64_t o,void*v,size_t n){uint8_t*p=v;size_t d=0;while(d<n){ssize_t r=pread(fd,p+d,n-d,(off_t)(o+d));if(r<=0)return 0;d+=(size_t)r;}return 1;}
static int hash_sealed(const char*path,const uint8_t*m1,const uint8_t*m2,uint8_t out[32]){int fd=-1,ok=0;struct stat st;uint8_t*b=0;size_t i,p1=(size_t)-1,p2=(size_t)-1;sha256_ctx c;if(!path||(fd=open(path,O_RDONLY|O_CLOEXEC))<0||fstat(fd,&st)||st.st_size<96||st.st_size>67108864)goto done;b=malloc((size_t)st.st_size);if(!b||!ra(fd,0,b,(size_t)st.st_size))goto done;for(i=0;i+48<=(size_t)st.st_size;i++){if(!memcmp(b+i,m1,16)){if(p1!=(size_t)-1)goto done;p1=i;}if(!memcmp(b+i,m2,16)){if(p2!=(size_t)-1)goto done;p2=i;}}if(p1==(size_t)-1||p2==(size_t)-1)goto done;memset(b+p1+16,0,32);memset(b+p2+16,0,32);si(&c);su(&c,b,(size_t)st.st_size);sf(&c,out);ok=1;done:if(b){memset(b,0,(size_t)st.st_size);free(b);}if(fd>=0)close(fd);return ok;}
static void hm(const uint8_t*d,size_t n,uint8_t o[32]){uint8_t ip[64],op[64],in[32];int i;sha256_ctx c;for(i=0;i<64;i++){uint8_t k=i<32?DXP_ANCHOR_KEY[i]:0;ip[i]=k^0x36;op[i]=k^0x5c;}si(&c);su(&c,ip,64);su(&c,d,n);sf(&c,in);si(&c);su(&c,op,64);su(&c,in,32);sf(&c,o);memset(in,0,32);}

static jbyteArray native_attest(JNIEnv*e,jclass t,jbyteArray signer,jstring engine,jstring anchor){(void)t;if(!signer||!engine||!anchor||(*e)->GetArrayLength(e,signer)!=32)return 0;uint8_t s[32],ed[32],ad[32],msg[52],tag[32];(*e)->GetByteArrayRegion(e,signer,0,32,(jbyte*)s);if(!eq(s,DXP_CERT_SHA256))return 0;const char*ep=(*e)->GetStringUTFChars(e,engine,0),*ap=(*e)->GetStringUTFChars(e,anchor,0);int ok=ep&&ap&&hash_sealed(ep,DXE_SELF_MARKER,DXE_PEER_MARKER,ed)&&eq(ed,DXA_PEER_SEAL+16)&&hash_sealed(ap,DXA_SELF_SEAL,DXA_PEER_SEAL,ad)&&eq(ad,DXA_SELF_SEAL+16);if(ep)(*e)->ReleaseStringUTFChars(e,engine,ep);if(ap)(*e)->ReleaseStringUTFChars(e,anchor,ap);if(!ok)return 0;int fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC);if(fd<0||read(fd,msg+32,16)!=16){if(fd>=0)close(fd);return 0;}close(fd);memcpy(msg,s,32);uint32_t pid=(uint32_t)getpid();msg[48]=pid>>24;msg[49]=pid>>16;msg[50]=pid>>8;msg[51]=pid;hm(msg,52,tag);jbyteArray out=(*e)->NewByteArray(e,48);uint8_t cap[48];memcpy(cap,msg+32,16);memcpy(cap+16,tag,32);(*e)->SetByteArrayRegion(e,out,0,48,(jbyte*)cap);memset(cap,0,48);memset(msg,0,52);return out;}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*vm,void*reserved){
    (void)reserved;if(!runtime_clean())return JNI_ERR;JNIEnv*e=0;if((*vm)->GetEnv(vm,(void**)&e,JNI_VERSION_1_6)!=JNI_OK)return JNI_ERR;
    char cls[DXP_ANCHOR_CLASS_LEN+1],name[DXP_ATTEST_NAME_LEN+1],sig[DXP_ATTEST_SIG_LEN+1];
    reveal(cls,DXP_ANCHOR_CLASS_X,DXP_ANCHOR_CLASS_LEN,DXP_ANCHOR_CLASS_MASK);
    reveal(name,DXP_ATTEST_NAME_X,DXP_ATTEST_NAME_LEN,DXP_ATTEST_NAME_MASK);
    reveal(sig,DXP_ATTEST_SIG_X,DXP_ATTEST_SIG_LEN,DXP_ATTEST_SIG_MASK);
    jclass c=(*e)->FindClass(e,cls);if(!c)return JNI_ERR;
    JNINativeMethod m={name,sig,(void*)native_attest};int ok=(*e)->RegisterNatives(e,c,&m,1)==0;
    memset(cls,0,sizeof(cls));memset(name,0,sizeof(name));memset(sig,0,sizeof(sig));
    return ok?JNI_VERSION_1_6:JNI_ERR;
}
