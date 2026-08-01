#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>
#include "generated_key.h"

__attribute__((used,section(".dxpseal"))) static const uint8_t DXP_SELF_SEAL[48]={DXP_ENGINE_SELF_MARKER_BYTES};
__attribute__((used,section(".dxppeer"))) static const uint8_t DXP_PEER_SEAL[48]={DXP_ENGINE_PEER_MARKER_BYTES};
static const uint8_t DXA_SELF_MARKER[16]={DXP_ANCHOR_SELF_MARKER_BYTES};
static const uint8_t DXA_PEER_MARKER[16]={DXP_ANCHOR_PEER_MARKER_BYTES};
static void reveal(char*out,const volatile uint8_t*in,size_t n,uint8_t mask){size_t i;for(i=0;i<n;i++)out[i]=(char)(in[i]^mask);out[n]=0;}
static int contains_bytes(const char*b,size_t n,const char*q,size_t m){size_t i;if(!m||m>n)return 0;for(i=0;i+m<=n;i++)if(!memcmp(b+i,q,m))return 1;return 0;}
static int runtime_clean(void){
    if(DXP_RUNTIME_GUARD==0)return 1;
    char path[DXP_RT_STATUS_PATH_LEN+1],key[DXP_RT_TRACER_KEY_LEN+1],status[4096];ssize_t n;int fd;
    reveal(path,DXP_RT_STATUS_PATH_X,DXP_RT_STATUS_PATH_LEN,DXP_RT_STATUS_PATH_MASK);
    reveal(key,DXP_RT_TRACER_KEY_X,DXP_RT_TRACER_KEY_LEN,DXP_RT_TRACER_KEY_MASK);
    fd=open(path,O_RDONLY|O_CLOEXEC);memset(path,0,sizeof(path));if(fd<0)return 0;n=read(fd,status,sizeof(status));close(fd);if(n<=0)return 0;
    char*p=0;size_t i;for(i=0;i+DXP_RT_TRACER_KEY_LEN<=(size_t)n;i++)if(!memcmp(status+i,key,DXP_RT_TRACER_KEY_LEN)){p=status+i+DXP_RT_TRACER_KEY_LEN;break;}
    memset(key,0,sizeof(key));if(!p)return 0;while(p<status+n&&(*p==' '||*p=='\t'))p++;if(p>=status+n||(*p>='1'&&*p<='9'))return 0;
    if(DXP_RUNTIME_GUARD<2)return 1;
    char maps_path[DXP_RT_MAPS_PATH_LEN+1];reveal(maps_path,DXP_RT_MAPS_PATH_X,DXP_RT_MAPS_PATH_LEN,DXP_RT_MAPS_PATH_MASK);
    fd=open(maps_path,O_RDONLY|O_CLOEXEC);memset(maps_path,0,sizeof(maps_path));if(fd<0)return 0;
    size_t cap=1048576,used=0;char*maps=(char*)malloc(cap);if(!maps){close(fd);return 0;}while(used<cap&&(n=read(fd,maps+used,cap-used))>0)used+=(size_t)n;close(fd);if(used==cap){free(maps);return 0;}
    const volatile uint8_t*xs[5]={DXP_RT_MARKER_1_X,DXP_RT_MARKER_2_X,DXP_RT_MARKER_3_X,DXP_RT_MARKER_4_X,DXP_RT_MARKER_5_X};
    const size_t ls[5]={DXP_RT_MARKER_1_LEN,DXP_RT_MARKER_2_LEN,DXP_RT_MARKER_3_LEN,DXP_RT_MARKER_4_LEN,DXP_RT_MARKER_5_LEN};
    const uint8_t ms[5]={DXP_RT_MARKER_1_MASK,DXP_RT_MARKER_2_MASK,DXP_RT_MARKER_3_MASK,DXP_RT_MARKER_4_MASK,DXP_RT_MARKER_5_MASK};
    int clean=1;for(i=0;i<5;i++){char marker[32];reveal(marker,xs[i],ls[i],ms[i]);if(contains_bytes(maps,used,marker,ls[i]))clean=0;memset(marker,0,sizeof(marker));if(!clean)break;}memset(maps,0,used);free(maps);return clean;
}

typedef struct { uint8_t data[64]; uint32_t len; uint64_t bits; uint32_t state[8]; } sha256_ctx;
static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define R(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define C(x,y,z) (((x)&(y))^(~(x)&(z)))
#define M(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
static void transform(sha256_ctx*c,const uint8_t*d){uint32_t w[64],a,b,x,e,f,g,h,t1,t2;int i;for(i=0;i<16;i++)w[i]=((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];for(i=16;i<64;i++){uint32_t s0=R(w[i-15],7)^R(w[i-15],18)^(w[i-15]>>3),s1=R(w[i-2],17)^R(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}a=c->state[0];b=c->state[1];x=c->state[2];uint32_t d0=c->state[3];e=c->state[4];f=c->state[5];g=c->state[6];h=c->state[7];for(i=0;i<64;i++){uint32_t s1=R(e,6)^R(e,11)^R(e,25);t1=h+s1+C(e,f,g)+K[i]+w[i];uint32_t s0=R(a,2)^R(a,13)^R(a,22);t2=s0+M(a,b,x);h=g;g=f;f=e;e=d0+t1;d0=x;x=b;b=a;a=t1+t2;}c->state[0]+=a;c->state[1]+=b;c->state[2]+=x;c->state[3]+=d0;c->state[4]+=e;c->state[5]+=f;c->state[6]+=g;c->state[7]+=h;}
static void init(sha256_ctx*c){c->len=0;c->bits=0;c->state[0]=0x6a09e667;c->state[1]=0xbb67ae85;c->state[2]=0x3c6ef372;c->state[3]=0xa54ff53a;c->state[4]=0x510e527f;c->state[5]=0x9b05688c;c->state[6]=0x1f83d9ab;c->state[7]=0x5be0cd19;}
static void update(sha256_ctx*c,const uint8_t*d,size_t n){size_t i;for(i=0;i<n;i++){c->data[c->len++]=d[i];if(c->len==64){transform(c,c->data);c->bits+=512;c->len=0;}}}
static void final(sha256_ctx*c,uint8_t out[32]){uint32_t i=c->len;int j;c->data[i++]=0x80;if(i>56){while(i<64)c->data[i++]=0;transform(c,c->data);i=0;}while(i<56)c->data[i++]=0;c->bits+=(uint64_t)c->len*8;for(j=7;j>=0;j--)c->data[56+7-j]=(uint8_t)(c->bits>>(j*8));transform(c,c->data);for(i=0;i<4;i++)for(j=0;j<8;j++)out[i+4*j]=(uint8_t)(c->state[j]>>(24-i*8));}
static void hmac_key(const uint8_t*key,const uint8_t*data,size_t n,uint8_t out[32]){uint8_t ip[64],op[64],inner[32];int i;for(i=0;i<64;i++){uint8_t k=i<32?key[i]:0;ip[i]=k^0x36;op[i]=k^0x5c;}sha256_ctx c;init(&c);update(&c,ip,64);update(&c,data,n);final(&c,inner);init(&c);update(&c,op,64);update(&c,inner,32);final(&c,out);memset(inner,0,32);}
static void hmac(const uint8_t*data,size_t n,uint8_t out[32]){hmac_key(DXP_KEY,data,n,out);}
static int equal32(const uint8_t*a,const uint8_t*b){uint8_t x=0;int i;for(i=0;i<32;i++)x|=a[i]^b[i];return x==0;}
static uint32_t be32(const uint8_t*p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static uint16_t le16(const uint8_t*p){return (uint16_t)p[0]|((uint16_t)p[1]<<8);}
static uint32_t le32(const uint8_t*p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static uint64_t le64(const uint8_t*p){uint64_t v=0;int i;for(i=7;i>=0;i--)v=(v<<8)|p[i];return v;}
static int read_at(int fd,uint64_t off,void*out,size_t n){uint8_t*p=(uint8_t*)out;size_t done=0;while(done<n){ssize_t r=pread(fd,p+done,n-done,(off_t)(off+done));if(r<=0)return 0;done+=(size_t)r;}return 1;}
static int lp(const uint8_t*b,size_t n,size_t*off,const uint8_t**out,size_t*len){uint32_t s;if(*off>n||n-*off<4)return 0;s=le32(b+*off);*off+=4;if((size_t)s>n-*off)return 0;*out=b+*off;*len=s;*off+=s;return 1;}
static int cert_from_signers(const uint8_t*b,size_t n,uint8_t out[32]){
    const uint8_t *outer,*signer,*signed_data,*ignored,*certs,*cert;size_t on,sn,sdn,in,cn,certn,o=0,s=0,d=0,c=0;sha256_ctx h;
    if(!lp(b,n,&o,&outer,&on)||o!=n||!lp(outer,on,&s,&signer,&sn)||!lp(signer,sn,&d,&signed_data,&sdn))return 0;
    d=0;if(!lp(signed_data,sdn,&d,&ignored,&in)||!lp(signed_data,sdn,&d,&certs,&cn)||!lp(certs,cn,&c,&cert,&certn))return 0;
    init(&h);update(&h,cert,certn);final(&h,out);return 1;
}
static int apk_cert_sha256(const char*path,uint8_t out[32]){
    static const uint8_t magic[16]={'A','P','K',' ','S','i','g',' ','B','l','o','c','k',' ','4','2'};
    int fd=-1,ok=0;struct stat st;uint8_t*tail=0,*block=0;size_t tailn,eocd,i,entries_end,off;uint64_t cd,bs,bo;const uint8_t*chosen=0;size_t chosen_n=0;
    if(!path||(fd=open(path,O_RDONLY|O_CLOEXEC))<0||fstat(fd,&st)||st.st_size<22)goto done;
    tailn=(size_t)(st.st_size<65557?st.st_size:65557);tail=(uint8_t*)malloc(tailn);if(!tail||!read_at(fd,(uint64_t)st.st_size-tailn,tail,tailn))goto done;
    eocd=(size_t)-1;for(i=tailn-22;;i--){if(le32(tail+i)==0x06054b50u&&i+22u+le16(tail+i+20)==tailn){eocd=i;break;}if(i==0)break;}if(eocd==(size_t)-1)goto done;
    cd=le32(tail+eocd+16);if(cd<24||(uint64_t)st.st_size<=cd)goto done;uint8_t footer[24];if(!read_at(fd,cd-24,footer,24)||memcmp(footer+8,magic,16))goto done;
    bs=le64(footer);if(bs<24||bs>cd-8||bs>16777216u)goto done;bo=cd-(bs+8);block=(uint8_t*)malloc((size_t)bs+8);if(!block||!read_at(fd,bo,block,(size_t)bs+8)||le64(block)!=bs)goto done;
    entries_end=(size_t)bs+8-24;off=8;while(off<entries_end){uint64_t len;uint32_t id;if(entries_end-off<12)goto done;len=le64(block+off);off+=8;if(len<4||len>entries_end-off)goto done;id=le32(block+off);if(id==0xf05368c0u||(id==0x7109871au&&!chosen)){chosen=block+off+4;chosen_n=(size_t)len-4;}off+=(size_t)len;}if(off!=entries_end||!chosen)goto done;
    ok=cert_from_signers(chosen,chosen_n,out);
done: if(block)free(block);if(tail)free(tail);if(fd>=0)close(fd);return ok;
}
static int apk_entry_sha256(const char*path,const char*wanted,size_t wanted_len,uint8_t out[32]){
    int fd=-1,ok=0;struct stat st;uint8_t*tail=0;size_t tailn,eocd,i;uint32_t cd,cd_size;uint16_t count;uint64_t off;
    if(!path||!wanted||!wanted_len||wanted_len>255||(fd=open(path,O_RDONLY|O_CLOEXEC))<0||fstat(fd,&st)||st.st_size<22)goto done;
    tailn=(size_t)(st.st_size<65557?st.st_size:65557);tail=malloc(tailn);if(!tail||!read_at(fd,(uint64_t)st.st_size-tailn,tail,tailn))goto done;
    eocd=(size_t)-1;for(i=tailn-22;;i--){if(le32(tail+i)==0x06054b50u&&i+22u+le16(tail+i+20)==tailn){eocd=i;break;}if(i==0)break;}if(eocd==(size_t)-1)goto done;
    count=le16(tail+eocd+10);cd_size=le32(tail+eocd+12);cd=le32(tail+eocd+16);if((uint64_t)cd+cd_size>(uint64_t)st.st_size)goto done;off=cd;
    for(i=0;i<count;i++){
        uint8_t h[46];if(!read_at(fd,off,h,sizeof(h))||le32(h)!=0x02014b50u)goto done;
        uint16_t method=le16(h+10),name_len=le16(h+28),extra_len=le16(h+30),comment_len=le16(h+32);uint32_t comp_size=le32(h+20),clear_size=le32(h+24),local=le32(h+42);
        if(name_len==wanted_len){char name[256];if(!read_at(fd,off+46,name,name_len))goto done;name[name_len]=0;if(!memcmp(name,wanted,name_len)){
            uint8_t lh[30];if(!read_at(fd,local,lh,sizeof(lh))||le32(lh)!=0x04034b50u||comp_size>33554432u||clear_size>33554432u)goto done;
            uint64_t data_off=(uint64_t)local+30u+le16(lh+26)+le16(lh+28);uint8_t*packed=malloc(comp_size?comp_size:1);uint8_t*clear=0;if(!packed||!read_at(fd,data_off,packed,comp_size)){if(packed)free(packed);goto done;}
            if(method==0&&comp_size==clear_size){sha256_ctx c;init(&c);update(&c,packed,comp_size);final(&c,out);ok=1;}
            else if(method==8){clear=malloc(clear_size?clear_size:1);if(clear){z_stream z;memset(&z,0,sizeof(z));z.next_in=packed;z.avail_in=comp_size;z.next_out=clear;z.avail_out=clear_size;if(inflateInit2(&z,-MAX_WBITS)==Z_OK){int zr=inflate(&z,Z_FINISH);if(zr==Z_STREAM_END&&z.total_out==clear_size){sha256_ctx c;init(&c);update(&c,clear,clear_size);final(&c,out);ok=1;}inflateEnd(&z);}}}
            if(clear){memset(clear,0,clear_size);free(clear);}memset(packed,0,comp_size);free(packed);goto done;
        }}
        off+=46u+name_len+extra_len+comment_len;if(off>(uint64_t)cd+cd_size)goto done;
    }
done:if(tail)free(tail);if(fd>=0)close(fd);return ok;
}
static int apk_stub_sha256(const char*path,uint8_t out[32]){
    char wanted[DXP_STUB_ENTRY_LEN+1];reveal(wanted,DXP_STUB_ENTRY_X,DXP_STUB_ENTRY_LEN,DXP_STUB_ENTRY_MASK);
    int ok=apk_entry_sha256(path,wanted,DXP_STUB_ENTRY_LEN,out);memset(wanted,0,sizeof(wanted));return ok;
}
static int verify_business_files(const char*path){
#if DXP_BUSINESS_SO_COUNT > 0
    size_t i;uint8_t digest[32];char name[256];
    for(i=0;i<DXP_BUSINESS_SO_COUNT;i++){
        size_t n=DXP_BUSINESS_SO_NAME_LENS[i];if(n==0||n>=sizeof(name))return 0;
        reveal(name,DXP_BUSINESS_SO_NAMES[i],n,DXP_BUSINESS_SO_NAME_MASKS[i]);
        int ok=apk_entry_sha256(path,name,n,digest)&&equal32(digest,DXP_BUSINESS_SO_SHA256[i]);
        memset(name,0,sizeof(name));memset(digest,0,sizeof(digest));if(!ok)return 0;
    }
#else
    (void)path;
#endif
    return 1;
}
static int hash_sealed(const char*path,const uint8_t*m1,const uint8_t*m2,uint8_t digest[32]){
    int fd=-1,ok=0;struct stat st;uint8_t*data=0;size_t i,p1=(size_t)-1,p2=(size_t)-1;sha256_ctx h;
    if(!path||(fd=open(path,O_RDONLY|O_CLOEXEC))<0||fstat(fd,&st)||st.st_size<96||st.st_size>67108864)goto done;
    data=(uint8_t*)malloc((size_t)st.st_size);if(!data||!read_at(fd,0,data,(size_t)st.st_size))goto done;
    for(i=0;i+48<=(size_t)st.st_size;i++){if(!memcmp(data+i,m1,16)){if(p1!=(size_t)-1)goto done;p1=i;}if(!memcmp(data+i,m2,16)){if(p2!=(size_t)-1)goto done;p2=i;}}
    if(p1==(size_t)-1||p2==(size_t)-1)goto done;memset(data+p1+16,0,32);memset(data+p2+16,0,32);
    init(&h);update(&h,data,(size_t)st.st_size);final(&h,digest);ok=1;
done: if(data){memset(data,0,(size_t)(st.st_size>0?st.st_size:0));free(data);}if(fd>=0)close(fd);return ok;
}
static int verify_capability(const uint8_t signer[32],const uint8_t*cap,size_t n){uint8_t msg[52],tag[32];uint32_t pid;if(!cap||n!=48)return 0;memcpy(msg,signer,32);memcpy(msg+32,cap,16);pid=(uint32_t)getpid();msg[48]=pid>>24;msg[49]=pid>>16;msg[50]=pid>>8;msg[51]=pid;hmac_key(DXP_ANCHOR_KEY,msg,52,tag);memset(msg,0,52);return equal32(tag,cap+16);}
static int verify_graph(JNIEnv*env,jbyteArray signer,jstring apk_path,jstring engine_path,jstring anchor_path,jbyteArray capability){
    if(!runtime_clean())return 0;
    if(!signer||!apk_path||!engine_path||!anchor_path||!capability||(*env)->GetArrayLength(env,signer)!=32||(*env)->GetArrayLength(env,capability)!=48)return 0;
    uint8_t s[32],cap[48],ed[32],ad[32],cert[32],stub[32];(*env)->GetByteArrayRegion(env,signer,0,32,(jbyte*)s);(*env)->GetByteArrayRegion(env,capability,0,48,(jbyte*)cap);if(!equal32(s,DXP_CERT_SHA256)||!verify_capability(s,cap,48))return 0;
    const char*ep=(*env)->GetStringUTFChars(env,engine_path,0),*an=(*env)->GetStringUTFChars(env,anchor_path,0),*ap=(*env)->GetStringUTFChars(env,apk_path,0);
    int ok=ep&&an&&ap&&hash_sealed(ep,DXP_SELF_SEAL,DXP_PEER_SEAL,ed)&&equal32(ed,DXP_SELF_SEAL+16)&&hash_sealed(an,DXA_SELF_MARKER,DXA_PEER_MARKER,ad)&&equal32(ad,DXP_PEER_SEAL+16)&&apk_cert_sha256(ap,cert)&&equal32(cert,DXP_CERT_SHA256)&&apk_stub_sha256(ap,stub)&&equal32(stub,DXP_STUB_DEX_SHA256)&&verify_business_files(ap);
    if(ep)(*env)->ReleaseStringUTFChars(env,engine_path,ep);if(an)(*env)->ReleaseStringUTFChars(env,anchor_path,an);if(ap)(*env)->ReleaseStringUTFChars(env,apk_path,ap);memset(s,0,32);memset(cap,0,48);return ok;
}

static jbyteArray native_decrypt(JNIEnv*env,jclass type,jbyteArray input,jbyteArray signer,jstring apk_path,jstring native_path,jstring anchor_path,jbyteArray capability){
    (void)type;if(!input||!verify_graph(env,signer,apk_path,native_path,anchor_path,capability))return 0;
    jsize n=(*env)->GetArrayLength(env,input);if(n<60)return 0;
    jbyte*raw=(*env)->GetByteArrayElements(env,input,0);uint8_t*p=(uint8_t*)raw;
    if(memcmp(p,"DXPROT01",8)!=0){(*env)->ReleaseByteArrayElements(env,input,raw,JNI_ABORT);return 0;}
    uint32_t size=be32(p+24);if((uint64_t)size+60u!=(uint64_t)n){(*env)->ReleaseByteArrayElements(env,input,raw,JNI_ABORT);return 0;}
    uint8_t tag[32];hmac(p,28u+size,tag);if(!equal32(tag,p+28+size)){(*env)->ReleaseByteArrayElements(env,input,raw,JNI_ABORT);return 0;}
    jbyteArray out=(*env)->NewByteArray(env,(jsize)size);uint8_t*clear=(uint8_t*)malloc(size);if(!clear){(*env)->ReleaseByteArrayElements(env,input,raw,JNI_ABORT);return 0;}
    uint32_t off=0,counter=0;while(off<size){uint8_t block[52],stream[32];memcpy(block,DXP_KEY,32);memcpy(block+32,p+8,16);block[48]=(uint8_t)(counter>>24);block[49]=(uint8_t)(counter>>16);block[50]=(uint8_t)(counter>>8);block[51]=(uint8_t)counter;sha256_ctx c;init(&c);update(&c,block,52);final(&c,stream);uint32_t j,remain=size-off<32?size-off:32;for(j=0;j<remain;j++)clear[off+j]=p[28+off+j]^stream[j];memset(stream,0,32);off+=remain;counter++;}
    (*env)->SetByteArrayRegion(env,out,0,(jsize)size,(jbyte*)clear);memset(clear,0,size);free(clear);(*env)->ReleaseByteArrayElements(env,input,raw,JNI_ABORT);return out;
}
static jboolean native_recheck(JNIEnv*env,jclass type,jbyteArray signer,jstring apk_path,jstring native_path,jstring anchor_path,jbyteArray capability){(void)type;return verify_graph(env,signer,apk_path,native_path,anchor_path,capability)?JNI_TRUE:JNI_FALSE;}

static jbyteArray native_share(JNIEnv*env,jclass type,jbyteArray signer,jstring apk_path,jstring native_path,
                               jstring anchor_path,jbyteArray capability,jbyteArray anchor_fragment,jstring challenge,jint phase,jint domain){
    (void)type;if(!anchor_fragment||(*env)->GetArrayLength(env,anchor_fragment)!=32||!challenge||phase<0||phase>3||domain<0||domain>7||
        !verify_graph(env,signer,apk_path,native_path,anchor_path,capability))return 0;
    const char*raw=(*env)->GetStringUTFChars(env,challenge,0);if(!raw)return 0;size_t n=strlen(raw);
    if(n==0||n>256){(*env)->ReleaseStringUTFChars(env,challenge,raw);return 0;}
    uint8_t fragment[32],key[32],msg[512],out[32],round[104],manifest[32];size_t p=0;int i,r;sha256_ctx manifest_hash;
    (*env)->GetByteArrayRegion(env,anchor_fragment,0,32,(jbyte*)fragment);
    for(i=0;i<32;i++)key[i]=(uint8_t)(DXP_BIND_A[i]^fragment[31-i]^DXP_KEY[(i*7)&31]^
        DXP_SELF_SEAL[16+((i+5)&31)]^DXP_PEER_SEAL[16+((i+19)&31)]);
    msg[p++]=(uint8_t)phase;msg[p++]=(uint8_t)domain;msg[p++]=(uint8_t)(n>>8);msg[p++]=(uint8_t)n;
    memcpy(msg+p,raw,n);p+=n;memcpy(msg+p,DXP_CERT_SHA256,32);p+=32;
    memcpy(msg+p,DXP_STUB_DEX_SHA256,32);p+=32;
    init(&manifest_hash);
#if DXP_BUSINESS_SO_COUNT > 0
    for(i=0;i<DXP_BUSINESS_SO_COUNT;i++)update(&manifest_hash,DXP_BUSINESS_SO_SHA256[i],32);
#else
    update(&manifest_hash,DXP_STUB_DEX_SHA256,32);
#endif
    final(&manifest_hash,manifest);memcpy(msg+p,manifest,32);p+=32;memcpy(msg+p,fragment,32);p+=32;
    hmac_key(key,msg,p,out);
    for(r=0;r<3;r++){
        memcpy(round,out,32);for(i=0;i<32;i++)round[32+i]=(uint8_t)(key[(i+r*5)&31]^fragment[(i+r*9)&31]);
        memcpy(round+64,manifest,32);round[96]=(uint8_t)phase;round[97]=(uint8_t)domain;round[98]=(uint8_t)r;round[99]=(uint8_t)n;
        memcpy(round+100,DXP_STUB_DEX_SHA256+r*4,4);hmac_key(key,round,104,out);
    }
    (*env)->ReleaseStringUTFChars(env,challenge,raw);jbyteArray result=(*env)->NewByteArray(env,32);
    if(result)(*env)->SetByteArrayRegion(env,result,0,32,(jbyte*)out);
    memset(fragment,0,sizeof(fragment));memset(key,0,sizeof(key));memset(msg,0,sizeof(msg));memset(out,0,sizeof(out));memset(round,0,sizeof(round));memset(manifest,0,sizeof(manifest));return result;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*vm,void*reserved){
    (void)reserved;JNIEnv*e=0;if((*vm)->GetEnv(vm,(void**)&e,JNI_VERSION_1_6)!=JNI_OK)return JNI_ERR;
    char cls[DXP_ENGINE_CLASS_LEN+1],dn[DXP_DECRYPT_NAME_LEN+1],rn[DXP_RECHECK_NAME_LEN+1],sn[DXP_SHARE_NAME_LEN+1];
    char ds[DXP_DECRYPT_SIG_LEN+1],rs[DXP_RECHECK_SIG_LEN+1],ss[DXP_SHARE_SIG_LEN+1];
    reveal(cls,DXP_ENGINE_CLASS_X,DXP_ENGINE_CLASS_LEN,DXP_ENGINE_CLASS_MASK);
    reveal(dn,DXP_DECRYPT_NAME_X,DXP_DECRYPT_NAME_LEN,DXP_DECRYPT_NAME_MASK);
    reveal(rn,DXP_RECHECK_NAME_X,DXP_RECHECK_NAME_LEN,DXP_RECHECK_NAME_MASK);
    reveal(sn,DXP_SHARE_NAME_X,DXP_SHARE_NAME_LEN,DXP_SHARE_NAME_MASK);
    reveal(ds,DXP_DECRYPT_SIG_X,DXP_DECRYPT_SIG_LEN,DXP_DECRYPT_SIG_MASK);
    reveal(rs,DXP_RECHECK_SIG_X,DXP_RECHECK_SIG_LEN,DXP_RECHECK_SIG_MASK);
    reveal(ss,DXP_SHARE_SIG_X,DXP_SHARE_SIG_LEN,DXP_SHARE_SIG_MASK);
    jclass c=(*e)->FindClass(e,cls);if(!c)return JNI_ERR;
    JNINativeMethod m[3]={{dn,ds,(void*)native_decrypt},{rn,rs,(void*)native_recheck},{sn,ss,(void*)native_share}};
    int ok=(*e)->RegisterNatives(e,c,m,3)==0;
    memset(cls,0,sizeof(cls));memset(dn,0,sizeof(dn));memset(rn,0,sizeof(rn));memset(sn,0,sizeof(sn));
    memset(ds,0,sizeof(ds));memset(rs,0,sizeof(rs));memset(ss,0,sizeof(ss));
    return ok?JNI_VERSION_1_6:JNI_ERR;
}
