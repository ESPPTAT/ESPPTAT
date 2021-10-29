#ifndef ESPPTAT_H
#define ESPPTAT_H

#include"pairing_3.h"
#include "zzn.h"
#include <stdlib.h>
#include <stdio.h>
typedef unsigned char u8;
typedef unsigned int u32;
#define AES_SECURITY 128
#define ATTRIBUTES_NUM 10
#define DISCLOSE_NUM 2
/////////////////////////////////
//CA的主密钥和系统参数
struct SPS_EQ_PRI_KEY_FOR_S_CA
{
    Big x;
    Big y[5];

};
struct SPS_EQ_PUB_KEY_FOR_S_CA
{
    G1 X;
    G1 Y[5];
};
struct SPS_EQ_PRI_KEY_FOR_U_CA
{
    Big x[2];
};
struct SET_COMMIT_PP
{
    G1 gq[ATTRIBUTES_NUM];
    G2 gq_[ATTRIBUTES_NUM];
};
struct SPS_EQ_PUB_KEY_FOR_U_CA
{
    G2 X_[2];
};
struct PP
{
#if 1 //test
    Big q;
#endif
    G1 w_;
    SPS_EQ_PUB_KEY_FOR_U_CA u_pub;
    SPS_EQ_PUB_KEY_FOR_S_CA s_pub;
    SET_COMMIT_PP pp_sc;
};

struct MSK
{
    Big q;
    SPS_EQ_PRI_KEY_FOR_U_CA u_pri;
    SPS_EQ_PRI_KEY_FOR_S_CA s_pri;
};
//卖方密钥和证书
struct SELLER_PRI_KEY
{
    Big x;
    Big y[5];

};
struct SELLER_PUB_KEY
{
    G2 X_;
    G2 Y_[5];
};
struct SELLER_KEY
{
    SELLER_PRI_KEY ssk;
    SELLER_PUB_KEY spk;

};
struct SELLER_CRED
{
    G1 Y;
    G2 Z_,Y_;
};
struct Pi_1
{
    Big c,sx;
    Big s[5];
};
//用户属性
struct USER_ATTRIBUTES
{
    Big a[ATTRIBUTES_NUM];
};
struct USER_DISCLOSE_ATTRIBUTES
{
    Big attr[DISCLOSE_NUM];
};
struct USER_PRI_KEY
{
    Big x;
    USER_ATTRIBUTES att;

};
struct USER_PUB_KEY
{
    G1 Y;
};
struct USER_KEY
{
    USER_PRI_KEY usk;
    USER_PUB_KEY upk;
    Big rou;
};
struct SPS_SIG
{
    G1 Z,Y;
    G2 Y_;
};
struct USER_CRED
{
    SPS_SIG sig;
    G1 Cu;
    G1 pk;
};
struct Pi_2
{
    Big c,s;
    G2 P;
};
//票据购买
struct SELLER_CRED_PROV
{
    SELLER_PUB_KEY spk;
    SELLER_CRED cred_s;
    G1 h;
    Pi_1 pi_1;
};

struct PI_3
{
    G1 fei;
    Big c,s_z,s_usk,s_dsrnd,s_ek,s_tid,s[4],s_miu,s_v;
};
struct USER_INIT
{
    PI_3 pi_3;
    USER_CRED cred_u;
    G1 _h;
    G1 _W;
    G1 alfa[5],beta[5];
    USER_DISCLOSE_ATTRIBUTES dis;
};
struct USER_TOK
{
    Big z,usk,dsrnd,ek,tid,vt;
    SELLER_CRED_PROV s_pub_cred;
    G1 T1,T2;
    G1 tk;

};
struct SELLER_ISSUE
{
    Big _tid,vt;
    G1 _alfa,_beta;
    G1 tk;
};
//票据验证
struct PI_4
{
    G1 fei;
    Big c;
    Big s_usk,s_dsrnd,s_ek,s_k,s_v,s_r;
};
struct TICKET_SHOW
{
    SELLER_PUB_KEY _spk;
    SELLER_CRED _cred_s;
    USER_CRED _cred_u;
    G2 K;
    G1 V;
    G1 _T1,_T2;
    Big tid,vt;
    Big ch,s;
    G1 C1_,C2_;
    PI_4 pi_4;
#if 0
    Big ek;
    G2 upk;
#endif
};
struct DS_INFO
{
    Big tid;
    Big ch,s;
    G1 C1_,C2_;
#if 0
    Big ek;
    G2 upk;
#endif
};
struct TRACE_PUB
{
    USER_PUB_KEY upk1;
    USER_PUB_KEY upk2;
};
//票据转让
struct F1_TRAN
{
    SELLER_PUB_KEY spk;
    SELLER_CRED cred_s;
    G1 _T1,_T2;
    G1 _tk;
    Big dsrnd,ek,tid,vt;
};
/////////////////////////
class ESPPTAT
{
private:
    PFC *pfc;
    G1 g;
    G2 g_;
    GT gt;
public:
    ESPPTAT(PFC *p);
    //初始化
    int SetUp(PP &pp,MSK &msk);
    //卖方注册
    int SellerRegister_S_Init(PP &pp,SELLER_KEY &seller_key,Pi_1 &pi_1);
    int SellerRegister_CA_Issue(PP &pp,MSK &msk,SELLER_PUB_KEY &spk,Pi_1 &pi_1,SELLER_CRED &cred_s);
    int SellerRegister_S_Rcv(PP &pp,SELLER_KEY &seller_key,SELLER_CRED &cred_s);
    //用户注册
    int UserRegister_U_Init(PP &pp,USER_KEY &user_key,Pi_2 &pi_2,USER_CRED &cred_u);
    int UserRegister_CA_Issue(PP &pp,MSK &msk,USER_PUB_KEY &upk,Pi_2 &pi_2,USER_ATTRIBUTES &attr,USER_CRED &cred_u);
    int UserRegister_U_Rcv(PP &pp,USER_KEY &user_key,USER_CRED &cred_u);
    //票据购买
    int TicktPurchasing_S_Init(PP &pp, SELLER_KEY &seller_key, SELLER_CRED &cred_s, SELLER_CRED_PROV &s_prov);
    int TicktPurchasing_U_Init(PP &pp,SELLER_CRED_PROV &s_prov,USER_KEY &user_key,USER_CRED &cred_u,USER_INIT &user_init,USER_TOK &tok);
    int TicktPurchasing_S_Issue(PP &pp, SELLER_KEY &seller_key, SELLER_CRED_PROV &s_prov, USER_INIT &user_init, SELLER_ISSUE &s_issue);
    int TicktPurchasing_U_Rcv(PP &pp,USER_TOK &tok,SELLER_ISSUE &s_issue);
    //当fu=1时票据转让
    int TicktTransfering_SU_f1_Tran(PP &pp,USER_KEY &user_key,USER_TOK &tok,F1_TRAN &f1_tran);
    int TicktTransfering_RU_f1_Rcv(PP &pp,USER_KEY &user_key,F1_TRAN &f1_tran,USER_TOK &tok);
    //票据验证
    int TicktShowing_U_Show(PP &pp,USER_KEY &user_key,USER_CRED &cred_u,USER_TOK &tok,TICKET_SHOW &tic);
    int TicktShowing_V_Verify(PP &pp,TICKET_SHOW &tic,DS_INFO &ds_info);
    //双花追踪
    int DB_Trace(PP &pp,DS_INFO &ds_info1,DS_INFO &ds_info2,TRACE_PUB &upk);

};

#endif // ESPPTAT_H
