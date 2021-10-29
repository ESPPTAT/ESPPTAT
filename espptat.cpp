#include "espptat.h"


ESPPTAT::ESPPTAT(PFC *p)
{
    pfc=p;
    pfc->random(g);
    pfc->random(g_);
    gt=pfc->pairing(g_,g);
}
int ESPPTAT::SetUp(PP &pp,MSK &msk)
{

    pfc->random(pp.w_);
    //generate sps-eq key for s
    pfc->random(msk.s_pri.x);
    pp.s_pub.X=pfc->mult(g,msk.s_pri.x);
    for(int i=0;i<=4;i++)
    {
        pfc->random(msk.s_pri.y[i]);
        pp.s_pub.Y[i]=pfc->mult(g,msk.s_pri.y[i]);
    }
    //generate sps-eq key for u
    for(int i=0;i<2;i++)
    {
        pfc->random(msk.u_pri.x[i]);
        pp.u_pub.X_[i]=pfc->mult(g_,msk.u_pri.x[i]);
    }
    //generate set commitment pp
    pfc->random(msk.q);
    Big q=msk.q;
    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
        pp.pp_sc.gq[i]=pfc->mult(g,q);
        pp.pp_sc.gq_[i]=pfc->mult(g_,q);
        q=pfc->Zpmulti(q,msk.q);
    }
#if 1 //test
    pp.q=msk.q;
#endif
    return 0;
}
int ESPPTAT::SellerRegister_S_Init(PP &pp,SELLER_KEY &seller_key,Pi_1 &pi_1)
{
    //Seller key gen
    pfc->random(seller_key.ssk.x);
    seller_key.spk.X_=pfc->mult(g_,seller_key.ssk.x);
    for(int i=0;i<=4;i++)
    {
        pfc->random(seller_key.ssk.y[i]);
        seller_key.spk.Y_[i]=pfc->mult(g_,seller_key.ssk.y[i]);
    }
    //computer pi_1
    Big gama,yita[5];
    G2 Rx_,Ry_[5];
    pfc->random(gama);
    Rx_=pfc->mult(g_,gama);
    for(int i=0;i<=4;i++)
    {
        pfc->random(yita[i]);
        Ry_[i]=pfc->mult(g_,yita[i]);
    }
    pfc->start_hash();
    pfc->add_to_hash(seller_key.spk.X_);
    for(int i=0;i<=4;i++)
    {
        pfc->add_to_hash(seller_key.spk.Y_[i]);
    }
    pfc->add_to_hash(Rx_);
    for(int i=0;i<=4;i++)
    {
        pfc->add_to_hash(Ry_[i]);
    }
    pi_1.c=pfc->finish_hash_to_group();
    Big t;
    t=pfc->Zpmulti(pi_1.c,seller_key.ssk.x);
    pi_1.sx=pfc->Zpsub(gama,t);
    for(int i=0;i<=4;i++)
    {
        t=pfc->Zpmulti(pi_1.c,seller_key.ssk.y[i]);
        pi_1.s[i]=pfc->Zpsub(yita[i],t);
    }
    return 0;
}
int ESPPTAT::SellerRegister_CA_Issue(PP &pp,MSK &msk,SELLER_PUB_KEY &spk,Pi_1 &pi_1,SELLER_CRED &cred_s)
{
    //verify pi_1
    G2 Rx_,Ry_[5],T_;
    Rx_=pfc->mult(g_,pi_1.sx);
    T_=pfc->mult(spk.X_,pi_1.c);
    Rx_=Rx_+T_;
    for(int i=0;i<=4;i++)
    {
        Ry_[i]=pfc->mult(g_,pi_1.s[i]);
        T_=pfc->mult(spk.Y_[i],pi_1.c);
        Ry_[i]=Ry_[i]+T_;
    }
    pfc->start_hash();
    pfc->add_to_hash(spk.X_);
    for(int i=0;i<=4;i++)
    {
        pfc->add_to_hash(spk.Y_[i]);
    }
    pfc->add_to_hash(Rx_);
    for(int i=0;i<=4;i++)
    {
        pfc->add_to_hash(Ry_[i]);
    }
    Big c=pfc->finish_hash_to_group();
    if(c != pi_1.c) return -1;
    //SPS-EQ sign
    Big r,r_inv;
    pfc->random(r);
    r_inv=pfc->Zpinverse(r);
    cred_s.Y=pfc->mult(g,r_inv);
    cred_s.Y_=pfc->mult(g_,r_inv);
    G2 SUM=pfc->mult(spk.X_,msk.s_pri.x);

    for(int i=0;i<=4;i++)
    {
        T_=pfc->mult(spk.Y_[i],msk.s_pri.y[i]);
        SUM=SUM+T_;
    }
    cred_s.Z_=pfc->mult(SUM,r);

    return 0;
}
int ESPPTAT::SellerRegister_S_Rcv(PP &pp,SELLER_KEY &seller_key,SELLER_CRED &cred_s)
{
    GT E1,E2;
    E1=pfc->pairing(cred_s.Y_,g);
    E2=pfc->pairing(g_,cred_s.Y);
    if(E1 != E2) return -1;
    GT M;
    E1=pfc->pairing(seller_key.spk.X_,pp.s_pub.X);
    for(int i=0;i<=4;i++)
    {
        M=pfc->pairing(seller_key.spk.Y_[i],pp.s_pub.Y[i]);
        E1=M*E1;
    }
    E2=pfc->pairing(cred_s.Z_,cred_s.Y);
    if(E1 != E2) return -2;
    return 0;
}
int ESPPTAT::UserRegister_U_Init(PP &pp, USER_KEY &user_key, Pi_2 &pi_2, USER_CRED &cred_u)
{
    //generate user key
    pfc->random(user_key.usk.x);
    user_key.upk.Y=pfc->mult(g,user_key.usk.x);
    //compute pi_2
    Big gama;
    pfc->random(gama);
    G1 R=pfc->mult(g,gama);
    pfc->start_hash();
    pfc->add_to_hash(user_key.upk.Y);
    pfc->add_to_hash(R);
    pi_2.c=pfc->finish_hash_to_group();
    Big t=pfc->Zpmulti(pi_2.c,user_key.usk.x);
    pi_2.s=pfc->Zpsub(gama,t);
    //init attr
    for(int i=0;i<ATTRIBUTES_NUM;i++)
        pfc->random(user_key.usk.att.a[i]);
    //compute Cu
    pfc->random(user_key.rou);
    cred_u.pk=user_key.upk.Y;
    cred_u.Cu=g;
    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
#if 1//test
        Big t=pfc->Zpsub(pp.q,user_key.usk.att.a[i]);
        cred_u.Cu=pfc->mult(cred_u.Cu,t);
#endif
    }
    cred_u.Cu=pfc->mult(cred_u.Cu,user_key.rou);
    pi_2.P=pfc->mult(g_,user_key.rou);
    return 0;
}
int ESPPTAT::UserRegister_CA_Issue(PP &pp, MSK &msk, USER_PUB_KEY &upk, Pi_2 &pi_2, USER_ATTRIBUTES &attr, USER_CRED &cred_u)
{
    //Verify pi_2
    G1 R,T;
    R=pfc->mult(g,pi_2.s);
    T=pfc->mult(upk.Y,pi_2.c);
    R=R+T;
    pfc->start_hash();
    pfc->add_to_hash(upk.Y);
    pfc->add_to_hash(R);
    Big c=pfc->finish_hash_to_group();
    if(c != pi_2.c) return -1;
    //verify set commitment
    GT E1,E2;
    E1=pfc->pairing(g_,cred_u.Cu);
    G1 Mu=g;
    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
#if 1 // test
        Big t=pfc->Zpsub(pp.q,attr.a[i]);
        Mu=pfc->mult(Mu,t);
#endif
    }
    E2=pfc->pairing(pi_2.P,Mu);
    if(E1 != E2) return -2;
    //SPS-EQ sign
    Big r,r_inv;
    pfc->random(r);
    r_inv=pfc->Zpinverse(r);
    cred_u.sig.Y=pfc->mult(g,r_inv);
    cred_u.sig.Y_=pfc->mult(g_,r_inv);
    cred_u.sig.Z=pfc->mult(cred_u.Cu,msk.u_pri.x[0])+pfc->mult(cred_u.pk,msk.u_pri.x[1]);
    cred_u.sig.Z=pfc->mult(cred_u.sig.Z,r);

    return 0;
}
int ESPPTAT::UserRegister_U_Rcv(PP &pp,USER_KEY &user_key,USER_CRED &cred_u)
{
    GT E1,E2;
    E1=pfc->pairing(cred_u.sig.Y_,g);
    E2=pfc->pairing(g_,cred_u.sig.Y);
    if(E1 != E2) return -1;
    GT M;
    E1=pfc->pairing(pp.u_pub.X_[0],cred_u.Cu)*pfc->pairing(pp.u_pub.X_[1],cred_u.pk);
    E2=pfc->pairing(cred_u.sig.Y_,cred_u.sig.Z);
    if(E1 != E2) return -2;
    return 0;
}
int ESPPTAT::TicktPurchasing_S_Init(PP &pp,SELLER_KEY &seller_key,SELLER_CRED &cred_s,SELLER_CRED_PROV &s_prov)
{
    ///////////////
    pfc->random(s_prov.h);

    //computer pi_1
    Big gama,yita[5];
    G2 Rx_,Ry_[5];
    pfc->random(gama);
    Rx_=pfc->mult(g_,gama);
    for(int i=0;i<=4;i++)
    {
        pfc->random(yita[i]);
        Ry_[i]=pfc->mult(g_,yita[i]);
    }
    pfc->start_hash();
    pfc->add_to_hash(seller_key.spk.X_);
    for(int i=0;i<=4;i++)
    {
        pfc->add_to_hash(seller_key.spk.Y_[i]);
    }
    pfc->add_to_hash(Rx_);
    for(int i=0;i<=4;i++)
    {
        pfc->add_to_hash(Ry_[i]);
    }
    s_prov.pi_1.c=pfc->finish_hash_to_group();
    Big t;
    t=pfc->Zpmulti(s_prov.pi_1.c,seller_key.ssk.x);
    s_prov.pi_1.sx=pfc->Zpsub(gama,t);
    for(int i=0;i<=4;i++)
    {
        t=pfc->Zpmulti(s_prov.pi_1.c,seller_key.ssk.y[i]);
        s_prov.pi_1.s[i]=pfc->Zpsub(yita[i],t);
    }
    //spk cred_s
    s_prov.spk.X_=seller_key.spk.X_;
    for(int i=0;i<5;i++)
    {
        s_prov.spk.Y_[i]=seller_key.spk.Y_[i];
    }
    s_prov.cred_s.Z_=cred_s.Z_;
    s_prov.cred_s.Y=cred_s.Y;
    s_prov.cred_s.Y_=cred_s.Y_;
    return 0;
}
int ESPPTAT::TicktPurchasing_U_Init(PP &pp,SELLER_CRED_PROV &s_prov,USER_KEY &user_key,USER_CRED &cred_u,USER_INIT &user_init,USER_TOK &tok)
{
    //Verifi cred_s
    GT E1,E2;
    E1=pfc->pairing(s_prov.cred_s.Y_,g);
    E2=pfc->pairing(g_,s_prov.cred_s.Y);
    if(E1 != E2) return -1;
    GT M;
    E1=pfc->pairing(s_prov.spk.X_,pp.s_pub.X);
    for(int i=0;i<=4;i++)
    {
        M=pfc->pairing(s_prov.spk.Y_[i],pp.s_pub.Y[i]);
        E1=M*E1;
    }
    E2=pfc->pairing(s_prov.cred_s.Z_,s_prov.cred_s.Y);
    if(E1 != E2) return -2;

    tok.s_pub_cred.spk.X_=s_prov.spk.X_;
    for(int i=0;i<5;i++)
    {
        tok.s_pub_cred.spk.Y_[i]=s_prov.spk.Y_[i];
    }
    tok.s_pub_cred.cred_s.Z_=s_prov.cred_s.Z_;
    tok.s_pub_cred.cred_s.Y=s_prov.cred_s.Y;
    tok.s_pub_cred.cred_s.Y_=s_prov.cred_s.Y_;
    //Verify Pi1
    G2 Rx_,Ry_[5],T_;
    Rx_=pfc->mult(g_,s_prov.pi_1.sx);
    T_=pfc->mult(s_prov.spk.X_,s_prov.pi_1.c);
    Rx_=Rx_+T_;
    for(int i=0;i<=4;i++)
    {
        Ry_[i]=pfc->mult(g_,s_prov.pi_1.s[i]);
        T_=pfc->mult(s_prov.spk.Y_[i],s_prov.pi_1.c);
        Ry_[i]=Ry_[i]+T_;
    }
    pfc->start_hash();
    pfc->add_to_hash(s_prov.spk.X_);
    for(int i=0;i<=4;i++)
    {
        pfc->add_to_hash(s_prov.spk.Y_[i]);
    }
    pfc->add_to_hash(Rx_);
    for(int i=0;i<=4;i++)
    {
        pfc->add_to_hash(Ry_[i]);
    }
    Big c=pfc->finish_hash_to_group();
    if(c != s_prov.pi_1.c) return -3;

    //disclose attr
    for(int i=0;i<DISCLOSE_NUM;i++)
    {
        user_init.dis.attr[i]=user_key.usk.att.a[i];
    }
    Big k,v;

    pfc->random(k);
    pfc->random(v);
    user_init.cred_u.Cu=pfc->mult(cred_u.Cu,v);
    user_init.cred_u.pk=pfc->mult(cred_u.pk,v);
    Big k_inv;
    k_inv=pfc->Zpinverse(k);
    user_init.cred_u.sig.Y=pfc->mult(cred_u.sig.Y,k_inv);
    user_init.cred_u.sig.Y_=pfc->mult(cred_u.sig.Y_,k_inv);
    Big m=pfc->Zpmulti(v,k);
    user_init.cred_u.sig.Z=pfc->mult(cred_u.sig.Z,m);

    //compute w
    user_init._W=g;
    for(int i=DISCLOSE_NUM;i<ATTRIBUTES_NUM;i++)
    {
#if 1//test
        Big t=pfc->Zpsub(pp.q,user_key.usk.att.a[i]);
        user_init._W=pfc->mult(user_init._W,t);
#endif
    }
    user_init._W=pfc->mult(user_init._W,user_key.rou);
    user_init._W=pfc->mult(user_init._W,v);
    //ps-blind
    pfc->random(tok.z);
    tok.usk=user_key.usk.x;
    pfc->random(tok.dsrnd);
    pfc->random(tok.ek);
    pfc->random(tok.tid);
    Big rand[4];
    for(int i=0;i<4;i++)
    {
        pfc->random(rand[i]);
    }

    user_init._h=pfc->mult(g,tok.z);
    tok.T1=s_prov.h;
    G1 T=pfc->mult(s_prov.h,tok.usk);
    user_init.alfa[0]=pfc->mult(g,rand[0]);
    user_init.alfa[0]=user_init.alfa[0]+T;
    T=pfc->mult(s_prov.h,tok.dsrnd);
    user_init.alfa[1]=pfc->mult(g,rand[1]);
    user_init.alfa[1]=user_init.alfa[1]+T;
    T=pfc->mult(s_prov.h,tok.ek);
    user_init.alfa[2]=pfc->mult(g,rand[2]);
    user_init.alfa[2]=user_init.alfa[2]+T;
    T=pfc->mult(s_prov.h,tok.tid);
    user_init.alfa[3]=pfc->mult(g,rand[3]);
    user_init.alfa[3]=user_init.alfa[3]+T;
    for(int i=0;i<4;i++)
    {
        user_init.beta[i]=pfc->mult(user_init._h,rand[i]);
    }
    //pi3
    Big gm_z,gm[4];
    Big yita[4],gm_miu,gm_v;
    pfc->random(gm_z);
    pfc->random(gm_miu);
    pfc->random(gm_v);
    for(int i=0;i<4;i++)
    {
        pfc->random(gm[i]);
        pfc->random(yita[i]);
    }
    G1 Rh,R[4],H[4],R_fei,R_k;
    Rh=pfc->mult(g,gm_z);
    for(int i=0;i<4;i++)
    {
        T=pfc->mult(s_prov.h,gm[i]);
        R[i]=pfc->mult(g,yita[i]);
        R[i]=R[i]+T;
        H[i]=pfc->mult(user_init._h,yita[i]);
    }
    user_init.pi_3.fei=pfc->mult(g,v);
    R_fei=pfc->mult(g,gm_v);
    R_k=pfc->mult(user_init.pi_3.fei,gm[0]);


    pfc->start_hash();
    pfc->add_to_hash(user_init._h);
    for(int i=0;i<4;i++)
        pfc->add_to_hash(user_init.alfa[i]);
    for(int i=0;i<4;i++)
        pfc->add_to_hash(user_init.beta[i]);
    pfc->add_to_hash(user_init.cred_u.pk);

    pfc->add_to_hash(Rh);

    for(int i=0;i<4;i++)
        pfc->add_to_hash(R[i]);

    for(int i=0;i<4;i++)
        pfc->add_to_hash(H[i]);
    pfc->add_to_hash(user_init.pi_3.fei);
    pfc->add_to_hash(R_fei);
    pfc->add_to_hash(R_k);

    user_init.pi_3.c=pfc->finish_hash_to_group();
    Big t=pfc->Zpmulti(tok.z,user_init.pi_3.c);
    user_init.pi_3.s_z=pfc->Zpsub(gm_z,t);
    t=pfc->Zpmulti(tok.usk,user_init.pi_3.c);
    user_init.pi_3.s_usk=pfc->Zpsub(gm[0],t);
    t=pfc->Zpmulti(tok.dsrnd,user_init.pi_3.c);
    user_init.pi_3.s_dsrnd=pfc->Zpsub(gm[1],t);
    t=pfc->Zpmulti(tok.ek,user_init.pi_3.c);
    user_init.pi_3.s_ek=pfc->Zpsub(gm[2],t);
    t=pfc->Zpmulti(tok.tid,user_init.pi_3.c);
    user_init.pi_3.s_tid=pfc->Zpsub(gm[3],t);
    for(int i=0;i<4;i++)
    {
        t=pfc->Zpmulti(rand[i],user_init.pi_3.c);
        user_init.pi_3.s[i]=pfc->Zpsub(yita[i],t);
    }
   // t=pfc->Zpmulti(user_key.miu,user_init.pi_3.c);
    user_init.pi_3.s_miu=pfc->Zpsub(gm_miu,t);
    t=pfc->Zpmulti(v,user_init.pi_3.c);
    user_init.pi_3.s_v=pfc->Zpsub(gm_v,t);
    return 0;
}
int ESPPTAT::TicktPurchasing_S_Issue(PP &pp, SELLER_KEY &seller_key, SELLER_CRED_PROV &s_prov, USER_INIT &user_init, SELLER_ISSUE &s_issue)
{
    //verify pi_3
    G1 Rh,R[4],H[4],T,T1,R_fei,R_k;
    G2 T_,S_;
    T=pfc->mult(g,user_init.pi_3.s_z);
    Rh=pfc->mult(user_init._h,user_init.pi_3.c);
    Rh=Rh+T;

    T=pfc->mult(s_prov.h,user_init.pi_3.s_usk);
    T1=pfc->mult(g,user_init.pi_3.s[0]);
    R[0]=pfc->mult(user_init.alfa[0],user_init.pi_3.c);
    R[0]=R[0]+T+T1;

    T=pfc->mult(s_prov.h,user_init.pi_3.s_dsrnd);
    T1=pfc->mult(g,user_init.pi_3.s[1]);
    R[1]=pfc->mult(user_init.alfa[1],user_init.pi_3.c);
    R[1]=R[1]+T+T1;

    T=pfc->mult(s_prov.h,user_init.pi_3.s_ek);
    T1=pfc->mult(g,user_init.pi_3.s[2]);
    R[2]=pfc->mult(user_init.alfa[2],user_init.pi_3.c);
    R[2]=R[2]+T+T1;

    T=pfc->mult(s_prov.h,user_init.pi_3.s_tid);
    T1=pfc->mult(g,user_init.pi_3.s[3]);
    R[3]=pfc->mult(user_init.alfa[3],user_init.pi_3.c);
    R[3]=R[3]+T+T1;

    for(int i=0;i<4;i++)
    {
        T=pfc->mult(user_init._h,user_init.pi_3.s[i]);
        H[i]=pfc->mult(user_init.beta[i],user_init.pi_3.c);
        H[i]=H[i]+T;

    }

    T=pfc->mult(g,user_init.pi_3.s_v);
    R_fei=pfc->mult(user_init.pi_3.fei,user_init.pi_3.c);
    R_fei=R_fei+T;

    T=pfc->mult(user_init.pi_3.fei,user_init.pi_3.s_usk);
    R_k=pfc->mult(user_init.cred_u.pk,user_init.pi_3.c);
    R_k=R_k+T;

    pfc->start_hash();
    pfc->add_to_hash(user_init._h);
    for(int i=0;i<4;i++)
        pfc->add_to_hash(user_init.alfa[i]);
    for(int i=0;i<4;i++)
        pfc->add_to_hash(user_init.beta[i]);
    pfc->add_to_hash(user_init.cred_u.pk);

    pfc->add_to_hash(Rh);

    for(int i=0;i<4;i++)
        pfc->add_to_hash(R[i]);

    for(int i=0;i<4;i++)
        pfc->add_to_hash(H[i]);

    pfc->add_to_hash(user_init.pi_3.fei);
    pfc->add_to_hash(R_fei);
    pfc->add_to_hash(R_k);


    Big c=pfc->finish_hash_to_group();
    if(c != user_init.pi_3.c) return -1;

    //verify CRED_U
    GT E1,E2;
    E1=pfc->pairing(user_init.cred_u.sig.Y_,g);
    E2=pfc->pairing(g_,user_init.cred_u.sig.Y);
    if(E1 != E2) return -2;
    GT M;
    E1=pfc->pairing(pp.u_pub.X_[0],user_init.cred_u.Cu)*pfc->pairing(pp.u_pub.X_[1],user_init.cred_u.pk);
    E2=pfc->pairing(user_init.cred_u.sig.Y_,user_init.cred_u.sig.Z);
    if(E1 != E2) return -3;
    //Verify disclose
    G2 W_=g_;
    for(int i=0;i<DISCLOSE_NUM;i++)
    {
        Big t=pfc->Zpsub(pp.q,user_init.dis.attr[i]);
        W_=pfc->mult(W_,t);
    }
    E1=pfc->pairing(W_,user_init._W);
    E2=pfc->pairing(g_,user_init.cred_u.Cu);
    if(E1 != E2) return -4;

    //DMS sign
    pfc->random(s_issue._tid);
    pfc->random(s_issue.vt);
    s_issue._beta=pfc->mult(user_init.beta[0],seller_key.ssk.y[0]);
    for(int i=1;i<4;i++)
    {
        T=pfc->mult(user_init.beta[i],seller_key.ssk.y[i]);
        s_issue._beta=s_issue._beta+T;
    }

    s_issue._alfa=pfc->mult(s_prov.h,seller_key.ssk.x);
    for(int i=0;i<4;i++)
    {
        T=pfc->mult(user_init.alfa[i],seller_key.ssk.y[i]);
        s_issue._alfa=s_issue._alfa+T;
    }

    Big t,s;
    s=pfc->Zpmulti(seller_key.ssk.y[3],s_issue._tid);
    t=pfc->Zpmulti(seller_key.ssk.y[4],s_issue.vt);
    s=pfc->Zpadd(s,t);
    T=pfc->mult(s_prov.h,s);
    s_issue._alfa=s_issue._alfa+T;
    //set tk
    s_issue.tk=pfc->mult(s_prov.h,seller_key.ssk.y[0]);
    return 0;
}
int ESPPTAT::TicktPurchasing_U_Rcv(PP &pp,USER_TOK &tok,SELLER_ISSUE &s_issue)
{

    tok.tid=pfc->Zpadd(tok.tid,s_issue._tid);
    tok.vt=s_issue.vt;

    Big inver_z=pfc->Zpinverse(tok.z);
    G1 T=pfc->mult(-s_issue._beta,inver_z);
    tok.T2=s_issue._alfa+T;
    //verify DMS sign
    GT E1,E2;
    E1=pfc->pairing(g_,tok.T2);
    G2 T_,S_;
    S_=tok.s_pub_cred.spk.X_;
    T_=pfc->mult(tok.s_pub_cred.spk.Y_[0],tok.usk);

    S_=S_+T_;
    T_=pfc->mult(tok.s_pub_cred.spk.Y_[1],tok.dsrnd);

    S_=S_+T_;
    T_=pfc->mult(tok.s_pub_cred.spk.Y_[2],tok.ek);

    S_=S_+T_;
    T_=pfc->mult(tok.s_pub_cred.spk.Y_[3],tok.tid);

    S_=S_+T_;

    T_=pfc->mult(tok.s_pub_cred.spk.Y_[4],tok.vt);
    S_=S_+T_;

    E2=pfc->pairing(S_,tok.T1);
    if(E1 != E2) return -1;
    //verify tk
    tok.tk=s_issue.tk;

    E1=pfc->pairing(tok.s_pub_cred.spk.Y_[0],tok.T1);
    E2=pfc->pairing(g_,tok.tk);
    if(E1 != E2) return -2;

    return 0;
}
int ESPPTAT::TicktTransfering_SU_f1_Tran(PP &pp,USER_KEY &user_key,USER_TOK &tok,F1_TRAN &f1_tran)
{
    //random tok
    Big r;
    pfc->random(r);
    f1_tran._tk=pfc->mult(tok.tk,r);
    f1_tran._T1=pfc->mult(tok.T1,r);
    G1 T=pfc->mult(-tok.tk,tok.usk);
    T=tok.T2+T;
    f1_tran._T2=pfc->mult(T,r);
    f1_tran.dsrnd=tok.dsrnd;
    f1_tran.ek=tok.ek;
    f1_tran.tid=tok.tid;
    f1_tran.vt=tok.vt;
    //spk cred_s
    f1_tran.spk.X_=tok.s_pub_cred.spk.X_;
    for(int i=0;i<5;i++)
    {
        f1_tran.spk.Y_[i]=tok.s_pub_cred.spk.Y_[i];
    }
    f1_tran.cred_s.Z_=tok.s_pub_cred.cred_s.Z_;
    f1_tran.cred_s.Y=tok.s_pub_cred.cred_s.Y;
    f1_tran.cred_s.Y_=tok.s_pub_cred.cred_s.Y_;
    return 0;
}
int ESPPTAT::TicktTransfering_RU_f1_Rcv(PP &pp,USER_KEY &user_key,F1_TRAN &f1_tran,USER_TOK &tok)
{
    GT E1,E2;
    E1=pfc->pairing(f1_tran.spk.Y_[0],f1_tran._T1);
    E2=pfc->pairing(g_,f1_tran._tk);
    if(E1 != E2) return -1;
    //compute T1,T2
    Big r;
    pfc->random(r);
    tok.tk=pfc->mult(f1_tran._tk,r);
    tok.T1=pfc->mult(f1_tran._T1,r);
    G1 T=pfc->mult(f1_tran._tk,user_key.usk.x);
    T=f1_tran._T2+T;
    tok.T2=pfc->mult(T,r);
    //Verify DMS
    tok.dsrnd=f1_tran.dsrnd;
    tok.usk=user_key.usk.x;
    tok.ek=f1_tran.ek;
    tok.tid=f1_tran.tid;
    tok.vt=f1_tran.vt;

    tok.s_pub_cred.spk.X_=f1_tran.spk.X_;
    for(int i=0;i<5;i++)
    {
        tok.s_pub_cred.spk.Y_[i]=f1_tran.spk.Y_[i];
    }
    tok.s_pub_cred.cred_s.Z_=f1_tran.cred_s.Z_;
    tok.s_pub_cred.cred_s.Y=f1_tran.cred_s.Y;
    tok.s_pub_cred.cred_s.Y_=f1_tran.cred_s.Y_;

    E1=pfc->pairing(g_,tok.T2);
    G2 T_,S_;
    S_=tok.s_pub_cred.spk.X_;
    T_=pfc->mult(tok.s_pub_cred.spk.Y_[0],tok.usk);
    S_=S_+T_;
    T_=pfc->mult(tok.s_pub_cred.spk.Y_[1],tok.dsrnd);
    S_=S_+T_;
    T_=pfc->mult(tok.s_pub_cred.spk.Y_[2],tok.ek);
    S_=S_+T_;
    T_=pfc->mult(tok.s_pub_cred.spk.Y_[3],tok.tid);
    S_=S_+T_;
    T_=pfc->mult(tok.s_pub_cred.spk.Y_[4],tok.vt);
    S_=S_+T_;
    E2=pfc->pairing(S_,tok.T1);
    if(E1 != E2) return -3;

    return 0;
}



int ESPPTAT::TicktShowing_U_Show(PP &pp,USER_KEY &user_key,USER_CRED &cred_u,USER_TOK &tok,TICKET_SHOW &tic)
{
    //SPS-EQ change present
    Big r1,r2,k1,k2,k3,v1,v2,k1_inver,k2_inver;
    pfc->random(v1);
    pfc->random(k1);
    k1_inver=pfc->Zpinverse(k1);
    tic._spk.X_=pfc->mult(tok.s_pub_cred.spk.X_,v1);
    for(int i=0;i<5;i++)
    {
        tic._spk.Y_[i]=pfc->mult(tok.s_pub_cred.spk.Y_[i],v1);
    }
    Big m;
    m=pfc->Zpmulti(v1,k1);
    tic._cred_s.Z_=pfc->mult(tok.s_pub_cred.cred_s.Z_,m);
    tic._cred_s.Y=pfc->mult(tok.s_pub_cred.cred_s.Y,k1_inver);
    tic._cred_s.Y_=pfc->mult(tok.s_pub_cred.cred_s.Y_,k1_inver);
    //cred derive
    pfc->random(v2);
    pfc->random(k2);
    tic._cred_u.Cu=pfc->mult(cred_u.Cu,v2);

    tic._cred_u.pk=pfc->mult(cred_u.pk,v2);

    k2_inver=pfc->Zpinverse(k2);
    tic._cred_u.sig.Y=pfc->mult(cred_u.sig.Y,k2_inver);
    tic._cred_u.sig.Y_=pfc->mult(cred_u.sig.Y_,k2_inver);
    m=pfc->Zpmulti(v2,k2);
    tic._cred_u.sig.Z=pfc->mult(cred_u.sig.Z,m);

    //tic derive
    pfc->random(r1);
    m=pfc->Zpmulti(r1,v1);
    tic._T1=pfc->mult(tok.T1,r1);
    tic._T2=pfc->mult(tok.T2,m);

    //double detect
    pfc->start_hash();
    pfc->add_to_hash(tic._spk.X_);
    for(int i=0;i<5;i++)
        pfc->add_to_hash(tic._spk.Y_[i]);
    pfc->add_to_hash(tic._cred_s.Z_);
    pfc->add_to_hash(tic._cred_s.Y);
    pfc->add_to_hash(tic._cred_s.Y_);

    pfc->add_to_hash(tic._cred_u.Cu);

    pfc->add_to_hash(tic._cred_u.pk);
    pfc->add_to_hash(tic._cred_u.sig.Z);
    pfc->add_to_hash(tic._cred_u.sig.Y);
    pfc->add_to_hash(tic._cred_u.sig.Y_);
    pfc->add_to_hash(tic._T1);
    pfc->add_to_hash(tic._T2);
    tic.ch=pfc->finish_hash_to_group();
    Big t=pfc->Zpmulti(tic.ch,tok.ek);
    tic.s=pfc->Zpadd(t,tok.dsrnd);

    //encrypt
    pfc->random(k3);
    tic.C1_=pfc->mult(pp.w_,k3);
    m=pfc->Zpmulti(k3,tok.ek);
    G1 T=pfc->mult(pp.w_,m);
    tic.C2_=T+user_key.upk.Y;
#if 0
    tic.ek=tok.ek;
    tic.upk=user_key.upk.Y_;
#endif
    //K and v
    tic.K=tic._spk.X_;
    G2 T_=pfc->mult(tic._spk.Y_[0],tok.usk);
    tic.K=tic.K+T_;
    T_=pfc->mult(tic._spk.Y_[1],tok.dsrnd);
    tic.K=tic.K+T_;
    T_=pfc->mult(tic._spk.Y_[2],tok.ek);
    tic.K=tic.K+T_;
    T_=pfc->mult(tic._spk.Y_[3],tok.tid);
    tic.K=tic.K+T_;
    T_=pfc->mult(tic._spk.Y_[4],tok.vt);
    tic.K=tic.K+T_;
    pfc->random(r2);
    T_=pfc->mult(g_,r2);
    tic.K=tic.K+T_;
    tic.V=pfc->mult(tic._T1,r2);

    //compute Pi4
    Big gm[7];
    for(int i=0;i<7;i++)
        pfc->random(gm[i]);
    G1 _g=pfc->mult(g,tic.ch);
    G1 Rv,Rs,R1,R2,Rfei,Rk;

    G2 RK=pfc->mult(tic._spk.Y_[0],gm[0]);
    T_=pfc->mult(tic._spk.Y_[1],gm[1]);
    RK=RK+T_;
    T_=pfc->mult(tic._spk.Y_[2],gm[2]);
    RK=RK+T_;
    T_=pfc->mult(g_,gm[4]);
    RK=RK+T_;
    Rv=pfc->mult(tic._T1,gm[4]);
    Rs=pfc->mult(g,gm[1]);
    Rs=Rs+pfc->mult(_g,gm[2]);
    R1=pfc->mult(pp.w_,gm[3]);
    R2=pfc->mult(g,gm[0])+pfc->mult(tic.C1_,gm[2]);

    tic.pi_4.fei=pfc->mult(g,v2);
    Rfei=pfc->mult(g,gm[5]);
    Rk=pfc->mult(tic.pi_4.fei,gm[0]);

    pfc->start_hash();
    pfc->add_to_hash(tic.K);
    pfc->add_to_hash(tic.V);
    pfc->add_to_hash(tic.s);
    pfc->add_to_hash(tic.C1_);
    pfc->add_to_hash(tic.C2_);

    pfc->add_to_hash(tic._cred_u.pk);

    pfc->add_to_hash(RK);

    pfc->add_to_hash(Rv);

    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);


    pfc->add_to_hash(tic.pi_4.fei);
    pfc->add_to_hash(Rfei);
    pfc->add_to_hash(Rk);

    tic.pi_4.c=pfc->finish_hash_to_group();

    t=pfc->Zpmulti(tic.pi_4.c,tok.usk);
    tic.pi_4.s_usk=pfc->Zpsub(gm[0],t);
    t=pfc->Zpmulti(tic.pi_4.c,tok.dsrnd);
    tic.pi_4.s_dsrnd=pfc->Zpsub(gm[1],t);
    t=pfc->Zpmulti(tic.pi_4.c,tok.ek);
    tic.pi_4.s_ek=pfc->Zpsub(gm[2],t);
    t=pfc->Zpmulti(tic.pi_4.c,k3);
    tic.pi_4.s_k=pfc->Zpsub(gm[3],t);

    t=pfc->Zpmulti(tic.pi_4.c,r2);
    tic.pi_4.s_r=pfc->Zpsub(gm[4],t);

    t=pfc->Zpmulti(tic.pi_4.c,v2);
    tic.pi_4.s_v=pfc->Zpsub(gm[5],t);


    //tic.pi_4.s_miu=pfc->Zpsub(gm[6],t);
    tic.tid=tok.tid;
    tic.vt=tok.vt;
    return 0;

}
int ESPPTAT::TicktShowing_V_Verify(PP &pp,TICKET_SHOW &tic,DS_INFO &ds_info)
{
    //Verify cred_s
    #if 1
    GT E1,E2;
    E1=pfc->pairing(tic._cred_s.Y_,g);
    E2=pfc->pairing(g_,tic._cred_s.Y);
    if(E1 != E2) return -1;
    GT M;
    E1=pfc->pairing(tic._spk.X_,pp.s_pub.X);
    for(int i=0;i<=4;i++)
    {
        M=pfc->pairing(tic._spk.Y_[i],pp.s_pub.Y[i]);
        E1=M*E1;
    }
    E2=pfc->pairing(tic._cred_s.Z_,tic._cred_s.Y);
    if(E1 != E2) return -2;

    //verify cred_u
    E1=pfc->pairing(tic._cred_u.sig.Y_,g);
    E2=pfc->pairing(g_,tic._cred_u.sig.Y);
    if(E1 != E2) return -3;
    E1=pfc->pairing(pp.u_pub.X_[0],tic._cred_u.Cu)*pfc->pairing(pp.u_pub.X_[1],tic._cred_u.pk);
    E2=pfc->pairing(tic._cred_u.sig.Y_,tic._cred_u.sig.Z);
    if(E1 != E2) return -4;
    //verify K,v
    G1 T=tic._T2+tic.V;
    E1=pfc->pairing(tic.K,tic._T1);
    E2=pfc->pairing(g_,T);
    if(E1 != E2) return -5;

    //Verify Pi_4
    G1 Rv,Rs,R1,R2,Rfei,Rk;

    G2 RK;
    G1 _g=pfc->mult(g,tic.ch);
    RK=pfc->mult(tic._spk.Y_[0],tic.pi_4.s_usk);
    G2 T_=pfc->mult(tic._spk.Y_[1],tic.pi_4.s_dsrnd);
    RK=RK+T_;
    T_=pfc->mult(tic._spk.Y_[2],tic.pi_4.s_ek);
    RK=RK+T_;
    T_=pfc->mult(g_,tic.pi_4.s_r);
    RK=RK+T_;
    T_=tic._spk.X_+pfc->mult(tic._spk.Y_[3],tic.tid)+pfc->mult(tic._spk.Y_[4],tic.vt);
    T_=tic.K+(-T_);
    T_=pfc->mult(T_,tic.pi_4.c);
    RK=RK+T_;
    Rv=pfc->mult(tic._T1,tic.pi_4.s_r)+pfc->mult(tic.V,tic.pi_4.c);
    Rs=pfc->mult(g,tic.pi_4.s_dsrnd)+pfc->mult(_g,tic.pi_4.s_ek)+pfc->mult(tic.pi_4.fei,tic.pi_4.c);
    R1=pfc->mult(pp.w_,tic.pi_4.s_k)+pfc->mult(tic.C1_,tic.pi_4.c);
    R2=pfc->mult(g,tic.pi_4.s_usk)+pfc->mult(tic.C1_,tic.pi_4.s_ek)+pfc->mult(tic.C2_,tic.pi_4.c);

    Rfei=pfc->mult(g,tic.pi_4.s_v)+pfc->mult(tic.pi_4.fei,tic.pi_4.c);
    Rk=pfc->mult(tic.pi_4.fei,tic.pi_4.s_usk)+pfc->mult(tic._cred_u.pk,tic.pi_4.c);

    pfc->start_hash();
    pfc->add_to_hash(tic.K);
    pfc->add_to_hash(tic.V);
    pfc->add_to_hash(tic.s);
    pfc->add_to_hash(tic.C1_);
    pfc->add_to_hash(tic.C2_);

    pfc->add_to_hash(tic._cred_u.pk);

    pfc->add_to_hash(RK);

    pfc->add_to_hash(Rv);

    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);


    pfc->add_to_hash(tic.pi_4.fei);
    pfc->add_to_hash(Rfei);
    pfc->add_to_hash(Rk);

    Big c=pfc->finish_hash_to_group();
    if(c != tic.pi_4.c) return -6;
    //restore ds_info
    ds_info.C1_=tic.C1_;
    ds_info.C2_=tic.C2_;
    ds_info.ch=tic.ch;
    ds_info.s=tic.s;
    ds_info.tid=tic.tid;
#endif
#if 0
    ds_info.ek=tic.ek;
    ds_info.upk=tic.upk;
#endif
    return 0;

}
//双花追踪
int ESPPTAT::DB_Trace(PP &pp, DS_INFO &ds_info1, DS_INFO &ds_info2, TRACE_PUB &upk)
{
    if(ds_info1.tid != ds_info2.tid) return -1;
    Big s,c,ek;
    s=pfc->Zpsub(ds_info1.s,ds_info2.s);
    c=pfc->Zpsub(ds_info1.ch,ds_info1.ch);
    c=pfc->Zpinverse(c);
    ek=pfc->Zpmulti(s,c);
    G1 T_=pfc->mult(-ds_info1.C1_,ek);
    upk.upk1.Y=ds_info1.C2_+T_;
    T_=pfc->mult(-ds_info2.C1_,ek);
    upk.upk2.Y=ds_info2.C2_+T_;
#if 0
    if(ds_info1.ek != ds_info2.ek) return -1;
    if(ds_info1.ek != ek) return -2;

    if(ds_info1.upk != upk.upk1.Y_) return -3;
    if(ds_info2.upk != upk.upk2.Y_) return -4;
#endif

    return 0;
}
