#include"espptat.h"
#include "pairing_3.h"
#include <ctime>
#include <time.h>
#define TEST_TIME 50
int correct_test()
{
    PFC pfc(AES_SECURITY);

    ESPPTAT E_Tickets(&pfc);
    int ret =0;
//1 SetUP
    PP pp;
    MSK msk;
    ret = E_Tickets.SetUp(pp,msk);
    if(ret != 0)
    {
        printf("E_Tickets.SetUp Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.SetUp pass\n");
//2 Seller Registration
    SELLER_KEY seller_key;
    Pi_1 pi_1;
    ret=E_Tickets.SellerRegister_S_Init(pp,seller_key,pi_1);
    if(ret != 0)
    {
        printf("E_Tickets.SellerRegister_S_Init Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.SellerRegister_S_Init pass\n");
    SELLER_CRED cred_s;
    ret=E_Tickets.SellerRegister_CA_Issue(pp,msk, seller_key.spk,pi_1,cred_s);
    if(ret != 0)
    {
        printf("E_Tickets.SellerRegister_CA_Issue Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.SellerRegister_CA_Issue pass\n");
    ret=E_Tickets.SellerRegister_S_Rcv(pp,seller_key,cred_s);
    if(ret != 0)
    {
        printf("E_Tickets.SellerRegister_S_Rcv Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.SellerRegister_S_Rcv pass\n");
//3 User Registration
    USER_KEY user_key;
    USER_CRED cred_u;
    Pi_2 pi_2;
    ret=E_Tickets.UserRegister_U_Init(pp,user_key,pi_2,cred_u);
    if(ret != 0)
    {
        printf("E_Tickets.UserRegister_U_Init Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.UserRegister_U_Init pass\n");

    ret=E_Tickets.UserRegister_CA_Issue(pp,msk,user_key.upk,pi_2,user_key.usk.att,cred_u);
    if(ret != 0)
    {
        printf("E_Tickets.UserRegister_CA_Issue Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.UserRegister_CA_Issue pass\n");
    ret=E_Tickets.UserRegister_U_Rcv(pp,user_key,cred_u);
    if(ret != 0)
    {
        printf("E_Tickets.UserRegister_U_Rcv Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.UserRegister_U_Rcv pass\n");

//3_ User Registration
    USER_KEY _user_key;
    USER_CRED _cred_u;
    Pi_2 _pi_2;
    ret=E_Tickets.UserRegister_U_Init(pp,_user_key,_pi_2,_cred_u);
    if(ret != 0)
    {
        printf("E_Tickets.UserRegister_U_Init Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.UserRegister_U_Init pass\n");

    ret=E_Tickets.UserRegister_CA_Issue(pp,msk,_user_key.upk,_pi_2,_user_key.usk.att,_cred_u);
    if(ret != 0)
    {
        printf("E_Tickets.UserRegister_CA_Issue Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.UserRegister_CA_Issue pass\n");
    ret=E_Tickets.UserRegister_U_Rcv(pp,_user_key,_cred_u);
    if(ret != 0)
    {
        printf("E_Tickets.UserRegister_U_Rcv Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.UserRegister_U_Rcv pass\n");
//4 Ticket Issuing
    SELLER_CRED_PROV s_prov;

    ret=E_Tickets.TicktPurchasing_S_Init(pp, seller_key, cred_s,s_prov);
    if(ret != 0)
    {
        printf("E_Tickets.TicktPurchasing_S_Init Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TicktPurchasing_S_Init pass\n");
    USER_INIT user_init;
    USER_TOK tok;
    ret=E_Tickets.TicktPurchasing_U_Init(pp,s_prov,user_key,cred_u,user_init,tok);
    if(ret != 0)
    {
        printf("E_Tickets.TicktPurchasing_U_Init Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TicktPurchasing_U_Init pass\n");
    SELLER_ISSUE s_issue;
    ret=E_Tickets.TicktPurchasing_S_Issue(pp,seller_key,s_prov,user_init,s_issue);
    if(ret != 0)
    {
        printf("E_Tickets.TicktPurchasing_S_Issue Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TicktPurchasing_S_Issue pass\n");
    ret=E_Tickets.TicktPurchasing_U_Rcv(pp,tok,s_issue);
    if(ret != 0)
    {
        printf("E_Tickets.TicktPurchasing_U_Rcv Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TicktPurchasing_U_Rcv pass\n");

//5 Ticket Transfer
    F1_TRAN f1_tran;
    ret=E_Tickets.TicktTransfering_SU_f1_Tran(pp,user_key,tok,f1_tran);
    if(ret != 0)
    {
        printf("E_Tickets.TicktTransfering_SU_f1_Tran Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TicktTransfering_SU_f1_Tran pass\n");
    USER_TOK _tok;
    ret=E_Tickets.TicktTransfering_RU_f1_Rcv(pp,_user_key,f1_tran,_tok);
    if(ret != 0)
    {
        printf("E_Tickets.TicktTransfering_RU_f1_Rcv Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TicktTransfering_RU_f1_Rcv pass\n");

//6 Ticket Showing
    TICKET_SHOW tic;
    ret=E_Tickets.TicktShowing_U_Show(pp,user_key,cred_u,tok,tic);
    if(ret != 0)
    {
        printf("E_Tickets.TicktShowing_U_Show Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TicktShowing_U_Show pass\n");
    DS_INFO ds_info;
    ret=E_Tickets.TicktShowing_V_Verify(pp,tic,ds_info);
    if(ret != 0)
    {
        printf("E_Tickets.TicktShowing_V_Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TicktShowing_V_Verify pass\n");
    /////////////
    TICKET_SHOW _tic;
    ret=E_Tickets.TicktShowing_U_Show(pp,_user_key,_cred_u,_tok,_tic);
    if(ret != 0)
    {
        printf("E_Tickets.TicktShowing_U_Show tran Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TicktShowing_U_Show tran pass\n");
    DS_INFO _ds_info;
    ret=E_Tickets.TicktShowing_V_Verify(pp,_tic,_ds_info);
    if(ret != 0)
    {
        printf("E_Tickets.TicktShowing_V_Verify tran Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.TicktShowing_V_Verify tran pass\n");

//7 DStrace
    TRACE_PUB upk;
    ret=E_Tickets.DB_Trace(pp,ds_info,_ds_info,upk);
    if(ret != 0)
    {
        printf("E_Tickets.DB_Trace tran Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("E_Tickets.DB_Trace tran pass\n");
    return 0;
}
int speed_test()
{
    int i;
    clock_t start,finish;
    double sum;
    PFC pfc(AES_SECURITY);

    ESPPTAT E_Tickets(&pfc);
    int ret =0;
    //1 SetUP
    PP pp;
    MSK msk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = E_Tickets.SetUp(pp,msk);
        if(ret != 0)
        {
            printf("E_Tickets.SetUp Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.SetUp ret : %d time =%f sec\n",ret,sum);
    //2 Seller Registration
    SELLER_KEY seller_key;
    Pi_1 pi_1;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.SellerRegister_S_Init(pp,seller_key,pi_1);
        if(ret != 0)
        {
            printf("E_Tickets.SellerRegister_S_Init Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.SellerRegister_S_Init ret : %d time =%f sec\n",ret,sum);
    SELLER_CRED cred_s;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.SellerRegister_CA_Issue(pp,msk, seller_key.spk,pi_1,cred_s);
        if(ret != 0)
        {
            printf("E_Tickets.SellerRegister_CA_Issue Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.SellerRegister_CA_Issue ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.SellerRegister_S_Rcv(pp,seller_key,cred_s);
        if(ret != 0)
        {
            printf("E_Tickets.SellerRegister_S_Rcv Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.SellerRegister_S_Rcv ret : %d time =%f sec\n",ret,sum);
    //2 User Registration
    USER_KEY user_key;
    USER_CRED cred_u;
    Pi_2 pi_2;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.UserRegister_U_Init(pp,user_key,pi_2,cred_u);
        if(ret != 0)
        {
            printf("E_Tickets.UserRegister_U_Init Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.UserRegister_U_Init ret : %d time =%f sec\n",ret,sum);

    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.UserRegister_CA_Issue(pp,msk,user_key.upk,pi_2,user_key.usk.att,cred_u);
        if(ret != 0)
        {
            printf("E_Tickets.UserRegister_CA_Issue Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.UserRegister_CA_Issue ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.UserRegister_U_Rcv(pp,user_key,cred_u);
        if(ret != 0)
        {
            printf("E_Tickets.UserRegister_U_Rcv Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.UserRegister_U_Rcv ret : %d time =%f sec\n",ret,sum);

    //2 User Registration
    USER_KEY _user_key;
    USER_CRED _cred_u;
    Pi_2 _pi_2;
    ret=E_Tickets.UserRegister_U_Init(pp,_user_key,_pi_2,_cred_u);
    if(ret != 0)
    {
        printf("E_Tickets.UserRegister_U_Init Erro ret =%d\n",ret);
        return 1;
    }

    ret=E_Tickets.UserRegister_CA_Issue(pp,msk,_user_key.upk,_pi_2,_user_key.usk.att,_cred_u);
    if(ret != 0)
    {
        printf("E_Tickets.UserRegister_CA_Issue Erro ret =%d\n",ret);
        return 1;
    }
    ret=E_Tickets.UserRegister_U_Rcv(pp,_user_key,_cred_u);
    if(ret != 0)
    {
        printf("E_Tickets.UserRegister_U_Rcv Erro ret =%d\n",ret);
        return 1;
    }
    //3 Ticket Issuing
    SELLER_CRED_PROV s_prov;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.TicktPurchasing_S_Init(pp, seller_key, cred_s,s_prov);
        if(ret != 0)
        {
            printf("E_Tickets.TicktPurchasing_S_Init Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.TicktPurchasing_S_Init ret : %d time =%f sec\n",ret,sum);
    USER_INIT user_init;
    USER_TOK tok;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.TicktPurchasing_U_Init(pp,s_prov,user_key,cred_u,user_init,tok);
        if(ret != 0)
        {
            printf("E_Tickets.TicktPurchasing_U_Init Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.TicktPurchasing_U_Init ret : %d time =%f sec\n",ret,sum);
    SELLER_ISSUE s_issue;
    u8 fs=1;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.TicktPurchasing_S_Issue(pp,seller_key,s_prov,user_init,s_issue);
        if(ret != 0)
        {
            printf("E_Tickets.TicktPurchasing_S_Issue Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.TicktPurchasing_S_Issue ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<1;i++)
    {
        ret=E_Tickets.TicktPurchasing_U_Rcv(pp,tok,s_issue);
        if(ret != 0)
        {
            printf("E_Tickets.TicktPurchasing_U_Rcv Erro ret =%d Time=%d\n",ret,i);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.TicktPurchasing_U_Rcv ret : %d time =%f sec\n",ret,sum);


    //4 Ticket Transfer
    F1_TRAN f1_tran;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.TicktTransfering_SU_f1_Tran(pp,user_key,tok,f1_tran);
        if(ret != 0)
        {
            printf("E_Tickets.TicktTransfering_SU_f1_Tran Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.TicktTransfering_SU_f1_Tran ret : %d time =%f sec\n",ret,sum);
    USER_TOK _tok;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.TicktTransfering_RU_f1_Rcv(pp,_user_key,f1_tran,_tok);
        if(ret != 0)
        {
            printf("E_Tickets.TicktTransfering_RU_f1_Rcv Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.TicktTransfering_RU_f1_Rcv ret : %d time =%f sec\n",ret,sum);
    //5 Ticket Showing
    TICKET_SHOW tic;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.TicktShowing_U_Show(pp,user_key,cred_u,tok,tic);
        if(ret != 0)
        {
            printf("E_Tickets.TicktShowing_U_Show Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.TicktShowing_U_Show ret : %d time =%f sec\n",ret,sum);
    DS_INFO ds_info;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.TicktShowing_V_Verify(pp,tic,ds_info);
        if(ret != 0)
        {
            printf("E_Tickets.TicktShowing_V_Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.TicktShowing_V_Verify ret : %d time =%f sec\n",ret,sum);
    /////////////
    TICKET_SHOW _tic;
    ret=E_Tickets.TicktShowing_U_Show(pp,_user_key,_cred_u,_tok,_tic);
    if(ret != 0)
    {
        printf("E_Tickets.TicktShowing_U_Show tran Erro ret =%d\n",ret);
        return 1;
    }
    DS_INFO _ds_info;
    ret=E_Tickets.TicktShowing_V_Verify(pp,_tic,_ds_info);
    if(ret != 0)
    {
        printf("E_Tickets.TicktShowing_V_Verify tran Erro ret =%d\n",ret);
        return 1;
    }

    //6 DStrace
    TRACE_PUB upk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret=E_Tickets.DB_Trace(pp,ds_info,_ds_info,upk);
        if(ret != 0)
        {
            printf("E_Tickets.DB_Trace tran Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("E_Tickets.DB_Trace ret : %d time =%f sec\n",ret,sum);
    return 0;



    return 0;
}
int main()
{

#if 0
    int ret =correct_test();
    if(ret != 0)
    {

        printf("E_Tickets correct_test Erro ret =%d\n",ret);
        return 1;
    }
    else
    {
        printf("*******************************************\n");
        printf("E_Tickets correct_test pass\n");
    }
#endif
#if 1
    int ret =speed_test();
    if(ret != 0)
    {
        printf("E_Tickets speed_test Erro ret =%d\n",ret);
        return 1;
    }
#endif
    return 0;
}
