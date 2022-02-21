/***********************************************************************************
************************************************************************************
* @author     Mengling LIU
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/
#ifndef __SIGN__
#define __SIGN__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"


struct Signature_PP
{
    EC_POINT *g; 
};


struct Signature_Instance
{
    EC_POINT *pk;
    BIGNUM *sk;
    BIGNUM *k;
};


// structure of result 
struct Signature_Result
{
    BIGNUM *r, *s;    
    EC_POINT *R; 
    EC_POINT *A;
};

void Signature_Instance_new(Signature_Instance &instance)
{
    instance.pk = EC_POINT_new(group);
    instance.sk = BN_new();
    instance.k = BN_new();
}

void Signature_Instance_free(Signature_Instance &instance)
{
    EC_POINT_free(instance.pk);
    BN_free(instance.sk);
    BN_free(instance.k);
}


void Signature_Result_new(Signature_Result &result)
{
    result.r = BN_new(); 
    result.s = BN_new();
    result.R = EC_POINT_new(group);
    result.A = EC_POINT_new(group);
}

void Signature_Result_free(Signature_Result &result)
{
    BN_free(result.r);
    BN_free(result.s);
    EC_POINT_free(result.R);
    EC_POINT_free(result.A);
}


void Signature_Instance_print(Signature_Instance &instance)
{
    cout << "Signature Instance >>> " << endl; 
    ECP_print(instance.pk, "instance.pk"); 
    BN_print(instance.sk, "instance.sk");
    BN_print(instance.k, "instance.k");   
} 

void Signature_Result_print(Signature_Result &result)
{
    SplitLine_print('-'); 
    cout << "Signature result >>> " << endl; 
    BN_print(result.r, "result.r"); 
    BN_print(result.s, "result.s"); 
    ECP_print(result.R, "result.R");
    ECP_print(result.A, "result.A");
} 

void Signature_Result_serialize(Signature_Result &result, ofstream &fout)
{
    BN_serialize(result.r, fout); 
    BN_serialize(result.s, fout);
    ECP_serialize(result.R,  fout);
    ECP_serialize(result.A,  fout);
} 

void Signature_Result_deserialize(Signature_Result &result, ifstream &fin)
{
    BN_deserialize(result.r, fin); 
    BN_deserialize(result.s, fin);
    ECP_deserialize(result.R,  fin); 
    ECP_deserialize(result.A,  fin);
} 

/* Setup algorithm */ 
void Signature_Setup(Signature_PP &pp)
{ 
    
    EC_POINT_copy(pp.g, generator); 
}

/* allocate memory for pp */ 
void Signature_PP_new(Signature_PP &pp)
{ 
    pp.g = EC_POINT_new(group);
}

/* free memory of pp */ 
void Signature_PP_free(Signature_PP &pp)
{ 
    EC_POINT_free(pp.g); 
}

/* KeyGen algorithm */ 
void Signature_KeyGen(Signature_PP &pp, Signature_Instance &instance)
{ 
    //BN_random(instance.sk); // sk \sample Z_p
    BN_hex2bn(&instance.sk, "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f");
    BN_hex2bn(&instance.k, "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a");
    EC_POINT_mul(group, instance.pk, instance.sk, NULL, NULL, bn_ctx); // pk = g1^sk  

    #ifdef DEBUG
    cout << "key generation finished >>>" << endl;  
    Signature_Instance_print(instance); 
    #endif
}


void Signature_Sign(Signature_PP &pp, 
                                   Signature_Instance &instance, 
                                   BIGNUM* &m, // m = hash(message) 
                                   Signature_Result &result)
{   
    BIGNUM *tmp=BN_new();
    BIGNUM *X=BN_new();
    BIGNUM *kinv=BN_new();
    BIGNUM *Y=BN_new();
    EC_POINT *point = EC_POINT_new(group);
    
    do{
        //BN_random(instance.k); // k <- Zq
        EC_POINT_mul(group, result.R, NULL, pp.g, instance.k, bn_ctx); // R = g1^k
        EC_POINT_get_affine_coordinates_GFp(group, result.R, X, Y, bn_ctx); // X = R's x coordinate
        //ECP_print(result.R, "result.R");
        //EC_POINT_set_affine_coordinates_GFp(group, point, X, Y, bn_ctx);
        //ECP_print(point, "recover from x,y");
        //BN_print(X, "X coordinate");
        //E_print(order, "order");
        BN_nnmod(result.r, X, order, bn_ctx); // r = X mod q
        BN_mod_inverse(kinv, instance.k, order, bn_ctx); // kinv = k^-1
        BN_mod_mul(tmp, instance.sk, result.r, order, bn_ctx); // tmp = r*sk mod q
        BN_mod_add_quick(result.s, tmp, m, order); // s = r*sk + m
        BN_mod_mul(result.s, result.s, kinv, order, bn_ctx); // s = k^-1(r*sk+m)

        EC_POINT_mul(group, result.A, m, instance.pk, result.r, bn_ctx); // A=g1^m pk^r

        if(!BN_is_zero(result.s)){
            break;
        }
    }while(1);
    BN_clear_free(tmp);
    BN_clear_free(X);
    BN_clear_free(kinv);

    #ifdef DEBUG
    Signature_Result_print(result); 
    #endif
}


bool Signature_Verify(Signature_PP &pp, 
                                    Signature_Instance &instance, 
                                    BIGNUM* &m, //m = hash(message)
                                    Signature_Result &result)
{
    BIGNUM *tmp=BN_new();
    BIGNUM *X=BN_new();
    BIGNUM *u1=BN_new();
    BIGNUM *u2=BN_new();
    EC_POINT *point = EC_POINT_new(group);
    bool Validity;
    BN_mod_inverse(u2, result.s, order, bn_ctx); // u2 = s^-1
    BN_mod_mul(u1, m, u2, order, bn_ctx); // u1 = m*s^-1
    BN_mod_mul(u2, result.r, u2, order, bn_ctx); // u2 = r*s^-1
    EC_POINT_mul(group, point, u1, instance.pk, u2, bn_ctx); // point = g1^m*s^-1 pk^r*s^-1
    EC_POINT_get_affine_coordinates_GFp(group, point, X, NULL, bn_ctx); // X = point's x coordinate
    BN_nnmod(u1, X, order, bn_ctx); // u1 = X mod q

    Validity = (BN_ucmp(u1, result.r) == 0); // Assert X mod q  == r

    #ifdef DEBUG 

    if (Validity) 
    { 
        cout<< "Signature accept >>>" << endl; 
    }
    else 
    {
        cout<< "Signature reject >>>" << endl; 
    }
    #endif

    BN_clear_free(tmp);
    BN_clear_free(X);
    BN_clear_free(u1); 
    BN_clear_free(u2);
    EC_POINT_free(point);
    return Validity;
}

#endif



