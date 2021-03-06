/***********************************************************************************
************************************************************************************
* @author     Mengling LIU
* @copyright  MIT license (see LICENSE file)
***********************************************************************************/
#ifndef __SIGMA__
#define __SIGMA__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

struct Sigma_PP
{
    EC_POINT *g; // g = twisted elgamal encryption's g
    EC_POINT *h; // h = twisted elgamal encryption's h
};

struct Sigma_Instance
{
    EC_POINT *twisted_ek; 
    // twisted_ek = twisted elgamal encryption's encryption key
    // R = signature's R = g1^k, g1 = signature's g1
    EC_POINT *U, *V; 
    // U = twisted elgamal encryption's result u
    // V = twisted elgamal encryption's result v
    // A = signature'A = g1^h Q^r , g1 = signature's g1, Q = signature' pk 
};

// structure of witness 
struct Sigma_Witness
{
    //BIGNUM *v; // v = signature's s
    BIGNUM *r; // r = twisted elgamal encryption's random value beta
};


// structure of proof 
struct Sigma_Proof
{
    EC_POINT *Y1, *Y2, *Y3, *Y4; // P's first round message
    BIGNUM *beta1, *beta2, *omega1, *omega2;    // P's response in Zq
};

void Sigma_Instance_new(Sigma_Instance &instance)
{
    instance.twisted_ek = EC_POINT_new(group);
    
    instance.U  = EC_POINT_new(group);
    instance.V  = EC_POINT_new(group);
}

void Sigma_Instance_free(Sigma_Instance &instance)
{
    EC_POINT_free(instance.twisted_ek);
   
    EC_POINT_free(instance.U);
    EC_POINT_free(instance.V);
}

void Sigma_Witness_new(Sigma_Witness &witness)
{
    
    witness.r = BN_new(); 
}

void Sigma_Witness_free(Sigma_Witness &witness)
{
    
    BN_free(witness.r); 
}

void Sigma_Proof_new(Sigma_Proof &proof)
{
    proof.Y2 = EC_POINT_new(group); 
    proof.Y3 = EC_POINT_new(group); 
    proof.Y1  = EC_POINT_new(group);
    proof.Y4  = EC_POINT_new(group);
    proof.beta1 = BN_new(); 
    proof.beta2 = BN_new();
    proof.omega1 = BN_new();
    proof.omega2 = BN_new();
}

void Sigma_Proof_free(Sigma_Proof &proof)
{
    EC_POINT_free(proof.Y2);
    EC_POINT_free(proof.Y3);
    EC_POINT_free(proof.Y1);
    EC_POINT_free(proof.Y4);
    BN_free(proof.beta1);
    BN_free(proof.beta2);
    BN_free(proof.omega1);
    BN_free(proof.omega2);
}


void Sigma_Instance_print(Sigma_Instance &instance)
{
    cout << "Sigma Instance >>> " << endl; 
    ECP_print(instance.twisted_ek, "instance.twisted_ek"); 
    
    ECP_print(instance.U, "instance.C1"); 
    ECP_print(instance.V, "instance.C2");     
} 

void Sigma_Witness_print(Sigma_Witness &witness)
{
    cout << "Sigma Witness >>> " << endl; 
    BN_print(witness.r, "witness.r"); 
} 

void Sigma_Proof_print_Zero(Sigma_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "Sigma proof >>> " << endl;
    ECP_print(proof.Y1, "proof.Y1 = g^mu"); 
    ECP_print(proof.Y2, "proof.Y2 = PK^mu"); 
    ECP_print(proof.Y3, "proof.Y3 = g^omega2.((C1/h)^beta2)^-1"); 
    ECP_print(proof.Y4, "proof.Y4 = pk^omega2.(C2^beta2)^-1"); 
    BN_print(proof.beta1, "proof.beta1"); 
    BN_print(proof.beta2, "proof.beta2"); 
    BN_print(proof.omega1, "proof.omega1"); 
    BN_print(proof.omega2, "proof.omega2");
} 

void Sigma_Proof_print_One(Sigma_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "Sigma proof >>> " << endl;
    ECP_print(proof.Y1, "proof.Y1 = g^omega1.(C1^beta1)^-1"); 
    ECP_print(proof.Y2, "proof.Y2 = PK^omega1.(C2^beta1)^-1"); 
    ECP_print(proof.Y3, "proof.Y3 = g^mu2"); 
    ECP_print(proof.Y4, "proof.Y4 = pk^mu2"); 
    BN_print(proof.beta1, "proof.beta1"); 
    BN_print(proof.beta2, "proof.beta2"); 
    BN_print(proof.omega1, "proof.omega1"); 
    BN_print(proof.omega2, "proof.omega2");
} 

void Sigma_Proof_serialize(Sigma_Proof &proof, ofstream &fout)
{
    ECP_serialize(proof.Y2, fout); 
    ECP_serialize(proof.Y3, fout);
    ECP_serialize(proof.Y1,  fout);
    BN_serialize(proof.beta1, fout); 
    BN_serialize(proof.beta2, fout); 
    BN_serialize(proof.omega1, fout); 
    BN_serialize(proof.omega2, fout); 
} 

void Sigma_Proof_deserialize(Sigma_Proof &proof, ifstream &fin)
{
    ECP_deserialize(proof.Y2, fin); 
    ECP_deserialize(proof.Y3, fin);
    ECP_deserialize(proof.Y1,  fin);
    BN_deserialize(proof.beta1, fin); 
    BN_deserialize(proof.beta2, fin); 
    BN_deserialize(proof.omega1, fin); 
    BN_deserialize(proof.omega2, fin);
} 

void Sigma_PP_print(Sigma_PP &pp)
{
    ECP_print(pp.g, "pp.g"); 
    ECP_print(pp.h, "pp.h"); 
}
/* Setup algorithm */ 
void Sigma_Setup(Sigma_PP &pp, EC_POINT* &h)
{ 
    
    EC_POINT_copy(pp.g, generator); 
    EC_POINT_copy(pp.h, h);  
    #ifdef DEBUG
    cout << "generate the public parameters for sigmaproof >>>" << endl; 
    Sigma_PP_print(pp); 
    #endif
}


/* allocate memory for pp */ 
void Sigma_PP_new(Sigma_PP &pp)
{ 
    pp.g = EC_POINT_new(group);
    pp.h = EC_POINT_new(group); 
}

/* free memory of pp */ 
void Sigma_PP_free(Sigma_PP &pp)
{ 
    EC_POINT_free(pp.g); 
    EC_POINT_free(pp.h); 
}

void Sigma_Prove_Zero(Sigma_PP &pp, 
                                   Sigma_Instance &instance, 
                                   Sigma_Witness &witness, 
                                   string &transcript_str, 
                                   Sigma_Proof &proof)
{    
    // initialize the transcript with instance 
    #ifdef DEBUG
    cout << "Sigma proof start >>>" << endl;  
    Sigma_Instance_print(instance); 
    Sigma_Witness_print(witness);
    #endif

    BIGNUM *mu = BN_new(); 
    BIGNUM *negone = BN_new();
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];


    BN_copy(negone, BN_1);
    BN_set_negative(negone, 1);
    


    EC_POINT *c1_h = EC_POINT_new(group); 
    vec_A[0] = instance.U; 
    vec_A[1] = pp.h; 
    vec_x[0] = BN_1; 
    vec_x[1] = negone;
    EC_POINTs_mul(group, c1_h, NULL, 2, vec_A, vec_x, bn_ctx); //c1_h = c1^1.h^-1



    BN_random(mu);
    BN_random(proof.beta2);
    BN_random(proof.omega2);

    EC_POINT_mul(group, proof.Y1, NULL, pp.g, mu, bn_ctx); // Y1 = g^mu
    EC_POINT_mul(group, proof.Y2, NULL, instance.twisted_ek, mu, bn_ctx); // Y2 =  PK^mu
    

    EC_POINT_mul(group, proof.Y3, NULL, c1_h, proof.beta2, bn_ctx); //   (c1/h)^beta2
    vec_A[0] = pp.g; 
    vec_A[1] = proof.Y3; 
    vec_x[0] = proof.omega2; 
    vec_x[1] = negone; 
    EC_POINTs_mul(group, proof.Y3, NULL, 2, vec_A, vec_x, bn_ctx); //g^omega2.((c1/h)^beta2)^-1

    EC_POINT_mul(group, proof.Y4, NULL, instance.V, proof.beta2, bn_ctx); //C2^beta2
    vec_A[0] = instance.twisted_ek; 
    vec_A[1] = proof.Y4; 
    vec_x[0] = proof.omega2; 
    vec_x[1] = negone; 
    EC_POINTs_mul(group, proof.Y4, NULL, 2, vec_A, vec_x, bn_ctx); // Y4 = pk^omega2.(C2^beta2)^-1

    // update the transcript with the first round message
    transcript_str += ECP_ep2string(proof.Y1) + ECP_ep2string(proof.Y2) 
                    + ECP_ep2string(proof.Y3) + ECP_ep2string(proof.Y4);  
    // compute the challenge
    BIGNUM *x = BN_new(); 
    Hash_String_to_BN(transcript_str, x); // challenge x
    //BN_mod(x, x, order, bn_ctx);
    BN_print(x, "x");

    // compute the response
    //BN_mod_sub(proof.beta1, x, proof.beta2,order, bn_ctx); // beta1 = x - beta2
    BN_sub(proof.beta1, x, proof.beta2);

    //BN_mod_mul(proof.omega1, proof.beta1, witness.r, order, bn_ctx); //beta1.r
    BN_mul(proof.omega1, proof.beta1, witness.r, bn_ctx);
    //BN_mod_add(proof.omega1, proof.omega1, mu, order, bn_ctx); //omega1 = beta1.r + mu
    BN_add(proof.omega1, proof.omega1, mu);

    BN_free(mu); 
    BN_free(negone);
    BN_free(x); 

    #ifdef DEBUG
    Sigma_Proof_print_Zero(proof); 
    #endif
}

void Sigma_Prove_One(Sigma_PP &pp, 
                                   Sigma_Instance &instance, 
                                   Sigma_Witness &witness, 
                                   string &transcript_str, 
                                   Sigma_Proof &proof)
{    
    // initialize the transcript with instance 
    #ifdef DEBUG
    cout << "Sigma proof start >>>" << endl;  
    Sigma_Instance_print(instance); 
    Sigma_Witness_print(witness);
    #endif

    BIGNUM *mu2 = BN_new(); 
    BIGNUM *negone = BN_new();
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];


    BN_copy(negone, BN_1);
    BN_set_negative(negone, 1);


    BN_random(mu2);
    BN_random(proof.beta1);
    BN_random(proof.omega1);

    EC_POINT_mul(group, proof.Y1, NULL, instance.U, proof.beta1, bn_ctx);
    vec_A[0] = pp.g; 
    vec_A[1] = proof.Y1;
    vec_x[0] = proof.omega1; 
    vec_x[1] = negone;
    EC_POINTs_mul(group, proof.Y1, NULL, 2, vec_A, vec_x, bn_ctx);

    EC_POINT_mul(group, proof.Y2, NULL, instance.V, proof.beta1, bn_ctx); // C2^beta2
    vec_A[0] = instance.twisted_ek; 
    vec_A[1] = proof.Y2;
    vec_x[0] = proof.omega1; 
    vec_x[1] = negone;
    EC_POINTs_mul(group, proof.Y2, NULL, 2, vec_A, vec_x, bn_ctx);


    EC_POINT_mul(group, proof.Y3, NULL, pp.g, mu2, bn_ctx); // Y3 =  g^mu2
    EC_POINT_mul(group, proof.Y4, NULL, instance.twisted_ek, mu2, bn_ctx); // Y4 =  pk^mu2
    

    // update the transcript with the first round message
    transcript_str += ECP_ep2string(proof.Y1) + ECP_ep2string(proof.Y2) 
                    + ECP_ep2string(proof.Y3) + ECP_ep2string(proof.Y4);  
    // compute the challenge
    BIGNUM *x = BN_new(); 
    Hash_String_to_BN(transcript_str, x); // challenge x
    //BN_mod(x, x, order, bn_ctx);
    BN_print(x, "x");

    // compute the response
    //BN_mod_sub(proof.beta1, x, proof.beta2,order, bn_ctx); // beta1 = x - beta2
    BN_sub(proof.beta2, x, proof.beta1);

    //BN_mod_mul(proof.omega1, proof.beta1, witness.r, order, bn_ctx); //beta1.r
    BN_mul(proof.omega2, proof.beta2, witness.r, bn_ctx);
    //BN_mod_add(proof.omega1, proof.omega1, mu, order, bn_ctx); //omega1 = beta1.r + mu
    BN_add(proof.omega2, proof.omega2, mu2);

    BN_free(mu2); 
    BN_free(negone);
    BN_free(x); 

    #ifdef DEBUG
    Sigma_Proof_print_One(proof); 
    #endif
}


// check Sigma  proof PI for C1 = Enc(twisted_ek, m; r1) and C2 = Enc(R, m; r2) the witness is (r1, r2, m)
bool Sigma_Verify(Sigma_PP &pp, 
                                    Sigma_Instance &instance, 
                                    string &transcript_str,
                                    Sigma_Proof &proof)
{
    // initialize the transcript with instance 

    BIGNUM *negone = BN_new();
    BN_copy(negone, BN_1);
    BN_set_negative(negone, 1);
    BN_print(negone,"negone");
    BIGNUM *beta1_beta2 = BN_new();
    BN_add(beta1_beta2, proof.beta1, proof.beta2); //beta1 + beta2

    BN_print(beta1_beta2, "beta1_beta2");

    EC_POINT *c1_h = EC_POINT_new(group); 
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = instance.U; 
    vec_A[1] = pp.h; 
    vec_x[0] = BN_1; 
    vec_x[1] = negone;
    EC_POINTs_mul(group, c1_h, NULL, 2, vec_A, vec_x, bn_ctx); //c1_h = c1^1.h^-1

    EC_POINT *a1 = EC_POINT_new(group);
    EC_POINT *a2 = EC_POINT_new(group);
    EC_POINT *a3 = EC_POINT_new(group);
    EC_POINT *a4 = EC_POINT_new(group);


    bool Va1,Va2,Va3,Va4;

    EC_POINT_mul(group, a1, NULL, instance.U, proof.beta1, bn_ctx);
    vec_A[0] = pp.g; 
    vec_A[1] = a1;
    vec_x[0] = proof.omega1; 
    vec_x[1] = negone;
    EC_POINTs_mul(group, a1, NULL, 2, vec_A, vec_x, bn_ctx); // a1= g^omega1.(C1^beta1)^-1
    Va1 = (EC_POINT_cmp(group, a1, proof.Y1, bn_ctx) == 0);
    #ifdef DEBUG
    
    if (Va1) 
    { 
        cout<< "(a1 = g^omega1.(C1^beta1)^-1) == Y1 >>>" << endl; 
        ECP_print(a1, "a1");
        ECP_print(proof.Y1, "Y1");
    }
    else 
    {
        cout<< "a1 unequal Y1 >>>" << endl; 
        ECP_print(a1, "a1");
        ECP_print(proof.Y1, "Y1");
    }
    #endif


    EC_POINT_mul(group, a2, NULL, instance.V, proof.beta1, bn_ctx); // C2^beta2
    vec_A[0] = instance.twisted_ek; 
    vec_A[1] = a2;
    vec_x[0] = proof.omega1; 
    vec_x[1] = negone;
    EC_POINTs_mul(group, a2, NULL, 2, vec_A, vec_x, bn_ctx); // a2= pk^omega1.(C2^beta1)^-1
    Va2 = (EC_POINT_cmp(group, a2, proof.Y2, bn_ctx) == 0);
    #ifdef DEBUG
    
    if (Va2) 
    { 
        cout<< "(a2= pk^omega1.(C2^beta1)^-1) == Y2 >>>" << endl; 
        ECP_print(a2, "a2");
        ECP_print(proof.Y2, "Y2");
    }
    else 
    {
        cout<< "a2 unequal Y2 >>>" << endl;
        ECP_print(a2, "a2");
        ECP_print(proof.Y2, "Y2"); 
    }
    #endif

    EC_POINT_mul(group, a3, NULL, c1_h, proof.beta2, bn_ctx);
    vec_A[0] = pp.g; 
    vec_A[1] = a3;
    vec_x[0] = proof.omega2; 
    vec_x[1] = negone;
    EC_POINTs_mul(group, a3, NULL, 2, vec_A, vec_x, bn_ctx); // a3= g^omega2.(C1_h^beta2)^-1
    Va3 = (EC_POINT_cmp(group, a3, proof.Y3, bn_ctx) == 0);
    #ifdef DEBUG
    
    if (Va3) 
    { 
        cout<< "(a3= g^omega2.(C1_h^beta2)^-1) == Y3 >>>" << endl; 
        ECP_print(a3, "a3");
        ECP_print(proof.Y3, "Y3");
    }
    else 
    {
        cout<< "a3 unequal Y3 >>>" << endl; 
        ECP_print(a3, "a3");
        ECP_print(proof.Y3, "Y3");
    }
    #endif

    EC_POINT_mul(group, a4, NULL, instance.V, proof.beta2, bn_ctx);
    vec_A[0] = instance.twisted_ek; 
    vec_A[1] = a4;
    vec_x[0] = proof.omega2; 
    vec_x[1] = negone;
    EC_POINTs_mul(group, a4, NULL, 2, vec_A, vec_x, bn_ctx); // a4= pk^omega2.(C2^beta2)^-1
    Va4 = (EC_POINT_cmp(group, a4, proof.Y4, bn_ctx) == 0);
    #ifdef DEBUG
    
    if (Va4) 
    { 
        cout<< "(a4= pk^omega2.(C2^beta2)^-1) == Y4 >>>" << endl; 
        ECP_print(a4, "a4");
        ECP_print(proof.Y4, "Y4");
    }
    else 
    {
        cout<< "a4 unequal Y4 >>>" << endl; 
        ECP_print(a4, "a4");
        ECP_print(proof.Y4, "Y4");
    }
    #endif


    // update the transcript with the first round message
    transcript_str += ECP_ep2string(a1) + ECP_ep2string(a2) 
                    + ECP_ep2string(a3) + ECP_ep2string(a4);
    
    // compute the challenge
    BIGNUM *x = BN_new(); 
    Hash_String_to_BN(transcript_str, x); 
    //BN_mod(x, x, order, bn_ctx);
    //BN_print(x, "x");


    bool V;
    V = (BN_cmp(beta1_beta2, x) == 0);

    bool Validity = V;
    #ifdef DEBUG
    
    if (Validity) 
    { 
        cout<< "Sigma proof for Twisted ElGamal ciphertext accepts >>>" << endl; 
        BN_print(beta1_beta2,  "beta1+beta2");
        BN_print(x,  "x");
    }
    else 
    {
        cout<< "Sigma proof for Twisted ElGamal ciphertext rejects >>>" << endl; 
        BN_print(beta1_beta2,  "beta1+beta2");
        BN_print(x,  "x");
    }
    #endif

    BN_free(x); 

    return Validity;
}

#endif



