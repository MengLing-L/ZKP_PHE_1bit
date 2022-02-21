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
    EC_POINT *twisted_ek, *R; 
    // twisted_ek = twisted elgamal encryption's encryption key
    // R = signature's R = g1^k, g1 = signature's g1
    EC_POINT *U, *V, *A; 
    // U = twisted elgamal encryption's result u
    // V = twisted elgamal encryption's result v
    // A = signature'A = g1^h Q^r , g1 = signature's g1, Q = signature' pk 
};

// structure of witness 
struct Sigma_Witness
{
    BIGNUM *v; // v = signature's s
    BIGNUM *r; // r = twisted elgamal encryption's random value beta
};


// structure of proof 
struct Sigma_Proof
{
    EC_POINT *Y1, *Y2, *Y3; // P's first round message
    BIGNUM *z1, *z2;    // P's response in Zq
};

void Sigma_Instance_new(Sigma_Instance &instance)
{
    instance.twisted_ek = EC_POINT_new(group);
    instance.R = EC_POINT_new(group);
    instance.U  = EC_POINT_new(group);
    instance.V  = EC_POINT_new(group);
    instance.A  = EC_POINT_new(group);
}

void Sigma_Instance_free(Sigma_Instance &instance)
{
    EC_POINT_free(instance.twisted_ek);
    EC_POINT_free(instance.R);
    EC_POINT_free(instance.U);
    EC_POINT_free(instance.V);
    EC_POINT_free(instance.A);
}

void Sigma_Witness_new(Sigma_Witness &witness)
{
    witness.v = BN_new();
    witness.r = BN_new(); 
}

void Sigma_Witness_free(Sigma_Witness &witness)
{
    BN_free(witness.v);
    BN_free(witness.r); 
}

void Sigma_Proof_new(Sigma_Proof &proof)
{
    proof.Y2 = EC_POINT_new(group); 
    proof.Y3 = EC_POINT_new(group); 
    proof.Y1  = EC_POINT_new(group);
    proof.z1 = BN_new(); 
    proof.z2 = BN_new();
}

void Sigma_Proof_free(Sigma_Proof &proof)
{
    EC_POINT_free(proof.Y2);
    EC_POINT_free(proof.Y3);
    EC_POINT_free(proof.Y1);
    BN_free(proof.z1);
    BN_free(proof.z2);
}


void Sigma_Instance_print(Sigma_Instance &instance)
{
    cout << "Plaintext Equality Instance >>> " << endl; 
    ECP_print(instance.twisted_ek, "instance.twisted_ek"); 
    ECP_print(instance.R, "instance.R"); 
    ECP_print(instance.U, "instance.U"); 
    ECP_print(instance.V, "instance.V");  
    ECP_print(instance.A, "instance.A");      
} 

void Sigma_Witness_print(Sigma_Witness &witness)
{
    cout << "Plaintext Equality Witness >>> " << endl; 
    BN_print(witness.v, "witness.v"); 
    BN_print(witness.r, "witness.r"); 
} 

void Sigma_Proof_print(Sigma_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "Sigma proof for Plaintext Equality >>> " << endl; 
    ECP_print(proof.Y2, "proof.Y2"); 
    ECP_print(proof.Y3, "proof.Y3"); 
    ECP_print(proof.Y1, "proof.Y1"); 
    BN_print(proof.z1, "proof.z1"); 
    BN_print(proof.z2, "proof.z2"); 
} 

void Sigma_Proof_serialize(Sigma_Proof &proof, ofstream &fout)
{
    ECP_serialize(proof.Y2, fout); 
    ECP_serialize(proof.Y3, fout);
    ECP_serialize(proof.Y1,  fout);
    BN_serialize(proof.z1, fout); 
    BN_serialize(proof.z2, fout); 
} 

void Sigma_Proof_deserialize(Sigma_Proof &proof, ifstream &fin)
{
    ECP_deserialize(proof.Y2, fin); 
    ECP_deserialize(proof.Y3, fin);
    ECP_deserialize(proof.Y1,  fin);
    BN_deserialize(proof.z1, fin); 
    BN_deserialize(proof.z2, fin); 
} 

void Sigma_PP_print(Sigma_PP &pp)
{
    ECP_print(pp.g, "pp.g"); 
    ECP_print(pp.h, "pp.h"); 
}
/* Setup algorithm */ 
void Sigma_Setup(Sigma_PP &pp, EC_POINT* &h)
{ 
    
    EC_POINT_copy(pp.g, h); 
    EC_POINT_copy(pp.h, generator);  
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

void Sigma_Prove(Sigma_PP &pp, 
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
    transcript_str += ECP_ep2string(instance.twisted_ek) + ECP_ep2string(instance.R) + 
                      ECP_ep2string(instance.U)  + ECP_ep2string(instance.V); 

    BIGNUM *p_beta = BN_new(); 
    BIGNUM *p_s = BN_new(); // the randomness of first round message


    BN_random(p_beta);
    BN_random(p_s);
    EC_POINT_mul(group, proof.Y2, NULL, instance.twisted_ek, p_beta, bn_ctx); // Y2 = T^p_beta
    EC_POINT_mul(group, proof.Y3, NULL, instance.R, p_s, bn_ctx); // Y3 =  R^p_s

    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h; 
    vec_x[0] = p_s; 
    vec_x[1] = p_beta; 
    EC_POINTs_mul(group, proof.Y1, NULL, 2, vec_A, vec_x, bn_ctx); // Y1 = g^p_s h^p_beta

    // update the transcript with the first round message
    transcript_str += ECP_ep2string(proof.Y2) + ECP_ep2string(proof.Y3) 
                    + ECP_ep2string(proof.Y1);  
    // compute the challenge
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(transcript_str, e); // challenge x

    BN_print(e, "e");

    // compute the response
    BN_mul(proof.z1, e, witness.v, bn_ctx); 
    BN_sub(proof.z1, p_s, proof.z1); // z1 = p_s-x*s mod q

    BN_mul(proof.z2, e, witness.r, bn_ctx); 
    BN_sub(proof.z2, p_beta, proof.z2); // z2 = p_beta - x*beta mod q  r = beta

    BN_free(p_s); 
    BN_free(p_beta);
    BN_free(e); 

    #ifdef DEBUG
    Sigma_Proof_print(proof); 
    #endif
}


// check Sigma  proof PI for C1 = Enc(twisted_ek, m; r1) and C2 = Enc(R, m; r2) the witness is (r1, r2, m)
bool Sigma_Verify(Sigma_PP &pp, 
                                    Sigma_Instance &instance, 
                                    string &transcript_str,
                                    Sigma_Proof &proof)
{
    // initialize the transcript with instance 
    transcript_str += ECP_ep2string(instance.twisted_ek) + ECP_ep2string(instance.R) + 
                      ECP_ep2string(instance.U)  + ECP_ep2string(instance.V); 

    // update the transcript
    transcript_str += ECP_ep2string(proof.Y2) + ECP_ep2string(proof.Y3) 
                    + ECP_ep2string(proof.Y1);  
    
    // compute the challenge
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(transcript_str, e); 
    BN_print(e, "e");

    bool V1, V2, V3; 
     
    EC_POINT *RIGHT = EC_POINT_new(group); 
 
    // check condition 1
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h;
    vec_x[0] = proof.z1; 
    vec_x[1] = proof.z2;
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx); // RIGHT = g^z1 h^z2
    
    vec_A[0] = instance.U; // U = result of encryption
    vec_A[1] = RIGHT;
    vec_x[0] = e;
    vec_x[1] = BN_1;
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx); // RIGHT = U^x g^z1 h^z2

    ECP_print(RIGHT, "RIGHT"); 

    V1 = (EC_POINT_cmp(group, proof.Y1, RIGHT, bn_ctx) == 0); // Asssert g^p_s h^p_beta =  U^x g^z1 h^z2

    // check condition 2
    vec_A[0] = instance.V; // V = result of encryption
    vec_A[1] = instance.twisted_ek; 
    vec_x[0] = e; 
    vec_x[1] = proof.z2;
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx);// RIGHT = V^x T^z2

    V2 = (EC_POINT_cmp(group, proof.Y2, RIGHT, bn_ctx) == 0); // Assert T^p_beta = V^x T^z2 

    // check condition 3
    vec_A[0] = instance.A; // Signature's result A = g1^h Q^r, r is the result of signature, Q is the pk of signature.
    vec_A[1] = instance.R; // Signature's point R = g1^k
    vec_x[0] = e; 
    vec_x[1] = proof.z1;
    EC_POINTs_mul(group, RIGHT, NULL, 2, vec_A, vec_x, bn_ctx); // RIGHT = (g1^h Q^r)^x R^z1
    
    V3 = (EC_POINT_cmp(group, proof.Y3, RIGHT, bn_ctx) == 0); // Assert  R^p_s = (g1^h Q^r)^x R^z1

    bool Validity = V1 && V2 & V3;
    #ifdef DEBUG
    cout << boolalpha << "Condition 1 : g^p_s h^p_beta ==  U^x g^z1 h^z2 = " << V1 << endl; 
    cout << boolalpha << "Condition 2 : T^p_beta = V^x T^z2 = " << V2 << endl; 
    cout << boolalpha << "Condition 3 : R^p_s = (g1^h Q^r)^x R^z1 =" << V3 << endl; 

    if (Validity) 
    { 
        cout<< "Sigma proof for twisted ElGamal ciphertext accepts >>>" << endl; 
    }
    else 
    {
        cout<< "Sigma proof for twisted ElGamal ciphertext rejects >>>" << endl; 
    }
    #endif

    BN_free(e); 

    return Validity;
}

#endif



