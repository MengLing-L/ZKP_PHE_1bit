#define DEBUG

#include "../depends/twisted_elgamal/twisted_elgamal.hpp"

void test_twisted_elgamal()
{
    SplitLine_print('-'); 
    cout << "begin the basic correctness test >>>" << endl; 
    
    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_PP_new(pp);
    size_t MSG_LEN = 32; 
    size_t TUNNING = 7; 
    size_t DEC_THREAD_NUM = 4;
    size_t IO_THREAD_NUM = 4;      
    Twisted_ElGamal_Setup(pp, MSG_LEN, TUNNING, DEC_THREAD_NUM, IO_THREAD_NUM);
    Twisted_ElGamal_Initialize(pp); 

    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_new(keypair); 
    Twisted_ElGamal_KeyGen(pp, keypair); 

    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_new(CT); 

    BIGNUM *m = BN_new(); 
    BIGNUM *m_prime = BN_new();

    /* random test */ 
    SplitLine_print('-'); 
    cout << "begin the random test >>>" << endl; 
    BN_random(m); 
    BN_mod(m, m, pp.BN_MSG_SIZE, bn_ctx);
    BN_print(m, "m"); 
    Twisted_ElGamal_Enc(pp, keypair.pk, m, CT);
    BIGNUM *X = BN_new(); 
    BIGNUM *Y = BN_new(); 
    EC_POINT_get_affine_coordinates_GFp(group, CT.X, X, Y, bn_ctx);
    unsigned char buffer[BN_LEN];
    BN_bn2bin(str, buffer);

    Twisted_ElGamal_PP_free(pp); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 
    BN_free(m);
    BN_free(m_prime); 
}

int main()
{  
    // curve id = NID_secp256k1
    global_initialize(NID_secp256k1);    
    // global_initialize(NID_secp256k1); 
    test_twisted_elgamal();
    global_finalize();
    
    return 0; 
}



