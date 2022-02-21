#include "../depends/twisted_elgamal/rust_twisted_elgamal.hpp"

extern "C"{
    void Rust_global_initialize(){
        global_initialize(NID_secp256k1);
    }
}

extern "C" {
    void Rust_Twisted_ElGamal_Enc(EC_POINT* pk_ret, BIGNUM *beta_ret, EC_GROUP* group_ret)
    {
        SplitLine_print('-'); 
        //cout << "begin the basic correctness test >>>" << endl; 
        
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
        //cout << "begin the random test >>>" << endl; 
        BN_random(m); 
        BN_mod(m, m, pp.BN_MSG_SIZE, bn_ctx);
        BN_print(m, "m"); 
        BIGNUM *beta = BN_new(); 
        BN_random(beta);
        BN_print(beta, "beta");
        Twisted_ElGamal_Enc(pp, keypair.pk, m, beta, CT);
        BN_copy(beta_ret, beta); 
        EC_POINT_copy(pk_ret, keypair.pk);
        //Twisted_ElGamal_Parallel_Dec(pp, keypair.sk, CT, m_prime); 
        //BN_print(m_prime, "m'"); 
    
        Twisted_ElGamal_PP_free(pp); 
        Twisted_ElGamal_KP_free(keypair); 
        Twisted_ElGamal_CT_free(CT); 
        BN_free(m);
        BN_free(m_prime);       
    }
}

extern "C"{
    void Rust_global_finalize(){
        global_finalize();
    }
}
