#define DEBUG

#include "../depends/twisted_elgamal/twisted_elgamal.hpp"
#include "../depends/sigma/sigma_proof.hpp"
#include <string.h>
#include <vector> 
using namespace std;

void generate_sigma_random_instance_witness(
								Twisted_ElGamal_PP &pp_tt,
                                Sigma_PP &pp, 
                                Sigma_Instance &instance, 
                                Sigma_Witness &witness, 
                                BIGNUM * &beta,
                                Twisted_ElGamal_CT &CT,
                                EC_POINT* &pk,
                                bool flag)
{
    SplitLine_print('-');  
    
    BN_copy(witness.r, beta);

    EC_POINT_copy(instance.twisted_ek, pk);

    EC_POINT_copy(instance.V, CT.X); 
    EC_POINT_copy(instance.U, CT.Y);

}

void test_protocol()
{
    SplitLine_print('-'); 
    cout << "Initialization >>>" << endl;

    Twisted_ElGamal_PP pp_tt; 
    Twisted_ElGamal_PP_new(pp_tt);
    size_t MSG_LEN = 32; 
    size_t TUNNING = 7; 
    size_t DEC_THREAD_NUM = 4;
    size_t IO_THREAD_NUM = 4;      
    Twisted_ElGamal_Setup(pp_tt, MSG_LEN, TUNNING, DEC_THREAD_NUM, IO_THREAD_NUM);
    Twisted_ElGamal_Initialize(pp_tt); 

    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_new(keypair); 
    Twisted_ElGamal_KeyGen(pp_tt, keypair); 

    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_new(CT); 

    Sigma_PP sigma;
    Sigma_PP_new(sigma);    
    Sigma_Setup(sigma, pp_tt.h);
    Sigma_Instance sigma_instance; 
    Sigma_Instance_new(sigma_instance); 
    Sigma_Witness sigma_witness; 
    Sigma_Witness_new(sigma_witness); 
    Sigma_Proof sigma_proof; 
    Sigma_Proof_new(sigma_proof); 

    SplitLine_print('-');

   
    cout << "Case 1: m = 0 >>>" << endl;


    cout << "Encrypt m >>>" << endl;
    BIGNUM *r = BN_new();
    BN_random(r);

    Twisted_ElGamal_Enc(pp_tt, keypair.pk, BN_0, r, CT);     

    generate_sigma_random_instance_witness(pp_tt, sigma, sigma_instance, sigma_witness, r, CT, keypair.pk, true); 

    string sigma_transcript_str;


    cout << "Generate the sigma proof >>>" << endl; 
    auto start_time = chrono::steady_clock::now(); // start to count the time
    sigma_transcript_str = ""; 
    Sigma_Prove_Zero(sigma, sigma_instance, sigma_witness, sigma_transcript_str, sigma_proof);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "Sigma proof generation takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;


    SplitLine_print('-');

    cout << "Verify the sigma proof >>>" << endl;
    start_time = chrono::steady_clock::now(); 
    sigma_transcript_str = ""; 
    Sigma_Verify(sigma, sigma_instance, sigma_transcript_str, sigma_proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Sigma proof verification takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    SplitLine_print('-');

    cout << "Case 1: m = 1 >>>" << endl;

    BN_random(r);

    Twisted_ElGamal_Enc(pp_tt, keypair.pk, BN_1, r, CT);     

    generate_sigma_random_instance_witness(pp_tt, sigma, sigma_instance, sigma_witness, r, CT, keypair.pk, true); 
    cout << "Generate the sigma proof >>>" << endl; 
    auto start_time = chrono::steady_clock::now(); // start to count the time
    sigma_transcript_str = ""; 
    Sigma_Prove_One(sigma, sigma_instance, sigma_witness, sigma_transcript_str, sigma_proof);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "Sigma proof generation takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;


    SplitLine_print('-');

    cout << "Verify the sigma proof >>>" << endl;
    start_time = chrono::steady_clock::now(); 
    sigma_transcript_str = ""; 
    Sigma_Verify(sigma, sigma_instance, sigma_transcript_str, sigma_proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Sigma proof verification takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    SplitLine_print('-');

    Sigma_PP_free(sigma); 
    Sigma_Instance_free(sigma_instance);
    Sigma_Witness_free(sigma_witness);
    Sigma_Proof_free(sigma_proof); 
    
    Twisted_ElGamal_PP_free(pp_tt); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 

    BN_free(r);

}

int main()
{  
    // curve id = NID_secp256k1
    global_initialize(NID_secp256k1);    
    // global_initialize(NID_secp256k1); 
    test_protocol();
    global_finalize();
    
    return 0; 
}
