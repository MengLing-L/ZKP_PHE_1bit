#define DEBUG

#include "../depends/twisted_elgamal/twisted_elgamal.hpp"
#include "../depends/bulletproofs/aggregate_bulletproof.hpp"
#include "../depends/sigma/sigma_proof.hpp"
#include "../depends/signature/signature.hpp"
#include <string.h>
#include <vector> 
using namespace std;

void generate_random_instance_witness(Bullet_PP &pp, 
                                      Bullet_Instance &instance, 
                                      Bullet_Witness &witness,
                                      vector<BIGNUM *> &m,
                                      vector<BIGNUM *> &beta, 
                                      bool STATEMENT_FLAG)
{
    if(STATEMENT_FLAG == true) cout << "generate a true statement pair" << endl; 
    else cout << "generate a random statement (false with overwhelming probability)" << endl; 
    BIGNUM *exp = BN_new(); 
    BN_set_word(exp, pp.RANGE_LEN);

    BIGNUM *BN_range_size = BN_new(); 
    BN_mod_exp(BN_range_size, BN_2, exp, order, bn_ctx); 
    cout << "range = [" << 0 << "," << BN_bn2hex(BN_range_size) <<")"<<endl; 
    for(auto i = 0; i < pp.AGG_NUM; i++)
    {
        BN_copy(witness.r[i], beta[i]);
        BN_copy(witness.v[i], m[i]);
        BN_print(witness.r[i], "witness.r");
        BN_print(witness.v[i], "witness.v");
        if (STATEMENT_FLAG == true){
            BN_mod(witness.v[i], witness.v[i], BN_range_size, bn_ctx);  
        }
        EC_POINT_mul(group, instance.C[i], witness.r[i], pp.h, witness.v[i], bn_ctx); 
    }
    cout << "random instance generation finished" << endl; 
}

void getU(EC_POINT* &U, vector<Twisted_ElGamal_CT> &CT, Twisted_ElGamal_PP &pp_tt){
    BIGNUM *tmp = BN_new();
    EC_POINT *point = EC_POINT_new(group);
    for(int i=0;i<CT.size(); i++){
        BN_set_word(tmp, pp_tt.MSG_LEN*(CT.size()-i-1)); //tmp = 32*(size-i-1)
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx); // tmp = 2^32*(size-i-1)
        EC_POINT_mul(group, point, NULL, CT[i].Y, tmp, bn_ctx); // point = ui^(2^32*(size-i-1))
        if(i==0){
            EC_POINT_copy(U, point); 
        }else{
            EC_POINT_add(group, U, U, point, bn_ctx); // U = U*ui^(2^32*(size-i-1))
        }
    }
    BN_free(tmp);
    EC_POINT_free(point);
}

void getV(EC_POINT* &V, vector<Twisted_ElGamal_CT> &CT, Twisted_ElGamal_PP &pp_tt){
    BIGNUM *tmp = BN_new();
    EC_POINT *point = EC_POINT_new(group);
    for(int i=0;i<CT.size(); i++){
        BN_set_word(tmp, pp_tt.MSG_LEN*(CT.size()-i-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        EC_POINT_mul(group, point, NULL, CT[i].X, tmp, bn_ctx);
        if(i==0){
            EC_POINT_copy(V, point); 
        }else{
            EC_POINT_add(group, V, V, point, bn_ctx); 
        }
    }
    BN_free(tmp);
    EC_POINT_free(point);
}

void generate_sigma_random_instance_witness(Twisted_ElGamal_PP &pp_tt,
                                Sigma_PP &pp, 
                                Sigma_Instance &instance, 
                                Sigma_Witness &witness, 
                                BIGNUM* &m,
                                vector<BIGNUM *> &beta,
                                vector<Twisted_ElGamal_CT> &CT,
                                EC_POINT* &pk,
                                EC_POINT* &R,
                                EC_POINT* &A,
                                bool flag)
{
    SplitLine_print('-');  
    BIGNUM *tmp = BN_new();
    for(int j=0; j<beta.size(); j++){
        BN_set_word(tmp, pp_tt.MSG_LEN*(beta.size()-j-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        BN_mod_mul(tmp, beta[j], tmp, order, bn_ctx);
        BN_mod_add(witness.r, witness.r, tmp, order, bn_ctx);
    }
    BN_copy(witness.v, m);

    EC_POINT_copy(instance.twisted_ek, pk);
    EC_POINT_copy(instance.R, R);
    EC_POINT_copy(instance.A, A);
    
    ECP_print(instance.U, "instance.U");
    getU(instance.U, CT, pp_tt); 
    ECP_print(instance.U, "instance.U");
    EC_POINT *point = EC_POINT_new(group);
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h;
    vec_x[0] = m; 
    vec_x[1] = witness.r;
    EC_POINTs_mul(group, point, NULL, 2, vec_A, vec_x, bn_ctx); //g^m h^beta
    ECP_print(point, "point");
    bool val = (EC_POINT_cmp(group, point, instance.U, bn_ctx) == 0); 
    if (val) 
    { 
        cout<< "equal point and U >>>" << endl; 
    }
    else 
    {
        cout<< "unequal point and U >>>" << endl; 
    }
    getV(instance.V, CT, pp_tt); 
}

void recovery_bignum_from_dec_nums(vector<BIGNUM *> &ret_num, BIGNUM* &m, Twisted_ElGamal_PP &pp){
    BIGNUM *recover_num = BN_new();
    BIGNUM *tmp = BN_new();
    for(int j=0; j<ret_num.size(); j++){
        BN_set_word(tmp, pp.MSG_LEN*(ret_num.size()-j-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        BN_mul(tmp, ret_num[j], tmp, bn_ctx);
        BN_add(recover_num, recover_num, tmp);
    }
    //BN_print(recover_num, "recover_num");
    bool Validity = (BN_ucmp(recover_num, m) == 0);
    BN_print(recover_num, "recovery_number");
    BN_print(m, "m");
    if (Validity) 
    { 
        cout<< "recovery accept >>>" << endl; 
    }
    else 
    {
        cout<< "recovery reject >>>" << endl; 
    }
    BN_free(recover_num);
    BN_free(tmp);
}

void get_32bit_4bytes_BigNumVec(vector<BIGNUM *> &ret_num, BIGNUM* &m, Twisted_ElGamal_PP &pp){
    unsigned char buffer[BN_LEN];
    BN_bn2bin(m, buffer);
    int ENC_SIZE = 4;
    char dest[ENC_SIZE];
    memset(dest, '\0', sizeof(dest));
    for(int i=0; i<(int)(BN_LEN/ENC_SIZE);i++){    
        strncpy(dest, (char *)(buffer + i*ENC_SIZE), ENC_SIZE);
        BN_bin2bn((unsigned char*)dest, 4, ret_num[i]);      
        //BN_print(ret_num[i]);
    }
    recovery_bignum_from_dec_nums(ret_num, m, pp);
}

//EC_POINT *A, *S, *T1, *T2;  
//   BIGNUM *taux, *mu, *tx; 
//   InnerProduct_Proof ip_proof;
//struct InnerProduct_Proof
//{
//  size of the vector = LOG_VECTOR_LEN
//    vector<EC_POINT *> vec_L; 
//   vector<EC_POINT *> vec_R; 
//    BIGNUM *a; 
//    BIGNUM *b;     
//};
void get_bullet_proof_size(Bullet_Proof &bullet_proof){
    size_t all=0;
    all += 4*POINT_LEN; //EC_POINT *A, *S, *T1, *T2;
    all += 3*BN_LEN; //BIGNUM *taux, *mu, *tx;
    all += 2*BN_LEN; //BIGNUM* a,*b
    all += bullet_proof.ip_proof.vec_L.size()*POINT_LEN;
    all += bullet_proof.ip_proof.vec_R.size()*POINT_LEN;
    cout << "bullet proof's size " << all << endl;
}
//// structure of proof 
//struct Sigma_Proof
//{
//   EC_POINT *Y1, *Y2, *Y3; // P's first round message
//  BIGNUM *z1, *z2;    // P's response in Zq
//};
void get_sigma_proof_size(Sigma_Proof &sigma_proof){
    size_t all=0;
    all += 3*POINT_LEN; //EC_POINT *Y1, *Y2, *Y3;
    all += 2*BN_LEN; ; //BIGNUM *z1, *z2; 
    cout << "sigma proof's size " << all << endl;
}

void get_ciphertext_size(vector<Twisted_ElGamal_CT> &CT){
    size_t all=0;
    all += 2*CT.size()*POINT_LEN; 
    cout << "Ciphertext's size " << all << endl;
}

void get_signature_s_size(){
    size_t all=0;
    all += BN_LEN; 
    cout << "Signature s's size " << all << endl;
}

void get_signature_r_size(){
    size_t all=0;
    all += BN_LEN; 
    cout << "Signature r's size " << all << endl;
}

void test_escrow_protocol()
{
    SplitLine_print('-'); 

    Signature_PP signature;
    Signature_PP_new(signature);    
    Signature_Setup(signature);
    Signature_Instance signature_instance; 
    Signature_Instance_new(signature_instance);
    Signature_Result signature_result;
    Signature_Result_new(signature_result);

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

    size_t RANGE_LEN = 32; // range size
    size_t AGG_NUM = BN_LEN/4;
    Bullet_PP pp; 
    Bullet_PP_new(pp, RANGE_LEN, AGG_NUM);  
    Bullet_Setup(pp, RANGE_LEN, AGG_NUM);
    Bullet_Instance instance; 
    Bullet_Witness witness; 
    Bullet_Proof proof; 
    Bullet_Instance_new(pp, instance); 
    Bullet_Witness_new(pp, witness); 
    Bullet_Proof_new(proof); 

    Sigma_PP sigma;
    Sigma_PP_new(sigma);    
    Sigma_Setup(sigma, pp_tt.h);
    Sigma_Instance sigma_instance; 
    Sigma_Instance_new(sigma_instance); 
    Sigma_Witness sigma_witness; 
    Sigma_Witness_new(sigma_witness); 
    Sigma_Proof sigma_proof; 
    Sigma_Proof_new(sigma_proof); 

   
    BIGNUM *m_prime = BN_new();
    BIGNUM *m = BN_new();

    BN_hex2bn(&m,"4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a");
    BIGNUM *hash=BN_new();
    BN_print(m, "m");
    Hash_BN_to_BN(m, hash);
    //BN_hex2bn(&hash,"4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a"); 
    cout << "generate hash value of private message >>>" << endl;
    BN_print(hash, "hash");

    cout << "generate the signature key pair >>>" << endl;
    Signature_KeyGen(signature, signature_instance);

    cout << "generate the signature of hash >>>" << endl;
    SplitLine_print('-');
    cout << "begin count signature generation time >>>" << endl;
    auto start_time = chrono::steady_clock::now(); // start to count the time
    Signature_Sign(signature, signature_instance, hash, signature_result);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "Signature generation takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    SplitLine_print('-');
    cout << "begin the twisted elgamal encryption >>>" << endl;  
    BN_print(signature_result.s, "signature_result.s"); 
    cout << "begin count encryption time >>>" << endl;
    start_time = chrono::steady_clock::now(); // start to count the time

    vector<BIGNUM *> split_each_4bytes_m(BN_LEN/4);
    BN_vec_new(split_each_4bytes_m);
    get_32bit_4bytes_BigNumVec(split_each_4bytes_m, signature_result.s, pp_tt);

    vector<BIGNUM *> each_4bytes_m_beta(BN_LEN/4);
    BN_vec_new(each_4bytes_m_beta);
    
    vector<Twisted_ElGamal_CT> each_4bytes_m_res_U_V(BN_LEN/4);
    for(auto i = 0; i < each_4bytes_m_res_U_V.size(); i++){
        Twisted_ElGamal_CT_new(each_4bytes_m_res_U_V[i]); 
    }
    
    //BIGNUM *beta = BN_new(); 
    for(int i=0; i<split_each_4bytes_m.size(); i++){
        BN_random(each_4bytes_m_beta[i]);
        BN_mod(split_each_4bytes_m[i], split_each_4bytes_m[i], pp_tt.BN_MSG_SIZE, bn_ctx);
        BN_print(split_each_4bytes_m[i], "split_each_4bytes_m");
        Twisted_ElGamal_Enc(pp_tt, keypair.pk, split_each_4bytes_m[i], each_4bytes_m_beta[i], each_4bytes_m_res_U_V[i]);     
    }

    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Encryption takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    SplitLine_print('-');


    generate_random_instance_witness(pp, instance, witness, split_each_4bytes_m, each_4bytes_m_beta, true);  

    generate_sigma_random_instance_witness(pp_tt, sigma, sigma_instance, sigma_witness, signature_result.s, each_4bytes_m_beta, each_4bytes_m_res_U_V, keypair.pk, signature_result.R, signature_result.A, true); 
    string transcript_str; 
    string sigma_transcript_str; 

    cout << "generate the bullet proof >>>" << endl;  
    cout << "begin count bullet proof generation time >>>" << endl;
    start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet_Prove(pp, instance, witness, transcript_str, proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Bullet proof generation takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    SplitLine_print('-');

    cout << "generate the sigma proof >>>" << endl; 
    cout << "begin count sigma proof generation time >>>" << endl;
    start_time = chrono::steady_clock::now(); // start to count the time
    sigma_transcript_str = ""; 
    Sigma_Prove(sigma, sigma_instance, sigma_witness, sigma_transcript_str, sigma_proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Sigma proof generation takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    SplitLine_print('-');
    get_bullet_proof_size(proof);
    get_sigma_proof_size(sigma_proof);
    get_ciphertext_size(each_4bytes_m_res_U_V);
    get_signature_s_size();
    get_signature_r_size();
    SplitLine_print('-');
    
    //cout << "verify the signature >>>" << endl; 
    //Signature_Verify(signature, signature_instance, hash, signature_result);
    //cout << "--------" << endl;
    cout << "Twited ElGamal decryption >>>" << endl;
    cout << "begin count Twited ElGamal decryption time >>>" << endl;
    start_time = chrono::steady_clock::now();
    vector<BIGNUM *> m_recoverys(BN_LEN/4);
    BN_vec_new(m_recoverys);
    for(int i=0; i<each_4bytes_m_res_U_V.size(); i++){
        Twisted_ElGamal_Parallel_Dec(pp_tt, keypair.sk, each_4bytes_m_res_U_V[i], m_recoverys[i]);
        BN_print(m_recoverys[i], "m'");
    }
    recovery_bignum_from_dec_nums(m_recoverys, signature_result.s, pp_tt);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Twited ElGamal decryption takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    SplitLine_print('-');

    transcript_str = ""; 
    cout << "verify the bullet proof >>>" << endl; 
    cout << "begin count bullet proof verification time >>>" << endl;
    start_time = chrono::steady_clock::now();
    Bullet_Verify(pp, instance, transcript_str, proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Bullet proof verification takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    SplitLine_print('-');

    cout << "verify the sigma proof >>>" << endl;
    cout << "begin count Sigma proof verification time >>>" << endl;
    start_time = chrono::steady_clock::now(); 
    sigma_transcript_str = ""; 
    Sigma_Verify(sigma, sigma_instance, sigma_transcript_str, sigma_proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Sigma proof verification takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    SplitLine_print('-');

    Signature_PP_free(signature);
    Signature_Instance_free(signature_instance);
    Signature_Result_free(signature_result);

    Sigma_PP_free(sigma); 
    Sigma_Instance_free(sigma_instance);
    Sigma_Witness_free(sigma_witness);
    Sigma_Proof_free(sigma_proof); 
    
    Twisted_ElGamal_PP_free(pp_tt); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 
    //BN_free(pp_tt.BN_MSG_SIZE); 

    Bullet_PP_free(pp); 
    Bullet_Instance_free(instance); 
    Bullet_Witness_free(witness); 
    Bullet_Proof_free(proof); 

    BN_free(m);
    BN_free(m_prime); 
    
    BN_vec_free(split_each_4bytes_m);
    BN_vec_free(each_4bytes_m_beta);
    BN_vec_free(m_recoverys);
}


int main()
{  
    // curve id = NID_secp256k1
    global_initialize(NID_secp256k1);    
    // global_initialize(NID_secp256k1); 
    test_escrow_protocol();
    global_finalize();
    
    return 0; 
}



