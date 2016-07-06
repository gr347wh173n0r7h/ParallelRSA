//Generate an RSA key pair, sign a message and verify it using crypto++ 5.6.1 or later.
//To compile: g++ gen.cpp -lcrypto++ -o gen

#include <string>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <time.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <fstream>
#include <cstdlib>
#include <pthread.h>
using namespace CryptoPP;

int K = 0;

void *GenKeyPair1(void *ptr){

    AutoSeededRandomPool rng;
    InvertibleRSAFunction privkey;
    privkey.Initialize(rng, K/2);

    Base64Encoder privkeysink(new FileSink("privkey1.txt"));
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

    RSAFunction pubkey(privkey);
    
    Base64Encoder pubkeysink(new FileSink("pubkey1.txt"));
    pubkey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();

    pthread_exit(NULL);
}

void *GenKeyPair2(void *ptr){

    AutoSeededRandomPool rng;
    InvertibleRSAFunction privkey;
    privkey.Initialize(rng, K/2);

    Base64Encoder privkeysink(new FileSink("privkey2.txt"));
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

    RSAFunction pubkey(privkey);
    
    Base64Encoder pubkeysink(new FileSink("pubkey2.txt"));
    pubkey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();

    pthread_exit(NULL);
}

void MergeFiles(){
    string filename1 = "privkey1.txt"; 
    ifstream file1(filename1.c_str());
    stringstream buffer1;

    buffer1 << file1.rdbuf();
    string str1 = buffer1.str();

    string filename2 = "privkey2.txt"; 
    ifstream file2(filename2.c_str());
    stringstream buffer2;

    buffer2 << file2.rdbuf();
    string str2 = buffer2.str();

    string filename3 = "pubkey1.txt"; 
    ifstream file3(filename3.c_str());
    stringstream buffer3;

    buffer3 << file3.rdbuf();
    string str3 = buffer3.str();

    string filename4 = "pubkey2.txt"; 
    ifstream file4(filename4.c_str());
    stringstream buffer4;

    buffer4 << file4.rdbuf();
    string str4 = buffer4.str();

    string privateKey = str1 + str2;
    string publicKey = str3 + str4;

    ofstream out1("privkey.txt");
    out1 << privateKey;

    ofstream out2("pubkey.txt");
    out2 << publicKey;

}

void Sign(string str){
    // string strContents = "A message to be signed";
    string strContents = str;
    //FileSource("tobesigned.dat", true, new StringSink(strContents));
    
    AutoSeededRandomPool rng;
    
    //Read private key
    CryptoPP::ByteQueue bytes;
    FileSource file("privkey.txt", true, new Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    RSA::PrivateKey privateKey;
    privateKey.Load(bytes);

    //Sign message
    RSASSA_PKCS1v15_SHA_Signer privkey(privateKey);
    SecByteBlock sbbSignature(privkey.SignatureLength());
    privkey.SignMessage( rng, (byte const*) strContents.data(), strContents.size(), sbbSignature);

    //Save result
    FileSink sink("message.dat"); //c
    sink.Put((byte const*) strContents.data(), strContents.size());
    FileSink sinksig("cipher.dat"); //m
    sinksig.Put(sbbSignature, sbbSignature.size());
}

void Verify(){
    //Read public key
    CryptoPP::ByteQueue bytes;
    FileSource file("pubkey.txt", true, new Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    RSA::PublicKey pubKey;
    pubKey.Load(bytes);

    RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

    //Read signed message
    string signedTxt;
    FileSource("message.dat", true, new StringSink(signedTxt)); //c
    string sig;
    FileSource("cipher.dat", true, new StringSink(sig)); //m

    string combined(signedTxt);
    combined.append(sig);

    //Verify signature
    try
    {
        StringSource(combined, true,
            new SignatureVerificationFilter(
                verifier, NULL,
                SignatureVerificationFilter::THROW_EXCEPTION
           )
        );
        // cout << "Signature OK" << endl;
    }
    catch(SignatureVerificationFilter::SignatureVerificationFailed &err)
    {
        cout << err.what() << endl;
    }

}

float avgS(float ary[], int N){
    float sum = 0;
    for(int i = 0; i < 10; i++){
        sum += ary[i];
    }
    return sum/10.0; 
}

void runRSA(float key_time[], float ecpt_time[], float dcpt_time[], string str, int N, int K, int i){
    clock_t c;      
    c = clock();

    pthread_t thread1, thread2;
    int rc;

    rc = pthread_create(&thread1, NULL, GenKeyPair1, (void *)&K);
    if (rc){
        cout << "Error:unable to create thread," << rc << endl;
        exit(-1);
    }
    pthread_join( thread1, NULL); 
    rc = pthread_create(&thread2, NULL, GenKeyPair2,(void *)&K);
    if (rc){
        cout << "Error:unable to create thread," << rc << endl;
        exit(-1);
    }
    pthread_join( thread1, NULL);  
    pthread_join( thread2, NULL); 
    // GenKeyPair(K);
    MergeFiles(); 
    key_time[i] = (((float)clock() - (float)c)/CLOCKS_PER_SEC) * 1000;
    Sign(str);
    ecpt_time[i] = (((float)clock() - (float)c)/CLOCKS_PER_SEC) * 1000;
    Verify();
    dcpt_time[i] =  (((float)clock() - (float)c)/CLOCKS_PER_SEC) * 1000;

}

int main(int argc, char* argv[]){
    int N = atoi(argv[1]);
    K = atoi(argv[2]);

    string filename = argv[3]; 
    ifstream file(filename.c_str());
    stringstream buffer;

    buffer << file.rdbuf();
    string str = buffer.str();
    cout << "Message size: " << left << setw(7) << str.size() << "Key Size: "<< setw(5) << K << endl;

    clock_t c;      
    c = clock();

    float key_time [10];
    float ecpt_time [10];
    float dcpt_time[10];

    for(int i = 0; i < N; i++){
        runRSA(key_time, ecpt_time, dcpt_time, str, N, K, i);
    }
    cout << left << setw(10) << avgS(key_time, N) << "\tAverage Key Generation Time" << endl;
    cout << left << setw(10) << avgS(ecpt_time, N) << "\tAverage Message Encryption Time" << endl;
    cout << left << setw(10) << avgS(dcpt_time, N) << "\tAverage Message Dencryption Time" << endl;
    cout << "-Total Run Time: " << left << setw(10) << (((float)clock() - (float)c)/CLOCKS_PER_SEC) * 1000 << endl;

}