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
using namespace CryptoPP;


void GenKeyPair(int K){
	// InvertibleRSAFunction is used directly only because the private key
	// won't actually be used to perform any cryptographic operation;
	// otherwise, an appropriate typedef'ed type from rsa.h would have been used.
	AutoSeededRandomPool rng;
	InvertibleRSAFunction privkey;
	privkey.Initialize(rng, K);

	// With the current version of Crypto++, MessageEnd() needs to be called
	// explicitly because Base64Encoder doesn't flush its buffer on destruction.
	Base64Encoder privkeysink(new FileSink("privkey.txt"));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();
	 
	// Suppose we want to store the public key separately,
	// possibly because we will be sending the public key to a third party.
	RSAFunction pubkey(privkey);
	
	Base64Encoder pubkeysink(new FileSink("pubkey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();

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
	GenKeyPair(K);
	key_time[i] = (((float)clock() - (float)c)/CLOCKS_PER_SEC) * 1000;
	Sign(str);
	ecpt_time[i] = (((float)clock() - (float)c)/CLOCKS_PER_SEC) * 1000;
	Verify();
	dcpt_time[i] =  (((float)clock() - (float)c)/CLOCKS_PER_SEC) * 1000;

}

int main(int argc, char* argv[]){
	int N = atoi(argv[1]);
	int K = atoi(argv[2]);
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