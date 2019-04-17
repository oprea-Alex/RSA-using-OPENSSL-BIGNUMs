#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>


#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "crypt32")


typedef struct rsa_public_key_st {
	ASN1_INTEGER* modulus;
	ASN1_INTEGER* publicExponent;
}RSA_PUBLIC_KEY_PKCS1;

DECLARE_ASN1_FUNCTIONS(RSA_PUBLIC_KEY_PKCS1)
ASN1_SEQUENCE(RSA_PUBLIC_KEY_PKCS1) = {
	ASN1_SIMPLE(RSA_PUBLIC_KEY_PKCS1,modulus,ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PUBLIC_KEY_PKCS1,publicExponent,ASN1_INTEGER)
}
ASN1_SEQUENCE_END(RSA_PUBLIC_KEY_PKCS1)
IMPLEMENT_ASN1_FUNCTIONS(RSA_PUBLIC_KEY_PKCS1)

typedef struct seq_st {
	ASN1_OBJECT* obID;
	ASN1_NULL * optional;
}SEQ;

DECLARE_ASN1_FUNCTIONS(SEQ)
ASN1_SEQUENCE(SEQ) = {
	ASN1_SIMPLE(SEQ, obID, ASN1_OBJECT),
	ASN1_OPT(SEQ, optional, ASN1_NULL)
} ASN1_SEQUENCE_END(SEQ)
IMPLEMENT_ASN1_FUNCTIONS(SEQ)

typedef struct rsa_public_key_pkcs1_st{
	SEQ* sequence;
	ASN1_BIT_STRING *publicinfo;
}RSA_PUBLIC_KEY_X509;

DECLARE_ASN1_FUNCTIONS(RSA_PUBLIC_KEY_X509)
ASN1_SEQUENCE(RSA_PUBLIC_KEY_X509) = {
	ASN1_SIMPLE(RSA_PUBLIC_KEY_X509, sequence, SEQ),
	ASN1_SIMPLE(RSA_PUBLIC_KEY_X509, publicinfo, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(RSA_PUBLIC_KEY_X509)
IMPLEMENT_ASN1_FUNCTIONS(RSA_PUBLIC_KEY_X509)


typedef struct rsa_private_key_st {
	ASN1_INTEGER* version;
	ASN1_INTEGER* modulus;
	ASN1_INTEGER* publicExponent;
	ASN1_INTEGER* privateExponent;
	ASN1_INTEGER* prime1;
	ASN1_INTEGER* prime2;
	ASN1_INTEGER* exponent1;
	ASN1_INTEGER* exponent2;
	ASN1_INTEGER* coefficient;
}RSA_PRIVATE_KEY_PKCS1;

DECLARE_ASN1_FUNCTIONS(RSA_PRIVATE_KEY_PKCS1)
ASN1_SEQUENCE(RSA_PRIVATE_KEY_PKCS1) = {
	ASN1_SIMPLE(RSA_PRIVATE_KEY_PKCS1, version, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY_PKCS1, modulus, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY_PKCS1, publicExponent, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY_PKCS1, privateExponent, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY_PKCS1, prime1, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY_PKCS1, prime2, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY_PKCS1, exponent1, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY_PKCS1, exponent2, ASN1_INTEGER),
	ASN1_SIMPLE(RSA_PRIVATE_KEY_PKCS1, coefficient, ASN1_INTEGER)
} ASN1_SEQUENCE_END(RSA_PRIVATE_KEY_PKCS1)
IMPLEMENT_ASN1_FUNCTIONS(RSA_PRIVATE_KEY_PKCS1)




void generate_key_pair(const unsigned int key_size, const char* pubkey_filename, const char* prvkey_filename) {
	BN_CTX* ctx = BN_CTX_new();

	//1. generez p,q pe key_size/2 biti cu safe=1
	BIGNUM* p = BN_new();
	BIGNUM* q = BN_new();
	BN_generate_prime_ex(p, key_size / 2, 1, NULL, NULL, NULL);
	BN_generate_prime_ex(q, key_size / 2, 1, NULL, NULL, NULL);
	///
	//2. n = p * q
	BIGNUM* n = BN_new();
	BN_mul(n, p, q, ctx);
	///
	//3. fi(n) = (p-1) * (q-1)
	BIGNUM* unu = BN_new();
	BN_set_word(unu, 1);

	BIGNUM* p_minus_1 = BN_new();
	BIGNUM* q_minus_1 = BN_new();

	BN_sub(p_minus_1, p, unu);
	BN_sub(q_minus_1, q, unu);

	BIGNUM* fi = BN_new();
	BN_mul(fi, p_minus_1, q_minus_1, ctx);
	///
	//4. verific gcd(e,fi) == 1
	BIGNUM* e = BN_new();
	BIGNUM* gcd = BN_new();
	/* aleg e a.i gcd(e,fi)=1 */
	int pub_exp[] = { 3, 17, 65537 };
	int status = 0;
	for (int i = 0; i < 3; i++)
	{

		BN_set_word(e, pub_exp[i]);
		BN_gcd(gcd, e, fi, ctx);

		status = BN_cmp(gcd, unu);
		if (status == 0) break;
		else printf("Am gasit e corect!\n");
	}
	///
	//5. calculez d, exp privat
	//a.i. d=e^(-1) mod fi 
	BIGNUM* d = BN_new();
	BN_mod_inverse(d, e, fi, ctx);

	/*-------------------------Verific cheile prin criptare/decriptare--------------------------*/

	// criptare cu exp public e
	//BIGNUM* plain = BN_new();
	//BIGNUM* cipher = BN_new();

	//BN_set_word(plain, 9999999);
	//BN_mod_exp(cipher, plain, e, n, ctx);
	//// decriptare cu exp privat d
	//BIGNUM* plain1 = BN_new();
	//BN_mod_exp(plain1, cipher, d, n, ctx);
	//int eq = BN_cmp(plain, plain1);
	//if (eq)
	//	printf("\nEROARE chei BN!\n");
	//else
	//	printf("\nCORECT chei BN!\n");
	/*------------------------------------------------------------------------------------------*/

	/*------------------------------------Populez instantele de key pub/prv---------------------*/
	RSA_PUBLIC_KEY_PKCS1* RSA_PUB = RSA_PUBLIC_KEY_PKCS1_new();

	BN_to_ASN1_INTEGER(e, RSA_PUB->publicExponent);
	BN_to_ASN1_INTEGER(n, RSA_PUB->modulus);

	RSA_PRIVATE_KEY_PKCS1* RSA_PRV = RSA_PRIVATE_KEY_PKCS1_new();

	BIGNUM* version = BN_new();
	BN_set_word(version, 0);

	BN_to_ASN1_INTEGER(version, RSA_PRV->version);
	BN_to_ASN1_INTEGER(n, RSA_PRV->modulus);
	BN_to_ASN1_INTEGER(e, RSA_PRV->publicExponent);
	BN_to_ASN1_INTEGER(d, RSA_PRV->privateExponent);
	BN_to_ASN1_INTEGER(p, RSA_PRV->prime1);
	BN_to_ASN1_INTEGER(q, RSA_PRV->prime2);

	BIGNUM* exponent1 = BN_new();
	BIGNUM* exponent2 = BN_new();
	BIGNUM* coefficient = BN_new();

	BN_mod(exponent1, d, p_minus_1, ctx);
	BN_mod(exponent2, d, q_minus_1, ctx);
	BN_mod_inverse(coefficient, q, p, ctx);

	BN_to_ASN1_INTEGER(exponent1, RSA_PRV->exponent1);
	BN_to_ASN1_INTEGER(exponent2, RSA_PRV->exponent2);
	BN_to_ASN1_INTEGER(coefficient, RSA_PRV->coefficient);


	/*Nu mai am nevoie de BN-uri in RAM*/
	BN_free(p);
	BN_free(q);
	BN_free(n);
	BN_free(p_minus_1);
	BN_free(q_minus_1);
	BN_free(unu);
	BN_free(fi);
	BN_free(e);
	BN_free(d);
	BN_free(exponent1);
	BN_free(exponent2);
	BN_free(coefficient);
	BN_CTX_free(ctx);
	/*--------------------------------------------------------------------------------------------*/
	unsigned char* rsa_pubkey_pkcs1_asn1 = NULL;
	unsigned char* rsa_prvkey_asn1 = NULL;
	int len_rsa_pubkey_pkcs1_asn1 = 0;
	int len_rsa_prvkey_asn1 = 0;


	len_rsa_pubkey_pkcs1_asn1 = i2d_RSA_PUBLIC_KEY_PKCS1(RSA_PUB, &rsa_pubkey_pkcs1_asn1); //trec din structura interna a cheii publice in format ASN1 conform PKCS #1
	RSA_PUBLIC_KEY_PKCS1_free(RSA_PUB); //dezaloc instanta cheii publice din RAM fiindca acum o am ca structura ASN1 in rsa_pubkey_pkcs1_asn1
								  //nu e nevoie de memset(0) pt ca RSA_PUB era cheia publica



	RSA_PUBLIC_KEY_X509* RSA_PUB_PKCS1 = RSA_PUBLIC_KEY_X509_new();
	RSA_PUB_PKCS1->sequence->obID = OBJ_nid2obj(NID_rsaEncryption); //populez secventa cu OBJECT IDENTIFIER-ul criptarii rsa
	ASN1_BIT_STRING_set(RSA_PUB_PKCS1->publicinfo, rsa_pubkey_pkcs1_asn1, len_rsa_pubkey_pkcs1_asn1);

	unsigned char* rsa_pub_key_x509 = NULL;
	int len_rsa_pub_key_x509 = 0;
	//obtin intreaga structura a cheii in ASN1, conform X.509
	len_rsa_pub_key_x509 = i2d_RSA_PUBLIC_KEY_X509(RSA_PUB_PKCS1, &rsa_pub_key_x509);
	RSA_PUBLIC_KEY_X509_free(RSA_PUB_PKCS1);

	FILE* fp_pub = fopen(pubkey_filename, "wb");
	if (fp_pub == NULL) printf("No rsakey.pub file!\n");

	PEM_write(fp_pub, "PUBLIC KEY", "", rsa_pub_key_x509, len_rsa_pub_key_x509);
	fclose(fp_pub);


	FILE* fp_prv = fopen(prvkey_filename, "wb");
	if (fp_prv == NULL) printf("No rsakey.prv file!\n");


	len_rsa_prvkey_asn1 = i2d_RSA_PRIVATE_KEY_PKCS1(RSA_PRV, &(rsa_prvkey_asn1));
	RSA_PRIVATE_KEY_PKCS1_free(RSA_PRV);
	PEM_write(fp_prv, "RSA PRIVATE KEY", "", rsa_prvkey_asn1, len_rsa_prvkey_asn1);
	fclose(fp_prv);

}



static int _write_to_file(const char *filename, const unsigned char *data,const unsigned int len)
{
	if (data == NULL)
		return 0;

	FILE *fp = fopen(filename, "wb");
	if (fp == NULL)
		return 0;

	fwrite(data, 1, len, fp);

	fclose(fp);

	return 1;
}

static int _read_from_file(const char *filename, unsigned char **data, unsigned int *len)
{
	if (data == NULL || len == NULL)
		return 0;

	FILE *fp = fopen(filename, "rb");
	if (fp == NULL)
		return 0;

	fseek(fp, 0, SEEK_END);
	*len = (unsigned int)ftell(fp);
	fseek(fp, 0, SEEK_SET);

	*data = (unsigned char *)malloc(*len);

	fread(*data, 1, *len, fp);
	fclose(fp);

	return 1;
}

unsigned int read_public_key(const char* filename, BIGNUM*& e, BIGNUM*& n) {
	FILE* fp = fopen(filename, "rb");

	unsigned char* str_pub_key = NULL;
	long len_pub_key = 0;
	char* c;

	PEM_read(fp, &c, &c, &str_pub_key, &len_pub_key);

	RSA_PUBLIC_KEY_X509* X509_pub_key = RSA_PUBLIC_KEY_X509_new();
	X509_pub_key = d2i_RSA_PUBLIC_KEY_X509(&X509_pub_key, (const unsigned char**)&str_pub_key, len_pub_key);

	RSA_PUBLIC_KEY_PKCS1* PKCS1_pub_key = RSA_PUBLIC_KEY_PKCS1_new();
	PKCS1_pub_key = d2i_RSA_PUBLIC_KEY_PKCS1(&PKCS1_pub_key, (const unsigned char**)&X509_pub_key->publicinfo->data, X509_pub_key->publicinfo->length);

	e = ASN1_INTEGER_to_BN(PKCS1_pub_key->publicExponent, e);
	n = ASN1_INTEGER_to_BN(PKCS1_pub_key->modulus, n);

	len_pub_key = PKCS1_pub_key->modulus->length;



	RSA_PUBLIC_KEY_PKCS1_free(PKCS1_pub_key);
	fclose(fp);

	return len_pub_key;
}


unsigned int read_private_key(const char* filename, BIGNUM*& d, BIGNUM*& n) {

	FILE* fp = fopen(filename, "rb");

	d = NULL;
	n = NULL;

	unsigned char* str_prv_key = NULL;
	long len_prv_key = 0;
	char* c;

	PEM_read(fp, &c, &c, &str_prv_key, &len_prv_key);
	RSA_PRIVATE_KEY_PKCS1* RSA_PRV = RSA_PRIVATE_KEY_PKCS1_new();
	RSA_PRV = d2i_RSA_PRIVATE_KEY_PKCS1(&RSA_PRV, (const unsigned char**)&str_prv_key, len_prv_key);
	
	d = ASN1_INTEGER_to_BN(RSA_PRV->privateExponent, d);
	n = ASN1_INTEGER_to_BN(RSA_PRV->modulus, n);

	len_prv_key = RSA_PRV->modulus->length;

	RSA_PRIVATE_KEY_PKCS1_free(RSA_PRV);
	return len_prv_key;
}



unsigned int read_plaintext_from_file(const char* filename, unsigned char** plaintext, const unsigned int key_length) {
	FILE* fp_plaintext = fopen(filename, "rb");

	fseek(fp_plaintext, 0, SEEK_END);
	int file_length = ftell(fp_plaintext);
	fseek(fp_plaintext, 0, SEEK_SET);

	if (file_length > (key_length - 11)) {
		printf("Lungimea datelor din fisierul %s depaseste lungimea %d a cheii!\n", filename, key_length);
		exit(0);
	}


	*plaintext = (unsigned char*)malloc(sizeof(unsigned char)*file_length);
	unsigned int plaintext_length = fread(*plaintext, sizeof(unsigned char), key_length - 11, fp_plaintext);
	
	fclose(fp_plaintext);
	return plaintext_length;
}

void add_padding(unsigned char*& padded_plaintext, const unsigned char* plaintext, const int len_plaintext, const int len_pub_key) {

	unsigned int padding_random_bytes = len_pub_key - len_plaintext - 3; // -3 bytes pentru ca lungimea fisierului de ciphertext trebuie sa aiba maximum lungimea cheii,
																		// cu tot cu padding
	padded_plaintext = (unsigned char*)malloc(sizeof(unsigned char) * (3 + padding_random_bytes));
	//3 de la 0x00 0x02 si 0x00 la final
	//padding_random_bytes pentru a determina nr de bytes random(minimum 8 este asigurat deja din functia read_public_key())

	padded_plaintext[0] = 0x00;
	padded_plaintext[1] = 0x02;
	unsigned char random_byte = 0x00;
	for (int i = 0; i < padding_random_bytes; i++) {

		while (random_byte == 0x00) {
			RAND_bytes(&random_byte, 1);
		}

		memcpy(padded_plaintext + i + 2, &random_byte, sizeof(unsigned char));
		random_byte = 0x00; //pentru a pastra randomness-ul, altfel primul byte nenul ar fi duplicat pe toata lungimea padding_random_bytes
	}
	padded_plaintext[2 + padding_random_bytes] = 0x00;
	memcpy(padded_plaintext + 3 + padding_random_bytes, plaintext, len_plaintext);
}

void encrypt(const char* plaintext_filename, const char* publickey_filename, const char* encrypted_filename) {


	BIGNUM* e = BN_new();
	BIGNUM* n = BN_new();

	unsigned int len_pub_key = read_public_key(publickey_filename, e, n);
	unsigned char* plaintext = NULL;
	unsigned int len_plaintext = read_plaintext_from_file(plaintext_filename, &plaintext, len_pub_key);
	
	unsigned char* padded_plaintext = NULL;
	add_padding(padded_plaintext, plaintext, len_plaintext, len_pub_key);

	BIGNUM* plaintextBN = BN_new();
	plaintextBN = BN_bin2bn(padded_plaintext, len_pub_key, plaintextBN);

	BIGNUM* ciphertextBN = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	

	BN_mod_exp(ciphertextBN, plaintextBN, e, n, ctx); //criptarea propriu-zisa


	unsigned char* ciphertext = NULL;
	unsigned int len_ciphertext = 0;
	ciphertext = (unsigned char*)malloc(sizeof(unsigned char) * len_pub_key + 2); //+2 de la primii 2 octeti de padding 0x00 0x02
	len_ciphertext = BN_bn2bin(ciphertextBN, ciphertext);

	_write_to_file(encrypted_filename, ciphertext, len_ciphertext);

	BN_CTX_free(ctx);
	BN_free(e);
	BN_free(n);
	BN_free(ciphertextBN);
	BN_free(plaintextBN);

	memset(plaintext, 0, len_plaintext);
	free(plaintext);
	memset(ciphertext, 0, len_plaintext);
	free(ciphertext);
}


void decrypt(const char* ciphertext_filename, const char* privatekey_filename, const char* plaintext_filename) {

	BIGNUM* d = BN_new();
	BIGNUM* n = BN_new();
	BN_CTX* ctx = BN_CTX_new();




	unsigned char* ciphertext = NULL;
	unsigned int len_ciphertext = 0;
	_read_from_file(ciphertext_filename, &ciphertext, &len_ciphertext);



	BIGNUM* ciphertextBN = BN_new();
	ciphertextBN = BN_bin2bn(ciphertext, len_ciphertext, ciphertextBN);
	unsigned int len_prv_key = read_private_key(privatekey_filename, d, n);

	BIGNUM* plaintextBN = BN_new();
	BN_mod_exp(plaintextBN, ciphertextBN, d, n, ctx);//decriptarea propriu-zisa

	unsigned char* padded_plaintext = NULL;
	unsigned char* plaintext = NULL;
	unsigned int len_plaintext = 0;
	
	padded_plaintext = (unsigned char*)malloc(sizeof(unsigned char) * len_prv_key);
	BN_bn2bin(plaintextBN, padded_plaintext);
	
	unsigned int len_padding = 1;
	while (padded_plaintext[len_padding] != 0x00) { //calculez lungimea padding-ului PKCS v1.5 ca sa extrag din el plaintextul
		len_padding++;
	}
	len_padding++;
	len_plaintext = len_prv_key - len_padding;
	plaintext = (unsigned char*)malloc(sizeof(unsigned char) * len_plaintext);
	memcpy(plaintext, padded_plaintext + len_padding, len_plaintext);




	_write_to_file(plaintext_filename, plaintext, len_plaintext);


	

	BN_CTX_free(ctx);
	BN_free(d);
	BN_free(n);
	BN_free(ciphertextBN);
	BN_free(plaintextBN);
	memset(ciphertext, 0, len_ciphertext);
	free(ciphertext);
	memset(padded_plaintext, 0, len_prv_key);
	free(padded_plaintext);
	memset(plaintext, 0, len_plaintext);
	free(plaintext);
}




void main(int argc, char* argv[]) {

	if (!strcmp(argv[1], "genkey")) generate_key_pair(atoi(argv[2]), argv[3], argv[4]); //key_size, pubkey_file, prvkey_file

	if (!strcmp(argv[1], "encrypt")) encrypt(argv[2], argv[3], argv[4]); //plaintext_file, pubkey_file, ciphertext_file

	if(!strcmp(argv[1],"decrypt")) decrypt(argv[2], argv[3], argv[4]); //ciphertext_file, prvkey_file, plaintext_file

	printf("\n=======================================Done=======================================!\n");

	getchar();
}