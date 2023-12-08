//Thanks for reading DISCLAIMER.txt

/*
	This samples shows how to encrypt some data using CKM_RSA_PKCS_OAEP mechanism.
	Samples generates a session keypair.
*/


#include <iostream>
#include <cryptoki.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

// OS Check
#ifdef NIX
	#include <dlfcn.h>
#else
	#include <windows.h>
#endif

// OS Check
#ifdef NIX
	void *libHandle = 0;
#else
	HINSTANCE libHandle = 0; 
#endif


CK_FUNCTION_LIST *p11Func = NULL;
CK_SLOT_ID slotId = 0;
CK_SESSION_HANDLE hSession = 0;
CK_BYTE *slotPin = NULL;
const char *libPath = NULL;
CK_OBJECT_HANDLE hPublic = 0; //Stores handle number of a public key.
CK_OBJECT_HANDLE hPrivate = 0; // Stores handle number of a private key.
CK_BYTE plainData[] = "Earth is the third planet of our Solar System.";
CK_BYTE *encrypted = NULL;
CK_BYTE *decrypted = NULL;
CK_ULONG encLen, decLen;
CK_RSA_PKCS_OAEP_PARAMS oaepParam = {0};


// This function loads a pkcs11 library. Path of the pkcs11 library is read using P11_LIB environment variable.
void loadHSMLibrary()
{
	libPath = getenv("P11_LIB");
	if(libPath==NULL)
	{
		cout << "P11_LIB environment variable not set." << endl;
		exit(1);
	}

	// OS Check	
	#ifdef NIX
		libHandle = dlopen(libPath, RTLD_NOW);
	#else
		libHandle = LoadLibrary(libPath);
	#endif


	if(!libHandle)
	{
		cout << "Failed to load P11 library. " << libPath << endl;
		exit(1);
	}

	// OS Check
	#ifdef NIX
		CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList)dlsym(libHandle,"C_GetFunctionList");
	#else
		CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(libHandle,"C_GetFunctionList");
	#endif

	C_GetFunctionList(&p11Func);
	if(!p11Func)
	{
		cout << "Failed to load P11 Functions." << endl;
		exit(1);
	}
}



// Before exiting, this functions performs some memory cleanup.
void freeResource()
{
	#ifdef NIX
		dlclose(libHandle);
	#else
		FreeLibrary(libHandle);
	#endif
        p11Func = NULL;
        slotPin = NULL;
}



// This function checks if a requested PKCS #11 operation was a success or a failure. 
void checkOperation(CK_RV rv, const char *message)
{
	if(rv!=CKR_OK)
	{
		cout << message << " failed with : " << rv << endl;
		printf("RV : %#08lx", rv);
		freeResource();
		exit(1);
	}
}



// This function connects this sample to a slot. It initializes the library, opens a new session and performs login.
void connectToSlot()
{
	checkOperation(p11Func->C_Initialize(NULL_PTR),"C_Initialize");
	checkOperation(p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession),"C_OpenSession");
	checkOperation(p11Func->C_Login(hSession, CKU_USER, slotPin, strlen((const char*)slotPin)),"C_Login");
}



// This function disconnects this sample from a slot. It first logs out of the slot, closes the session and then finalizes the library.
void disconnectFromSlot()
{
	checkOperation(p11Func->C_Logout(hSession),"C_Logout");
	checkOperation(p11Func->C_CloseSession(hSession),"C_CloseSesion");
	checkOperation(p11Func->C_Finalize(NULL_PTR),"C_Finalize");
}



// This function generates an RSA 2048 bit Key pair.
void generateRsaKeyPair()
{
    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN};
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ULONG keySize = 2048;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x00, 0x00, 0x01};
    CK_UTF8CHAR pubLabel[] = "rsa_public";
    CK_UTF8CHAR priLabel[] = "rsa_private";

    CK_ATTRIBUTE attribPub[] = 
    {
        {CKA_TOKEN,             &no,                sizeof(CK_BBOOL)},
        {CKA_PRIVATE,           &no,                sizeof(CK_BBOOL)},
        {CKA_VERIFY,            &yes,               sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,           &yes,               sizeof(CK_BBOOL)},
        {CKA_MODULUS_BITS,      &keySize,        	sizeof(CK_ULONG)},
        {CKA_PUBLIC_EXPONENT,   &publicExponent,    sizeof(publicExponent)},
        {CKA_LABEL,             &pubLabel,          sizeof(pubLabel)}
    };
    CK_ULONG attribLenPub = sizeof(attribPub) / sizeof(*attribPub);


    CK_ATTRIBUTE attribPri[] = 
    {
        {CKA_TOKEN,             &no,                sizeof(CK_BBOOL)},
        {CKA_PRIVATE,           &yes,               sizeof(CK_BBOOL)},
        {CKA_SIGN,              &yes,               sizeof(CK_BBOOL)},
        {CKA_DECRYPT,           &yes,               sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,         &yes,               sizeof(CK_BBOOL)},
        {CKA_LABEL,             &priLabel,          sizeof(priLabel)}
    };
    CK_ULONG attribLenPri = sizeof(attribPri) / sizeof(*attribPri);

    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPub, attribLenPub, attribPri, attribLenPri, &hPublic, &hPrivate), "C_GenerateKeyPair");
    
    cout << "RSA keypair generated as handle #" << hPublic << " for public key and handle #" << hPrivate << " for a private key." << endl;
    
}



// Converts a byte data to hex.
void printHex(unsigned char *data, int size)
{
	for(int ctr = 0; ctr<size; ctr++)
	{
		printf("%02x", data[ctr]);
	}
	cout << endl;
}


void initOAEP()
{
    oaepParam.source = CKZ_DATA_SPECIFIED;
    oaepParam.pSourceData = NULL;
    oaepParam.ulSourceDataLen = 0;
    oaepParam.hashAlg = CKM_SHA_1;
    oaepParam.mgf = CKG_MGF1_SHA1;
}

// This function encrypt data 
void encryptData()
{
	initOAEP();
	CK_MECHANISM mech = {CKM_RSA_PKCS_OAEP, &oaepParam, sizeof(oaepParam)};
	checkOperation(p11Func->C_EncryptInit(hSession, &mech, hPublic), "C_EncryptInit");
	checkOperation(p11Func->C_Encrypt(hSession, plainData, sizeof(plainData)-1, NULL, &encLen), "C_Encrypt");
	encrypted = new CK_BYTE[encLen];
	checkOperation(p11Func->C_Encrypt(hSession, plainData, sizeof(plainData)-1, encrypted, &encLen), "C_Encrypt");
	cout << "Encrypted data as Hex - " << endl;
	printHex(encrypted, encLen);
}



// This functiond decrypts the encrypted data
void decryptData()
{
	CK_MECHANISM mech = {CKM_RSA_PKCS_OAEP, &oaepParam, sizeof(oaepParam)};
	checkOperation(p11Func->C_DecryptInit(hSession, &mech, hPrivate), "C_DecryptInit");
	checkOperation(p11Func->C_Decrypt(hSession, encrypted, encLen, NULL, &decLen), "C_Decrypt");
	decrypted = new CK_BYTE[decLen];
	checkOperation(p11Func->C_Decrypt(hSession, encrypted, encLen, decrypted, &decLen), "C_Decrypt");
	cout << "Decrypted data as Hex - " << endl;
	printHex(decrypted, decLen);
}


// This function shows the usage of the executable.
void usage(char exeName[30])
{
	cout << "Command usage is :-" << endl;
	cout << exeName << " <slot number> " << "<slot password>" << endl;
	exit(0);
}



int main(int argc, char **argv)
{
	if(argc!=3) 
		usage(argv[0]); 
	else 
	{
		slotId = atoi(argv[1]);
		slotPin = new CK_BYTE[strlen(argv[2])];
		slotPin = (CK_BYTE_PTR)argv[2];
	}

	loadHSMLibrary();
	cout << "P11 library loaded." << endl;
	connectToSlot();
	cout << "Connected via session : " << hSession << endl;
    generateRsaKeyPair();

	cout << "Plain data as hex - " << endl;
	printHex(plainData, sizeof(plainData)-1);
	encryptData();
	decryptData();
	disconnectFromSlot();
	cout << "Disconnected from slot." << endl;
	freeResource();
	return 0;
}
