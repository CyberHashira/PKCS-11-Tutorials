//Thanks for reading DISCLAIMER.txt

/*
	This samples shows how to sign some data using CKM_RSA_PKCS mechanism.
	- Samples generates a session keypair.
	- This sample will Sign and Verify some data.
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
CK_BYTE *signature = NULL;
CK_ULONG sigLen = 0;


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
<<<<<<< HEAD
		printf("RV : 0x%08x", rv);
=======
		printf("RV : %#08lx", rv);
>>>>>>> 8b0a8ad (Minors changes + new samples)
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



// This function signs the plain data 
void signData()
{
	CK_MECHANISM mech = {CKM_RSA_PKCS};
	checkOperation(p11Func->C_SignInit(hSession, &mech, hPrivate), "C_SignInit");
	checkOperation(p11Func->C_Sign(hSession, plainData, sizeof(plainData)-1, NULL, &sigLen), "C_Sign");
	signature = new CK_BYTE[sigLen];
	checkOperation(p11Func->C_Sign(hSession, plainData, sizeof(plainData)-1, signature, &sigLen), "C_Sign");
	cout << "Plaindata signed - " << endl;
	printHex(signature, sigLen);
}



// This functiond decrypts the encrypted data
void verifyData()
{
	CK_MECHANISM mech = {CKM_RSA_PKCS};
	checkOperation(p11Func->C_VerifyInit(hSession, &mech, hPublic), "C_VerifyInit");
	checkOperation(p11Func->C_Verify(hSession, plainData, sizeof(plainData)-1, signature, sigLen), "C_Verify");
	cout << "Signed data verified." << endl;
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
	signData();
	verifyData();
	disconnectFromSlot();
	cout << "Disconnected from slot." << endl;
	freeResource();
	return 0;
}
