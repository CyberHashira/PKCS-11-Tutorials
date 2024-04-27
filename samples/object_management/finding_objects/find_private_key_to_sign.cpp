//Thanks for reading DISCLAIMER.txt

/*
    This sample demonstrates the working of C_FindObjects functions. It does the following -
        - Find a specified private key from a token.
        - Use that private key to sign a file.
        - Write signature to a file.


	Following steps are required before executing this sample -
	1. Generate a private key using p11tool using the following command.
		p11tool --login --generate-privkey=rsa --bits=2048 --label mySigningKey --outfile=verification.pub
	2. Create a text file as follows.
		echo -n "Earth is the third planet of our Solar System." > earth.txt


	# Verify signature as shown below.
		hashi@CyberHashira finding_objects % openssl pkeyutl -verify -in earth.txt -rawin -inkey verification.pub -pubin -sigfile signature_file 
		Signature Verified Successfully

	# Using some other public key should result in a verification failure as shown below
		hashi@CyberHashira finding_objects % openssl pkeyutl -verify -in earth.txt -rawin -inkey another_pubkey.pub -pubin -sigfile signature_file 
		Signature Verification Failure
*/



#include <iostream>
#include <cryptoki.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>

using namespace std;

// OS Check
#ifdef NIX
	#include <dlfcn.h> // For Unix/Linux OS
#else
	#include <windows.h> // For Windows OS
#endif

// OS Check
#ifdef NIX
	void *libHandle = 0;
#else
	HINSTANCE libHandle = 0; 
#endif


CK_FUNCTION_LIST *p11Func = NULL; // Maintains the list of all obtained PKCS#11 functions.
CK_SLOT_ID slotId; // Stores the slot ID.
CK_SESSION_HANDLE hSession; // Stores the session handle.
CK_BYTE *slotPin = NULL; // Stores the slot pin.
const char *libPath = NULL; // Stores the library path.
CK_BYTE *keyLabel = NULL; // Label of the signing key.
CK_OBJECT_HANDLE sigKeyHandle = 0; // Handle number of the signing key.
CK_BYTE RAW_DATA[] = "Earth is the third planet of our Solar System."; // Data to sign
CK_BYTE *signature = NULL; // Stores the signature.
CK_ULONG sigLen = 0;


// Function declarations
void loadHSMLibrary();
void connectToSlot();
void disconnectFromSlot();
void checkOperation(CK_RV, const char*);
void freeResource();
void usage();
void findSigningKey();
void signData();
void writeSignature();



// This function loads a pkcs11 library. Path of the pkcs11 library is read using P11_LIB environment variable.
void loadHSMLibrary()
{
	libPath = getenv("P11_LIB"); // Read P11_LIB environment variable.
	if(libPath==NULL)
	{
		cout << "P11_LIB environment variable not set." << endl;
		exit(1);
	}

	// OS Check	
	#ifdef NIX
		libHandle = dlopen(libPath, RTLD_NOW); // Load library for Unix/Linux
	#else
		libHandle = LoadLibrary(libPath); // Load Library for Windows.
	#endif


	if(!libHandle)
	{
		cout << "Failed to load P11 library. " << libPath << endl;
		exit(1);
	}

	// OS Check
	#ifdef NIX
		CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList)dlsym(libHandle,"C_GetFunctionList"); // Obtain function list on Unix/Linux OS.
	#else
		CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(libHandle,"C_GetFunctionList"); // Obtain function on Windows.
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




// This function finds a private key.
void findSigningKey()
{
    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_OBJECT_HANDLE *objHandle = new CK_OBJECT_HANDLE[1];
    CK_ULONG objCount=0;
    CK_ATTRIBUTE attrib[] = 
    {
        { CKA_CLASS, &objClass, sizeof(CK_OBJECT_CLASS)},
        { CKA_LABEL, keyLabel, strlen((const char*)keyLabel)}
    };
    CK_ULONG attribLen = sizeof(attrib)/sizeof(*attrib);

    checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, attribLen), "C_FindObjectsInit");
    checkOperation(p11Func->C_FindObjects(hSession, objHandle, 1, &objCount), "C_FindObjects");
	checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");
    if(objCount==0)
    {
        cout << "Private not found." << endl;
    }
	else
	{
		cout << keyLabel << " found." << endl;
		sigKeyHandle = objHandle[0];
		signData();
	}
}




// Sign data
void signData()
{
	CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS};
	checkOperation(p11Func->C_SignInit(hSession, &mech, sigKeyHandle), "C_SignInit");
	checkOperation(p11Func->C_Sign(hSession, RAW_DATA, sizeof(RAW_DATA)-1, NULL, &sigLen), "C_Sign");
	signature = new CK_BYTE[sigLen];
	checkOperation(p11Func->C_Sign(hSession, RAW_DATA, sizeof(RAW_DATA)-1, signature, &sigLen), "C_Sign");
	cout << "Data signed." << endl;
	writeSignature();
}



// Writes signature to a file.
void writeSignature()
{
	ofstream outFile;
	outFile.open("signature_file", ios::out|ios::binary);
	outFile.write((const char*)signature, sigLen);
	outFile.flush();
	outFile.close();
}




// This function shows the usage of the executable.
void usage(char exeName[30])
{
	cout << "Command usage is :-" << endl;
	cout << exeName << " <slot number> " << " <slot password> " << " <signing_key_label> " << endl;
	exit(0);
}



int main(int argc, char **argv)
{
	if(argc!=4) 
		usage(argv[0]); 
	else 
	{
		slotId = atoi(argv[1]);
		slotPin = new CK_BYTE[strlen(argv[2])];
		slotPin = (CK_BYTE_PTR)argv[2];
        keyLabel = new CK_BYTE[strlen(argv[3])];
        keyLabel = (CK_BYTE_PTR)argv[3];
	}

	loadHSMLibrary();
	cout << "P11 library loaded." << endl;
	connectToSlot();
	cout << "Connected via session : " << hSession << endl;
    findSigningKey();
	disconnectFromSlot();
	cout << "Disconnected from slot." << endl;
	freeResource();
	return 0;
}