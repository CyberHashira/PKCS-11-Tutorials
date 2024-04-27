//Thanks for reading DISCLAIMER.txt

/*
    This sample demonstrates the working of C_FindObjects functions. It does the following -
        
        - Count all keys.
        - Count all ECC private keys.
        - Count all RSA public keys.
        - Count all secret keys.
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


// Function declarations
void loadHSMLibrary();
void connectToSlot();
void disconnectFromSlot();
void checkOperation(CK_RV, const char*);
void freeResource();
void usage();
void countAllObjects();
void countPrivateKeys();
void countPublicKeys();
void countSecretKeys();


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


// This function shows the usage of the executable.
void usage(char exeName[30])
{
	cout << "Command usage is :-" << endl;
	cout << exeName << " <slot number> " << " <slot password> " << " <signing_key_label> " << endl;
	exit(0);
}


// This function counts the number of objects in a token.
void countAllObjects()
{
    CK_BBOOL yes = CK_TRUE;
    CK_OBJECT_HANDLE objHandle[10];
    CK_ULONG objCount = 0;
    CK_ULONG totalObjects = 0;

    CK_ATTRIBUTE attrib[] = 
    {
        { CKA_TOKEN, &yes, sizeof(CK_BBOOL)}
    };
    CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

    checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, attribLen), "C_FindObjectsInit");
    do
    {
        checkOperation(p11Func->C_FindObjects(hSession, objHandle, 10, &objCount), "C_FindObjects");
        totalObjects+=objCount;
    } while(objCount!=0);
    checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");
    cout << "Objects found : " << totalObjects << endl;
}


// This functions counts the number of ECC private keys in a token.
void countPrivateKeys()
{
    CK_BBOOL yes = CK_TRUE;
    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE objType = CKK_EC;
    CK_OBJECT_HANDLE objHandle[10];
    CK_ULONG objCount = 0;
    CK_ULONG totalObjects = 0;

    CK_ATTRIBUTE attrib[] = 
    {
        { CKA_TOKEN, &yes, sizeof(CK_BBOOL)},
        { CKA_CLASS, &objClass, sizeof(CK_OBJECT_CLASS)},
        { CKA_KEY_TYPE, &objType, sizeof(CK_KEY_TYPE)}
    };
    CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

    checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, attribLen), "C_FindObjectsInit");
    do
    {
        checkOperation(p11Func->C_FindObjects(hSession, objHandle, 10, &objCount), "C_FindObjects");
        totalObjects+=objCount;
    } while(objCount!=0);
    checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");
    cout << "ECC Private keys found : " << totalObjects << endl;
}


// This functions counts the number of RSA public keys in a token.
void countPublicKeys()
{
    CK_BBOOL yes = CK_TRUE;
    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE objType = CKK_RSA;
    CK_OBJECT_HANDLE objHandle[10];
    CK_ULONG objCount = 0;
    CK_ULONG totalObjects = 0;

    CK_ATTRIBUTE attrib[] = 
    {
        { CKA_TOKEN, &yes, sizeof(CK_BBOOL)},
        { CKA_CLASS, &objClass, sizeof(CK_OBJECT_CLASS)},
        { CKA_KEY_TYPE, &objType, sizeof(CK_KEY_TYPE)}
    };
    CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

    checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, attribLen), "C_FindObjectsInit");
    do
    {
        checkOperation(p11Func->C_FindObjects(hSession, objHandle, 10, &objCount), "C_FindObjects");
        totalObjects+=objCount;
    } while(objCount!=0);
    checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");
    cout << "RSA Public keys found : " << totalObjects << endl;
}


// This functions counts the number of AES keys in a token.
void countSecretKeys()
{
    CK_BBOOL yes = CK_TRUE;
    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE objType = CKK_AES;
    CK_OBJECT_HANDLE objHandle[10];
    CK_ULONG objCount = 0;
    CK_ULONG totalObjects = 0;

    CK_ATTRIBUTE attrib[] = 
    {
        { CKA_TOKEN, &yes, sizeof(CK_BBOOL)},
        { CKA_CLASS, &objClass, sizeof(CK_OBJECT_CLASS)},
        { CKA_KEY_TYPE, &objType, sizeof(CK_KEY_TYPE)}
    };
    CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

    checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, attribLen), "C_FindObjectsInit");
    do
    {
        checkOperation(p11Func->C_FindObjects(hSession, objHandle, 10, &objCount), "C_FindObjects");
        totalObjects+=objCount;
    } while(objCount!=0);
    checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");
    cout << "AES keys found : " << totalObjects << endl;
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
    countAllObjects();
    countPrivateKeys();
    countPublicKeys();
    countSecretKeys();
	disconnectFromSlot();
	cout << "Disconnected from slot." << endl;
	freeResource();
	return 0;
}