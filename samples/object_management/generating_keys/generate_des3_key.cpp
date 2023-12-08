//Thanks for reading DISCLAIMER.txt

/*
	This samples shows how to generate DES3 key using PKCS#11 API.
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
CK_OBJECT_HANDLE objHandle = 0;



// This function loads a pkcs11 library. Path of the pkcs11 library is read using P11_LIB environment variable.
void loadHSMLibrary()
{
	libPath = getenv("P11_LIB");
	if(libPath==NULL)
	{
		cout << "P11_LIB environment variable not set." << endl;
                cout << "Set P11_LIB environment variable to the pkcs11 library to use." << endl << endl;
                cout << "Example :-" << endl;
                cout << "On Unix/Linux : " << endl;
                cout << "export P11_LIB=/opt/softhsm2/lib/softhsm/libsofthsm2.so" << endl;
		cout << "On Windows " << endl;
		cout << "set P11_LIB=C:\\SoftHSM2\\lib\\softhsm2.dll" << endl;
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



// This function generates a DES-3 Key with the following properties.
// token object|sensitive|read-only|non-extractable|can encrypt and decrypt|private object
void generateDes3Key()
{
    CK_MECHANISM mech = {CKM_DES3_KEY_GEN};
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_UTF8CHAR label[] = "des3_key";

    CK_ATTRIBUTE attrib[] = 
    {
        {CKA_TOKEN,         &yes,       sizeof(CK_BBOOL)},
        {CKA_PRIVATE,       &yes,       sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,     &yes,       sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE,   &no,        sizeof(CK_BBOOL)},
        {CKA_MODIFIABLE,    &no,        sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,       &yes,       sizeof(CK_BBOOL)},
        {CKA_DECRYPT,       &yes,       sizeof(CK_BBOOL)},
        {CKA_LABEL,         &label,     sizeof(label)}
    };
	
    CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

    checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen, &objHandle), "C_GenerateKey");

    cout << "DES-3 Key generated as handle : " << objHandle << endl;
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
    generateDes3Key();
	disconnectFromSlot();
	cout << "Disconnected from slot." << endl;
	freeResource();
	return 0;
}
