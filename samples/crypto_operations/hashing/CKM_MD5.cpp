//Thanks for reading DISCLAIMER.txt

/*
	This sample demonstrates how to generate hash of a data using CKM_MD5 mechanism.
*/



#include <iostream>
#include <cryptoki.h>
#include <stdlib.h>
#include <string.h>

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
CK_BYTE plainData[] = "Earth is the third planet of our Solar System."; // Plaindata
CK_BYTE *digest = NULL; // to store hash.
CK_ULONG digestLen = 0; // length of digest.




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



// Converts byte array to Hex String.
void printHex(CK_BYTE *bytes, int len)
{
	for(int ctr=0; ctr<len; ctr++)
	{
		printf("%02x", bytes[ctr]);
	}
	cout << endl;
}



// This function generates the hash
void generateHash()
{
	CK_MECHANISM mech = {CKM_MD5};
	checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");
	checkOperation(p11Func->C_Digest(hSession, plainData, sizeof(plainData)-1, NULL, &digestLen), "C_Digest");
	digest = new CK_BYTE[digestLen];
	checkOperation(p11Func->C_Digest(hSession, plainData, sizeof(plainData)-1, digest, &digestLen), "C_Digest");
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
	
	cout << endl << "Plaindata as Hex -" << endl;
	printHex(plainData, sizeof(plainData)-1);
	generateHash();
	cout << "MD5 Hash : ";
	printHex(digest, digestLen);

	disconnectFromSlot();
	cout << "Disconnected from slot." << endl;
	freeResource();
	return 0;
}