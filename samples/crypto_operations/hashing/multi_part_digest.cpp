//Thanks for reading DISCLAIMER.txt

/*
	This sample demonstrates how to perform multi-part digest. 
	It takes a file as input and calculates then hash of that file.
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
CK_BYTE plainData[] = "Earth is the third planet of our Solar System."; // Plaindata
CK_BYTE *digest = NULL; // to store hash.
CK_ULONG digestLen = 0; // length of digest.
char *fileName = NULL;
int fileSize = 0;
CK_BYTE *buffer = NULL;


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



// This function read the size of a file
void getFileSize()
{
	ifstream readFile;
	readFile.open(fileName, ios::in|ios::binary);
	readFile.seekg(0, ios::end);
	fileSize = readFile.tellg();
	readFile.close();
}



// This function generates the hash of a file.
void hash_of_a_file()
{
	ifstream readFile;
	CK_ULONG bufferLen = 32;
	int bytes_to_read = fileSize;
	CK_MECHANISM mech = {CKM_SHA256};

	readFile.open(fileName, ios::in|ios::binary);
	checkOperation(p11Func->C_DigestInit(hSession, &mech), "C_DigestInit");

	do
	{
		buffer = new CK_BYTE[bufferLen];
		readFile.read((char*)buffer, bufferLen);
		checkOperation(p11Func->C_DigestUpdate(hSession, buffer, bufferLen), "C_DigestUpdate");
		bytes_to_read = bytes_to_read - bufferLen;
		if (bytes_to_read < bufferLen && bytes_to_read > 0)
		{
			buffer = new CK_BYTE[bytes_to_read];
			readFile.read((char*)buffer, bytes_to_read);
			checkOperation(p11Func->C_DigestUpdate(hSession, buffer, bytes_to_read), "C_DigestUpdate");
			bytes_to_read = 0;
		}
	} while(bytes_to_read!=0);

	checkOperation(p11Func->C_DigestFinal(hSession, NULL, &digestLen), "C_DigestFinal");
	digest = new CK_BYTE[digestLen];
	checkOperation(p11Func->C_DigestFinal(hSession, digest, &digestLen), "C_DigestFinal");
	readFile.close();
}



// This function shows the usage of the executable.
void usage(char exeName[30])
{
	cout << "Command usage is :-" << endl;
	cout << exeName << " <slot number> " << " <slot password> " << " < file_name > " << endl;
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
		fileName = new char[strlen(argv[3])];
		fileName = argv[3];
	}

	loadHSMLibrary();
	cout << "P11 library loaded." << endl;
	connectToSlot();
	cout << "Connected via session : " << hSession << endl;

	cout << "Reading file " << fileName << endl;
	getFileSize();
	cout << "Size of file : " << fileSize << endl;

	hash_of_a_file();
	cout << "SHA-256 Hash : ";
	printHex(digest, digestLen);
	disconnectFromSlot();
	cout << "Disconnected from slot." << endl;
	freeResource();
	return 0;
}