//Thanks for reading DISCLAIMER.txt

/*
	This samples demonstrates the following :-
	- Loads PKCS #11 library (softhsm)
	- Retrieves the list of all available slots with tokens.
	- Displays information about those slots and tokens.
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
CK_SLOT_ID *slots = NULL;
const char *libPath;



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
		cout << "Failed to load pkcs#11 library. " << libPath << endl;
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
		cout << "Failed to load pkcs#11 functions." << endl;
		exit(1);
	}
}



// Before exiting, this functions performs some memory cleanup.
void freeResource()
{
	// OS Check
	#ifdef NIX
        	dlclose(libHandle);
	#else
		FreeLibrary(libHandle);
	#endif
        p11Func = NULL;
	slots = NULL;
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



// This function displays information about a slot.
void show_slot_info(CK_SLOT_ID slotId)
{
	CK_SLOT_INFO slotInfo;
	CK_VERSION hardwareVersion;
	CK_VERSION firmwareVersion;

	checkOperation(p11Func->C_GetSlotInfo(slotId, &slotInfo), "C_GetSlotInfo");

	cout << "SLOT INFORMATION :-" << endl;
	cout << "\tDescription : "; cout.write((const char*)slotInfo.slotDescription, sizeof(slotInfo.slotDescription)); cout << endl;
	cout << "\tManufacturer : "; cout.write((const char*)slotInfo.manufacturerID, sizeof(slotInfo.manufacturerID)); cout << endl;
	hardwareVersion = slotInfo.hardwareVersion;
	firmwareVersion = slotInfo.firmwareVersion;
	cout << "\tHardware Version : " << (int)hardwareVersion.major << "." << (int)hardwareVersion.minor << endl;
	cout << "\tFirmware Version : " << (int)firmwareVersion.major << "." << (int)firmwareVersion.minor << endl;
}



// This function displays information about a slot with token.
void show_token_info(CK_SLOT_ID slotId)
{
	CK_TOKEN_INFO tokenInfo;
	CK_VERSION hardwareVersion;
	CK_VERSION firmwareVersion;
	checkOperation(p11Func->C_GetTokenInfo(slotId, &tokenInfo), "C_GetTokenInfo");
	cout << "Token Information -" << endl;
	cout << "\tLabel "; cout.write((const char*)tokenInfo.label, sizeof(tokenInfo.label)); cout <<endl;
	cout << "\tManufacturer "; cout.write((const char*)tokenInfo.manufacturerID, sizeof(tokenInfo.manufacturerID)); cout <<endl;
	cout << "\tModel "; cout.write((const char*)tokenInfo.model, sizeof(tokenInfo.model)); cout <<endl;
	cout << "\tSerial "; cout.write((const char*)tokenInfo.serialNumber, sizeof(tokenInfo.serialNumber)); cout <<endl;
	cout << "\tMax Session Count " << tokenInfo.ulMaxSessionCount << endl;
	cout << "\tSession Count " << tokenInfo.ulSessionCount << endl;
	cout << "\tMax RW Session Count " << tokenInfo.ulMaxRwSessionCount << endl;
	cout << "\tRW Session Count " << tokenInfo.ulRwSessionCount << endl;
	cout << "\tMax Pin Len " << tokenInfo.ulMaxPinLen << endl;
	cout << "\tMin Pin Len " << tokenInfo.ulMinPinLen << endl;
	cout << "\tTotal Public Memory " << tokenInfo.ulTotalPublicMemory << endl;
	cout << "\tFree Public Memory " << tokenInfo.ulFreePublicMemory  << endl;
	cout << "\tTotal Private Memory " << tokenInfo.ulTotalPrivateMemory << endl;
	cout << "\tFree Private Memory " << tokenInfo.ulFreePrivateMemory << endl;
	hardwareVersion = tokenInfo.hardwareVersion;
	firmwareVersion = tokenInfo.firmwareVersion;
	cout << "\tHardware version " << (int)hardwareVersion.major << "." << (int)hardwareVersion.minor << endl;
	cout << "\tFirmware version " << (int)firmwareVersion.major << "." << (int)firmwareVersion.minor << endl;
	cout << "\tUTC-Time " << tokenInfo.utcTime << endl;
}



// This function gets the list of all detected slots..
void show_all_slots()
{
	CK_ULONG no_of_slots;

	checkOperation(p11Func->C_GetSlotList(CK_TRUE, NULL_PTR, &no_of_slots), "C_GetSlotList");
	cout << no_of_slots << " slots detected." << endl;
	slots = new CK_SLOT_ID[no_of_slots];
	checkOperation(p11Func->C_GetSlotList(CK_TRUE, slots, &no_of_slots), "C_GetSlotList");
	
	for(int ctr=0; ctr<no_of_slots; ctr++)
	{
		cout << "-------------------------------------------" << endl;
		cout << "Slot : " << slots[ctr] << endl;
		show_slot_info(slots[ctr]);
		show_token_info(slots[ctr]);
		cout << "-------------------------------------------" << endl;
	}
	
}



// Main function..
int main(int argc, char **argv)
{
	loadHSMLibrary();
	cout << "PKCS#11 library loaded." << endl;
	
	checkOperation(p11Func->C_Initialize(NULL_PTR), "C_Initialize");
	show_all_slots();
	checkOperation(p11Func->C_Finalize(NULL_PTR), "C_Finalize");
	freeResource();
	return 0;
}