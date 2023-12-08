//Thanks for reading DISCLAIMER.txt

/*
	This samples demonstrates the following :-
    When C_Initialize is called, it tries to detect all slots and stores all that information in memory.
    This program demonstrates that C_GetSlotInfo tries to obtain information from that memory. Here's what it tries to do.
	- Loads PKCS #11 library
	- This program has a loop that repeats thrice and does the following
        > Calls C_Initialize
		> Calls C_GetSlotInfo and pauses.
		> When this program pauses, a user can open another terminal and create a new slot.
		> Pressing any key continues execution of this program and C_Finalize is called.
	- After three loops this program quits.
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
		cout << slots[ctr] << endl;
	}
	
}



int main(int argc, char **argv)
{
    int ctr=0;
	loadHSMLibrary();
	cout << "PKCS#11 library loaded." << endl;
	
    do
    {
        checkOperation(p11Func->C_Initialize(NULL_PTR), "C_Initialize");
        show_all_slots();
        cout << "press any key to continue..." << endl;
        cin.get();
        checkOperation(p11Func->C_Finalize(NULL_PTR), "C_Finalize");
        ctr++;
    }while(ctr<3);
	
	freeResource();
	return 0;
}