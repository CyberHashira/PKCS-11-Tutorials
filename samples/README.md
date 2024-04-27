#PKCS #11 Samples code
-----------------------

These are some pkcs#11 samples that I've provided for viewers on YouTube. These sample codes were tested on SoftHSM2.

	* * Last Update : Apr-27-2024 * *



Table of Contents 
------------------


1. connect_disconnect 	: contains sample codes that shows how to connect/disconnect from a token using pkcs#11 API. These are some of those samples.
	- connect_disconnect_windows.cpp  :	sample code for Windows operating system.
	- connect_disconnect_linux.cpp	  : 	sample code for Linux/Unix operating system.
	- all_platforms.cpp 		  : 	sample code that works for all platforms.
		# To compile on windows - 
			g++ all_platform.cpp -o all_platform -I../include
		# To compile on Linux/Unix/Mac OS	
			g++ all_platform.cpp -o all_platform -I../include -DNIX

2. slots_and_tokens 	: contains samples codes that shows how to work with slots and tokens.
	- get_slot_list.cpp.............: displays the list of detected slots.
	- get_slot_list2.cpp............: shows the behavior of C_GetSlotList.
	- get_slot_list3.cpp............: shows how to reinitialize cryptoki to get an updated list of slots.
	- slots_and_token_info.cpp......: shows how to use C_GetSlotInfo and C_GetTokenInfo.


3. object_management	: contains sample codes that shows how to generate, modify, find, and delete objects.

	- GENERATING-KEYS
		- createobject_data.cpp		  : shows how to create a data object using PKCS#11 API.
		- generate_aes_key.cpp............: shows how to generate AES key using PKCS#11 API.
		- generate_des3_key.cpp...........: shows how to generate DES3 key using PKCS #11 API.
		- generate_rsa_keypair.cpp........: shows how to generare RSA keypair using PKCS#11 API.
		- generate_ecdsa_keypair.cpp......: shows how to generate ECDSA keypair using PKCS#11 API.
	- FINDING OBJECTS
		- count_all_keys.cpp..............: shows how to use C_FindObjects function.
		- find_private_key_to_sing.cpp....: shows how to use a private key store in a token to sign some data.

4. crypto_operations	: contains sample codes that shows how to perform cryptographic operations such as encryption, signing etc.

	- HASHING
		- CKM_MD5.cpp.....................: shows how to generate hash using CKM_MD5 mechanism.
		- CKM_SHA_1.cpp...................: shows how to generate hash using CKM_SHA_1 mechanism.
		- CKM_SHA256.cpp..................: shows how to generate hash using CKM_SHA256 mechanism.
		- multi_part_digest.cpp...........: shows how to generate hash of a file using multi-part digest operation.
	- ENCRYPTION
		- CKM_DES3_ECB.cpp................: shows how to encrypt using CKM_DES3_ECB mechanism.
		- CKM_AES_CBC_PAD.cpp.............: shows how to encrypt using CKM_AES_CBC_PAD mechanism.
		- CKM_AES_CTR.cpp.................: shows how to encrypt using CKM_AES_CTR mechanism.
		- CKM_AES_GCM.cpp.................: shows how to encrypt using CKM_AES_GCM mechanism.
		- CKM_RSA_X_509.cpp...............: shows how to encrypt using CKM_RSA_X_509 mechanism.
		- CKM_RSA_PKCS.cpp................: shows how to encrypt using CKM_RSA_PKCS mechanism.
		- CKM_RSA_PKCS_OAEP.cpp...........: shows how to encrypt using CKM_RSA_PKCS_OAEP mechanism.
	- SIGNING
		- CKM_ECDSA.cpp...................: shows how to sign using CKM_ECDSA mechanism.
		- CKM_RSA_PKCS.cpp................: shows how to sign using CKM_RSA_PKCS mechanism.
		- CKM_SHA1_RSA_PKCS.cpp...........: shows how to sign using CKM_SHA1_RSA_PKCS mechanism.
		- CKM_SHA256_RSA_PKCS.cpp.........: shows how to sign using CKM_SHA256_RSA_PKCS mechanism.
		- CKM_SHA256_PKCS_PKCS_PSS.cpp....: shows how to sign using CKM_SHA256_RSA_PKCS_PSS mechanism.
	- MISCELLANEOUS
		- C_GenerateRandom.cpp............: shows how to generate random data using C_GenerateRandom.
		- C_SeedRandom.cpp................: shows how to seed PRNG.
