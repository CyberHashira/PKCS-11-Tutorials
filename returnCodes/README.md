#PKCS #11 Return Codes
-----------------------

This is a list of common return codes in PKCS#11. The success, failure and status of a PKCS#11 return code can be determined using these return codes.

	* * Last Update : Jan-26-2024 * *



RETURN CODES -
------------
| Return Code | Value | Meaning |
| ------------|-------|---------|
| CKR_OK      					| 0x00000000 | Everything's good |
| CKR_SLOT_ID_INVALID 			| 0x00000003 | Slot id is invalid |
| CKR_GENERAL_ERROR   			| 0x00000005 | Function failed for some unknown reason |
| CKR_ARGUMENT_BAD    			| 0x00000007 | An argument passed into a function is invalid |
| CKR_ATTRIBUTE_READ_ONLY 		| 0x00000010 | An attempt made to change a READ-ONLY attribute |
| CKR_ATTRIBUTE_SENSITIVE   	| 0x00000011 | An attempt was made to read a sensitive attribute | 
| CKR_ATTRIBUTE_TYPE_INVALID    | 0x00000012 | Attribute for an object is invalid |
| CKR_ATTRIBUTE_VALUE_INVALID   | 0x00000013 | Value of an attribute is invalid |
| CKR_DATA_INVALID				| 0x00000020 | Invalid data passed into a function |           
| CKR_DATA_LEN_RANGE            | 0x00000021 | Data passed into a function exceeds a valid range |
| CKR_DEVICE_ERROR              | 0x00000030 | A token could not process a requested operation due to some failure |
| CKR_DEVICE_MEMORY             | 0x00000031 | A token is out of memory |
| CKR_ENCRYPTED_DATA_INVALID	| 0x00000040 | Specified ciphertext is not valid for decrypt operation |
| CKR_ENCRYPTED_DATA_LEN_RANGE	| 0x00000041 | Length of the cipher text is not valid for a specified decrypt operation |
| CKR_FUNCTION_CANCELED         | 0x00000050 | An active function was cancelled mid operation. |
| CKR_FUNCTION_NOT_SUPPORTED    | 0x00000054 | An attempt was made to execute an unsupported function |
| CKR_KEY_HANDLE_INVALID        | 0x00000060 | Handle number of a key is invalid |
| CKR_KEY_SIZE_RANGE            | 0x00000062 | Length of a key in not in the allowed range |
| CKR_KEY_TYPE_INCONSISTENT     | 0x00000063 | Incorrect type of key used for a mechanism |
| CKR_KEY_NOT_WRAPPABLE         | 0x00000069 | Token does not allow a certain type of key to be wrapped |
| CKR_KEY_UNEXTRACTABLE         | 0x0000006A | Key has CKA_EXTRACTABLE set as CK_FALSE |
| CKR_MECHANISM_INVALID         | 0x00000070 | An attempt was made to use a disallowed/unsupported/invalid mechanism |
| CKR_MECHANISM_PARAM_INVALID   | 0x00000071 | Parameter passed for a mechanism is invalid. | 
| CKR_OBJECT_HANDLE_INVALID     | 0x00000082 | Handle number of an object is invalid. |
| CKR_OPERATION_NOT_INITIALED	| 0x00000091 | Requested cryptographic operation is not initialized. |
| CKR_PIN_INCORRECT             | 0x000000A0 | Incorrect pin was used for C_Login |
| CKR_PIN_EXPIRED               | 0x000000A3 | Expired pin was used for C_Login |
| CKR_PIN_LOCKED                | 0x000000A4 | Pin locked due to multiple failed attempts |
| CKR_SESSION_HANDLE_INVALID    | 0x000000B3 | Session handle being used does not exist |
| CKR_SIGNATURE_INVALID         | 0x000000C0 | Signature verification failed. |
| CKR_SIGNATURE_LEN_RANGE       | 0x000000C1 | Length of the signature is invalid |
| CKR_OPERATION_NOT_INITIALIZED	| 0x00000091 | Requested cryptographic operation is not initialized. |
| CKR_TEMPLATE_INCOMPLETE       | 0x000000D0 | Incomplete information in an attribute template |
| CKR_TEMPLATE_INCONSISTENT     | 0x000000D1 | Incorrect information in an attribute template |
| CKR_TOKEN_NOT_PRESENT         | 0x000000E0 | Referenced slot does not have a token present in it. |
| CKR_USER_ALREADY_LOGGED_IN 	| 0x00000100 | A user is already logged into a token |
| CKR_USER_NOT_LOGGED_IN        | 0x00000101 | A user is required to be logged in. |
| CKR_USER_PIN_NOT_INITIALIZED  | 0x00000102 | Normal user is not initialized. |
| CKR_USER_TYPE_INVALID         | 0x00000103 | Type of user not valid for a token |
| CKR_RANDOM_SEED_NOT_SUPPORTED | 0x00000120 | Seeding a PRNG is not supported for the token |
| CKR_RANDOM_NO_RNG			    | 0x00000121 | No PRNG available to generate random data |
| CKR_CRYPTOKI_NOT_INITIALIZED 	| 0x00000190 | C_Initialized not called. |
| CKR_CRYPTOKI_ALREADY_INITIALIZED | 0x00000191 | C_Initialized called more than once |
| CKR_VENDOR_DEFINED 			| 0x80000000 | Error code reserved for a vendor to use. |
