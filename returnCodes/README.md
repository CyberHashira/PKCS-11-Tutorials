#PKCS #11 Return Codes
-----------------------

This is a list of common return codes in PKCS#11. The success, failure and status of a PKCS#11 return code can be determined using these return codes.

	* * Last Update : Dec-08-2023 * *



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
| CKR_FUNCTION_NOT_SUPPORTED    | 0x00000054 | An attempt was made to execute an unsupported function |
| CKR_KEY_HANDLE_INVALID        | 0x00000060 | Handle number of a key is invalid |
| CKR_KEY_SIZE_RANGE            | 0x00000062 | Length of a key in not in the allowed range |
| CKR_KEY_TYPE_INCONSISTENT     | 
| CKR_KEY_NOT_WRAPPABLE
| CKR_KEY_UNEXTRACTABLE
| CKR_MECHANISM_INVALID
+ CKR_MECHANISM_PARAM_INVALID
+ CKR_OBJECT_HANDLE_INVALID
+ CKR_PIN_INCORRECT
+ CKR_PIN_EXPIRED
+ CKR_PIN_LOCKED
+ CKR_SESSION_HANDLE_INVALID
+ CKR_SIGNATURE_INVALID
+ CKR_SIGNATURE_LEN_RANGE
+ CKR_TEMPLATE_INCOMPLETE
+ CKR_TEMPLATE_INCONSISTENT
+ CKR_TOKEN_NOT_PRESENT
