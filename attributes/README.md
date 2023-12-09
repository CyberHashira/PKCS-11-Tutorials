#PKCS #11 Return Codes
-----------------------

These are some common attributes using in PKCS#11. Attributes are used for describing the properties of an object. These attributes are used when generating an 
object, finding an object, modifying an object and reading an object. 

	* * Last Update : Dec-08-2023 * *



ATTRIBUTES -
----------

| ATTRIBUTES     | Description | Data type |
|:---------------|-------------|----------:|
| CKA_CLASS             | Class of an object. For e.g. CKO_SECRET_KEY, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY | CK_OBJECT_CLASS |
| CKA_TOKEN             | Session object or Token Object | CK_BBOOL |
| CKA_PRIVATE           | Authentication required for accessing an object | CK_BBOOL |
| CKA_LABEL             | Label of an object. | CK_BYTE |
| CKA_VALUE             | Value of an object. | CK_BYTE |
| CKA_KEY_TYPE          | Type of key. For e.g. AES, RSA, DSA etc. | CK_KEY_TYPE |
| CKA_ID                | Some value to be used as an identifier.. For e.g. serial | CK_BYTE |
| CKA_SENSITIVE         | Marks an object as sensitive | CK_BBOOL |
| CKA_ENCRYPT           | Object can encrypt | CK_BBOOL |
| CKA_DECRYPT           | Object can decrypt | CK_BBOOL |
| CKA_WRAP              | Object can wrap another object | CK_BBOOL |
| CKA_UNWRAP            | Object can unwrap another object | CK_BBOOL |
| CKA_SIGN              | Object can sign | CK_BBOOL |
| CKA_VERIFY            | Object can verify | CK_BBOOL |
| CKA_DERIVE            | Object can derive another object | CK_BBOOL |
| CKA_MODULUS           | Modulus of an RSA key | CK_BYTE |
| CKA_MODULUS_BITS      | Size of RSA key | CK_ULONG |
| CKA_PUBLIC_EXPONENT   | Public Exponent of RSA key | CK_BYTE |
| CKA_VALUE_LEN         | Size of a secret key | CK_BYTE |
| CKA_LOCAL             | If true, object was generated inside a hardware token | CK_BBOOL |
| CKA_EXTRACTABLE       | Object can be extracted from a token | CK_BBOOL |
| CKA_NEVER_EXTRACTABLE | True if CKA_EXTRACTABLE has always been false | CK_BBOOL |
| CKA_ALWAYS_SENSITIVE  | True if CKA_SENSTITIVE has always been sensitive | CK_BBOOL |
| CKA_MODIFIABLE        | Object can be modified | CK_BBOOL |
| CKA_EC_PARAMS         | ECDSA curve | CK_BYTE |
| CKA_EC_POINT          | ECDSA public key | CK_BYTE |
| CKA_VENDOR_DEFINED    | An attribute reserved for vendor use | Not defined |
