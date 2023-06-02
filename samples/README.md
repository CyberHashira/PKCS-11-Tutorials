PKCS #11 Samples code
------------------------

These are some pkcs#11 samples that I've provided for viewers on YouTube. These sample codes were tested on SoftHSM2.

Last Update : May-26-2023



Table of Contents 
------------------


1. connect_disconnect 	: contains sample codes that shows how to connect/disconnect from a token using pkcs#11 API. These are some of those samples.
	- connect_disconnect_windows.cpp  :	sample code for Windows operating system.
	- connect_disconnect_linux.cpp	: sample code for Linux/Unix operating system.
	- all_platforms.cpp : sample code that works for all platforms.
		# To compile on windows - 
			g++ all_platform.cpp -o all_platform -I../include
		# To compile on Linux/Unix/Mac OS	
			g++ all_platform.cpp -o all_platform -I../include -DNIX

2. slots_and_tokens 	: contains samples codes that shows how to work with slots and tokens.
	- get_slot_list.cpp	: displays the list of detected slots.
	- get_slot_list2.cpp : shows the behavior of C_GetSlotList.
	- get_slot_list3.cpp : shows how to reinitialize cryptoki to get an updated list of slots.
	- slots_and_token_info.cpp : shows how to use C_GetSlotInfo and C_GetTokenInfo.



