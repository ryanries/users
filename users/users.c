// users.exe
// Written by Ryan Ries, January 2013
// Uses wtsapi32.dll to report extended properties about user sessions on local or remote computers.
// Modification of bin headers with editbin.exe was required to make this work on eaerlier versions of Windows at the time when this was written,
// But I think setting the SUBSYSTEM:CONSOLE linker switch fixed the issue.

#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <WtsApi32.h>
#pragma comment(lib, "WtsApi32.lib")

void main(int argc, char *argv[])
{
	char *helpMsg = "\nUSAGE: users.exe [hostname]\n\nNot specifying a hostname implies localhost.\nThis command will return information about users currently logged onto\na local or remote computer, including the client's hostname and IP.\nUsers.exe was written by Ryan Ries.\n";
	char *hostName, *connState = "";
	char *addrFamily = "";
	HANDLE hHost = NULL;
	int retVal = 0;
	unsigned int i = 0;
	PWTS_SESSION_INFO pSessionInfo = 0;
	DWORD dwSessionCount, pBytesReturned = 0;
	LPTSTR pUser, pDomain, pClientName, pClientAddress;
	PWTS_CLIENT_ADDRESS pClientAddressStruct = NULL;

	if(argc > 2)
	{
		printf(helpMsg);
		return;
	}
	if(argc == 2)
	{
		if(strchr(argv[1],'?') || strchr(argv[1],'/') || strchr(argv[1],'\\'))
		{
			printf(helpMsg);
			return;
		}
	}
	
	if(argc < 2)
		hostName = "localhost";
	else
		hostName = argv[1];

	hHost = WTSOpenServer(hostName);	
	retVal = WTSEnumerateSessions(hHost, 0, 1, &pSessionInfo, &dwSessionCount);	
	if(retVal == 0)
	{
		printf("ERROR %d: Could not connect to %s!", GetLastError(), hostName);
		WTSCloseServer(hHost);
		return;
	}

	printf("\n");
	for(i = 0; i < dwSessionCount; i++)
	{		
		WTS_SESSION_INFO si = pSessionInfo[i];
		// To weed out nonsense
		if(si.SessionId > 2048 || si.SessionId < 0)
			continue;
		WTSQuerySessionInformation(hHost, si.SessionId, WTSUserName, &pUser, &pBytesReturned);
        WTSQuerySessionInformation(hHost, si.SessionId, WTSDomainName, &pDomain, &pBytesReturned);
        WTSQuerySessionInformation(hHost, si.SessionId, WTSClientName, &pClientName, &pBytesReturned);
		WTSQuerySessionInformation(hHost, si.SessionId, WTSClientAddress, &pClientAddress, &pBytesReturned);
		pClientAddressStruct = (PWTS_CLIENT_ADDRESS)pClientAddress;

		switch(pClientAddressStruct->AddressFamily)
		{
		case 0:
            addrFamily = "AF_UNSPEC";
            break;
		case 2:
            addrFamily = "AF_INET";
            break;
		case 6:
            addrFamily = "AF_IPX";
            break;
		case 17:
			addrFamily = "AF_NETBIOS";
            break;
		default:
			addrFamily = "Unknown";
			break;
		}

		printf("Session ID  : %i\n", si.SessionId);
		if(strlen(pUser) < 1)
			printf("Domain\\User : System\n");
		else
			printf("Domain\\User : %s\\%s\n", pDomain, pUser);
		if(strlen(pClientName) < 1)
			printf("Client Name : Local\n");
		else
			printf("Client Name : %s\n", pClientName);
		if(pClientAddressStruct->Address[2] == 0 || addrFamily == "AF_UNSPEC")
			printf("Net Address : n/a\n");
		else
			printf("Net Address : %u.%u.%u.%u (%s)\n", pClientAddressStruct->Address[2], pClientAddressStruct->Address[3], pClientAddressStruct->Address[4], pClientAddressStruct->Address[5], addrFamily);		
		
		switch(si.State)
		{
		case 0:
			connState = "Active";
			break;
		case 1:
			connState = "Connected";
			break;
		case 4:
			connState = "Disconnected";
			break;
		case 5:
			connState = "Idle";
			break;
		default:
			connState = "Unknown";
			break;
		}
		printf("Conn. State : %s\n", connState);
		printf("\n");		
		WTSFreeMemory(pClientAddress);
		WTSFreeMemory(pClientName);
		WTSFreeMemory(pDomain);
		WTSFreeMemory(pUser);
	}
	WTSFreeMemory(pSessionInfo);
	WTSCloseServer(hHost);
}