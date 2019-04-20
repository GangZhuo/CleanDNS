#include "win.h"
#include "../src/log.h"

void win_init()
{
	WSADATA wsaData;
	int err;

	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		loge("FATAL ERROR: unable to initialise Winsock 2.x.\n");
		exit(-1);
	}
}

void win_uninit()
{
	WSACleanup();
}

/* See https://support.microsoft.com/en-us/kb/263823 */
int disable_udp_connreset(SOCKET sockfd)
{
	DWORD dwBytesReturned = 0;
	BOOL bNewBehavior = FALSE;
	DWORD status;

	/* disable  new behavior using
	   IOCTL: SIO_UDP_CONNRESET */
	status = WSAIoctl(sockfd, SIO_UDP_CONNRESET,
		&bNewBehavior, sizeof(bNewBehavior),
		NULL, 0, &dwBytesReturned,
		NULL, NULL);
	if (SOCKET_ERROR == status) {
		loge("WSAIoctl(SIO_UDP_CONNRESET) error: %d\n", errno);
		return -1;
	}
	return 0;
}

const char* win_strerror(int err_code)
{
	static char s_errstr[2048];

	LPSTR errString = NULL;  /* will be allocated and filled by FormatMessage */

	int size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM, /* use windows internal message table */
		0,       /* 0 since source is internal message table */
		err_code, /*this is the error code returned by WSAGetLastError()
				  Could just as well have been an error code from generic
				  Windows errors from GetLastError() */
		0,        /*auto-determine language to use */
		(LPSTR)& errString, /* this is WHERE we want FormatMessage
							to plunk the error string.  Note the
							peculiar pass format:  Even though
							errString is already a pointer, we
							pass &errString (which is really type LPSTR* now)
							and then CAST IT to (LPSTR).  This is a really weird
							trip up.. but its how they do it on msdn:
							http://msdn.microsoft.com/en-us/library/ms679351(VS.85).aspx */
		0,                 /* min size for buffer */
		0);               /* 0, since getting message from system tables */

	memset(s_errstr, 0, sizeof(s_errstr));

	strncpy(s_errstr, errString, sizeof(s_errstr) - 1);

	LocalFree(errString); /* if you don't do this, you will get an
	 ever so slight memory leak, since we asked
	 FormatMessage to FORMAT_MESSAGE_ALLOCATE_BUFFER,
	 and it does so using LocalAlloc
	 Gotcha!  I guess. */

	return s_errstr;
}


