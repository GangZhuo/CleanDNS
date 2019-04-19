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
