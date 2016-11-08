#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#define MAXBUF  0xFFFF

int __cdecl main()
{
	HANDLE handle, console;
	UINT i, j;
	INT16 priority = 0;
	unsigned char packet[MAXBUF], temp[20] = "Michael Jackson";
	UINT packet_len;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;

	handle = WinDivertOpen("ip && (tcp.DstPort == 80  || tcp.SrcPort == 80) && tcp.PayloadLength > 0", WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192))
	{
		fprintf(stderr, "error: failed to set packet queue length (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048))
	{
		fprintf(stderr, "error: failed to set packet queue time (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		WinDivertHelperParsePacket(packet, packet_len, &ip_header,
			&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
			&udp_header, NULL, NULL);

		if (tcp_header->DstPort == htons(80)) {
			for (i = 0; i < packet_len; i++)
			{
				if (packet[i] == 0x67 && packet[i + 1] == 0x7a && packet[i + 2] == 0x69 && packet[i + 3] == 0x70)
				{
					packet[i] = 0x20;
					packet[i + 1] = 0x20;
					packet[i + 2] = 0x20;
					packet[i + 3] = 0x20;
					WinDivertHelperCalcChecksums((PVOID)packet, packet_len, 0);
					break;
				}
			}
		}
		else if (tcp_header->SrcPort == htons(80)) {
			for (i = 0; i < packet_len; i++)
			{
				for (j = 0; j < 15; j++)
				{
					if (packet[i + j] != temp[j])
						break;
				}
				if (j == 15) {
					packet[i] = 71;
					packet[i + 1] = 73;
					packet[i + 2] = 76;
					packet[i + 3] = 66;
					packet[i + 4] = 69;
					packet[i + 5] = 82;
					packet[i + 6] = 84;
					WinDivertHelperCalcChecksums((PVOID)packet, packet_len, 0);
					break;
				}
			}
		}
		if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
		{
			fprintf(stderr, "warning: failed to reinject packet (%d)\n",
				GetLastError());
		}
	}
}