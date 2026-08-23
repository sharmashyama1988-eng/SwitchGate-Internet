#ifndef SWITCHGATE_CORE_H
#define SWITCHGATE_CORE_H

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h>
  #include <windns.h>
  #include <stdio.h>
  #include <stdlib.h>

  #pragma comment(lib, "ws2_32.lib")
  #pragma comment(lib, "iphlpapi.lib")
  #pragma comment(lib, "dnsapi.lib")
  #pragma comment(lib, "advapi32.lib")

  #ifdef SWITCHGATE_EXPORTS
    #define SWITCHGATE_API __declspec(dllexport)
  #else
    #define SWITCHGATE_API __declspec(dllimport)
  #endif
#else
  #define SWITCHGATE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ==========================================
// Deep-Level System Network Management APIs
// ==========================================

/**
 * Instantly terminates a specific TCP connection in the Windows Kernel using MIB_TCP_STATE_DELETE_TCB.
 */
SWITCHGATE_API int TerminateTcpConnection(unsigned long local_ip, unsigned short local_port,
                                          unsigned long remote_ip, unsigned short remote_port);

/**
 * Instantly kills all active TCP sockets owned by a specific Process ID (PID).
 * Returns the number of terminated connections.
 */
SWITCHGATE_API int TerminateSocketsByPid(unsigned long pid);

/**
 * Instantly kills all active TCP sockets connected to a specific Remote IP address.
 * Returns the number of terminated connections.
 */
SWITCHGATE_API int TerminateSocketsByRemoteIp(unsigned long remote_ip);

/**
 * Master Panic Kill: Instantly terminates all active non-local TCP connections on the system.
 * Returns the number of terminated connections.
 */
SWITCHGATE_API int TerminateAllExternalSockets(void);

/**
 * Sends a native hardware ARP request to resolve MAC address for a given IPv4 address in <1ms.
 * Output: mac_out (buffer of at least 6 bytes).
 * Returns 0 on success, non-zero on failure.
 */
SWITCHGATE_API int SendNativeArp(unsigned long target_ip, unsigned char* mac_out);

/**
 * Queries the active default gateway IP, Gateway Hardware MAC, and Interface Index via GetBestRoute.
 * Returns 0 on success.
 */
SWITCHGATE_API int GetRealGatewayInfo(unsigned long* gw_ip_out, unsigned char* gw_mac_out, unsigned long* if_index_out);

/**
 * Flushes the native Windows DNS Resolver Cache at the Win32 subsystem level.
 * Returns 1 on success, 0 on failure.
 */
SWITCHGATE_API int FlushDnsNativeCache(void);

#ifdef __cplusplus
}
#endif

#endif // SWITCHGATE_CORE_H
