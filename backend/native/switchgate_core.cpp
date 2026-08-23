#define SWITCHGATE_EXPORTS
#include "switchgate_core.h"

// Forward declaration for dynamic linking of DnsFlushResolverCache if needed
typedef BOOL(WINAPI* DnsFlushResolverCacheFn)(VOID);

SWITCHGATE_API int TerminateTcpConnection(unsigned long local_ip, unsigned short local_port,
                                          unsigned long remote_ip, unsigned short remote_port) {
#ifdef _WIN32
    MIB_TCPROW row;
    ZeroMemory(&row, sizeof(row));
    row.dwState = 12; // MIB_TCP_STATE_DELETE_TCB
    row.dwLocalAddr = local_ip;
    row.dwLocalPort = local_port;
    row.dwRemoteAddr = remote_ip;
    row.dwRemotePort = remote_port;

    DWORD ret = SetTcpEntry(&row);
    return (ret == NO_ERROR) ? 1 : 0;
#else
    return 0;
#endif
}

SWITCHGATE_API int TerminateSocketsByPid(unsigned long target_pid) {
#ifdef _WIN32
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return 0;

    PMIB_TCPTABLE_OWNER_PID pTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!pTable) return 0;

    int terminated_count = 0;
    if (GetExtendedTcpTable(pTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID* row = &pTable->table[i];
            if (row->dwOwningPid == target_pid) {
                MIB_TCPROW rstRow;
                ZeroMemory(&rstRow, sizeof(rstRow));
                rstRow.dwState = 12; // MIB_TCP_STATE_DELETE_TCB
                rstRow.dwLocalAddr = row->dwLocalAddr;
                rstRow.dwLocalPort = row->dwLocalPort;
                rstRow.dwRemoteAddr = row->dwRemoteAddr;
                rstRow.dwRemotePort = row->dwRemotePort;

                if (SetTcpEntry(&rstRow) == NO_ERROR) {
                    terminated_count++;
                }
            }
        }
    }

    free(pTable);
    return terminated_count;
#else
    return 0;
#endif
}

SWITCHGATE_API int TerminateSocketsByRemoteIp(unsigned long remote_ip) {
#ifdef _WIN32
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return 0;

    PMIB_TCPTABLE_OWNER_PID pTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!pTable) return 0;

    int terminated_count = 0;
    if (GetExtendedTcpTable(pTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID* row = &pTable->table[i];
            if (row->dwRemoteAddr == remote_ip) {
                MIB_TCPROW rstRow;
                ZeroMemory(&rstRow, sizeof(rstRow));
                rstRow.dwState = 12; // MIB_TCP_STATE_DELETE_TCB
                rstRow.dwLocalAddr = row->dwLocalAddr;
                rstRow.dwLocalPort = row->dwLocalPort;
                rstRow.dwRemoteAddr = row->dwRemoteAddr;
                rstRow.dwRemotePort = row->dwRemotePort;

                if (SetTcpEntry(&rstRow) == NO_ERROR) {
                    terminated_count++;
                }
            }
        }
    }

    free(pTable);
    return terminated_count;
#else
    return 0;
#endif
}

SWITCHGATE_API int TerminateAllExternalSockets(void) {
#ifdef _WIN32
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return 0;

    PMIB_TCPTABLE_OWNER_PID pTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!pTable) return 0;

    int terminated_count = 0;
    if (GetExtendedTcpTable(pTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID* row = &pTable->table[i];
            unsigned long rem = row->dwRemoteAddr;
            // Skip loopback (127.0.0.0/8) and INADDR_ANY (0.0.0.0)
            if (rem == 0 || (rem & 0xFF) == 127) {
                continue;
            }

            MIB_TCPROW rstRow;
            ZeroMemory(&rstRow, sizeof(rstRow));
            rstRow.dwState = 12; // MIB_TCP_STATE_DELETE_TCB
            rstRow.dwLocalAddr = row->dwLocalAddr;
            rstRow.dwLocalPort = row->dwLocalPort;
            rstRow.dwRemoteAddr = row->dwRemoteAddr;
            rstRow.dwRemotePort = row->dwRemotePort;

            if (SetTcpEntry(&rstRow) == NO_ERROR) {
                terminated_count++;
            }
        }
    }

    free(pTable);
    return terminated_count;
#else
    return 0;
#endif
}

SWITCHGATE_API int SendNativeArp(unsigned long target_ip, unsigned char* mac_out) {
#ifdef _WIN32
    ULONG macLen = 6;
    DWORD ret = SendARP(target_ip, 0, (PULONG)mac_out, &macLen);
    return (ret == NO_ERROR && macLen == 6) ? 0 : -1;
#else
    return -1;
#endif
}

SWITCHGATE_API int GetRealGatewayInfo(unsigned long* gw_ip_out, unsigned char* gw_mac_out, unsigned long* if_index_out) {
#ifdef _WIN32
    MIB_IPFORWARDROW routeRow;
    ZeroMemory(&routeRow, sizeof(routeRow));
    
    // Query default route to public DNS (8.8.8.8)
    unsigned long dest = inet_addr("8.8.8.8");
    if (GetBestRoute(dest, 0, &routeRow) != NO_ERROR) {
        return -1;
    }

    if (gw_ip_out) *gw_ip_out = routeRow.dwForwardNextHop;
    if (if_index_out) *if_index_out = routeRow.dwForwardIfIndex;

    if (gw_mac_out) {
        ULONG macLen = 6;
        if (SendARP(routeRow.dwForwardNextHop, 0, (PULONG)gw_mac_out, &macLen) != NO_ERROR) {
            ZeroMemory(gw_mac_out, 6);
        }
    }

    return 0;
#else
    return -1;
#endif
}

SWITCHGATE_API int FlushDnsNativeCache(void) {
#ifdef _WIN32
    HMODULE hDnsApi = LoadLibraryA("dnsapi.dll");
    if (hDnsApi) {
        DnsFlushResolverCacheFn pfnFlush = (DnsFlushResolverCacheFn)GetProcAddress(hDnsApi, "DnsFlushResolverCache");
        if (pfnFlush) {
            BOOL ret = pfnFlush();
            FreeLibrary(hDnsApi);
            return ret ? 1 : 0;
        }
        FreeLibrary(hDnsApi);
    }
    return 0;
#else
    return 0;
#endif
}
