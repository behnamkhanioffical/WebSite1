# WebSite1
file:///C:/Users/BEHNAMKHANI/Documents/My%20Web%20Sites/WebSite1/iisstart.htm#DllHost_RASDLG.LOG

Remote Access Diagnostic Report
Report Version:	1.0
Date and Time:	2/3/2022 4:49:31 AM
Username:	BEHNAMKHANI-PC\BEHNAMKHANI
Computer Name:	BEHNAMKHANI-PC
Windows Directory:	C:\Windows
Windows Version:	7601.PRO.AMD64

Table Of Contents
Tracing and Event Logs
Tracing Logs
DllHost_RASDLG.LOG
Explorer_RASAPI32.LOG
Explorer_RASDLG.LOG
Explorer_RASGCW.LOG
Explorer_RASMANCS.LOG
IpHlpSvc.LOG
IPNATHLP.LOG
KMDDSP.LOG
NDPTSP.LOG
PPP.LOG
RASAUTO.LOG
RASCCP.LOG
RASIPCP.LOG
RASIPHLP.LOG
RASIPV6CP.LOG
RASMAN.LOG
RASPAP.LOG
RASTAPI.LOG
svchost_RASAPI32.LOG
svchost_RASCHAP.LOG
svchost_RASDLG.LOG
svchost_RASMANCS.LOG
tapi32.LOG
tapisrv.LOG
VPNIKE.LOG
Modem Logs
Connection Manager Logs
IP Security Log
Remote Access Event Logs
Security Event Logs
Installation Information
Information Files
Installation Check
Installed Networking Components
Registry Check
Configuration Information
Installed Devices
Process Information
Command-Line Utilities
arp.exe -a
ipconfig.exe /all
ipconfig.exe /displaydns
route.exe print
net.exe start
netstat.exe -e
netstat.exe -o
netstat.exe -s
netstat.exe -n
nbtstat.exe -c
nbtstat.exe -n
nbtstat.exe -r
nbtstat.exe -S
netsh.exe dump
Phone Book Files
Tracing Logs [ Table Of Contents ]
DllHost_RASDLG.LOG [ Table Of Contents ]
-------------------------------------------------------------------------------
C:\Windows\tracing\DllHost_RASDLG.LOG
-------------------------------------------------------------------------------

[6960] 02-03 04:48:57:987: UnLoadDiagnosticDll
Explorer_RASAPI32.LOG [ Table Of Contents ]
Explorer_RASDLG.LOG [ Table Of Contents ]
-------------------------------------------------------------------------------
C:\Windows\tracing\Explorer_RASDLG.LOG
-------------------------------------------------------------------------------

[4252] 02-03 04:49:00:962: DgCommand(n=0,i=1705,c=$1166a)
[4252] 02-03 04:49:00:969: ElInit
[4252] 02-03 04:49:06:559: ElCommand(n=0,i=1723,c=$1167a)
[4252] 02-03 04:49:10:535: ElCommand(n=0,i=1732,c=$11684)
[4252] 02-03 04:49:12:455: ElCommand(n=0,i=1719,c=$11678)
[4252] 02-03 04:49:15:994: ElCommand(n=0,i=1731,c=$11676)
[4252] 02-03 04:49:25:543: ElCommand(n=0,i=1719,c=$11678)
[4252] 02-03 04:49:26:317: ElCommand(n=0,i=1730,c=$11680)
[4252] 02-03 04:49:28:549: ElCommand(n=1024,i=1721,c=$1167e)
[4252] 02-03 04:49:28:549: ElCommand(n=768,i=1721,c=$1167e)
[4252] 02-03 04:49:30:095: ElCommand(n=0,i=1,c=$11686)
[4252] 02-03 04:49:30:095: ElSave()
[4252] 02-03 04:49:30:095: MsgDlgUtil
[4252] 02-03 04:49:30:111: SetOffDesktop(h=$00011674,a=5)
[4252] 02-03 04:49:31:162: SetOffDesktop(h=$00011674,a=5)
[3980] 02-03 04:49:31:167: ElGenerateReport
Explorer_RASGCW.LOG [ Table Of Contents ]
Explorer_RASMANCS.LOG [ Table Of Contents ]
IpHlpSvc.LOG [ Table Of Contents ]
-------------------------------------------------------------------------------
C:\Windows\tracing\IpHlpSvc.LOG
-------------------------------------------------------------------------------


[6392] 04:49:22: Get lock (00000000000006FC) invoked at d:\w7rtm\net\netio\iphlpsvc\service\teredo.c : TeredoTimerCallback : 1088

[6392] 04:49:22: Lock (00000000000006FC) acquired at d:\w7rtm\net\netio\iphlpsvc\service\teredo.c : TeredoTimerCallback : 1088. Return 0

[6392] 04:49:22: TeredoStartClient:  0x0000000002802270 (CompartmentId 1)

[6392] 04:49:22: ListeningApplications is 0

[6392] 04:49:22: TeredoReferenceClient: ++1 & d:\w7rtm\net\netio\iphlpsvc\service\client.c:2035

[6392] 04:49:22: GetAddrInfoW(teredo.ipv6.microsoft.com.) returned error 11004 in compartment 1

[6392] 04:49:22: Unable to resolve the server

[6392] 04:49:22: TeredoStartClient: Failed. Stopping.

[6392] 04:49:22: TeredoStopClient 0x0000000002802270 (compartment 1, state 8)

[6392] 04:49:22: Get lock (0000000000000708) invoked at d:\w7rtm\net\netio\iphlpsvc\service\history.c : TeredoRecordInterfaceConnectivity : 373

[6392] 04:49:22: Lock (0000000000000708) acquired at d:\w7rtm\net\netio\iphlpsvc\service\history.c : TeredoRecordInterfaceConnectivity : 373. Return 0

[6392] 04:49:22: Lock (0000000000000708) released at d:\w7rtm\net\netio\iphlpsvc\service\history.c : TeredoRecordInterfaceConnectivity : 416. Return 1

[6392] 04:49:22: TeredoSqmStopClient: Timestamp 4695193.

[6392] 04:49:22: TeredoSqmStopClient: SessionDuration = 4654 seconds

[6392] 04:49:22: TeredoStopIo

[6392] 04:49:22: TeredoClientStopIoComplete: ClientState = 1, Client = 0x0000000002802270

[6392] 04:49:22: Get lock (00000000000006FC) invoked at d:\w7rtm\net\netio\iphlpsvc\service\client.c : TeredoClientStopIoComplete : 2594

[6392] 04:49:22: Lock (00000000000006FC) acquired at d:\w7rtm\net\netio\iphlpsvc\service\client.c : TeredoClientStopIoComplete : 2594. Return 0

[6392] 04:49:22: Teredo Timer has been set to: timeout = 20506 ms, period = 0 ms, timer memory pointer = 0000000001CF5640

[6392] 04:49:22: Lock (00000000000006FC) released at d:\w7rtm\net\netio\iphlpsvc\service\client.c : TeredoClientStopIoComplete : 2668. Return 1

[6392] 04:49:22: TeredoDereferenceClient: --2 & d:\w7rtm\net\netio\iphlpsvc\service\client.c:2672

[6392] 04:49:22: processing TeredoSqmPeriodicCallback: Tickcount: 4695193

[6392] 04:49:22: Entering SqmUploadFiles

[6392] 04:49:22: TeredoTimerCallback (41365).

[6392] 04:49:22: Teredo Timer has been set to: timeout = 41365 ms, period = 0 ms, timer memory pointer = 0000000001CF5640

[6392] 04:49:22: Lock (00000000000006FC) released at d:\w7rtm\net\netio\iphlpsvc\service\teredo.c : TeredoTimerCallback : 1246. Return 1
IPNATHLP.LOG [ Table Of Contents ]
KMDDSP.LOG [ Table Of Contents ]
NDPTSP.LOG [ Table Of Contents ]
PPP.LOG [ Table Of Contents ]
RASAUTO.LOG [ Table Of Contents ]
RASCCP.LOG [ Table Of Contents ]
RASIPCP.LOG [ Table Of Contents ]
RASIPHLP.LOG [ Table Of Contents ]
RASIPV6CP.LOG [ Table Of Contents ]
RASMAN.LOG [ Table Of Contents ]
RASPAP.LOG [ Table Of Contents ]
RASTAPI.LOG [ Table Of Contents ]
svchost_RASAPI32.LOG [ Table Of Contents ]
svchost_RASCHAP.LOG [ Table Of Contents ]
svchost_RASDLG.LOG [ Table Of Contents ]
svchost_RASMANCS.LOG [ Table Of Contents ]
tapi32.LOG [ Table Of Contents ]
tapisrv.LOG [ Table Of Contents ]
VPNIKE.LOG [ Table Of Contents ]
Modem Logs [ Table Of Contents ]
 Unable to show modem tracing logs or no log files were present.       
                                                                     
Connection Manager Logs [ Table Of Contents ]
 Unable to show Connection Manager logs or no log files were present.  
                                                                     
IP Security Log [ Table Of Contents ]
 Unable to show IPsec tracing logs or no log files were present.       
                                                                     
Remote Access Event Logs [ Table Of Contents ]
Event Type:     Information 
Event Source:   Microsoft-Windows-UserPnp 
Event Category: None 
Event ID:       20001 
Date:           2/3/2022 
Time:           4:45:08 AM 
User:           NT AUTHORITY\SYSTEM 
Computer:       BEHNAMKHANI-PC 
Description:
Cannot load the NetBIOS gateway DLL component because of the following error: NULL Driver  
                                                                     

Event Type:     Information 
Event Source:   Microsoft-Windows-UserPnp 
Event Category: None 
Event ID:       20001 
Date:           2/3/2022 
Time:           4:42:28 AM 
User:           NT AUTHORITY\SYSTEM 
Computer:       BEHNAMKHANI-PC 
Description:
Cannot load the NetBIOS gateway DLL component because of the following error: NULL Driver  
                                                                     

Event Type:     Information 
Event Source:   Microsoft-Windows-UserPnp 
Event Category: None 
Event ID:       20001 
Date:           2/3/2022 
Time:           4:37:54 AM 
User:           NT AUTHORITY\SYSTEM 
Computer:       BEHNAMKHANI-PC 
Description:
Cannot load the NetBIOS gateway DLL component because of the following error: NULL Driver  
                                                                     

Event Type:     Information 
Event Source:   Microsoft-Windows-UserPnp 
Event Category: None 
Event ID:       20003 
Date:           2/3/2022 
Time:           4:35:35 AM 
User:           NT AUTHORITY\SYSTEM 
Computer:       BEHNAMKHANI-PC 
Description:
Cannot enumerate Registry key values. tunnel  
                                                                     

Event Type:     Information 
Event Source:   Microsoft-Windows-UserPnp 
Event Category: None 
Event ID:       20003 
Date:           2/3/2022 
Time:           4:34:49 AM 
User:           NT AUTHORITY\SYSTEM 
Computer:       BEHNAMKHANI-PC 
Description:
Cannot enumerate Registry key values. tunnel  
                                                                     

Event Type:     Information 
Event Source:   Microsoft-Windows-UserPnp 
Event Category: None 
Event ID:       20001 
Date:           2/3/2022 
Time:           3:58:25 AM 
User:           NT AUTHORITY\SYSTEM 
Computer:       BEHNAMKHANI-PC 
Description:
Cannot load the NetBIOS gateway DLL component because of the following error: NULL Driver  
                                                                     

Event Type:     Information 
Event Source:   Microsoft-Windows-UserPnp 
Event Category: None 
Event ID:       20001 
Date:           2/3/2022 
Time:           3:58:24 AM 
User:           NT AUTHORITY\SYSTEM 
Computer:       BEHNAMKHANI-PC 
Description:
Cannot load the NetBIOS gateway DLL component because of the following error: FileRepository\netnvm64.inf_amd64_neutral_59c2a018fe2cf0b4\netnvm64.inf  
                                                                     

Event Type:     Information 
Event Source:   Microsoft-Windows-UserPnp 
Event Category: None 
Event ID:       20003 
Date:           2/3/2022 
Time:           3:58:22 AM 
User:           NT AUTHORITY\SYSTEM 
Computer:       BEHNAMKHANI-PC 
Description:
Cannot enumerate Registry key values. NVENETFD  
                                                                     

Event Type:     Information 
Event Source:   Microsoft-Windows-UserPnp 
Event Category: None 
Event ID:       20001 
Date:           2/3/2022 
Time:           3:58:17 AM 
User:           NT AUTHORITY\SYSTEM 
Computer:       BEHNAMKHANI-PC 
Description:
Cannot load the NetBIOS gateway DLL component because of the following error: NULL Driver  
                                                                     

Event Type:     Information 
Event Source:   Microsoft-Windows-UserPnp 
Event Category: None 
Event ID:       20001 
Date:           2/3/2022 
Time:           3:58:17 AM 
User:           NT AUTHORITY\SYSTEM 
Computer:       BEHNAMKHANI-PC 
Description:
Cannot load the NetBIOS gateway DLL component because of the following error: NULL Driver  
                                                                     
Security Event Logs [ Table Of Contents ]
 Unable to show security event logs or no log entries were present.    
                                                                     
Information Files [ Table Of Contents ]
File Name       : C:\Windows\inf\netrasa.inf 
Last Write Time : 04/18/2021 22:22 
Creation Time   : 04/18/2021 22:22 
File Size       : 31184 bytes 

File Name       : C:\Windows\inf\netrass.inf 
Last Write Time : 04/18/2021 22:22 
Creation Time   : 04/18/2021 22:22 
File Size       : 5296 bytes 

File Name       : C:\Windows\inf\netrast.inf 
Last Write Time : 04/18/2021 22:22 
Creation Time   : 04/18/2021 22:22 
File Size       : 14258 bytes 
Installation Check [ Table Of Contents ]
sw\{eeab7790-c514-11d1-b42b-00805fc1270e} = OK.
ms_irdaminiport                           = Not Found.
ms_irmodemminiport                        = Not Found.
ms_l2tpminiport                           = OK.
ms_sstpminiport                           = OK.
ms_pptpminiport                           = OK.
ms_ptiminiport                            = Not Found.
ms_pppoeminiport                          = OK.
ms_ndiswanatalk                           = Not Found.
ms_ndiswanbh                              = OK.
ms_ndiswanip                              = OK.
ms_ndiswanipx                             = Not Found.
ms_pppoe                                  = OK.
ms_pptp                                   = OK.
ms_l2tp                                   = OK.
ms_sstp                                   = OK.
ms_rascli                                 = Not Found.
ms_rassrv                                 = OK.
ms_steelhead                              = OK.
ms_ndiswan                                = OK.
ms_rasman                                 = OK.
Installed Networking Components [ Table Of Contents ]
Network Adapters                                                       
----------------                                                     
*isatap              Microsoft ISATAP Adapter #7
*isatap              Microsoft ISATAP Adapter #6
usb\class_e0&subclass_01&prot_03 Remote NDIS based Internet Sharing Device #8
*isatap              Microsoft ISATAP Adapter #5
*isatap              Microsoft ISATAP Adapter #2
*isatap              Microsoft ISATAP Adapter #4
*isatap              Microsoft ISATAP Adapter
usb\class_e0&subclass_01&prot_03 Remote NDIS based Internet Sharing Device #9
*isatap              Microsoft ISATAP Adapter #3
usb\class_e0&subclass_01&prot_03 Remote NDIS based Internet Sharing Device #7
{5d624f94-8850-40c3-a3fa-a4fd2080baf3}\vwifimp Microsoft Virtual WiFi Miniport Adapter #2
pci\ven_14e4&dev_432b Broadcom 802.11n Network Adapter
bth\ms_bthpan        Bluetooth Device (Personal Area Network)
bth\ms_rfcomm        Bluetooth Device (RFCOMM Protocol TDI)
usb\class_e0&subclass_01&prot_03 Remote NDIS based Internet Sharing Device #6
usb\class_e0&subclass_01&prot_03 Remote NDIS based Internet Sharing Device #5
usb\class_e0&subclass_01&prot_03 Remote NDIS based Internet Sharing Device #4
usb\class_e0&subclass_01&prot_03 Remote NDIS based Internet Sharing Device #3
usb\class_e0&subclass_01&prot_03 Remote NDIS based Internet Sharing Device #2
{5d624f94-8850-40c3-a3fa-a4fd2080baf3}\vwifimp Microsoft Virtual WiFi Miniport Adapter
usb\class_e0&subclass_01&prot_03 Remote NDIS based Internet Sharing Device
ms_agilevpnminiport  WAN Miniport (IKEv2)
sw\{eeab7790-c514-11d1-b42b-00805fc1270e} RAS Async Adapter
ms_ndiswanip         WAN Miniport (IP)
ms_ndiswanbh         WAN Miniport (Network Monitor)
ms_ndiswanipv6       WAN Miniport (IPv6)
ms_pppoeminiport     WAN Miniport (PPPOE)
ms_pptpminiport      WAN Miniport (PPTP)
ms_l2tpminiport      WAN Miniport (L2TP)
ms_sstpminiport      WAN Miniport (SSTP)

Network Protocols                                                      
-----------------                                                    
ms_agilevpn          AgileVpn based VPN
ms_tcpip6_tunnel     Microsoft TCP/IP version 6 - Tunnels
ms_tcpip_tunnel      Internet Protocol (TCP/IP) - Tunnels
ms_smb               Microsoft NetbiosSmb
ms_wanarp            Remote Access IP ARP Driver
ms_netbt_smb         Message-oriented TCP/IP Protocol (SMB session)
ms_netbt             WINS Client(TCP/IP) Protocol
ms_tcpip6            Internet Protocol Version 6 (TCP/IPv6)
ms_tcpip             Internet Protocol Version 4 (TCP/IPv4)
ms_lltdio            Link-Layer Topology Discovery Mapper I/O Driver
ms_rspndr            Link-Layer Topology Discovery Responder
ms_wanarpv6          Remote Access IPv6 ARP Driver
ms_pppoe             Point to Point Protocol Over Ethernet
ms_pptp              Point to Point Tunneling Protocol
ms_l2tp              Layer 2 Tunneling Protocol
ms_ndiswan           Remote Access NDIS WAN Driver
ms_sstp              SSTP based VPN
ms_ndisuio           NDIS Usermode I/O Protocol

Network Services                                                       
----------------                                                     
ms_vwifi             Virtual WiFi Filter Driver
ms_nativewifip       NativeWiFi Filter
ms_ndiscap           NDIS Capture LightWeight Filter
ms_pacer             QoS Packet Scheduler
ms_server            File and Printer Sharing for Microsoft Networks
ms_netbios           NetBIOS Interface
ms_wfplwf            WFP Lightweight Filter
ms_steelhead         Steelhead
ms_rassrv            Dial-Up Server
ms_rasman            Remote Access Connection Manager

Network Clients                                                        
---------------                                                      
Registry Check [ Table Of Contents ]
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsyncMac]
"Type"=dword:00000001
"Start"=dword:00000003
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,44,00,\
  52,00,49,00,56,00,45,00,52,00,53,00,5c,00,61,00,73,00,79,00,6e,00,63,00,6d,\
  00,61,00,63,00,2e,00,73,00,79,00,73,00,00,00
"DisplayName"="@%systemroot%\\system32\\rascfg.dll,-32000"
"Description"="@%systemroot%\\system32\\rascfg.dll,-32000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsyncMac\Enum]
"0"="SW\\{eeab7790-c514-11d1-b42b-00805fc1270e}\\asyncmac"
"Count"=dword:00000001
"NextInstance"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpFilterDriver]
"DisplayName"="@%systemroot%\\system32\\rascfg.dll,-32013"
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,44,00,\
  52,00,49,00,56,00,45,00,52,00,53,00,5c,00,69,00,70,00,66,00,6c,00,74,00,64,\
  00,72,00,76,00,2e,00,73,00,79,00,73,00,00,00
"Description"="@%systemroot%\\system32\\rascfg.dll,-32013"
"ErrorControl"=dword:00000001
"Start"=dword:00000003
"Type"=dword:00000001
"DependOnService"=hex(7):54,00,63,00,70,00,69,00,70,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpNat]
"DisplayName"="IP Network Address Translator"
"ImagePath"=hex(2):53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  72,00,69,00,76,00,65,00,72,00,73,00,5c,00,69,00,70,00,6e,00,61,00,74,00,2e,\
  00,73,00,79,00,73,00,00,00
"ErrorControl"=dword:00000001
"Start"=dword:00000003
"Type"=dword:00000001
"DependOnService"=hex(7):54,00,63,00,70,00,69,00,70,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpNat\Enum]
"0"="Root\\LEGACY_IPNAT\\0000"
"Count"=dword:00000001
"NextInstance"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisTapi]
"Type"=dword:00000001
"Start"=dword:00000003
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,44,00,\
  52,00,49,00,56,00,45,00,52,00,53,00,5c,00,6e,00,64,00,69,00,73,00,74,00,61,\
  00,70,00,69,00,2e,00,73,00,79,00,73,00,00,00
"DisplayName"="@%systemroot%\\system32\\rascfg.dll,-32001"
"Description"="@%systemroot%\\system32\\rascfg.dll,-32001"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisTapi\Parameters]
"AsyncEventQueueSize"=dword:00000300

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisTapi\Enum]
"0"="Root\\MS_NDISWANBH\\0000"
"Count"=dword:00000003
"NextInstance"=dword:00000003
"1"="Root\\MS_NDISWANIP\\0000"
"2"="Root\\MS_NDISWANIPV6\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan]
"Type"=dword:00000001
"Start"=dword:00000003
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,44,00,\
  52,00,49,00,56,00,45,00,52,00,53,00,5c,00,6e,00,64,00,69,00,73,00,77,00,61,\
  00,6e,00,2e,00,73,00,79,00,73,00,00,00
"DisplayName"="@%systemroot%\\system32\\rascfg.dll,-32002"
"Description"="@%systemroot%\\system32\\rascfg.dll,-32002"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan\Linkage]
"Bind"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,32,00,39,\
  00,38,00,39,00,38,00,43,00,39,00,44,00,2d,00,42,00,30,00,41,00,34,00,2d,00,\
  34,00,46,00,45,00,46,00,2d,00,42,00,44,00,42,00,36,00,2d,00,35,00,37,00,41,\
  00,35,00,36,00,32,00,30,00,32,00,32,00,43,00,45,00,45,00,7d,00,00,00,5c,00,\
  44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,37,00,38,00,30,00,33,00,32,\
  00,42,00,37,00,45,00,2d,00,34,00,39,00,36,00,38,00,2d,00,34,00,32,00,44,00,\
  33,00,2d,00,39,00,46,00,33,00,37,00,2d,00,32,00,38,00,37,00,45,00,41,00,38,\
  00,36,00,43,00,30,00,41,00,41,00,41,00,7d,00,00,00,5c,00,44,00,65,00,76,00,\
  69,00,63,00,65,00,5c,00,7b,00,38,00,45,00,33,00,30,00,31,00,41,00,35,00,32,\
  00,2d,00,41,00,46,00,46,00,41,00,2d,00,34,00,46,00,34,00,39,00,2d,00,42,00,\
  39,00,43,00,41,00,2d,00,43,00,37,00,39,00,30,00,39,00,36,00,41,00,31,00,41,\
  00,30,00,35,00,36,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,\
  5c,00,7b,00,44,00,46,00,34,00,41,00,39,00,44,00,32,00,43,00,2d,00,38,00,37,\
  00,34,00,32,00,2d,00,34,00,45,00,42,00,31,00,2d,00,38,00,37,00,30,00,33,00,\
  2d,00,44,00,33,00,39,00,35,00,43,00,34,00,31,00,38,00,33,00,46,00,33,00,33,\
  00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,45,00,\
  34,00,33,00,44,00,32,00,34,00,32,00,42,00,2d,00,39,00,45,00,41,00,42,00,2d,\
  00,34,00,36,00,32,00,36,00,2d,00,41,00,39,00,35,00,32,00,2d,00,34,00,36,00,\
  36,00,34,00,39,00,46,00,42,00,42,00,39,00,33,00,39,00,41,00,7d,00,00,00,5c,\
  00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,37,00,31,00,46,00,38,00,\
  39,00,37,00,44,00,37,00,2d,00,45,00,42,00,37,00,43,00,2d,00,34,00,44,00,38,\
  00,44,00,2d,00,38,00,39,00,44,00,42,00,2d,00,41,00,43,00,38,00,30,00,44,00,\
  39,00,44,00,44,00,32,00,32,00,37,00,30,00,7d,00,00,00,00,00
"Route"=hex(7):22,00,7b,00,32,00,39,00,38,00,39,00,38,00,43,00,39,00,44,00,2d,\
  00,42,00,30,00,41,00,34,00,2d,00,34,00,46,00,45,00,46,00,2d,00,42,00,44,00,\
  42,00,36,00,2d,00,35,00,37,00,41,00,35,00,36,00,32,00,30,00,32,00,32,00,43,\
  00,45,00,45,00,7d,00,22,00,00,00,22,00,7b,00,37,00,38,00,30,00,33,00,32,00,\
  42,00,37,00,45,00,2d,00,34,00,39,00,36,00,38,00,2d,00,34,00,32,00,44,00,33,\
  00,2d,00,39,00,46,00,33,00,37,00,2d,00,32,00,38,00,37,00,45,00,41,00,38,00,\
  36,00,43,00,30,00,41,00,41,00,41,00,7d,00,22,00,00,00,22,00,7b,00,38,00,45,\
  00,33,00,30,00,31,00,41,00,35,00,32,00,2d,00,41,00,46,00,46,00,41,00,2d,00,\
  34,00,46,00,34,00,39,00,2d,00,42,00,39,00,43,00,41,00,2d,00,43,00,37,00,39,\
  00,30,00,39,00,36,00,41,00,31,00,41,00,30,00,35,00,36,00,7d,00,22,00,00,00,\
  22,00,7b,00,44,00,46,00,34,00,41,00,39,00,44,00,32,00,43,00,2d,00,38,00,37,\
  00,34,00,32,00,2d,00,34,00,45,00,42,00,31,00,2d,00,38,00,37,00,30,00,33,00,\
  2d,00,44,00,33,00,39,00,35,00,43,00,34,00,31,00,38,00,33,00,46,00,33,00,33,\
  00,7d,00,22,00,00,00,22,00,7b,00,45,00,34,00,33,00,44,00,32,00,34,00,32,00,\
  42,00,2d,00,39,00,45,00,41,00,42,00,2d,00,34,00,36,00,32,00,36,00,2d,00,41,\
  00,39,00,35,00,32,00,2d,00,34,00,36,00,36,00,34,00,39,00,46,00,42,00,42,00,\
  39,00,33,00,39,00,41,00,7d,00,22,00,00,00,22,00,7b,00,37,00,31,00,46,00,38,\
  00,39,00,37,00,44,00,37,00,2d,00,45,00,42,00,37,00,43,00,2d,00,34,00,44,00,\
  38,00,44,00,2d,00,38,00,39,00,44,00,42,00,2d,00,41,00,43,00,38,00,30,00,44,\
  00,39,00,44,00,44,00,32,00,32,00,37,00,30,00,7d,00,22,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,4e,00,64,00,69,\
  00,73,00,57,00,61,00,6e,00,5f,00,7b,00,32,00,39,00,38,00,39,00,38,00,43,00,\
  39,00,44,00,2d,00,42,00,30,00,41,00,34,00,2d,00,34,00,46,00,45,00,46,00,2d,\
  00,42,00,44,00,42,00,36,00,2d,00,35,00,37,00,41,00,35,00,36,00,32,00,30,00,\
  32,00,32,00,43,00,45,00,45,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,\
  00,65,00,5c,00,4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,5f,00,7b,00,37,00,\
  38,00,30,00,33,00,32,00,42,00,37,00,45,00,2d,00,34,00,39,00,36,00,38,00,2d,\
  00,34,00,32,00,44,00,33,00,2d,00,39,00,46,00,33,00,37,00,2d,00,32,00,38,00,\
  37,00,45,00,41,00,38,00,36,00,43,00,30,00,41,00,41,00,41,00,7d,00,00,00,5c,\
  00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,4e,00,64,00,69,00,73,00,57,00,\
  61,00,6e,00,5f,00,7b,00,38,00,45,00,33,00,30,00,31,00,41,00,35,00,32,00,2d,\
  00,41,00,46,00,46,00,41,00,2d,00,34,00,46,00,34,00,39,00,2d,00,42,00,39,00,\
  43,00,41,00,2d,00,43,00,37,00,39,00,30,00,39,00,36,00,41,00,31,00,41,00,30,\
  00,35,00,36,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,\
  4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,5f,00,7b,00,44,00,46,00,34,00,41,\
  00,39,00,44,00,32,00,43,00,2d,00,38,00,37,00,34,00,32,00,2d,00,34,00,45,00,\
  42,00,31,00,2d,00,38,00,37,00,30,00,33,00,2d,00,44,00,33,00,39,00,35,00,43,\
  00,34,00,31,00,38,00,33,00,46,00,33,00,33,00,7d,00,00,00,5c,00,44,00,65,00,\
  76,00,69,00,63,00,65,00,5c,00,4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,5f,\
  00,7b,00,45,00,34,00,33,00,44,00,32,00,34,00,32,00,42,00,2d,00,39,00,45,00,\
  41,00,42,00,2d,00,34,00,36,00,32,00,36,00,2d,00,41,00,39,00,35,00,32,00,2d,\
  00,34,00,36,00,36,00,34,00,39,00,46,00,42,00,42,00,39,00,33,00,39,00,41,00,\
  7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,4e,00,64,00,69,\
  00,73,00,57,00,61,00,6e,00,5f,00,7b,00,37,00,31,00,46,00,38,00,39,00,37,00,\
  44,00,37,00,2d,00,45,00,42,00,37,00,43,00,2d,00,34,00,44,00,38,00,44,00,2d,\
  00,38,00,39,00,44,00,42,00,2d,00,41,00,43,00,38,00,30,00,44,00,39,00,44,00,\
  44,00,32,00,32,00,37,00,30,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan\Parameters]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan\Enum]
"0"="Root\\MS_NDISWANBH\\0000"
"Count"=dword:00000003
"NextInstance"=dword:00000003
"1"="Root\\MS_NDISWANIP\\0000"
"2"="Root\\MS_NDISWANIPV6\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PptpMiniport]
"Type"=dword:00000001
"Start"=dword:00000003
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,44,00,\
  52,00,49,00,56,00,45,00,52,00,53,00,5c,00,72,00,61,00,73,00,70,00,70,00,74,\
  00,70,00,2e,00,73,00,79,00,73,00,00,00
"DisplayName"="@%systemroot%\\system32\\rascfg.dll,-32006"
"Description"="@%systemroot%\\system32\\rascfg.dll,-32006"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PptpMiniport\Enum]
"0"="Root\\MS_PPTPMINIPORT\\0000"
"Count"=dword:00000001
"NextInstance"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rassstp]
"Type"=dword:00000001
"Start"=dword:00000003
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,44,00,\
  52,00,49,00,56,00,45,00,52,00,53,00,5c,00,72,00,61,00,73,00,73,00,73,00,74,\
  00,70,00,2e,00,73,00,79,00,73,00,00,00
"DisplayName"="@%systemroot%\\system32\\sstpsvc.dll,-202"
"Description"="@%systemroot%\\system32\\sstpsvc.dll,-202"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rassstp\Enum]
"0"="Root\\MS_SSTPMINIPORT\\0000"
"Count"=dword:00000001
"NextInstance"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd]
"Type"=dword:00000001
"Start"=dword:00000003
"ErrorControl"=dword:00000001
"Tag"=dword:00000001
"ImagePath"=hex(2):53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,44,00,\
  52,00,49,00,56,00,45,00,52,00,53,00,5c,00,72,00,61,00,73,00,61,00,63,00,64,\
  00,2e,00,73,00,79,00,73,00,00,00
"DisplayName"="Remote Access Auto Connection Driver"
"Group"="Streams Drivers"
"Description"="Remote Access Auto Connection Driver"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd\Parameters]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd\Security]
"Security"=hex:01,00,14,88,78,00,00,00,84,00,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,48,00,03,00,00,00,00,00,14,00,fd,01,02,00,01,01,00,00,00,00,00,\
  05,12,00,00,00,00,00,18,00,ff,01,0f,00,01,02,00,00,00,00,00,05,20,00,00,00,\
  20,02,00,00,00,00,14,00,8d,01,02,00,01,01,00,00,00,00,00,05,0b,00,00,00,01,\
  01,00,00,00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd\Enum]
"0"="Root\\LEGACY_RASACD\\0000"
"Count"=dword:00000001
"NextInstance"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto]
"DisplayName"="@%Systemroot%\\system32\\rasauto.dll,-200"
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,73,\
  00,76,00,63,00,68,00,6f,00,73,00,74,00,2e,00,65,00,78,00,65,00,20,00,2d,00,\
  6b,00,20,00,6e,00,65,00,74,00,73,00,76,00,63,00,73,00,00,00
"Description"="@%Systemroot%\\system32\\rasauto.dll,-201"
"ObjectName"="localSystem"
"ErrorControl"=dword:00000001
"Start"=dword:00000003
"Type"=dword:00000020
"DependOnService"=hex(7):52,00,61,00,73,00,4d,00,61,00,6e,00,00,00,54,00,61,00,\
  70,00,69,00,53,00,72,00,76,00,00,00,52,00,61,00,73,00,41,00,63,00,64,00,00,\
  00,00,00
"ServiceSidType"=dword:00000001
"RequiredPrivileges"=hex(7):53,00,65,00,49,00,6d,00,70,00,65,00,72,00,73,00,6f,\
  00,6e,00,61,00,74,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,\
  65,00,00,00,53,00,65,00,54,00,63,00,62,00,50,00,72,00,69,00,76,00,69,00,6c,\
  00,65,00,67,00,65,00,00,00,53,00,65,00,49,00,6e,00,63,00,72,00,65,00,61,00,\
  73,00,65,00,51,00,75,00,6f,00,74,00,61,00,50,00,72,00,69,00,76,00,69,00,6c,\
  00,65,00,67,00,65,00,00,00,53,00,65,00,43,00,68,00,61,00,6e,00,67,00,65,00,\
  4e,00,6f,00,74,00,69,00,66,00,79,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,\
  00,67,00,65,00,00,00,53,00,65,00,43,00,72,00,65,00,61,00,74,00,65,00,47,00,\
  6c,00,6f,00,62,00,61,00,6c,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,\
  00,65,00,00,00,53,00,65,00,41,00,73,00,73,00,69,00,67,00,6e,00,50,00,72,00,\
  69,00,6d,00,61,00,72,00,79,00,54,00,6f,00,6b,00,65,00,6e,00,50,00,72,00,69,\
  00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,00,00
"FailureActions"=hex:84,03,00,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,c0,d4,01,00,01,00,00,00,e0,93,04,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto\Parameters]
"ServiceDll"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  72,00,61,00,73,00,61,00,75,00,74,00,6f,00,2e,00,64,00,6c,00,6c,00,00,00
"ServiceDllUnloadOnStop"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto\Security]
"Security"=hex:01,00,04,80,5c,00,00,00,68,00,00,00,00,00,00,00,14,00,00,00,02,\
  00,48,00,03,00,00,00,00,00,14,00,fd,01,02,00,01,01,00,00,00,00,00,05,12,00,\
  00,00,00,00,18,00,ff,01,0f,00,01,02,00,00,00,00,00,05,20,00,00,00,20,02,00,\
  00,00,00,14,00,8d,01,02,00,01,01,00,00,00,00,00,05,0b,00,00,00,01,01,00,00,\
  00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rasl2tp]
"Type"=dword:00000001
"Start"=dword:00000003
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,44,00,\
  52,00,49,00,56,00,45,00,52,00,53,00,5c,00,72,00,61,00,73,00,6c,00,32,00,74,\
  00,70,00,2e,00,73,00,79,00,73,00,00,00
"DisplayName"="@%systemroot%\\system32\\rascfg.dll,-32005"
"Description"="@%systemroot%\\system32\\rascfg.dll,-32005"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rasl2tp\Enum]
"0"="Root\\MS_L2TPMINIPORT\\0000"
"Count"=dword:00000001
"NextInstance"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan]
"DisplayName"="@%Systemroot%\\system32\\rasmans.dll,-200"
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,73,\
  00,76,00,63,00,68,00,6f,00,73,00,74,00,2e,00,65,00,78,00,65,00,20,00,2d,00,\
  6b,00,20,00,6e,00,65,00,74,00,73,00,76,00,63,00,73,00,00,00
"Description"="@%Systemroot%\\system32\\rasmans.dll,-201"
"ObjectName"="localSystem"
"ErrorControl"=dword:00000001
"Start"=dword:00000003
"Type"=dword:00000020
"DependOnService"=hex(7):54,00,61,00,70,00,69,00,73,00,72,00,76,00,00,00,53,00,\
  73,00,74,00,70,00,53,00,76,00,63,00,00,00,00,00
"ServiceSidType"=dword:00000001
"RequiredPrivileges"=hex(7):53,00,65,00,49,00,6d,00,70,00,65,00,72,00,73,00,6f,\
  00,6e,00,61,00,74,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,\
  65,00,00,00,53,00,65,00,49,00,6e,00,63,00,72,00,65,00,61,00,73,00,65,00,51,\
  00,75,00,6f,00,74,00,61,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,\
  65,00,00,00,53,00,65,00,54,00,63,00,62,00,50,00,72,00,69,00,76,00,69,00,6c,\
  00,65,00,67,00,65,00,00,00,53,00,65,00,43,00,68,00,61,00,6e,00,67,00,65,00,\
  4e,00,6f,00,74,00,69,00,66,00,79,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,\
  00,67,00,65,00,00,00,53,00,65,00,43,00,72,00,65,00,61,00,74,00,65,00,47,00,\
  6c,00,6f,00,62,00,61,00,6c,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,\
  00,65,00,00,00,53,00,65,00,41,00,73,00,73,00,69,00,67,00,6e,00,50,00,72,00,\
  69,00,6d,00,61,00,72,00,79,00,54,00,6f,00,6b,00,65,00,6e,00,50,00,72,00,69,\
  00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,00,00
"FailureActions"=hex:80,51,01,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,c0,d4,01,00,01,00,00,00,e0,93,04,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\Parameters]
"ServiceDll"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  72,00,61,00,73,00,6d,00,61,00,6e,00,73,00,2e,00,64,00,6c,00,6c,00,00,00
"Medias"=hex(7):72,00,61,00,73,00,74,00,61,00,70,00,69,00,00,00,00,00
"CustomDLL"=hex(7):00,00,00,00
"ServiceDllUnloadOnStop"=dword:00000001
"AllowL2TPWeakCrypto"=dword:00000000
"AllowPPTPWeakCrypto"=dword:00000000
"KeepRasConnections"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\PPP]
"MaxConfigure"=dword:0000000a
"MaxFailure"=dword:0000000a
"MaxReject"=dword:00000005
"MaxTerminate"=dword:00000002
"Multilink"=dword:00000000
"NegotiateTime"=dword:00000096
"RestartTimer"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\PPP\ControlProtocols]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\PPP\ControlProtocols\BuiltIn]
"Path"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,\
  00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,\
  61,00,73,00,70,00,70,00,70,00,2e,00,64,00,6c,00,6c,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\PPP\ControlProtocols\Chap]
"Path"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,\
  00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,\
  61,00,73,00,63,00,68,00,61,00,70,00,2e,00,64,00,6c,00,6c,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP]
"Path"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,\
  00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,\
  61,00,73,00,70,00,70,00,70,00,2e,00,64,00,6c,00,6c,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\13]
@="Microsoft"
"FriendlyName"="@%SystemRoot%\\system32\\rastls.dll,-2001"
"Path"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,\
  00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,\
  61,00,73,00,74,00,6c,00,73,00,2e,00,64,00,6c,00,6c,00,00,00
"ConfigCLSID"="{58AB2366-D597-11d1-B90E-00C04FC9B263}"
"ConfigUiPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  72,00,61,00,73,00,74,00,6c,00,73,00,2e,00,64,00,6c,00,6c,00,00,00
"IdentityPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  72,00,61,00,73,00,74,00,6c,00,73,00,2e,00,64,00,6c,00,6c,00,00,00
"InteractiveUIPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,\
  00,6f,00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,\
  5c,00,72,00,61,00,73,00,74,00,6c,00,73,00,2e,00,64,00,6c,00,6c,00,00,00
"InvokePasswordDialog"=dword:00000000
"InvokeUsernameDialog"=dword:00000000
"MPPEEncryptionSupported"=dword:00000001
"NoRootRevocationCheck"=dword:00000001
"PerPolicyConfig"=dword:00000001
"Properties"=dword:1328d8af
"RolesSupported"=dword:00000003
"StandaloneSupported"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\25]
@="Microsoft"
"FriendlyName"="@%SystemRoot%\\system32\\rastls.dll,-2002"
"Path"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,\
  00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,\
  61,00,73,00,74,00,6c,00,73,00,2e,00,64,00,6c,00,6c,00,00,00
"ConfigCLSID"="{58AB2366-D597-11d1-B90E-00C04FC9B263}"
"ConfigUiPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  72,00,61,00,73,00,74,00,6c,00,73,00,2e,00,64,00,6c,00,6c,00,00,00
"IdentityPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  72,00,61,00,73,00,74,00,6c,00,73,00,2e,00,64,00,6c,00,6c,00,00,00
"InteractiveUIPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,\
  00,6f,00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,\
  5c,00,72,00,61,00,73,00,74,00,6c,00,73,00,2e,00,64,00,6c,00,6c,00,00,00
"InvokePasswordDialog"=dword:00000000
"InvokeUsernameDialog"=dword:00000000
"MPPEEncryptionSupported"=dword:00000001
"NoRootRevocationCheck"=dword:00000001
"PerPolicyConfig"=dword:00000001
"Properties"=dword:173ef8bf
"RolesSupported"=dword:00000023
"StandaloneSupported"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\26]
@="Microsoft"
"FriendlyName"="@%SystemRoot%\\system32\\raschap.dll,-2002"
"Path"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,\
  00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,\
  61,00,73,00,63,00,68,00,61,00,70,00,2e,00,64,00,6c,00,6c,00,00,00
"ConfigCLSID"="{2af6bcaa-f526-4803-aeb8-5777ce386647}"
"ConfigUiPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  72,00,61,00,73,00,63,00,68,00,61,00,70,00,2e,00,64,00,6c,00,6c,00,00,00
"IdentityPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  72,00,61,00,73,00,63,00,68,00,61,00,70,00,2e,00,64,00,6c,00,6c,00,00,00
"InteractiveUIPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,\
  00,6f,00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,\
  5c,00,72,00,61,00,73,00,63,00,68,00,61,00,70,00,2e,00,64,00,6c,00,6c,00,00,\
  00
"InvokePasswordDialog"=dword:00000000
"InvokeUsernameDialog"=dword:00000000
"MPPEEncryptionSupported"=dword:00000001
"PerPolicyConfig"=dword:00000001
"Properties"=dword:032c406e
"RolesSupported"=dword:00000017
"StandaloneSupported"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\Security]
"Security"=hex:01,00,04,80,48,00,00,00,54,00,00,00,00,00,00,00,14,00,00,00,02,\
  00,34,00,02,00,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,0b,00,\
  00,00,00,00,18,00,ff,01,0f,00,01,02,00,00,00,00,00,05,20,00,00,00,20,02,00,\
  00,01,01,00,00,00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasPppoe]
"Type"=dword:00000001
"Start"=dword:00000003
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,44,00,\
  52,00,49,00,56,00,45,00,52,00,53,00,5c,00,72,00,61,00,73,00,70,00,70,00,70,\
  00,6f,00,65,00,2e,00,73,00,79,00,73,00,00,00
"DisplayName"="@%systemroot%\\system32\\rascfg.dll,-32007"
"Description"="@%systemroot%\\system32\\rascfg.dll,-32007"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasPppoe\Linkage]
"Bind"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,37,00,36,\
  00,43,00,38,00,41,00,43,00,34,00,39,00,2d,00,45,00,35,00,44,00,43,00,2d,00,\
  34,00,42,00,45,00,30,00,2d,00,39,00,38,00,45,00,34,00,2d,00,42,00,33,00,46,\
  00,41,00,41,00,33,00,33,00,31,00,38,00,43,00,33,00,32,00,7d,00,00,00,5c,00,\
  44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,43,00,41,00,33,00,45,00,31,\
  00,42,00,44,00,45,00,2d,00,33,00,45,00,45,00,35,00,2d,00,34,00,42,00,37,00,\
  44,00,2d,00,41,00,31,00,34,00,34,00,2d,00,38,00,34,00,35,00,35,00,41,00,32,\
  00,30,00,36,00,34,00,34,00,30,00,43,00,7d,00,00,00,5c,00,44,00,65,00,76,00,\
  69,00,63,00,65,00,5c,00,7b,00,33,00,31,00,30,00,46,00,34,00,46,00,43,00,41,\
  00,2d,00,32,00,32,00,35,00,33,00,2d,00,34,00,46,00,34,00,35,00,2d,00,41,00,\
  46,00,38,00,30,00,2d,00,32,00,45,00,35,00,43,00,34,00,43,00,46,00,39,00,30,\
  00,39,00,30,00,39,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,\
  5c,00,7b,00,44,00,37,00,37,00,33,00,36,00,36,00,44,00,43,00,2d,00,38,00,34,\
  00,33,00,30,00,2d,00,34,00,33,00,30,00,30,00,2d,00,42,00,38,00,32,00,46,00,\
  2d,00,38,00,45,00,38,00,34,00,41,00,38,00,31,00,35,00,31,00,38,00,36,00,43,\
  00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,37,00,\
  38,00,35,00,37,00,44,00,38,00,42,00,45,00,2d,00,36,00,31,00,42,00,39,00,2d,\
  00,34,00,43,00,30,00,41,00,2d,00,38,00,36,00,39,00,39,00,2d,00,30,00,36,00,\
  32,00,33,00,43,00,46,00,43,00,44,00,46,00,39,00,42,00,37,00,7d,00,00,00,5c,\
  00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,39,00,31,00,41,00,36,00,\
  38,00,30,00,35,00,44,00,2d,00,31,00,30,00,30,00,32,00,2d,00,34,00,38,00,44,\
  00,43,00,2d,00,39,00,37,00,34,00,30,00,2d,00,44,00,45,00,46,00,38,00,36,00,\
  41,00,37,00,39,00,37,00,31,00,33,00,31,00,7d,00,00,00,5c,00,44,00,65,00,76,\
  00,69,00,63,00,65,00,5c,00,7b,00,37,00,45,00,42,00,34,00,38,00,30,00,30,00,\
  33,00,2d,00,36,00,45,00,32,00,35,00,2d,00,34,00,43,00,33,00,38,00,2d,00,42,\
  00,34,00,32,00,43,00,2d,00,41,00,37,00,43,00,41,00,35,00,42,00,36,00,45,00,\
  31,00,31,00,39,00,39,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,\
  00,5c,00,7b,00,30,00,42,00,43,00,38,00,38,00,33,00,44,00,32,00,2d,00,44,00,\
  41,00,46,00,42,00,2d,00,34,00,32,00,30,00,32,00,2d,00,38,00,37,00,34,00,41,\
  00,2d,00,42,00,39,00,43,00,34,00,43,00,35,00,42,00,42,00,33,00,43,00,43,00,\
  46,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,44,\
  00,35,00,44,00,32,00,38,00,42,00,41,00,41,00,2d,00,37,00,33,00,34,00,46,00,\
  2d,00,34,00,38,00,38,00,35,00,2d,00,38,00,43,00,38,00,39,00,2d,00,46,00,33,\
  00,45,00,41,00,45,00,44,00,46,00,41,00,39,00,31,00,46,00,36,00,7d,00,00,00,\
  5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,36,00,35,00,42,00,42,\
  00,36,00,42,00,44,00,36,00,2d,00,36,00,43,00,44,00,42,00,2d,00,34,00,33,00,\
  41,00,35,00,2d,00,42,00,34,00,35,00,30,00,2d,00,36,00,34,00,41,00,32,00,32,\
  00,38,00,37,00,43,00,37,00,30,00,42,00,31,00,7d,00,00,00,5c,00,44,00,65,00,\
  76,00,69,00,63,00,65,00,5c,00,7b,00,46,00,45,00,37,00,43,00,44,00,35,00,42,\
  00,37,00,2d,00,31,00,46,00,44,00,42,00,2d,00,34,00,38,00,38,00,44,00,2d,00,\
  42,00,36,00,34,00,33,00,2d,00,30,00,39,00,30,00,33,00,31,00,30,00,39,00,44,\
  00,37,00,44,00,38,00,38,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,\
  65,00,5c,00,7b,00,33,00,35,00,34,00,31,00,36,00,38,00,41,00,37,00,2d,00,41,\
  00,30,00,39,00,43,00,2d,00,34,00,39,00,33,00,34,00,2d,00,38,00,39,00,35,00,\
  42,00,2d,00,46,00,38,00,39,00,46,00,41,00,33,00,43,00,30,00,42,00,42,00,44,\
  00,34,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,\
  41,00,36,00,44,00,44,00,37,00,46,00,31,00,44,00,2d,00,35,00,36,00,44,00,36,\
  00,2d,00,34,00,43,00,41,00,39,00,2d,00,38,00,31,00,46,00,42,00,2d,00,42,00,\
  43,00,34,00,33,00,35,00,42,00,35,00,30,00,46,00,35,00,39,00,33,00,7d,00,00,\
  00,00,00
"Route"=hex(7):22,00,7b,00,37,00,36,00,43,00,38,00,41,00,43,00,34,00,39,00,2d,\
  00,45,00,35,00,44,00,43,00,2d,00,34,00,42,00,45,00,30,00,2d,00,39,00,38,00,\
  45,00,34,00,2d,00,42,00,33,00,46,00,41,00,41,00,33,00,33,00,31,00,38,00,43,\
  00,33,00,32,00,7d,00,22,00,00,00,22,00,7b,00,43,00,41,00,33,00,45,00,31,00,\
  42,00,44,00,45,00,2d,00,33,00,45,00,45,00,35,00,2d,00,34,00,42,00,37,00,44,\
  00,2d,00,41,00,31,00,34,00,34,00,2d,00,38,00,34,00,35,00,35,00,41,00,32,00,\
  30,00,36,00,34,00,34,00,30,00,43,00,7d,00,22,00,00,00,22,00,7b,00,33,00,31,\
  00,30,00,46,00,34,00,46,00,43,00,41,00,2d,00,32,00,32,00,35,00,33,00,2d,00,\
  34,00,46,00,34,00,35,00,2d,00,41,00,46,00,38,00,30,00,2d,00,32,00,45,00,35,\
  00,43,00,34,00,43,00,46,00,39,00,30,00,39,00,30,00,39,00,7d,00,22,00,00,00,\
  22,00,7b,00,44,00,37,00,37,00,33,00,36,00,36,00,44,00,43,00,2d,00,38,00,34,\
  00,33,00,30,00,2d,00,34,00,33,00,30,00,30,00,2d,00,42,00,38,00,32,00,46,00,\
  2d,00,38,00,45,00,38,00,34,00,41,00,38,00,31,00,35,00,31,00,38,00,36,00,43,\
  00,7d,00,22,00,00,00,22,00,7b,00,37,00,38,00,35,00,37,00,44,00,38,00,42,00,\
  45,00,2d,00,36,00,31,00,42,00,39,00,2d,00,34,00,43,00,30,00,41,00,2d,00,38,\
  00,36,00,39,00,39,00,2d,00,30,00,36,00,32,00,33,00,43,00,46,00,43,00,44,00,\
  46,00,39,00,42,00,37,00,7d,00,22,00,00,00,22,00,7b,00,39,00,31,00,41,00,36,\
  00,38,00,30,00,35,00,44,00,2d,00,31,00,30,00,30,00,32,00,2d,00,34,00,38,00,\
  44,00,43,00,2d,00,39,00,37,00,34,00,30,00,2d,00,44,00,45,00,46,00,38,00,36,\
  00,41,00,37,00,39,00,37,00,31,00,33,00,31,00,7d,00,22,00,00,00,22,00,7b,00,\
  37,00,45,00,42,00,34,00,38,00,30,00,30,00,33,00,2d,00,36,00,45,00,32,00,35,\
  00,2d,00,34,00,43,00,33,00,38,00,2d,00,42,00,34,00,32,00,43,00,2d,00,41,00,\
  37,00,43,00,41,00,35,00,42,00,36,00,45,00,31,00,31,00,39,00,39,00,7d,00,22,\
  00,00,00,22,00,7b,00,30,00,42,00,43,00,38,00,38,00,33,00,44,00,32,00,2d,00,\
  44,00,41,00,46,00,42,00,2d,00,34,00,32,00,30,00,32,00,2d,00,38,00,37,00,34,\
  00,41,00,2d,00,42,00,39,00,43,00,34,00,43,00,35,00,42,00,42,00,33,00,43,00,\
  43,00,46,00,7d,00,22,00,00,00,22,00,7b,00,44,00,35,00,44,00,32,00,38,00,42,\
  00,41,00,41,00,2d,00,37,00,33,00,34,00,46,00,2d,00,34,00,38,00,38,00,35,00,\
  2d,00,38,00,43,00,38,00,39,00,2d,00,46,00,33,00,45,00,41,00,45,00,44,00,46,\
  00,41,00,39,00,31,00,46,00,36,00,7d,00,22,00,00,00,22,00,7b,00,36,00,35,00,\
  42,00,42,00,36,00,42,00,44,00,36,00,2d,00,36,00,43,00,44,00,42,00,2d,00,34,\
  00,33,00,41,00,35,00,2d,00,42,00,34,00,35,00,30,00,2d,00,36,00,34,00,41,00,\
  32,00,32,00,38,00,37,00,43,00,37,00,30,00,42,00,31,00,7d,00,22,00,00,00,22,\
  00,7b,00,46,00,45,00,37,00,43,00,44,00,35,00,42,00,37,00,2d,00,31,00,46,00,\
  44,00,42,00,2d,00,34,00,38,00,38,00,44,00,2d,00,42,00,36,00,34,00,33,00,2d,\
  00,30,00,39,00,30,00,33,00,31,00,30,00,39,00,44,00,37,00,44,00,38,00,38,00,\
  7d,00,22,00,00,00,22,00,7b,00,33,00,35,00,34,00,31,00,36,00,38,00,41,00,37,\
  00,2d,00,41,00,30,00,39,00,43,00,2d,00,34,00,39,00,33,00,34,00,2d,00,38,00,\
  39,00,35,00,42,00,2d,00,46,00,38,00,39,00,46,00,41,00,33,00,43,00,30,00,42,\
  00,42,00,44,00,34,00,7d,00,22,00,00,00,22,00,7b,00,41,00,36,00,44,00,44,00,\
  37,00,46,00,31,00,44,00,2d,00,35,00,36,00,44,00,36,00,2d,00,34,00,43,00,41,\
  00,39,00,2d,00,38,00,31,00,46,00,42,00,2d,00,42,00,43,00,34,00,33,00,35,00,\
  42,00,35,00,30,00,46,00,35,00,39,00,33,00,7d,00,22,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,52,00,61,00,73,\
  00,50,00,70,00,70,00,6f,00,65,00,5f,00,7b,00,37,00,36,00,43,00,38,00,41,00,\
  43,00,34,00,39,00,2d,00,45,00,35,00,44,00,43,00,2d,00,34,00,42,00,45,00,30,\
  00,2d,00,39,00,38,00,45,00,34,00,2d,00,42,00,33,00,46,00,41,00,41,00,33,00,\
  33,00,31,00,38,00,43,00,33,00,32,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,\
  00,63,00,65,00,5c,00,52,00,61,00,73,00,50,00,70,00,70,00,6f,00,65,00,5f,00,\
  7b,00,43,00,41,00,33,00,45,00,31,00,42,00,44,00,45,00,2d,00,33,00,45,00,45,\
  00,35,00,2d,00,34,00,42,00,37,00,44,00,2d,00,41,00,31,00,34,00,34,00,2d,00,\
  38,00,34,00,35,00,35,00,41,00,32,00,30,00,36,00,34,00,34,00,30,00,43,00,7d,\
  00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,52,00,61,00,73,00,\
  50,00,70,00,70,00,6f,00,65,00,5f,00,7b,00,33,00,31,00,30,00,46,00,34,00,46,\
  00,43,00,41,00,2d,00,32,00,32,00,35,00,33,00,2d,00,34,00,46,00,34,00,35,00,\
  2d,00,41,00,46,00,38,00,30,00,2d,00,32,00,45,00,35,00,43,00,34,00,43,00,46,\
  00,39,00,30,00,39,00,30,00,39,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,\
  63,00,65,00,5c,00,52,00,61,00,73,00,50,00,70,00,70,00,6f,00,65,00,5f,00,7b,\
  00,44,00,37,00,37,00,33,00,36,00,36,00,44,00,43,00,2d,00,38,00,34,00,33,00,\
  30,00,2d,00,34,00,33,00,30,00,30,00,2d,00,42,00,38,00,32,00,46,00,2d,00,38,\
  00,45,00,38,00,34,00,41,00,38,00,31,00,35,00,31,00,38,00,36,00,43,00,7d,00,\
  00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,52,00,61,00,73,00,50,\
  00,70,00,70,00,6f,00,65,00,5f,00,7b,00,37,00,38,00,35,00,37,00,44,00,38,00,\
  42,00,45,00,2d,00,36,00,31,00,42,00,39,00,2d,00,34,00,43,00,30,00,41,00,2d,\
  00,38,00,36,00,39,00,39,00,2d,00,30,00,36,00,32,00,33,00,43,00,46,00,43,00,\
  44,00,46,00,39,00,42,00,37,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,\
  00,65,00,5c,00,52,00,61,00,73,00,50,00,70,00,70,00,6f,00,65,00,5f,00,7b,00,\
  39,00,31,00,41,00,36,00,38,00,30,00,35,00,44,00,2d,00,31,00,30,00,30,00,32,\
  00,2d,00,34,00,38,00,44,00,43,00,2d,00,39,00,37,00,34,00,30,00,2d,00,44,00,\
  45,00,46,00,38,00,36,00,41,00,37,00,39,00,37,00,31,00,33,00,31,00,7d,00,00,\
  00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,52,00,61,00,73,00,50,00,\
  70,00,70,00,6f,00,65,00,5f,00,7b,00,37,00,45,00,42,00,34,00,38,00,30,00,30,\
  00,33,00,2d,00,36,00,45,00,32,00,35,00,2d,00,34,00,43,00,33,00,38,00,2d,00,\
  42,00,34,00,32,00,43,00,2d,00,41,00,37,00,43,00,41,00,35,00,42,00,36,00,45,\
  00,31,00,31,00,39,00,39,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,\
  65,00,5c,00,52,00,61,00,73,00,50,00,70,00,70,00,6f,00,65,00,5f,00,7b,00,30,\
  00,42,00,43,00,38,00,38,00,33,00,44,00,32,00,2d,00,44,00,41,00,46,00,42,00,\
  2d,00,34,00,32,00,30,00,32,00,2d,00,38,00,37,00,34,00,41,00,2d,00,42,00,39,\
  00,43,00,34,00,43,00,35,00,42,00,42,00,33,00,43,00,43,00,46,00,7d,00,00,00,\
  5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,52,00,61,00,73,00,50,00,70,\
  00,70,00,6f,00,65,00,5f,00,7b,00,44,00,35,00,44,00,32,00,38,00,42,00,41,00,\
  41,00,2d,00,37,00,33,00,34,00,46,00,2d,00,34,00,38,00,38,00,35,00,2d,00,38,\
  00,43,00,38,00,39,00,2d,00,46,00,33,00,45,00,41,00,45,00,44,00,46,00,41,00,\
  39,00,31,00,46,00,36,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,\
  00,5c,00,52,00,61,00,73,00,50,00,70,00,70,00,6f,00,65,00,5f,00,7b,00,36,00,\
  35,00,42,00,42,00,36,00,42,00,44,00,36,00,2d,00,36,00,43,00,44,00,42,00,2d,\
  00,34,00,33,00,41,00,35,00,2d,00,42,00,34,00,35,00,30,00,2d,00,36,00,34,00,\
  41,00,32,00,32,00,38,00,37,00,43,00,37,00,30,00,42,00,31,00,7d,00,00,00,5c,\
  00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,52,00,61,00,73,00,50,00,70,00,\
  70,00,6f,00,65,00,5f,00,7b,00,46,00,45,00,37,00,43,00,44,00,35,00,42,00,37,\
  00,2d,00,31,00,46,00,44,00,42,00,2d,00,34,00,38,00,38,00,44,00,2d,00,42,00,\
  36,00,34,00,33,00,2d,00,30,00,39,00,30,00,33,00,31,00,30,00,39,00,44,00,37,\
  00,44,00,38,00,38,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,\
  5c,00,52,00,61,00,73,00,50,00,70,00,70,00,6f,00,65,00,5f,00,7b,00,33,00,35,\
  00,34,00,31,00,36,00,38,00,41,00,37,00,2d,00,41,00,30,00,39,00,43,00,2d,00,\
  34,00,39,00,33,00,34,00,2d,00,38,00,39,00,35,00,42,00,2d,00,46,00,38,00,39,\
  00,46,00,41,00,33,00,43,00,30,00,42,00,42,00,44,00,34,00,7d,00,00,00,5c,00,\
  44,00,65,00,76,00,69,00,63,00,65,00,5c,00,52,00,61,00,73,00,50,00,70,00,70,\
  00,6f,00,65,00,5f,00,7b,00,41,00,36,00,44,00,44,00,37,00,46,00,31,00,44,00,\
  2d,00,35,00,36,00,44,00,36,00,2d,00,34,00,43,00,41,00,39,00,2d,00,38,00,31,\
  00,46,00,42,00,2d,00,42,00,43,00,34,00,33,00,35,00,42,00,35,00,30,00,46,00,\
  35,00,39,00,33,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasPppoe\Enum]
"0"="Root\\MS_PPPOEMINIPORT\\0000"
"Count"=dword:00000001
"NextInstance"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess]
"ConfigurationFlags"=dword:00000000
"DisplayName"="@%Systemroot%\\system32\\mprdim.dll,-200"
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,73,\
  00,76,00,63,00,68,00,6f,00,73,00,74,00,2e,00,65,00,78,00,65,00,20,00,2d,00,\
  6b,00,20,00,6e,00,65,00,74,00,73,00,76,00,63,00,73,00,00,00
"Description"="@%Systemroot%\\system32\\mprdim.dll,-201"
"ObjectName"="localSystem"
"ErrorControl"=dword:00000001
"Start"=dword:00000004
"Type"=dword:00000020
"DependOnGroup"=hex(7):4e,00,65,00,74,00,42,00,49,00,4f,00,53,00,47,00,72,00,\
  6f,00,75,00,70,00,00,00,00,00
"DependOnService"=hex(7):52,00,70,00,63,00,53,00,53,00,00,00,42,00,66,00,65,00,\
  00,00,52,00,61,00,73,00,4d,00,61,00,6e,00,00,00,48,00,74,00,74,00,70,00,00,\
  00,00,00
"ServiceSidType"=dword:00000001
"RequiredPrivileges"=hex(7):53,00,65,00,43,00,68,00,61,00,6e,00,67,00,65,00,4e,\
  00,6f,00,74,00,69,00,66,00,79,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,\
  67,00,65,00,00,00,53,00,65,00,4c,00,6f,00,61,00,64,00,44,00,72,00,69,00,76,\
  00,65,00,72,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,\
  53,00,65,00,49,00,6d,00,70,00,65,00,72,00,73,00,6f,00,6e,00,61,00,74,00,65,\
  00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,53,00,65,00,\
  41,00,75,00,64,00,69,00,74,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,\
  00,65,00,00,00,00,00
"FailureActions"=hex:84,03,00,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,c0,d4,01,00,01,00,00,00,e0,93,04,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Accounting]
"AccountSessionIdStart"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Accounting\Providers]
"ActiveProvider"="{1AA7F846-C7F5-11D0-A376-00C04FC9DA04}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Accounting\Providers\{1AA7F840-C7F5-11D0-A376-00C04FC9DA04}]
"ConfigClsid"="{1AA7F840-C7F5-11D0-A376-00C04FC9DA04}"
"DisplayName"="@%Systemroot%\\system32\\mprddm.dll,-202"
"VendorName"="Microsoft"
"ProviderTypeGUID"="{76560D00-2BFD-11d2-9539-3078302C2030}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Accounting\Providers\{1AA7F846-C7F5-11D0-A376-00C04FC9DA04}]
"Path"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,\
  00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,6d,00,\
  70,00,72,00,64,00,64,00,6d,00,2e,00,64,00,6c,00,6c,00,00,00
"ConfigClsid"=""
"DisplayName"="@%Systemroot%\\system32\\mprddm.dll,-203"
"ProviderTypeGUID"="{76560D81-2BFD-11d2-9539-3078302C2030}"
"VendorName"="Microsoft"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Authentication]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Authentication\Providers]
"ActiveProvider"="{1AA7F841-C7F5-11D0-A376-00C04FC9DA04}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Authentication\Providers\{1AA7F83F-C7F5-11D0-A376-00C04FC9DA04}]
"ConfigClsid"="{1AA7F83F-C7F5-11D0-A376-00C04FC9DA04}"
"DisplayName"="@%Systemroot%\\system32\\mprddm.dll,-201"
"VendorName"="Microsoft"
"ProviderTypeGUID"="{76560D00-2BFD-11d2-9539-3078302C2030}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Authentication\Providers\{1AA7F841-C7F5-11D0-A376-00C04FC9DA04}]
"Path"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,\
  00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,6d,00,\
  70,00,72,00,64,00,64,00,6d,00,2e,00,64,00,6c,00,6c,00,00,00
"ConfigClsid"=""
"DisplayName"="@%Systemroot%\\system32\\mprddm.dll,-200"
"VendorName"="Microsoft"
"ProviderTypeGUID"="{76560D01-2BFD-11d2-9539-3078302C2030}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\DemandDialManager]
"DllPath"="%SystemRoot%\\System32\\mprddm.dll"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces]
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\0]
"InterfaceName"="Loopback"
"Type"=dword:00000005
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\0\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\0\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\1]
"InterfaceName"="Internal"
"Type"=dword:00000004
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\1\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\1\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\10]
"InterfaceName"="{D5D28BAA-734F-4885-8C89-F3EAEDFA91F6}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\10\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\10\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\11]
"InterfaceName"="{65BB6BD6-6CDB-43A5-B450-64A2287C70B1}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\11\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\11\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\12]
"InterfaceName"="{FE7CD5B7-1FDB-488D-B643-0903109D7D88}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\12\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\12\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\13]
"InterfaceName"="{A6DD7F1D-56D6-4CA9-81FB-BC435B50F593}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\13\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\13\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\2]
"InterfaceName"="{76C8AC49-E5DC-4BE0-98E4-B3FAA3318C32}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\2\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\2\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\3]
"InterfaceName"="{CA3E1BDE-3EE5-4B7D-A144-8455A206440C}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\3\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\3\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\4]
"InterfaceName"="{310F4FCA-2253-4F45-AF80-2E5C4CF90909}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\4\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\4\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\5]
"InterfaceName"="{D77366DC-8430-4300-B82F-8E84A815186C}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\5\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\5\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\6]
"InterfaceName"="{7857D8BE-61B9-4C0A-8699-0623CFCDF9B7}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\6\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\6\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\7]
"InterfaceName"="{91A6805D-1002-48DC-9740-DEF86A797131}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\7\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\7\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\8]
"InterfaceName"="{7EB48003-6E25-4C38-B42C-A7CA5B6E1199}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\8\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\8\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\9]
"InterfaceName"="{0BC883D2-DAFB-4202-874A-B9C4C5BB3CCF}"
"Type"=dword:00000003
"Enabled"=dword:00000001
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\9\Ip]
"ProtocolId"=dword:00000021
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Interfaces\9\Ipv6]
"ProtocolId"=dword:00000057
"InterfaceInfo"=hex:01,00,00,00,68,00,00,00,03,00,00,00,05,00,ff,ff,48,00,00,\
  00,00,00,00,00,40,00,00,00,04,00,ff,ff,04,00,00,00,01,00,00,00,40,00,00,00,\
  07,00,ff,ff,10,00,00,00,01,00,00,00,48,00,00,00,00,00,00,00,01,00,00,00,00,\
  00,00,00,58,02,c2,01,08,07,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters]
"ServiceDLL"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  6d,00,70,00,72,00,64,00,69,00,6d,00,2e,00,64,00,6c,00,6c,00,00,00
"QuarantineInstalled"=dword:00000001
"LoggingFlags"=dword:00000002
"ServerFlags"=dword:00802602
"ServiceDllUnloadOnStop"=dword:00000001
"Stamp"=dword:00000000
"UsersConfigured"=dword:00000000
"RouterType"=dword:00000007

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout]
"MaxDenials"=dword:00000000
"ResetTime (mins)"=dword:00000b40

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\IKEV2]
"idleTimeout"=dword:0000012c
"networkBlackoutTime"=dword:00000708
"saLifeTime"=dword:00007080
"saDataSize"=dword:00019000
"ConfigOptions"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\Ip]
"AllowClientIpAddresses"=dword:00000000
"AllowNetworkAccess"=dword:00000001
"EnableIn"=dword:00000001
"EnableRoute"=dword:00000001
"IpAddress"="0.0.0.0"
"IpMask"="0.0.0.0"
"UseDhcpAddressing"=dword:00000001
"EnableNetbtBcastFwd"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\Ipv6]
"AdvertiseDefaultRoute"=dword:00000001
"AllowNetworkAccess"=dword:00000001
"EnableIn"=dword:00000000
"EnableRoute"=dword:00000001
"UseDhcpAddressing"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\Nbf]
"AllowNetworkAccess"=dword:00000001
"EnableIn"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Performance]
"Library"="rasctrs.dll"
"Open"="OpenRasPerformanceData"
"Close"="CloseRasPerformanceData"
"Collect"="CollectRasPerformanceData"
"InstallType"=dword:00000001
"PerfIniFile"="rasctrs.ini"
"First Counter"=dword:0000089e
"Last Counter"=dword:000008c4
"First Help"=dword:0000089f
"Last Help"=dword:000008c5

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy]
"Allow LM Authentication"=dword:00000000
"ProductDir"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  49,00,41,00,53,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\01]
@="IAS.ProxyPolicyEnforcer"
"Requests"="0 1 2"
"Responses"="0 1 2 3 4"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\02]
@="IAS.Realm"
"Providers"="1"
"Requests"="0 1"
"Responses"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\03]
@="IAS.Realm"
"Requests"="0 1"
"Responses"="0"
"Providers"="0 2"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\04]
@="IAS.NTSamNames"
"Providers"="1"
"Responses"="0"
"Requests"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\05]
@="IAS.CRPBasedEAP"
"Providers"="1"
"Requests"="0 2"
"Responses"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\06]
@="IAS.Realm"
"Providers"="1"
"Requests"="0"
"Responses"="0"
"Replays"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\07]
@="IAS.NTSamNames"
"Providers"="1"
"Requests"="0"
"Responses"="0"
"Replays"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\08]
@="IAS.MachineNameMapper"
"Providers"="1"
"Requests"="0"
"Responses"="0"
"Replays"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\09]
@="IAS.BaseCampHost"
"Replays"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\10]
@="IAS.RadiusProxy"
"Providers"="2"
"Responses"="0"
"Replays"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\11]
@="IAS.ExternalAuthNames"
"Providers"="2"
"Requests"="0"
"Responses"="1"
"Replays"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\12]
@="IAS.NTSamAuthentication"
"Requests"="0"
"Responses"="0 1 2"
"Providers"="1"
"Replays"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\13]
@="IAS.UserAccountValidation"
"Providers"="1 3"
"Requests"="0"
"Replays"="0"
"Responses"="0 1"
"Reasons"="33"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\14]
@="IAS.MachineAccountValidation"
"Providers"="1"
"Requests"="0"
"Responses"="0 1"
"Replays"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\15]
@="IAS.EAPIdentity"
"Providers"="1"
"Requests"="0"
"Replays"="0"
"Responses"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\16]
@="IAS.QuarantineEvaluator"
"Providers"="1"
"Requests"="0"
"Replays"="0"
"Responses"="0 1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\17]
@="IAS.PolicyEnforcer"
"Providers"="1 3"
"Requests"="0"
"Replays"="0"
"Responses"="0 1"
"Reasons"="33"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\18]
@="IAS.NTSamPerUser"
"Providers"="1 3"
"Requests"="0"
"Replays"="0"
"Responses"="0 1"
"Reasons"="33"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\19]
@="IAS.URHandler"
"Providers"="1 3"
"Requests"="0"
"Replays"="0"
"Responses"="0 1"
"Reasons"="33"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\20]
@="IAS.RAPBasedEAP"
"Providers"="1"
"Requests"="0 2"
"Replays"="0"
"Responses"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\21]
@="IAS.PostEapRestrictions"
"Providers"="0 1 3"
"Requests"="0"
"Replays"="0"
"Responses"="0 1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\22]
@="IAS.PostQuarantineEvaluator"
"Providers"="1"
"Requests"="0"
"Replays"="0"
"Responses"="1 2 5"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\23]
@="IAS.ChangePassword"
"Providers"="1"
"Requests"="0"
"Replays"="0"
"Responses"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\24]
@="IAS.AuthorizationHost"
"Replays"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\25]
@="IAS.EAPTerminator"
"Providers"="0 1"
"Requests"="0 2"
"Replays"="0"
"Responses"="1 2 3 5"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\26]
@="IAS.DatabaseAccounting"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\27]
@="IAS.Accounting"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\28]
@="IAS.MSChapErrorReporter"
"Providers"="0 1 3"
"Requests"="0"
"Replays"="0"
"Responses"="2"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\RouterManagers]
"Stamp"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\RouterManagers\Ip]
"ProtocolId"=dword:00000021
"GlobalInfo"=hex:01,00,00,00,78,00,00,00,02,00,00,00,03,00,ff,ff,08,00,00,00,\
  01,00,00,00,30,00,00,00,06,00,ff,ff,34,00,00,00,01,00,00,00,38,00,00,00,00,\
  00,00,00,00,00,00,00,01,00,00,00,06,00,00,00,02,00,00,00,01,00,00,00,03,00,\
  00,00,0a,00,00,00,16,27,00,00,03,00,00,00,17,27,00,00,05,00,00,00,12,27,00,\
  00,07,00,00,00,08,00,00,00,78,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"DLLPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,69,\
  00,70,00,72,00,74,00,72,00,6d,00,67,00,72,00,2e,00,64,00,6c,00,6c,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\RouterManagers\Ipv6]
"ProtocolId"=dword:00000057
"GlobalInfo"=hex:01,00,00,00,78,00,00,00,02,00,00,00,0f,00,ff,ff,08,00,00,00,\
  01,00,00,00,30,00,00,00,06,00,ff,ff,34,00,00,00,01,00,00,00,38,00,00,00,00,\
  00,00,00,00,00,00,00,01,00,00,00,06,00,00,00,02,00,00,00,01,00,00,00,16,27,\
  00,00,03,00,00,00,17,27,00,00,05,00,00,00,12,27,00,00,07,00,00,00,03,00,00,\
  00,0a,00,00,00,08,00,00,00,78,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"DLLPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,69,\
  00,70,00,72,00,74,00,72,00,6d,00,67,00,72,00,2e,00,64,00,6c,00,6c,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\RoutingTableManager]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\RoutingTableManager\Instance 00000]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\RoutingTableManager\Instance 00000\AddressFamily 00002]
"AddressSize"=dword:00000004
"MaxChangeNotifyRegistrations"=dword:00000010
"MaxHandlesReturnedInEnum"=dword:00000019
"MaxNextHopsInRoute"=dword:00000003
"MaxOpaqueInfoPointers"=dword:00000005
"ViewsSupported"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\RoutingTableManager\Instance 00000\AddressFamily 00023]
"AddressSize"=dword:00000010
"MaxChangeNotifyRegistrations"=dword:00000010
"MaxHandlesReturnedInEnum"=dword:00000019
"MaxNextHopsInRoute"=dword:00000003
"MaxOpaqueInfoPointers"=dword:00000005
"ViewsSupported"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Security]
"Security"=hex:01,00,04,80,5c,00,00,00,68,00,00,00,00,00,00,00,14,00,00,00,02,\
  00,48,00,03,00,00,00,00,00,14,00,fd,01,02,00,01,01,00,00,00,00,00,05,12,00,\
  00,00,00,00,18,00,ff,01,0f,00,01,02,00,00,00,00,00,05,20,00,00,00,20,02,00,\
  00,00,00,14,00,8d,01,02,00,01,01,00,00,00,00,00,05,0b,00,00,00,01,01,00,00,\
  00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wanarp]
"NdisMajorVersion"=dword:00000006
"NdisMinorVersion"=dword:00000014
"Type"=dword:00000001
"Start"=dword:00000003
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,44,00,\
  52,00,49,00,56,00,45,00,52,00,53,00,5c,00,77,00,61,00,6e,00,61,00,72,00,70,\
  00,2e,00,73,00,79,00,73,00,00,00
"DisplayName"="@%systemroot%\\system32\\rascfg.dll,-32011"
"Description"="@%systemroot%\\system32\\rascfg.dll,-32011"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wanarp\Linkage]
"Bind"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,4e,00,64,00,69,\
  00,73,00,57,00,61,00,6e,00,49,00,70,00,00,00,00,00
"Route"=hex(7):22,00,4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,49,00,70,00,22,\
  00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,57,00,61,00,6e,\
  00,61,00,72,00,70,00,5f,00,4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,49,00,\
  70,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}]
"Class"="Net"
"ClassDesc"="@NetCfgx.dll,-1502"
@="Network adapters"
"IconPath"=hex(7):25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,\
  74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,73,\
  00,65,00,74,00,75,00,70,00,61,00,70,00,69,00,2e,00,64,00,6c,00,6c,00,2c,00,\
  2d,00,35,00,00,00,00,00
"Installer32"="NetCfgx.dll,NetClassInstaller"
"EnumPropPages32"="NetCfgx.dll,NetPropPageProvider"
"LowerLogoVersion"="6.0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0000]
"NewDeviceInstall"=dword:00000000
"NetCfgInstanceId"="{71F897D7-EB7C-4D8D-89DB-AC80D9DD2270}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000029
"*MediaType"=dword:0000000c
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000000
"DeviceInstanceID"="ROOT\\MS_SSTPMINIPORT\\0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0a,00,0f,00,94,01
"MinWanEndpoints"=dword:00000000
"MaxWanEndpoints"=dword:00000003
"WanEndpoints"=dword:00000002
"ComponentId"="ms_sstpminiport"
"InfPath"="netsstpa.inf"
"InfSection"="Ndi-Mp-Sstp"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7601.17514"
"MatchingDeviceId"="ms_sstpminiport"
"DriverDesc"="WAN Miniport (SSTP)"
"EnableForRas"=dword:00000000
"EnableForRouting"=dword:00000000
"EnableForOutboundRouting"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0000\Linkage]
"RootDevice"=hex(7):7b,00,37,00,31,00,46,00,38,00,39,00,37,00,44,00,37,00,2d,\
  00,45,00,42,00,37,00,43,00,2d,00,34,00,44,00,38,00,44,00,2d,00,38,00,39,00,\
  44,00,42,00,2d,00,41,00,43,00,38,00,30,00,44,00,39,00,44,00,44,00,32,00,32,\
  00,37,00,30,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,37,00,31,\
  00,46,00,38,00,39,00,37,00,44,00,37,00,2d,00,45,00,42,00,37,00,43,00,2d,00,\
  34,00,44,00,38,00,44,00,2d,00,38,00,39,00,44,00,42,00,2d,00,41,00,43,00,38,\
  00,30,00,44,00,39,00,44,00,44,00,32,00,32,00,37,00,30,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0000\Ndi]
"Service"="RasSstp"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0000\Ndi\Interfaces]
"UpperRange"="ndiscowan"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0001]
"NewDeviceInstall"=dword:00000000
"NetCfgInstanceId"="{29898C9D-B0A4-4FEF-BDB6-57A562022CEE}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000029
"*MediaType"=dword:0000000c
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000001
"DeviceInstanceID"="ROOT\\MS_AGILEVPNMINIPORT\\0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0a,00,17,00,02,00
"MinWanEndpoints"=dword:00000000
"MaxWanEndpoints"=dword:00000003
"WanEndpoints"=dword:00000002
"ComponentId"="ms_agilevpnminiport"
"InfPath"="netavpna.inf"
"InfSection"="Ndi-Mp-AgileVpn"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7601.23403"
"MatchingDeviceId"="ms_agilevpnminiport"
"DriverDesc"="WAN Miniport (IKEv2)"
"EnableForRas"=dword:00000000
"EnableForRouting"=dword:00000000
"EnableForOutboundRouting"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0001\Linkage]
"RootDevice"=hex(7):7b,00,32,00,39,00,38,00,39,00,38,00,43,00,39,00,44,00,2d,\
  00,42,00,30,00,41,00,34,00,2d,00,34,00,46,00,45,00,46,00,2d,00,42,00,44,00,\
  42,00,36,00,2d,00,35,00,37,00,41,00,35,00,36,00,32,00,30,00,32,00,32,00,43,\
  00,45,00,45,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,32,00,39,\
  00,38,00,39,00,38,00,43,00,39,00,44,00,2d,00,42,00,30,00,41,00,34,00,2d,00,\
  34,00,46,00,45,00,46,00,2d,00,42,00,44,00,42,00,36,00,2d,00,35,00,37,00,41,\
  00,35,00,36,00,32,00,30,00,32,00,32,00,43,00,45,00,45,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0001\Ndi]
"Service"="RasAgileVpn"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0001\Ndi\Interfaces]
"UpperRange"="ndiscowan"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0002]
"NewDeviceInstall"=dword:00000000
"NetCfgInstanceId"="{E43D242B-9EAB-4626-A952-46649FBB939A}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000029
"*MediaType"=dword:0000000c
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000002
"DeviceInstanceID"="ROOT\\MS_L2TPMINIPORT\\0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0a,00,18,00,00,00
"MinWanEndpoints"=dword:00000000
"MaxWanEndpoints"=dword:00000003
"WanEndpoints"=dword:00000002
"ComponentId"="ms_l2tpminiport"
"InfPath"="netrasa.inf"
"InfSection"="Ndi-Mp-L2tp"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7601.24559"
"MatchingDeviceId"="ms_l2tpminiport"
"DriverDesc"="WAN Miniport (L2TP)"
"EnableForRas"=dword:00000000
"EnableForRouting"=dword:00000000
"EnableForOutboundRouting"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0002\Linkage]
"RootDevice"=hex(7):7b,00,45,00,34,00,33,00,44,00,32,00,34,00,32,00,42,00,2d,\
  00,39,00,45,00,41,00,42,00,2d,00,34,00,36,00,32,00,36,00,2d,00,41,00,39,00,\
  35,00,32,00,2d,00,34,00,36,00,36,00,34,00,39,00,46,00,42,00,42,00,39,00,33,\
  00,39,00,41,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,45,00,34,\
  00,33,00,44,00,32,00,34,00,32,00,42,00,2d,00,39,00,45,00,41,00,42,00,2d,00,\
  34,00,36,00,32,00,36,00,2d,00,41,00,39,00,35,00,32,00,2d,00,34,00,36,00,36,\
  00,34,00,39,00,46,00,42,00,42,00,39,00,33,00,39,00,41,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0002\Ndi]
"Service"="Rasl2tp"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0002\Ndi\Interfaces]
"UpperRange"="ndiscowan"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0003]
"NewDeviceInstall"=dword:00000000
"NetCfgInstanceId"="{DF4A9D2C-8742-4EB1-8703-D395C4183F33}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000029
"*MediaType"=dword:0000000c
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000003
"DeviceInstanceID"="ROOT\\MS_PPTPMINIPORT\\0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0a,00,20,00,dd,00
"MinWanEndpoints"=dword:00000000
"MaxWanEndpoints"=dword:00000003
"TapiLineName"="RAS VPN Line"
"InactivityIdleSeconds"="60"
"TcpPortNumber"=dword:000006bb
"TcpDisconnectTimeout"=dword:0000001e
"TcpConnectTimeout"=dword:0000001e
"ClientIpAddresses"=hex(7):00,00
"ClientIpMasks"=hex(7):00,00
"AuthenticateIncomingCalls"=dword:00000000
"WanEndpoints"=dword:00000002
"ComponentId"="ms_pptpminiport"
"InfPath"="netrasa.inf"
"InfSection"="Ndi-Mp-Pptp"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7601.24559"
"MatchingDeviceId"="ms_pptpminiport"
"DriverDesc"="WAN Miniport (PPTP)"
"EnableForRas"=dword:00000000
"EnableForRouting"=dword:00000000
"EnableForOutboundRouting"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0003\Linkage]
"RootDevice"=hex(7):7b,00,44,00,46,00,34,00,41,00,39,00,44,00,32,00,43,00,2d,\
  00,38,00,37,00,34,00,32,00,2d,00,34,00,45,00,42,00,31,00,2d,00,38,00,37,00,\
  30,00,33,00,2d,00,44,00,33,00,39,00,35,00,43,00,34,00,31,00,38,00,33,00,46,\
  00,33,00,33,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,44,00,46,\
  00,34,00,41,00,39,00,44,00,32,00,43,00,2d,00,38,00,37,00,34,00,32,00,2d,00,\
  34,00,45,00,42,00,31,00,2d,00,38,00,37,00,30,00,33,00,2d,00,44,00,33,00,39,\
  00,35,00,43,00,34,00,31,00,38,00,33,00,46,00,33,00,33,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0003\Ndi]
"Service"="PptpMiniport"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0003\Ndi\Interfaces]
"UpperRange"="ndiscowan"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0004]
"NewDeviceInstall"=dword:00000000
"NetCfgInstanceId"="{8E301A52-AFFA-4F49-B9CA-C79096A1A056}"
"*IfType"=dword:00000017
"Characteristics"=dword:00000029
"*MediaType"=dword:0000000c
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000000
"DeviceInstanceID"="ROOT\\MS_PPPOEMINIPORT\\0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0a,00,1f,00,0e,01
"MinWanEndpoints"=dword:00000000
"MaxWanEndpoints"=dword:00000003
"TapiLineName"="RAS PPPOE Line"
"WanEndpoints"=dword:00000001
"ComponentId"="ms_pppoeminiport"
"InfPath"="netrasa.inf"
"InfSection"="Ndi-Mp-Pppoe"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7601.24559"
"MatchingDeviceId"="ms_pppoeminiport"
"DriverDesc"="WAN Miniport (PPPOE)"
"EnableForRas"=dword:00000000
"EnableForRouting"=dword:00000000
"EnableForOutboundRouting"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0004\Linkage]
"RootDevice"=hex(7):7b,00,38,00,45,00,33,00,30,00,31,00,41,00,35,00,32,00,2d,\
  00,41,00,46,00,46,00,41,00,2d,00,34,00,46,00,34,00,39,00,2d,00,42,00,39,00,\
  43,00,41,00,2d,00,43,00,37,00,39,00,30,00,39,00,36,00,41,00,31,00,41,00,30,\
  00,35,00,36,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,38,00,45,\
  00,33,00,30,00,31,00,41,00,35,00,32,00,2d,00,41,00,46,00,46,00,41,00,2d,00,\
  34,00,46,00,34,00,39,00,2d,00,42,00,39,00,43,00,41,00,2d,00,43,00,37,00,39,\
  00,30,00,39,00,36,00,41,00,31,00,41,00,30,00,35,00,36,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0004\Ndi]
"Service"="RasPppoe"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0004\Ndi\Interfaces]
"UpperRange"="ndiscowan"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0005]
"NewDeviceInstall"=dword:00000000
"NetCfgInstanceId"="{9A399D81-2EAD-4F23-BCDD-637FC13DCD51}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000029
"*MediaType"=dword:00000000
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000000
"DeviceInstanceID"="ROOT\\MS_NDISWANIPV6\\0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0a,00,1e,00,00,01
"ComponentId"="ms_ndiswanipv6"
"InfPath"="netrasa.inf"
"InfSection"="Ndi-Mp-Ipv6"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7601.24559"
"MatchingDeviceId"="ms_ndiswanipv6"
"DriverDesc"="WAN Miniport (IPv6)"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0005\Linkage]
"RootDevice"=hex(7):4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,49,00,70,00,76,\
  00,36,00,00,00,00,00
"UpperBind"=hex(7):57,00,61,00,6e,00,61,00,72,00,70,00,76,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,4e,00,64,00,69,\
  00,73,00,57,00,61,00,6e,00,49,00,70,00,76,00,36,00,00,00,00,00
"FilterList"=hex(7):7b,00,39,00,41,00,33,00,39,00,39,00,44,00,38,00,31,00,2d,\
  00,32,00,45,00,41,00,44,00,2d,00,34,00,46,00,32,00,33,00,2d,00,42,00,43,00,\
  44,00,44,00,2d,00,36,00,33,00,37,00,46,00,43,00,31,00,33,00,44,00,43,00,44,\
  00,35,00,31,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0005\Ndi]
"BindForm"="NdisWanIpv6"
"Service"="NdisWan"
"RequiredAll"="MS_wanarpv6"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0005\Ndi\Interfaces]
"UpperRange"="ndiswanipv6"
"LowerRange"="wan"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0006]
"NewDeviceInstall"=dword:00000000
"NetCfgInstanceId"="{5BF54C7E-91DA-457D-80BF-333677D7E316}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000029
"NetLuidIndex"=dword:00000001
"DeviceInstanceID"="ROOT\\MS_NDISWANBH\\0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0a,00,1a,00,f6,00
"EnumExportPref"=dword:00000000
"ComponentId"="ms_ndiswanbh"
"InfPath"="netrasa.inf"
"InfSection"="Ndi-Mp-Bh"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7601.24559"
"MatchingDeviceId"="ms_ndiswanbh"
"DriverDesc"="WAN Miniport (Network Monitor)"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0006\Linkage]
"RootDevice"=hex(7):4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,42,00,68,00,00,\
  00,00,00
"UpperBind"=hex(7):00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,4e,00,64,00,69,\
  00,73,00,57,00,61,00,6e,00,42,00,68,00,00,00,00,00
"FilterList"=hex(7):7b,00,35,00,42,00,46,00,35,00,34,00,43,00,37,00,45,00,2d,\
  00,39,00,31,00,44,00,41,00,2d,00,34,00,35,00,37,00,44,00,2d,00,38,00,30,00,\
  42,00,46,00,2d,00,33,00,33,00,33,00,36,00,37,00,37,00,44,00,37,00,45,00,33,\
  00,31,00,36,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0006\Ndi]
"BindForm"="NdisWanBh"
"Service"="NdisWan"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0006\Ndi\Interfaces]
"UpperRange"="ndiswanbh"
"LowerRange"="wan"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0007]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{8D616583-4B43-4EE3-ABEA-D198AE9B7988}"
"*IfType"=dword:00000001
"Characteristics"=dword:00000009
"NetLuidIndex"=dword:00000000
"DeviceInstanceID"="BTH\\MS_RFCOMM\\7&1BB168B6&0&0"
"InstallTimeStamp"=hex:e6,07,01,00,00,00,1e,00,06,00,25,00,01,00,4b,02
"ComponentId"="bth\\ms_rfcomm"
"InfPath"="tdibth.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,69,00,72,00,64,00,61,00,2e,00,69,00,6e,\
  00,66,00,00,00,62,00,74,00,68,00,2e,00,69,00,6e,00,66,00,00,00,00,00
"InfSection"="RFCOMM.Install"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="bth\\ms_rfcomm"
"DriverDesc"="Bluetooth Device (RFCOMM Protocol TDI)"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0007\Ndi]
"HelpText"="Bluetooth RFCOMM HelpText"
"Service"="RFCOMM"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0007\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0008]
"NewDeviceInstall"=dword:00000000
"NetCfgInstanceId"="{2CAA64ED-BAA3-4473-B637-DEC65A14C8AA}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000029
"*MediaType"=dword:00000000
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000004
"DeviceInstanceID"="ROOT\\MS_NDISWANIP\\0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0a,00,1c,00,b1,03
"ComponentId"="ms_ndiswanip"
"InfPath"="netrasa.inf"
"InfSection"="Ndi-Mp-Ip"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7601.24559"
"MatchingDeviceId"="ms_ndiswanip"
"DriverDesc"="WAN Miniport (IP)"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0008\Linkage]
"RootDevice"=hex(7):4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,49,00,70,00,00,\
  00,00,00
"UpperBind"=hex(7):57,00,61,00,6e,00,61,00,72,00,70,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,4e,00,64,00,69,\
  00,73,00,57,00,61,00,6e,00,49,00,70,00,00,00,00,00
"FilterList"=hex(7):7b,00,32,00,43,00,41,00,41,00,36,00,34,00,45,00,44,00,2d,\
  00,42,00,41,00,41,00,33,00,2d,00,34,00,34,00,37,00,33,00,2d,00,42,00,36,00,\
  33,00,37,00,2d,00,44,00,45,00,43,00,36,00,35,00,41,00,31,00,34,00,43,00,38,\
  00,41,00,41,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0008\Ndi]
"BindForm"="NdisWanIp"
"Service"="NdisWan"
"RequiredAll"="MS_wanarp"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0008\Ndi\Interfaces]
"UpperRange"="ndiswanip"
"LowerRange"="wan"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0009]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{0BC883D2-DAFB-4202-874A-B9C4C5BB3CCF}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000084
"NetLuidIndex"=dword:0000000e
"DeviceInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&CA14D76&1&0000"
"InstallTimeStamp"=hex:e6,07,01,00,04,00,1b,00,0f,00,27,00,30,00,2e,03
"BusType"="15"
"ComponentId"="usb\\class_e0&subclass_01&prot_03"
"BusNumber"="0"
"InfPath"="wceisvista.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,72,00,6e,00,64,00,69,00,73,00,2e,00,69,\
  00,6e,00,66,00,00,00,00,00
"InfSection"="RNDIS.NT.5.1"
"ProviderName"="Microsoft Corporation"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="usb\\class_e0&subclass_01&prot_03"
"DriverDesc"="Remote NDIS based Internet Sharing Device"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0009\Linkage]
"RootDevice"=hex(7):7b,00,30,00,42,00,43,00,38,00,38,00,33,00,44,00,32,00,2d,\
  00,44,00,41,00,46,00,42,00,2d,00,34,00,32,00,30,00,32,00,2d,00,38,00,37,00,\
  34,00,41,00,2d,00,42,00,39,00,43,00,34,00,43,00,35,00,42,00,42,00,33,00,43,\
  00,43,00,46,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,30,00,42,\
  00,43,00,38,00,38,00,33,00,44,00,32,00,2d,00,44,00,41,00,46,00,42,00,2d,00,\
  34,00,32,00,30,00,32,00,2d,00,38,00,37,00,34,00,41,00,2d,00,42,00,39,00,43,\
  00,34,00,43,00,35,00,42,00,42,00,33,00,43,00,43,00,46,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,30,00,42,00,43,00,38,00,38,00,33,00,44,00,32,00,2d,\
  00,44,00,41,00,46,00,42,00,2d,00,34,00,32,00,30,00,32,00,2d,00,38,00,37,00,\
  34,00,41,00,2d,00,42,00,39,00,43,00,34,00,43,00,35,00,42,00,42,00,33,00,43,\
  00,43,00,46,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,30,\
  00,42,00,43,00,38,00,38,00,33,00,44,00,32,00,2d,00,44,00,41,00,46,00,42,00,\
  2d,00,34,00,32,00,30,00,32,00,2d,00,38,00,37,00,34,00,41,00,2d,00,42,00,39,\
  00,43,00,34,00,43,00,35,00,42,00,42,00,33,00,43,00,43,00,46,00,7d,00,2d,00,\
  7b,00,42,00,37,00,30,00,44,00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,\
  00,35,00,2d,00,34,00,44,00,34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,\
  42,00,38,00,41,00,42,00,31,00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0009\Ndi]
"Service"="usb_rndisx"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0009\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0009\Ndi\params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0009\Ndi\params\NetworkAddress]
"ParamDesc"="Network Address"
"type"="edit"
"LimitText"="12"
"UpperCase"="1"
"default"=" "
"optional"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0010]
"NewDeviceInstall"=dword:00000000
"NetCfgInstanceId"="{78032B7E-4968-42D3-9F37-287EA86C0AAA}"
"*IfType"=dword:00000017
"Characteristics"=dword:0000002a
"NetLuidIndex"=dword:00000001
"DeviceInstanceID"="SW\\{EEAB7790-C514-11D1-B42B-00805FC1270E}\\ASYNCMAC"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0a,00,23,00,b6,03
"PnPCapabilities"=dword:00000001
"ComponentId"="sw\\{eeab7790-c514-11d1-b42b-00805fc1270e}"
"InfPath"="netrasa.inf"
"InfSection"="Ndi-Mp-AsyncMac"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7601.24559"
"MatchingDeviceId"="sw\\{eeab7790-c514-11d1-b42b-00805fc1270e}"
"DriverDesc"="RAS Async Adapter"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0010\Linkage]
"RootDevice"=hex(7):7b,00,37,00,38,00,30,00,33,00,32,00,42,00,37,00,45,00,2d,\
  00,34,00,39,00,36,00,38,00,2d,00,34,00,32,00,44,00,33,00,2d,00,39,00,46,00,\
  33,00,37,00,2d,00,32,00,38,00,37,00,45,00,41,00,38,00,36,00,43,00,30,00,41,\
  00,41,00,41,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,57,00,61,00,6e,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,37,00,38,\
  00,30,00,33,00,32,00,42,00,37,00,45,00,2d,00,34,00,39,00,36,00,38,00,2d,00,\
  34,00,32,00,44,00,33,00,2d,00,39,00,46,00,33,00,37,00,2d,00,32,00,38,00,37,\
  00,45,00,41,00,38,00,36,00,43,00,30,00,41,00,41,00,41,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0010\Ndi]
"Service"="AsyncMac"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0010\Ndi\Interfaces]
"UpperRange"="ndiswanasync"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0011]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{91A6805D-1002-48DC-9740-DEF86A797131}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000001
"*MediaType"=dword:00000000
"*PhysicalMediaType"=dword:0000000a
"NetLuidIndex"=dword:00000007
"DeviceInstanceID"="BTH\\MS_BTHPAN\\7&1BB168B6&0&2"
"InstallTimeStamp"=hex:e6,07,01,00,00,00,1e,00,06,00,25,00,04,00,14,00
"ServiceId"=dword:00000003
"ServiceLangT"="en"
"ServiceName"="Personal Ad Hoc User Service"
"ServiceDesc"="Personal Ad Hoc User Service"
"ComponentId"="bth\\ms_bthpan"
"InfPath"="bthpan.inf"
"InfSection"="BthPan.Install"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7601.23863"
"MatchingDeviceId"="bth\\ms_bthpan"
"DriverDesc"="Bluetooth Device (Personal Area Network)"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0011\Linkage]
"RootDevice"=hex(7):7b,00,39,00,31,00,41,00,36,00,38,00,30,00,35,00,44,00,2d,\
  00,31,00,30,00,30,00,32,00,2d,00,34,00,38,00,44,00,43,00,2d,00,39,00,37,00,\
  34,00,30,00,2d,00,44,00,45,00,46,00,38,00,36,00,41,00,37,00,39,00,37,00,31,\
  00,33,00,31,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,39,00,31,\
  00,41,00,36,00,38,00,30,00,35,00,44,00,2d,00,31,00,30,00,30,00,32,00,2d,00,\
  34,00,38,00,44,00,43,00,2d,00,39,00,37,00,34,00,30,00,2d,00,44,00,45,00,46,\
  00,38,00,36,00,41,00,37,00,39,00,37,00,31,00,33,00,31,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0011\Ndi]
"HelpText"="Bluetooth PAN HelpText"
"Service"="BthPan"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0011\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="nolower, bluetooth"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013]
"CoInstallers32"=hex(7):62,00,63,00,6d,00,77,00,6c,00,63,00,6f,00,69,00,2e,00,\
  64,00,6c,00,6c,00,2c,00,20,00,42,00,43,00,4d,00,57,00,6c,00,61,00,6e,00,43,\
  00,6f,00,49,00,6e,00,73,00,74,00,61,00,6c,00,6c,00,00,00,00,00
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{7857D8BE-61B9-4C0A-8699-0623CFCDF9B7}"
"*IfType"=dword:00000047
"Characteristics"=dword:00000084
"*MediaType"=dword:00000010
"*PhysicalMediaType"=dword:00000009
"NetLuidIndex"=dword:00000000
"DeviceInstanceID"="PCI\\VEN_14E4&DEV_432B&SUBSYS_008E106B&REV_01\\A9464BFFFF9B002500"
"InstallTimeStamp"=hex:e6,07,01,00,00,00,1e,00,06,00,25,00,0d,00,60,03
"PortAuthSendControlState"=dword:00000002
"PortAuthReceiveControlState"=dword:00000002
"PortAuthSendAuthorizationState"=dword:00000001
"PortAuthReceiveAuthorizationState"=dword:00000001
"EnableSoftAP"="0"
"EnableAutoConnect"="0"
"WowlKeyRot"="1"
"WEP"=""
"NetworkType"="-1"
"SSID"=""
"ledbh0"="-1"
"ledbh1"="-1"
"ledbh2"="-1"
"ledbh3"="-1"
"ledblinkslow"="-1"
"ledblinkmed"="-1"
"ledblinkfast"="-1"
"leddc"="0"
"scan_channel_time"="-1"
"scan_unassoc_time"="-1"
"scan_home_time"="-1"
"scan_passes"="-1"
"BadFramePreempt"="0"
"Interference_Mode"="-1"
"ccx_rm"="1"
"ccx_rm_limit"="300"
"EFCEnable"="0"
"WME"="-1"
"PowerSaveMode"="2"
"BusType"="5"
"ComponentId"="pci\\ven_14e4&dev_432b"
"*PriorityVLANTag"="0"
"11HNetworks"="1"
"11NPreamble"="0"
"Afterburner"="1"
"antdiv"="-1"
"ApCompatMode"="1"
"AssocRoamPref"="1"
"band"="0"
"BandPref"="0"
"BandwidthCap"="2"
"BtAmp"="1"
"BTCoexist"="3"
"Chanspec"="11"
"frag"="2346"
"FrameBursting"="1"
"IBSSGProtection"="2"
"IBSSMode"="0"
"LOM"="0"
"MixedCell"="0"
"PLCPHeader"="0"
"PwrOut"="100"
"Rate"="0"
"RateA"="0"
"RoamDelta"="3"
"RoamTrigger"="3"
"rts"="2347"
"ShortGI"="-1"
"WakeUpCapabilities"="3"
"InfPath"="oem52.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,76,00,77,00,69,00,66,00,69,00,62,00,75,\
  00,73,00,2e,00,69,00,6e,00,66,00,00,00,00,00
"InfSection"="BCM43XNM_NT61"
"InfSectionExt"=".NTAMD64"
"ProviderName"="Broadcom"
"DriverDateData"=hex:00,80,7a,3c,78,ed,ca,01
"DriverDate"="5-7-2010"
"DriverVersion"="5.60.350.11"
"MatchingDeviceId"="pci\\ven_14e4&dev_432b"
"DriverDesc"="Broadcom 802.11n Network Adapter"
"PnPCapabilities"=dword:00000010
"NICPowerState"=dword:0000000f
"Intolerant"="1"
"MPC"="1"
"NetworkAddress"="BC0F9A7C281D"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Linkage]
"RootDevice"=hex(7):7b,00,37,00,38,00,35,00,37,00,44,00,38,00,42,00,45,00,2d,\
  00,36,00,31,00,42,00,39,00,2d,00,34,00,43,00,30,00,41,00,2d,00,38,00,36,00,\
  39,00,39,00,2d,00,30,00,36,00,32,00,33,00,43,00,46,00,43,00,44,00,46,00,39,\
  00,42,00,37,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,37,00,38,\
  00,35,00,37,00,44,00,38,00,42,00,45,00,2d,00,36,00,31,00,42,00,39,00,2d,00,\
  34,00,43,00,30,00,41,00,2d,00,38,00,36,00,39,00,39,00,2d,00,30,00,36,00,32,\
  00,33,00,43,00,46,00,43,00,44,00,46,00,39,00,42,00,37,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,37,00,38,00,35,00,37,00,44,00,38,00,42,00,45,00,2d,\
  00,36,00,31,00,42,00,39,00,2d,00,34,00,43,00,30,00,41,00,2d,00,38,00,36,00,\
  39,00,39,00,2d,00,30,00,36,00,32,00,33,00,43,00,46,00,43,00,44,00,46,00,39,\
  00,42,00,37,00,7d,00,2d,00,7b,00,35,00,43,00,42,00,46,00,38,00,31,00,42,00,\
  46,00,2d,00,35,00,30,00,35,00,35,00,2d,00,34,00,37,00,43,00,44,00,2d,00,39,\
  00,30,00,35,00,35,00,2d,00,41,00,37,00,36,00,42,00,32,00,42,00,34,00,45,00,\
  33,00,36,00,39,00,38,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,37,\
  00,38,00,35,00,37,00,44,00,38,00,42,00,45,00,2d,00,36,00,31,00,42,00,39,00,\
  2d,00,34,00,43,00,30,00,41,00,2d,00,38,00,36,00,39,00,39,00,2d,00,30,00,36,\
  00,32,00,33,00,43,00,46,00,43,00,44,00,46,00,39,00,42,00,37,00,7d,00,2d,00,\
  7b,00,45,00,34,00,37,00,35,00,43,00,46,00,39,00,41,00,2d,00,36,00,30,00,43,\
  00,44,00,2d,00,34,00,34,00,33,00,39,00,2d,00,41,00,37,00,35,00,46,00,2d,00,\
  30,00,30,00,37,00,39,00,43,00,45,00,30,00,45,00,31,00,38,00,41,00,31,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,37,00,38,00,35,00,37,00,44,00,\
  38,00,42,00,45,00,2d,00,36,00,31,00,42,00,39,00,2d,00,34,00,43,00,30,00,41,\
  00,2d,00,38,00,36,00,39,00,39,00,2d,00,30,00,36,00,32,00,33,00,43,00,46,00,\
  43,00,44,00,46,00,39,00,42,00,37,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,\
  00,44,00,36,00,35,00,39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,\
  36,00,35,00,2d,00,38,00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,\
  00,45,00,44,00,36,00,30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,\
  30,00,00,00,7b,00,37,00,38,00,35,00,37,00,44,00,38,00,42,00,45,00,2d,00,36,\
  00,31,00,42,00,39,00,2d,00,34,00,43,00,30,00,41,00,2d,00,38,00,36,00,39,00,\
  39,00,2d,00,30,00,36,00,32,00,33,00,43,00,46,00,43,00,44,00,46,00,39,00,42,\
  00,37,00,7d,00,2d,00,7b,00,42,00,37,00,30,00,44,00,36,00,34,00,36,00,30,00,\
  2d,00,33,00,36,00,33,00,35,00,2d,00,34,00,44,00,34,00,32,00,2d,00,42,00,38,\
  00,36,00,36,00,2d,00,42,00,38,00,41,00,42,00,31,00,41,00,32,00,34,00,34,00,\
  35,00,34,00,43,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi]
"HelpText"="The Broadcom 802.11 Network Adapter provides wireless local area networking."
"Service"="BCM43XX"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\IHVExtensions]
"ExtensibilityDLL"="%SystemRoot%\\System32\\bcmihvsrv64.dll"
"UIExtensibilityCLSID"="{AAA6DEE9-31B9-4f18-AB39-82EF9B06EB73}"
"AdapterOUI"=dword:00001018

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="ethernet,wlan,vwifi"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\*PriorityVLANTag]
"ParamDesc"="Priority & VLAN"
"type"="enum"
"default"="0"
"optional"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\*PriorityVLANTag\enum]
"0"="Priority & VLAN Disabled"
"1"="Priority Enabled"
"2"="VLAN Enabled"
"3"="Priority & VLAN Enabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\11HNetworks]
"ParamDesc"="802.11h+d"
"type"="enum"
"default"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\11HNetworks\enum]
"1"="Loose 11h"
"2"="Strict 11h"
"4"="Loose 11h+d"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\11NPreamble]
"ParamDesc"="802.11n Preamble"
"type"="enum"
"default"="-1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\11NPreamble\enum]
"-1"="Auto"
"0"="Mixed Mode"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\Afterburner]
"ParamDesc"="Afterburner"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\Afterburner\enum]
"0"="Disabled"
"1"="Enabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\antdiv]
"ParamDesc"="Antenna Diversity"
"type"="enum"
"default"="-1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\antdiv\enum]
"-1"="Auto"
"0"="Main"
"1"="Aux"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\ApCompatMode]
"ParamDesc"="AP Compatibility Mode"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\ApCompatMode\enum]
"1"="Broader Compatibility"
"0"="Higher Performance"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\AssocRoamPref]
"ParamDesc"="Association Roam Preference"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\AssocRoamPref\enum]
"0"="Disabled"
"1"="Enabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\band]
"ParamDesc"="Disable Bands"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\band\enum]
"0"="None"
"1"="Disable 802.11g/b"
"2"="Disable 802.11a"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\BandPref]
"ParamDesc"="Band Preference"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\BandPref\enum]
"0"="None"
"1"="Prefer 802.11a"
"2"="Prefer 802.11g/b"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\BandwidthCap]
"ParamDesc"="Bandwidth Capability"
"type"="enum"
"default"="2"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\BandwidthCap\enum]
"0"="11a/b/g:20MHz"
"1"="11a/b/g:20/40MHz"
"2"="11a:20/40;11bg:20MHz"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\BtAmp]
"ParamDesc"="BT-AMP"
"type"="enum"
"default"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\BtAmp\enum]
"0"="Disabled"
"1"="Enabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\BTCoexist]
"ParamDesc"="Bluetooth Collaboration"
"type"="enum"
"default"="3"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\BTCoexist\enum]
"0"="Disable"
"1"="Enable"
"3"="Auto"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\Chanspec]
"ParamDesc"="WZC IBSS Channel Number"
"type"="enum"
"default"="11"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\Chanspec\enum]
"36"=" 36(20MHz)"
"40"=" 40(20MHz)"
"44"=" 44(20MHz)"
"48"=" 48(20MHz)"
"52"=" 52(20MHz)"
"56"=" 56(20MHz)"
"60"=" 60(20MHz)"
"64"=" 64(20MHz)"
"100"="100(20MHz)"
"104"="104(20MHz)"
"108"="108(20MHz)"
"112"="112(20MHz)"
"116"="116(20MHz)"
"120"="120(20MHz)"
"124"="124(20MHz)"
"128"="128(20MHz)"
"132"="132(20MHz)"
"136"="136(20MHz)"
"140"="140(20MHz)"
"149"="149(20MHz)"
"153"="153(20MHz)"
"157"="157(20MHz)"
"161"="161(20MHz)"
"165"="165(20MHz)"
"36al"=" 36(40MHz-L)"
"44al"=" 44(40MHz-L)"
"52al"=" 52(40MHz-L)"
"60al"=" 60(40MHz-L)"
"100al"="100(40MHz-L)"
"108al"="108(40MHz-L)"
"116al"="116(40MHz-L)"
"124al"="124(40MHz-L)"
"132al"="132(40MHz-L)"
"149al"="149(40MHz-L)"
"157al"="157(40MHz-L)"
"1"="  1(20MHz)"
"2"="  2(20MHz)"
"3"="  3(20MHz)"
"4"="  4(20MHz)"
"5"="  5(20MHz)"
"6"="  6(20MHz)"
"7"="  7(20MHz)"
"8"="  8(20MHz)"
"9"="  9(20MHz)"
"10"=" 10(20MHz)"
"11"=" 11(20MHz)"
"12"=" 12(20MHz)"
"13"=" 13(20MHz)"
"14"=" 14(20MHz)"
"1bl"="  1(40MHz-L)"
"6bl"="  6(40MHz-L)"
"6bu"="  6(40MHz-U)"
"11bu"=" 11(40MHz-U)"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\frag]
"ParamDesc"="Fragmentation Threshold"
"type"="dword"
"min"="256"
"max"="2346"
"default"="2346"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\FrameBursting]
"ParamDesc"="XPress (TM) Technology"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\FrameBursting\enum]
"0"="Disabled"
"1"="Enabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\IBSSGProtection]
"ParamDesc"="IBSS 54g(tm) Protection Mode"
"type"="enum"
"default"="2"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\IBSSGProtection\enum]
"0"="Disabled"
"2"="Auto"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\IBSSMode]
"ParamDesc"="IBSS Mode"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\IBSSMode\enum]
"0"="802.11a/b Only"
"2"="802.11a/b/g Auto"
"4"="802.11a/b/g Performance"
"5"="802.11a/b/g/n Auto"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\Intolerant]
"ParamDesc"="40MHz Intolerant"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\Intolerant\enum]
"0"="Disabled"
"1"="Enabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\LOM]
"ParamDesc"="Disable Upon Wired Connect"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\LOM\enum]
"0"="Disabled"
"1"="Enabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\MixedCell]
"ParamDesc"="Mixed Cell Support"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\MixedCell\enum]
"0"="Disabled"
"1"="Enabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\MPC]
"ParamDesc"="Minimum Power Consumption"
"type"="enum"
"default"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\MPC\enum]
"0"="Disabled"
"1"="Enabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\NetworkAddress]
"ParamDesc"="Locally Administered MAC Address"
"type"="edit"
"LimitText"="12"
"UpperCase"="1"
"default"=""
"optional"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\PLCPHeader]
"ParamDesc"="BSS PLCP Header"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\PLCPHeader\enum]
"-1"="Long"
"0"="Auto (Short/Long)"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\PwrOut]
"ParamDesc"="Power Output"
"type"="enum"
"default"="100"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\PwrOut\enum]
"100"="100%"
"75"="75%"
"50"="50%"
"25"="25%"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\Rate]
"ParamDesc"="Rate (802.11b/g)"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\Rate\enum]
"0"="Best Rate"
"2"=" 1"
"4"=" 2"
"11"=" 5.5"
"12"=" 6"
"18"=" 9"
"22"="11"
"24"="12"
"36"="18"
"48"="24"
"72"="36"
"96"="48"
"108"="54"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\RateA]
"ParamDesc"="Rate (802.11a)"
"type"="enum"
"default"="0"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\RateA\enum]
"0"="Best Rate"
"12"=" 6"
"18"=" 9"
"24"="12"
"36"="18"
"48"="24"
"72"="36"
"96"="48"
"108"="54"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\RoamDelta]
"ParamDesc"="Roam Tendency"
"type"="enum"
"default"="3"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\RoamDelta\enum]
"0"="Aggressive"
"1"="Moderate"
"2"="Conservative"
"3"="Auto"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\RoamTrigger]
"ParamDesc"="Roaming Decision"
"type"="enum"
"default"="3"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\RoamTrigger\enum]
"3"="Auto"
"1"="Optimize Bandwidth"
"0"="Default"
"2"="Optimize Distance"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\rts]
"ParamDesc"="RTS Threshold"
"type"="dword"
"min"="0"
"max"="2347"
"default"="2347"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\ShortGI]
"ParamDesc"="Short GI"
"type"="enum"
"default"="-1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\ShortGI\enum]
"-1"="Auto"
"0"="Disabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\WakeUpCapabilities]
"ParamDesc"="Wake-Up Mode"
"type"="enum"
"default"="3"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\WakeUpCapabilities\enum]
"0"="None"
"1"="Magic Packet"
"2"="Wake Up Frame"
"28"="LossOfLink"
"3"="Magic & WakeUp Frame"
"29"="MagicPkt & LinkLoss"
"30"="WakeUpPkt & LinkLoss"
"31"="All"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\WME]
"ParamDesc"="WMM"
"type"="enum"
"default"="-1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0013\Ndi\params\WME\enum]
"-1"="Auto"
"1"="Enabled"
"0"="Disabled"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0014]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{600EC8A1-C676-4D79-918F-FE130EC9F336}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000009
"*MediaType"=dword:0000000f
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000005
"DeviceInstanceID"="ROOT\\*ISATAP\\0001"
"InstallTimeStamp"=hex:e6,07,02,00,03,00,02,00,17,00,35,00,33,00,16,01
"Type"="13"
"ComponentId"="*isatap"
"NetworkAddress"=""
"InfPath"="nettun.inf"
"InfSection"="ISATAP.ndi"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="*isatap"
"DriverDesc"="Microsoft ISATAP Adapter"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0014\Linkage]
"RootDevice"=hex(7):7b,00,36,00,30,00,30,00,45,00,43,00,38,00,41,00,31,00,2d,\
  00,43,00,36,00,37,00,36,00,2d,00,34,00,44,00,37,00,39,00,2d,00,39,00,31,00,\
  38,00,46,00,2d,00,46,00,45,00,31,00,33,00,30,00,45,00,43,00,39,00,46,00,33,\
  00,33,00,36,00,7d,00,00,00,00,00
"UpperBind"=hex(7):54,00,43,00,50,00,49,00,50,00,36,00,54,00,55,00,4e,00,4e,00,\
  45,00,4c,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,36,00,30,\
  00,30,00,45,00,43,00,38,00,41,00,31,00,2d,00,43,00,36,00,37,00,36,00,2d,00,\
  34,00,44,00,37,00,39,00,2d,00,39,00,31,00,38,00,46,00,2d,00,46,00,45,00,31,\
  00,33,00,30,00,45,00,43,00,39,00,46,00,33,00,33,00,36,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0014\Ndi]
"Service"="tunnel"
"HelpText"="Microsoft ISATAP Adapter Driver"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0014\Ndi\Interfaces]
"LowerRange"="tunnel"
"UpperRange"="ndis5_ip6_tunnel"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0014\Ndi\Params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0014\Ndi\Params\NetworkAddress]
"ParamDesc"="Network Address"
"Default"=""
"Type"="text"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0014\Ndi\Params\Type]
"ParamDesc"="Type"
"Default"=""
"Type"="int"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0015]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{A6DD7F1D-56D6-4CA9-81FB-BC435B50F593}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000084
"NetLuidIndex"=dword:0000000a
"DeviceInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&1B9D08D4&0&0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,03,00,18,00,3a,00,42,03
"BusType"="15"
"ComponentId"="usb\\class_e0&subclass_01&prot_03"
"BusNumber"="0"
"InfPath"="wceisvista.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,72,00,6e,00,64,00,69,00,73,00,2e,00,69,\
  00,6e,00,66,00,00,00,00,00
"InfSection"="RNDIS.NT.5.1"
"ProviderName"="Microsoft Corporation"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="usb\\class_e0&subclass_01&prot_03"
"DriverDesc"="Remote NDIS based Internet Sharing Device"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0015\Linkage]
"RootDevice"=hex(7):7b,00,41,00,36,00,44,00,44,00,37,00,46,00,31,00,44,00,2d,\
  00,35,00,36,00,44,00,36,00,2d,00,34,00,43,00,41,00,39,00,2d,00,38,00,31,00,\
  46,00,42,00,2d,00,42,00,43,00,34,00,33,00,35,00,42,00,35,00,30,00,46,00,35,\
  00,39,00,33,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,41,00,36,\
  00,44,00,44,00,37,00,46,00,31,00,44,00,2d,00,35,00,36,00,44,00,36,00,2d,00,\
  34,00,43,00,41,00,39,00,2d,00,38,00,31,00,46,00,42,00,2d,00,42,00,43,00,34,\
  00,33,00,35,00,42,00,35,00,30,00,46,00,35,00,39,00,33,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,41,00,36,00,44,00,44,00,37,00,46,00,31,00,44,00,2d,\
  00,35,00,36,00,44,00,36,00,2d,00,34,00,43,00,41,00,39,00,2d,00,38,00,31,00,\
  46,00,42,00,2d,00,42,00,43,00,34,00,33,00,35,00,42,00,35,00,30,00,46,00,35,\
  00,39,00,33,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,41,\
  00,36,00,44,00,44,00,37,00,46,00,31,00,44,00,2d,00,35,00,36,00,44,00,36,00,\
  2d,00,34,00,43,00,41,00,39,00,2d,00,38,00,31,00,46,00,42,00,2d,00,42,00,43,\
  00,34,00,33,00,35,00,42,00,35,00,30,00,46,00,35,00,39,00,33,00,7d,00,2d,00,\
  7b,00,42,00,37,00,30,00,44,00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,\
  00,35,00,2d,00,34,00,44,00,34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,\
  42,00,38,00,41,00,42,00,31,00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0015\Ndi]
"Service"="usb_rndisx"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0015\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0015\Ndi\params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0015\Ndi\params\NetworkAddress]
"ParamDesc"="Network Address"
"type"="edit"
"LimitText"="12"
"UpperCase"="1"
"default"=" "
"optional"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0016]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{872DD157-C7A3-400E-8FD1-539EB0951715}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000009
"*MediaType"=dword:0000000f
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000006
"DeviceInstanceID"="ROOT\\*ISATAP\\0002"
"InstallTimeStamp"=hex:e6,07,01,00,00,00,1e,00,17,00,02,00,16,00,1d,00
"Type"="13"
"ComponentId"="*isatap"
"NetworkAddress"=""
"InfPath"="nettun.inf"
"InfSection"="ISATAP.ndi"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="*isatap"
"DriverDesc"="Microsoft ISATAP Adapter"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0016\Linkage]
"RootDevice"=hex(7):7b,00,38,00,37,00,32,00,44,00,44,00,31,00,35,00,37,00,2d,\
  00,43,00,37,00,41,00,33,00,2d,00,34,00,30,00,30,00,45,00,2d,00,38,00,46,00,\
  44,00,31,00,2d,00,35,00,33,00,39,00,45,00,42,00,30,00,39,00,35,00,31,00,37,\
  00,31,00,35,00,7d,00,00,00,00,00
"UpperBind"=hex(7):54,00,43,00,50,00,49,00,50,00,36,00,54,00,55,00,4e,00,4e,00,\
  45,00,4c,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,38,00,37,\
  00,32,00,44,00,44,00,31,00,35,00,37,00,2d,00,43,00,37,00,41,00,33,00,2d,00,\
  34,00,30,00,30,00,45,00,2d,00,38,00,46,00,44,00,31,00,2d,00,35,00,33,00,39,\
  00,45,00,42,00,30,00,39,00,35,00,31,00,37,00,31,00,35,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0016\Ndi]
"Service"="tunnel"
"HelpText"="Microsoft ISATAP Adapter Driver"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0016\Ndi\Interfaces]
"LowerRange"="tunnel"
"UpperRange"="ndis5_ip6_tunnel"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0016\Ndi\Params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0016\Ndi\Params\NetworkAddress]
"ParamDesc"="Network Address"
"Default"=""
"Type"="text"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0016\Ndi\Params\Type]
"ParamDesc"="Type"
"Default"=""
"Type"="int"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0017]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{FE7CD5B7-1FDB-488D-B643-0903109D7D88}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000084
"NetLuidIndex"=dword:0000000b
"DeviceInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&2FA2EFD3&1&0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,11,00,1c,00,12,00,9d,01
"BusType"="15"
"ComponentId"="usb\\class_e0&subclass_01&prot_03"
"BusNumber"="0"
"InfPath"="wceisvista.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,72,00,6e,00,64,00,69,00,73,00,2e,00,69,\
  00,6e,00,66,00,00,00,00,00
"InfSection"="RNDIS.NT.5.1"
"ProviderName"="Microsoft Corporation"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="usb\\class_e0&subclass_01&prot_03"
"DriverDesc"="Remote NDIS based Internet Sharing Device"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0017\Linkage]
"RootDevice"=hex(7):7b,00,46,00,45,00,37,00,43,00,44,00,35,00,42,00,37,00,2d,\
  00,31,00,46,00,44,00,42,00,2d,00,34,00,38,00,38,00,44,00,2d,00,42,00,36,00,\
  34,00,33,00,2d,00,30,00,39,00,30,00,33,00,31,00,30,00,39,00,44,00,37,00,44,\
  00,38,00,38,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,46,00,45,\
  00,37,00,43,00,44,00,35,00,42,00,37,00,2d,00,31,00,46,00,44,00,42,00,2d,00,\
  34,00,38,00,38,00,44,00,2d,00,42,00,36,00,34,00,33,00,2d,00,30,00,39,00,30,\
  00,33,00,31,00,30,00,39,00,44,00,37,00,44,00,38,00,38,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,46,00,45,00,37,00,43,00,44,00,35,00,42,00,37,00,2d,\
  00,31,00,46,00,44,00,42,00,2d,00,34,00,38,00,38,00,44,00,2d,00,42,00,36,00,\
  34,00,33,00,2d,00,30,00,39,00,30,00,33,00,31,00,30,00,39,00,44,00,37,00,44,\
  00,38,00,38,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,46,\
  00,45,00,37,00,43,00,44,00,35,00,42,00,37,00,2d,00,31,00,46,00,44,00,42,00,\
  2d,00,34,00,38,00,38,00,44,00,2d,00,42,00,36,00,34,00,33,00,2d,00,30,00,39,\
  00,30,00,33,00,31,00,30,00,39,00,44,00,37,00,44,00,38,00,38,00,7d,00,2d,00,\
  7b,00,42,00,37,00,30,00,44,00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,\
  00,35,00,2d,00,34,00,44,00,34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,\
  42,00,38,00,41,00,42,00,31,00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0017\Ndi]
"Service"="usb_rndisx"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0017\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0017\Ndi\params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0017\Ndi\params\NetworkAddress]
"ParamDesc"="Network Address"
"type"="edit"
"LimitText"="12"
"UpperCase"="1"
"default"=" "
"optional"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0018]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{7EB48003-6E25-4C38-B42C-A7CA5B6E1199}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000084
"NetLuidIndex"=dword:0000000f
"DeviceInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&CA14D76&2&0000"
"InstallTimeStamp"=hex:e6,07,01,00,04,00,1b,00,15,00,1b,00,04,00,1b,01
"BusType"="15"
"ComponentId"="usb\\class_e0&subclass_01&prot_03"
"BusNumber"="0"
"InfPath"="wceisvista.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,72,00,6e,00,64,00,69,00,73,00,2e,00,69,\
  00,6e,00,66,00,00,00,00,00
"InfSection"="RNDIS.NT.5.1"
"ProviderName"="Microsoft Corporation"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="usb\\class_e0&subclass_01&prot_03"
"DriverDesc"="Remote NDIS based Internet Sharing Device"
"PortAuthSendControlState"=dword:00000002
"PortAuthReceiveControlState"=dword:00000002
"PortAuthSendAuthorizationState"=dword:00000001
"PortAuthReceiveAuthorizationState"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0018\Linkage]
"RootDevice"=hex(7):7b,00,37,00,45,00,42,00,34,00,38,00,30,00,30,00,33,00,2d,\
  00,36,00,45,00,32,00,35,00,2d,00,34,00,43,00,33,00,38,00,2d,00,42,00,34,00,\
  32,00,43,00,2d,00,41,00,37,00,43,00,41,00,35,00,42,00,36,00,45,00,31,00,31,\
  00,39,00,39,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,37,00,45,\
  00,42,00,34,00,38,00,30,00,30,00,33,00,2d,00,36,00,45,00,32,00,35,00,2d,00,\
  34,00,43,00,33,00,38,00,2d,00,42,00,34,00,32,00,43,00,2d,00,41,00,37,00,43,\
  00,41,00,35,00,42,00,36,00,45,00,31,00,31,00,39,00,39,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,37,00,45,00,42,00,34,00,38,00,30,00,30,00,33,00,2d,\
  00,36,00,45,00,32,00,35,00,2d,00,34,00,43,00,33,00,38,00,2d,00,42,00,34,00,\
  32,00,43,00,2d,00,41,00,37,00,43,00,41,00,35,00,42,00,36,00,45,00,31,00,31,\
  00,39,00,39,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,37,\
  00,45,00,42,00,34,00,38,00,30,00,30,00,33,00,2d,00,36,00,45,00,32,00,35,00,\
  2d,00,34,00,43,00,33,00,38,00,2d,00,42,00,34,00,32,00,43,00,2d,00,41,00,37,\
  00,43,00,41,00,35,00,42,00,36,00,45,00,31,00,31,00,39,00,39,00,7d,00,2d,00,\
  7b,00,42,00,37,00,30,00,44,00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,\
  00,35,00,2d,00,34,00,44,00,34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,\
  42,00,38,00,41,00,42,00,31,00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0018\Ndi]
"Service"="usb_rndisx"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0018\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0018\Ndi\params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0018\Ndi\params\NetworkAddress]
"ParamDesc"="Network Address"
"type"="edit"
"LimitText"="12"
"UpperCase"="1"
"default"=" "
"optional"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0019]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{354168A7-A09C-4934-895B-F89FA3C0BBD4}"
"*IfType"=dword:00000047
"Characteristics"=dword:00000001
"*MediaType"=dword:00000010
"*PhysicalMediaType"=dword:00000009
"NetLuidIndex"=dword:00000005
"DeviceInstanceID"="{5D624F94-8850-40C3-A3FA-A4FD2080BAF3}\\VWIFIMP\\5&121F6484&0&01"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,10,00,1c,00,11,00,b0,01
"PortAuthSendControlState"=dword:00000002
"PortAuthReceiveControlState"=dword:00000002
"PortAuthSendAuthorizationState"=dword:00000001
"PortAuthReceiveAuthorizationState"=dword:00000001
"BusNumber"="0"
"ComponentId"="{5d624f94-8850-40c3-a3fa-a4fd2080baf3}\\vwifimp"
"InfPath"="netvwifimp.inf"
"InfSection"="vwifimp.ndi"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="{5d624f94-8850-40c3-a3fa-a4fd2080baf3}\\vwifimp"
"DriverDesc"="Microsoft Virtual WiFi Miniport Adapter"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0019\Linkage]
"RootDevice"=hex(7):7b,00,33,00,35,00,34,00,31,00,36,00,38,00,41,00,37,00,2d,\
  00,41,00,30,00,39,00,43,00,2d,00,34,00,39,00,33,00,34,00,2d,00,38,00,39,00,\
  35,00,42,00,2d,00,46,00,38,00,39,00,46,00,41,00,33,00,43,00,30,00,42,00,42,\
  00,44,00,34,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,33,00,35,\
  00,34,00,31,00,36,00,38,00,41,00,37,00,2d,00,41,00,30,00,39,00,43,00,2d,00,\
  34,00,39,00,33,00,34,00,2d,00,38,00,39,00,35,00,42,00,2d,00,46,00,38,00,39,\
  00,46,00,41,00,33,00,43,00,30,00,42,00,42,00,44,00,34,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,33,00,35,00,34,00,31,00,36,00,38,00,41,00,37,00,2d,\
  00,41,00,30,00,39,00,43,00,2d,00,34,00,39,00,33,00,34,00,2d,00,38,00,39,00,\
  35,00,42,00,2d,00,46,00,38,00,39,00,46,00,41,00,33,00,43,00,30,00,42,00,42,\
  00,44,00,34,00,7d,00,2d,00,7b,00,45,00,34,00,37,00,35,00,43,00,46,00,39,00,\
  41,00,2d,00,36,00,30,00,43,00,44,00,2d,00,34,00,34,00,33,00,39,00,2d,00,41,\
  00,37,00,35,00,46,00,2d,00,30,00,30,00,37,00,39,00,43,00,45,00,30,00,45,00,\
  31,00,38,00,41,00,31,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,33,\
  00,35,00,34,00,31,00,36,00,38,00,41,00,37,00,2d,00,41,00,30,00,39,00,43,00,\
  2d,00,34,00,39,00,33,00,34,00,2d,00,38,00,39,00,35,00,42,00,2d,00,46,00,38,\
  00,39,00,46,00,41,00,33,00,43,00,30,00,42,00,42,00,44,00,34,00,7d,00,2d,00,\
  7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,39,00,2d,00,37,00,44,00,41,\
  00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,00,45,00,34,00,31,00,2d,00,\
  42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,30,00,35,00,34,00,32,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,33,00,35,00,34,00,31,00,36,00,\
  38,00,41,00,37,00,2d,00,41,00,30,00,39,00,43,00,2d,00,34,00,39,00,33,00,34,\
  00,2d,00,38,00,39,00,35,00,42,00,2d,00,46,00,38,00,39,00,46,00,41,00,33,00,\
  43,00,30,00,42,00,42,00,44,00,34,00,7d,00,2d,00,7b,00,42,00,37,00,30,00,44,\
  00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,00,35,00,2d,00,34,00,44,00,\
  34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,42,00,38,00,41,00,42,00,31,\
  00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,00,2d,00,30,00,30,00,30,00,\
  30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0019\Ndi]
"Service"="vwifimp"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0019\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="wlan,ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0020]
"NewDeviceInstall"=dword:00000000
"NetCfgInstanceId"="{D77366DC-8430-4300-B82F-8E84A815186C}"
"*IfType"=dword:00000047
"Characteristics"=dword:00000001
"*MediaType"=dword:00000010
"*PhysicalMediaType"=dword:00000009
"NetLuidIndex"=dword:00000006
"DeviceInstanceID"="{5D624F94-8850-40C3-A3FA-A4FD2080BAF3}\\VWIFIMP\\5&121F6484&1&02"
"InstallTimeStamp"=hex:e6,07,02,00,03,00,02,00,17,00,03,00,29,00,e1,03
"PortAuthSendControlState"=dword:00000002
"PortAuthReceiveControlState"=dword:00000002
"PortAuthSendAuthorizationState"=dword:00000001
"PortAuthReceiveAuthorizationState"=dword:00000001
"BusNumber"="0"
"ComponentId"="{5d624f94-8850-40c3-a3fa-a4fd2080baf3}\\vwifimp"
"InfPath"="oem53.inf"
"InfSection"="vwifimp.ndi"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="{5d624f94-8850-40c3-a3fa-a4fd2080baf3}\\vwifimp"
"DriverDesc"="Microsoft Virtual WiFi Miniport Adapter"
"PnPCapabilities"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0020\Linkage]
"RootDevice"=hex(7):7b,00,44,00,37,00,37,00,33,00,36,00,36,00,44,00,43,00,2d,\
  00,38,00,34,00,33,00,30,00,2d,00,34,00,33,00,30,00,30,00,2d,00,42,00,38,00,\
  32,00,46,00,2d,00,38,00,45,00,38,00,34,00,41,00,38,00,31,00,35,00,31,00,38,\
  00,36,00,43,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,44,00,37,\
  00,37,00,33,00,36,00,36,00,44,00,43,00,2d,00,38,00,34,00,33,00,30,00,2d,00,\
  34,00,33,00,30,00,30,00,2d,00,42,00,38,00,32,00,46,00,2d,00,38,00,45,00,38,\
  00,34,00,41,00,38,00,31,00,35,00,31,00,38,00,36,00,43,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,44,00,37,00,37,00,33,00,36,00,36,00,44,00,43,00,2d,\
  00,38,00,34,00,33,00,30,00,2d,00,34,00,33,00,30,00,30,00,2d,00,42,00,38,00,\
  32,00,46,00,2d,00,38,00,45,00,38,00,34,00,41,00,38,00,31,00,35,00,31,00,38,\
  00,36,00,43,00,7d,00,2d,00,7b,00,45,00,34,00,37,00,35,00,43,00,46,00,39,00,\
  41,00,2d,00,36,00,30,00,43,00,44,00,2d,00,34,00,34,00,33,00,39,00,2d,00,41,\
  00,37,00,35,00,46,00,2d,00,30,00,30,00,37,00,39,00,43,00,45,00,30,00,45,00,\
  31,00,38,00,41,00,31,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,44,\
  00,37,00,37,00,33,00,36,00,36,00,44,00,43,00,2d,00,38,00,34,00,33,00,30,00,\
  2d,00,34,00,33,00,30,00,30,00,2d,00,42,00,38,00,32,00,46,00,2d,00,38,00,45,\
  00,38,00,34,00,41,00,38,00,31,00,35,00,31,00,38,00,36,00,43,00,7d,00,2d,00,\
  7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,39,00,2d,00,37,00,44,00,41,\
  00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,00,45,00,34,00,31,00,2d,00,\
  42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,30,00,35,00,34,00,32,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,44,00,37,00,37,00,33,00,36,00,\
  36,00,44,00,43,00,2d,00,38,00,34,00,33,00,30,00,2d,00,34,00,33,00,30,00,30,\
  00,2d,00,42,00,38,00,32,00,46,00,2d,00,38,00,45,00,38,00,34,00,41,00,38,00,\
  31,00,35,00,31,00,38,00,36,00,43,00,7d,00,2d,00,7b,00,42,00,37,00,30,00,44,\
  00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,00,35,00,2d,00,34,00,44,00,\
  34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,42,00,38,00,41,00,42,00,31,\
  00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,00,2d,00,30,00,30,00,30,00,\
  30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0020\Ndi]
"Service"="vwifimp"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0020\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="wlan,ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0021]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{65BB6BD6-6CDB-43A5-B450-64A2287C70B1}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000084
"NetLuidIndex"=dword:0000000c
"DeviceInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&2FA2EFD3&2&0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,12,00,19,00,15,00,99,02
"BusType"="15"
"ComponentId"="usb\\class_e0&subclass_01&prot_03"
"BusNumber"="0"
"InfPath"="wceisvista.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,72,00,6e,00,64,00,69,00,73,00,2e,00,69,\
  00,6e,00,66,00,00,00,00,00
"InfSection"="RNDIS.NT.5.1"
"ProviderName"="Microsoft Corporation"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="usb\\class_e0&subclass_01&prot_03"
"DriverDesc"="Remote NDIS based Internet Sharing Device"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0021\Linkage]
"RootDevice"=hex(7):7b,00,36,00,35,00,42,00,42,00,36,00,42,00,44,00,36,00,2d,\
  00,36,00,43,00,44,00,42,00,2d,00,34,00,33,00,41,00,35,00,2d,00,42,00,34,00,\
  35,00,30,00,2d,00,36,00,34,00,41,00,32,00,32,00,38,00,37,00,43,00,37,00,30,\
  00,42,00,31,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,36,00,35,\
  00,42,00,42,00,36,00,42,00,44,00,36,00,2d,00,36,00,43,00,44,00,42,00,2d,00,\
  34,00,33,00,41,00,35,00,2d,00,42,00,34,00,35,00,30,00,2d,00,36,00,34,00,41,\
  00,32,00,32,00,38,00,37,00,43,00,37,00,30,00,42,00,31,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,36,00,35,00,42,00,42,00,36,00,42,00,44,00,36,00,2d,\
  00,36,00,43,00,44,00,42,00,2d,00,34,00,33,00,41,00,35,00,2d,00,42,00,34,00,\
  35,00,30,00,2d,00,36,00,34,00,41,00,32,00,32,00,38,00,37,00,43,00,37,00,30,\
  00,42,00,31,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,36,\
  00,35,00,42,00,42,00,36,00,42,00,44,00,36,00,2d,00,36,00,43,00,44,00,42,00,\
  2d,00,34,00,33,00,41,00,35,00,2d,00,42,00,34,00,35,00,30,00,2d,00,36,00,34,\
  00,41,00,32,00,32,00,38,00,37,00,43,00,37,00,30,00,42,00,31,00,7d,00,2d,00,\
  7b,00,42,00,37,00,30,00,44,00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,\
  00,35,00,2d,00,34,00,44,00,34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,\
  42,00,38,00,41,00,42,00,31,00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0021\Ndi]
"Service"="usb_rndisx"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0021\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0021\Ndi\params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0021\Ndi\params\NetworkAddress]
"ParamDesc"="Network Address"
"type"="edit"
"LimitText"="12"
"UpperCase"="1"
"default"=" "
"optional"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0022]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{D5D28BAA-734F-4885-8C89-F3EAEDFA91F6}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000084
"NetLuidIndex"=dword:00000002
"DeviceInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&2FA2EFD3&3&0000"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,13,00,04,00,09,00,38,02
"BusType"="15"
"ComponentId"="usb\\class_e0&subclass_01&prot_03"
"BusNumber"="0"
"InfPath"="wceisvista.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,72,00,6e,00,64,00,69,00,73,00,2e,00,69,\
  00,6e,00,66,00,00,00,00,00
"InfSection"="RNDIS.NT.5.1"
"ProviderName"="Microsoft Corporation"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="usb\\class_e0&subclass_01&prot_03"
"DriverDesc"="Remote NDIS based Internet Sharing Device"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0022\Linkage]
"RootDevice"=hex(7):7b,00,44,00,35,00,44,00,32,00,38,00,42,00,41,00,41,00,2d,\
  00,37,00,33,00,34,00,46,00,2d,00,34,00,38,00,38,00,35,00,2d,00,38,00,43,00,\
  38,00,39,00,2d,00,46,00,33,00,45,00,41,00,45,00,44,00,46,00,41,00,39,00,31,\
  00,46,00,36,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,44,00,35,\
  00,44,00,32,00,38,00,42,00,41,00,41,00,2d,00,37,00,33,00,34,00,46,00,2d,00,\
  34,00,38,00,38,00,35,00,2d,00,38,00,43,00,38,00,39,00,2d,00,46,00,33,00,45,\
  00,41,00,45,00,44,00,46,00,41,00,39,00,31,00,46,00,36,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,44,00,35,00,44,00,32,00,38,00,42,00,41,00,41,00,2d,\
  00,37,00,33,00,34,00,46,00,2d,00,34,00,38,00,38,00,35,00,2d,00,38,00,43,00,\
  38,00,39,00,2d,00,46,00,33,00,45,00,41,00,45,00,44,00,46,00,41,00,39,00,31,\
  00,46,00,36,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,44,\
  00,35,00,44,00,32,00,38,00,42,00,41,00,41,00,2d,00,37,00,33,00,34,00,46,00,\
  2d,00,34,00,38,00,38,00,35,00,2d,00,38,00,43,00,38,00,39,00,2d,00,46,00,33,\
  00,45,00,41,00,45,00,44,00,46,00,41,00,39,00,31,00,46,00,36,00,7d,00,2d,00,\
  7b,00,42,00,37,00,30,00,44,00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,\
  00,35,00,2d,00,34,00,44,00,34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,\
  42,00,38,00,41,00,42,00,31,00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0022\Ndi]
"Service"="usb_rndisx"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0022\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0022\Ndi\params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0022\Ndi\params\NetworkAddress]
"ParamDesc"="Network Address"
"type"="edit"
"LimitText"="12"
"UpperCase"="1"
"default"=" "
"optional"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0023]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{469D2865-5AE0-4A6A-818F-11EE859BA73C}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000009
"*MediaType"=dword:0000000f
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000007
"DeviceInstanceID"="ROOT\\*ISATAP\\0003"
"InstallTimeStamp"=hex:e6,07,02,00,03,00,02,00,15,00,16,00,07,00,b0,02
"Type"="13"
"ComponentId"="*isatap"
"NetworkAddress"=""
"InfPath"="nettun.inf"
"InfSection"="ISATAP.ndi"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="*isatap"
"DriverDesc"="Microsoft ISATAP Adapter"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0023\Linkage]
"RootDevice"=hex(7):7b,00,34,00,36,00,39,00,44,00,32,00,38,00,36,00,35,00,2d,\
  00,35,00,41,00,45,00,30,00,2d,00,34,00,41,00,36,00,41,00,2d,00,38,00,31,00,\
  38,00,46,00,2d,00,31,00,31,00,45,00,45,00,38,00,35,00,39,00,42,00,41,00,37,\
  00,33,00,43,00,7d,00,00,00,00,00
"UpperBind"=hex(7):54,00,43,00,50,00,49,00,50,00,36,00,54,00,55,00,4e,00,4e,00,\
  45,00,4c,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,34,00,36,\
  00,39,00,44,00,32,00,38,00,36,00,35,00,2d,00,35,00,41,00,45,00,30,00,2d,00,\
  34,00,41,00,36,00,41,00,2d,00,38,00,31,00,38,00,46,00,2d,00,31,00,31,00,45,\
  00,45,00,38,00,35,00,39,00,42,00,41,00,37,00,33,00,43,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0023\Ndi]
"Service"="tunnel"
"HelpText"="Microsoft ISATAP Adapter Driver"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0023\Ndi\Interfaces]
"LowerRange"="tunnel"
"UpperRange"="ndis5_ip6_tunnel"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0023\Ndi\Params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0023\Ndi\Params\NetworkAddress]
"ParamDesc"="Network Address"
"Default"=""
"Type"="text"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0023\Ndi\Params\Type]
"ParamDesc"="Type"
"Default"=""
"Type"="int"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0024]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{310F4FCA-2253-4F45-AF80-2E5C4CF90909}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000084
"NetLuidIndex"=dword:00000010
"DeviceInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&166054E7&0&0000"
"InstallTimeStamp"=hex:e6,07,01,00,00,00,1e,00,06,00,29,00,36,00,a9,00
"BusType"="15"
"ComponentId"="usb\\class_e0&subclass_01&prot_03"
"BusNumber"="0"
"InfPath"="wceisvista.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,72,00,6e,00,64,00,69,00,73,00,2e,00,69,\
  00,6e,00,66,00,00,00,00,00
"InfSection"="RNDIS.NT.5.1"
"ProviderName"="Microsoft Corporation"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="usb\\class_e0&subclass_01&prot_03"
"DriverDesc"="Remote NDIS based Internet Sharing Device"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0024\Linkage]
"RootDevice"=hex(7):7b,00,33,00,31,00,30,00,46,00,34,00,46,00,43,00,41,00,2d,\
  00,32,00,32,00,35,00,33,00,2d,00,34,00,46,00,34,00,35,00,2d,00,41,00,46,00,\
  38,00,30,00,2d,00,32,00,45,00,35,00,43,00,34,00,43,00,46,00,39,00,30,00,39,\
  00,30,00,39,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,33,00,31,\
  00,30,00,46,00,34,00,46,00,43,00,41,00,2d,00,32,00,32,00,35,00,33,00,2d,00,\
  34,00,46,00,34,00,35,00,2d,00,41,00,46,00,38,00,30,00,2d,00,32,00,45,00,35,\
  00,43,00,34,00,43,00,46,00,39,00,30,00,39,00,30,00,39,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,33,00,31,00,30,00,46,00,34,00,46,00,43,00,41,00,2d,\
  00,32,00,32,00,35,00,33,00,2d,00,34,00,46,00,34,00,35,00,2d,00,41,00,46,00,\
  38,00,30,00,2d,00,32,00,45,00,35,00,43,00,34,00,43,00,46,00,39,00,30,00,39,\
  00,30,00,39,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,33,\
  00,31,00,30,00,46,00,34,00,46,00,43,00,41,00,2d,00,32,00,32,00,35,00,33,00,\
  2d,00,34,00,46,00,34,00,35,00,2d,00,41,00,46,00,38,00,30,00,2d,00,32,00,45,\
  00,35,00,43,00,34,00,43,00,46,00,39,00,30,00,39,00,30,00,39,00,7d,00,2d,00,\
  7b,00,42,00,37,00,30,00,44,00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,\
  00,35,00,2d,00,34,00,44,00,34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,\
  42,00,38,00,41,00,42,00,31,00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0024\Ndi]
"Service"="usb_rndisx"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0024\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0024\Ndi\params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0024\Ndi\params\NetworkAddress]
"ParamDesc"="Network Address"
"type"="edit"
"LimitText"="12"
"UpperCase"="1"
"default"=" "
"optional"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0025]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{76C8AC49-E5DC-4BE0-98E4-B3FAA3318C32}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000084
"NetLuidIndex"=dword:00000011
"DeviceInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&166054E7&1&0000"
"InstallTimeStamp"=hex:e6,07,02,00,04,00,03,00,00,00,15,00,18,00,00,01
"BusType"="15"
"ComponentId"="usb\\class_e0&subclass_01&prot_03"
"BusNumber"="0"
"InfPath"="wceisvista.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,72,00,6e,00,64,00,69,00,73,00,2e,00,69,\
  00,6e,00,66,00,00,00,00,00
"InfSection"="RNDIS.NT.5.1"
"ProviderName"="Microsoft Corporation"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="usb\\class_e0&subclass_01&prot_03"
"DriverDesc"="Remote NDIS based Internet Sharing Device"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0025\Linkage]
"RootDevice"=hex(7):7b,00,37,00,36,00,43,00,38,00,41,00,43,00,34,00,39,00,2d,\
  00,45,00,35,00,44,00,43,00,2d,00,34,00,42,00,45,00,30,00,2d,00,39,00,38,00,\
  45,00,34,00,2d,00,42,00,33,00,46,00,41,00,41,00,33,00,33,00,31,00,38,00,43,\
  00,33,00,32,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,37,00,36,\
  00,43,00,38,00,41,00,43,00,34,00,39,00,2d,00,45,00,35,00,44,00,43,00,2d,00,\
  34,00,42,00,45,00,30,00,2d,00,39,00,38,00,45,00,34,00,2d,00,42,00,33,00,46,\
  00,41,00,41,00,33,00,33,00,31,00,38,00,43,00,33,00,32,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,37,00,36,00,43,00,38,00,41,00,43,00,34,00,39,00,2d,\
  00,45,00,35,00,44,00,43,00,2d,00,34,00,42,00,45,00,30,00,2d,00,39,00,38,00,\
  45,00,34,00,2d,00,42,00,33,00,46,00,41,00,41,00,33,00,33,00,31,00,38,00,43,\
  00,33,00,32,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,37,\
  00,36,00,43,00,38,00,41,00,43,00,34,00,39,00,2d,00,45,00,35,00,44,00,43,00,\
  2d,00,34,00,42,00,45,00,30,00,2d,00,39,00,38,00,45,00,34,00,2d,00,42,00,33,\
  00,46,00,41,00,41,00,33,00,33,00,31,00,38,00,43,00,33,00,32,00,7d,00,2d,00,\
  7b,00,42,00,37,00,30,00,44,00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,\
  00,35,00,2d,00,34,00,44,00,34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,\
  42,00,38,00,41,00,42,00,31,00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0025\Ndi]
"Service"="usb_rndisx"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0025\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0025\Ndi\params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0025\Ndi\params\NetworkAddress]
"ParamDesc"="Network Address"
"type"="edit"
"LimitText"="12"
"UpperCase"="1"
"default"=" "
"optional"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0026]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{7B1273F9-62B6-4436-8AAA-57E2DDE36F7D}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000009
"*MediaType"=dword:0000000f
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000008
"DeviceInstanceID"="ROOT\\*ISATAP\\0004"
"InstallTimeStamp"=hex:e6,07,02,00,04,00,03,00,00,00,02,00,03,00,41,03
"Type"="13"
"ComponentId"="*isatap"
"NetworkAddress"=""
"InfPath"="nettun.inf"
"InfSection"="ISATAP.ndi"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="*isatap"
"DriverDesc"="Microsoft ISATAP Adapter"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0026\Linkage]
"RootDevice"=hex(7):7b,00,37,00,42,00,31,00,32,00,37,00,33,00,46,00,39,00,2d,\
  00,36,00,32,00,42,00,36,00,2d,00,34,00,34,00,33,00,36,00,2d,00,38,00,41,00,\
  41,00,41,00,2d,00,35,00,37,00,45,00,32,00,44,00,44,00,45,00,33,00,36,00,46,\
  00,37,00,44,00,7d,00,00,00,00,00
"UpperBind"=hex(7):54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,37,00,42,\
  00,31,00,32,00,37,00,33,00,46,00,39,00,2d,00,36,00,32,00,42,00,36,00,2d,00,\
  34,00,34,00,33,00,36,00,2d,00,38,00,41,00,41,00,41,00,2d,00,35,00,37,00,45,\
  00,32,00,44,00,44,00,45,00,33,00,36,00,46,00,37,00,44,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0026\Ndi]
"Service"="tunnel"
"HelpText"="Microsoft ISATAP Adapter Driver"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0026\Ndi\Interfaces]
"LowerRange"="tunnel"
"UpperRange"="ndis5_ip6_tunnel"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0026\Ndi\Params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0026\Ndi\Params\NetworkAddress]
"ParamDesc"="Network Address"
"Default"=""
"Type"="text"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0026\Ndi\Params\Type]
"ParamDesc"="Type"
"Default"=""
"Type"="int"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0027]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{CA3E1BDE-3EE5-4B7D-A144-8455A206440C}"
"*IfType"=dword:00000006
"Characteristics"=dword:00000084
"NetLuidIndex"=dword:00000012
"DeviceInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&235BEC5B&0&0000"
"InstallTimeStamp"=hex:e6,07,02,00,03,00,02,00,11,00,28,00,29,00,86,01
"BusType"="15"
"ComponentId"="usb\\class_e0&subclass_01&prot_03"
"BusNumber"="0"
"InfPath"="wceisvista.inf"
"IncludedInfs"=hex(7):6e,00,65,00,74,00,72,00,6e,00,64,00,69,00,73,00,2e,00,69,\
  00,6e,00,66,00,00,00,00,00
"InfSection"="RNDIS.NT.5.1"
"ProviderName"="Microsoft Corporation"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="usb\\class_e0&subclass_01&prot_03"
"DriverDesc"="Remote NDIS based Internet Sharing Device"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0027\Linkage]
"RootDevice"=hex(7):7b,00,43,00,41,00,33,00,45,00,31,00,42,00,44,00,45,00,2d,\
  00,33,00,45,00,45,00,35,00,2d,00,34,00,42,00,37,00,44,00,2d,00,41,00,31,00,\
  34,00,34,00,2d,00,38,00,34,00,35,00,35,00,41,00,32,00,30,00,36,00,34,00,34,\
  00,30,00,43,00,7d,00,00,00,00,00
"UpperBind"=hex(7):4e,00,64,00,69,00,73,00,75,00,69,00,6f,00,00,00,52,00,61,00,\
  73,00,50,00,70,00,70,00,6f,00,65,00,00,00,72,00,73,00,70,00,6e,00,64,00,72,\
  00,00,00,6c,00,6c,00,74,00,64,00,69,00,6f,00,00,00,54,00,63,00,70,00,69,00,\
  70,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,43,00,41,\
  00,33,00,45,00,31,00,42,00,44,00,45,00,2d,00,33,00,45,00,45,00,35,00,2d,00,\
  34,00,42,00,37,00,44,00,2d,00,41,00,31,00,34,00,34,00,2d,00,38,00,34,00,35,\
  00,35,00,41,00,32,00,30,00,36,00,34,00,34,00,30,00,43,00,7d,00,00,00,00,00
"FilterList"=hex(7):7b,00,43,00,41,00,33,00,45,00,31,00,42,00,44,00,45,00,2d,\
  00,33,00,45,00,45,00,35,00,2d,00,34,00,42,00,37,00,44,00,2d,00,41,00,31,00,\
  34,00,34,00,2d,00,38,00,34,00,35,00,35,00,41,00,32,00,30,00,36,00,34,00,34,\
  00,30,00,43,00,7d,00,2d,00,7b,00,42,00,35,00,46,00,34,00,44,00,36,00,35,00,\
  39,00,2d,00,37,00,44,00,41,00,41,00,2d,00,34,00,35,00,36,00,35,00,2d,00,38,\
  00,45,00,34,00,31,00,2d,00,42,00,45,00,32,00,32,00,30,00,45,00,44,00,36,00,\
  30,00,35,00,34,00,32,00,7d,00,2d,00,30,00,30,00,30,00,30,00,00,00,7b,00,43,\
  00,41,00,33,00,45,00,31,00,42,00,44,00,45,00,2d,00,33,00,45,00,45,00,35,00,\
  2d,00,34,00,42,00,37,00,44,00,2d,00,41,00,31,00,34,00,34,00,2d,00,38,00,34,\
  00,35,00,35,00,41,00,32,00,30,00,36,00,34,00,34,00,30,00,43,00,7d,00,2d,00,\
  7b,00,42,00,37,00,30,00,44,00,36,00,34,00,36,00,30,00,2d,00,33,00,36,00,33,\
  00,35,00,2d,00,34,00,44,00,34,00,32,00,2d,00,42,00,38,00,36,00,36,00,2d,00,\
  42,00,38,00,41,00,42,00,31,00,41,00,32,00,34,00,34,00,35,00,34,00,43,00,7d,\
  00,2d,00,30,00,30,00,30,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0027\Ndi]
"Service"="usb_rndisx"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0027\Ndi\Interfaces]
"UpperRange"="ndis5"
"LowerRange"="ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0027\Ndi\params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0027\Ndi\params\NetworkAddress]
"ParamDesc"="Network Address"
"type"="edit"
"LimitText"="12"
"UpperCase"="1"
"default"=" "
"optional"="1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0028]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{27660F46-48BF-466E-844A-D1FB3D0DDE32}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000009
"*MediaType"=dword:0000000f
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000004
"DeviceInstanceID"="ROOT\\*ISATAP\\0000"
"InstallTimeStamp"=hex:e6,07,02,00,03,00,02,00,15,00,0e,00,19,00,60,02
"Type"="13"
"ComponentId"="*isatap"
"NetworkAddress"=""
"InfPath"="nettun.inf"
"InfSection"="ISATAP.ndi"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="*isatap"
"DriverDesc"="Microsoft ISATAP Adapter"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0028\Linkage]
"RootDevice"=hex(7):7b,00,32,00,37,00,36,00,36,00,30,00,46,00,34,00,36,00,2d,\
  00,34,00,38,00,42,00,46,00,2d,00,34,00,36,00,36,00,45,00,2d,00,38,00,34,00,\
  34,00,41,00,2d,00,44,00,31,00,46,00,42,00,33,00,44,00,30,00,44,00,44,00,45,\
  00,33,00,32,00,7d,00,00,00,00,00
"UpperBind"=hex(7):54,00,43,00,50,00,49,00,50,00,36,00,54,00,55,00,4e,00,4e,00,\
  45,00,4c,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,32,00,37,\
  00,36,00,36,00,30,00,46,00,34,00,36,00,2d,00,34,00,38,00,42,00,46,00,2d,00,\
  34,00,36,00,36,00,45,00,2d,00,38,00,34,00,34,00,41,00,2d,00,44,00,31,00,46,\
  00,42,00,33,00,44,00,30,00,44,00,44,00,45,00,33,00,32,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0028\Ndi]
"Service"="tunnel"
"HelpText"="Microsoft ISATAP Adapter Driver"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0028\Ndi\Interfaces]
"LowerRange"="tunnel"
"UpperRange"="ndis5_ip6_tunnel"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0028\Ndi\Params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0028\Ndi\Params\NetworkAddress]
"ParamDesc"="Network Address"
"Default"=""
"Type"="text"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0028\Ndi\Params\Type]
"ParamDesc"="Type"
"Default"=""
"Type"="int"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0029]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{E3836FEC-53DA-4045-9344-9AE94528CBCE}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000009
"*MediaType"=dword:0000000f
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:00000009
"DeviceInstanceID"="ROOT\\*ISATAP\\0005"
"InstallTimeStamp"=hex:e6,07,02,00,04,00,03,00,01,00,04,00,31,00,b8,00
"Type"="13"
"ComponentId"="*isatap"
"NetworkAddress"=""
"InfPath"="nettun.inf"
"InfSection"="ISATAP.ndi"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="*isatap"
"DriverDesc"="Microsoft ISATAP Adapter"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0029\Linkage]
"RootDevice"=hex(7):7b,00,45,00,33,00,38,00,33,00,36,00,46,00,45,00,43,00,2d,\
  00,35,00,33,00,44,00,41,00,2d,00,34,00,30,00,34,00,35,00,2d,00,39,00,33,00,\
  34,00,34,00,2d,00,39,00,41,00,45,00,39,00,34,00,35,00,32,00,38,00,43,00,42,\
  00,43,00,45,00,7d,00,00,00,00,00
"UpperBind"=hex(7):54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,45,00,33,\
  00,38,00,33,00,36,00,46,00,45,00,43,00,2d,00,35,00,33,00,44,00,41,00,2d,00,\
  34,00,30,00,34,00,35,00,2d,00,39,00,33,00,34,00,34,00,2d,00,39,00,41,00,45,\
  00,39,00,34,00,35,00,32,00,38,00,43,00,42,00,43,00,45,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0029\Ndi]
"Service"="tunnel"
"HelpText"="Microsoft ISATAP Adapter Driver"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0029\Ndi\Interfaces]
"LowerRange"="tunnel"
"UpperRange"="ndis5_ip6_tunnel"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0029\Ndi\Params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0029\Ndi\Params\NetworkAddress]
"ParamDesc"="Network Address"
"Default"=""
"Type"="text"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0029\Ndi\Params\Type]
"ParamDesc"="Type"
"Default"=""
"Type"="int"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0030]
"NewDeviceInstall"=dword:00000001
"NetCfgInstanceId"="{84DD37E2-005E-46DE-A956-449EDC03DDFB}"
"*IfType"=dword:00000083
"Characteristics"=dword:00000009
"*MediaType"=dword:0000000f
"*PhysicalMediaType"=dword:00000000
"NetLuidIndex"=dword:0000000a
"DeviceInstanceID"="ROOT\\*ISATAP\\0006"
"InstallTimeStamp"=hex:e6,07,02,00,04,00,03,00,01,00,05,00,23,00,d3,01
"Type"="13"
"ComponentId"="*isatap"
"NetworkAddress"=""
"InfPath"="nettun.inf"
"InfSection"="ISATAP.ndi"
"ProviderName"="Microsoft"
"DriverDateData"=hex:00,80,8c,a3,c5,94,c6,01
"DriverDate"="6-21-2006"
"DriverVersion"="6.1.7600.16385"
"MatchingDeviceId"="*isatap"
"DriverDesc"="Microsoft ISATAP Adapter"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0030\Linkage]
"RootDevice"=hex(7):7b,00,38,00,34,00,44,00,44,00,33,00,37,00,45,00,32,00,2d,\
  00,30,00,30,00,35,00,45,00,2d,00,34,00,36,00,44,00,45,00,2d,00,41,00,39,00,\
  35,00,36,00,2d,00,34,00,34,00,39,00,45,00,44,00,43,00,30,00,33,00,44,00,44,\
  00,46,00,42,00,7d,00,00,00,00,00
"UpperBind"=hex(7):54,00,43,00,50,00,49,00,50,00,36,00,54,00,55,00,4e,00,4e,00,\
  45,00,4c,00,00,00,54,00,63,00,70,00,69,00,70,00,36,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,38,00,34,\
  00,44,00,44,00,33,00,37,00,45,00,32,00,2d,00,30,00,30,00,35,00,45,00,2d,00,\
  34,00,36,00,44,00,45,00,2d,00,41,00,39,00,35,00,36,00,2d,00,34,00,34,00,39,\
  00,45,00,44,00,43,00,30,00,33,00,44,00,44,00,46,00,42,00,7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0030\Ndi]
"Service"="tunnel"
"HelpText"="Microsoft ISATAP Adapter Driver"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0030\Ndi\Interfaces]
"LowerRange"="tunnel"
"UpperRange"="ndis5_ip6_tunnel"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0030\Ndi\Params]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0030\Ndi\Params\NetworkAddress]
"ParamDesc"="Network Address"
"Default"=""
"Type"="text"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0030\Ndi\Params\Type]
"ParamDesc"="Type"
"Default"=""
"Type"="int"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#BTH#MS_BTHPAN#7&1bb168b6&0&2#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="BTH\\MS_BTHPAN\\7&1bb168b6&0&2"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#BTH#MS_BTHPAN#7&1bb168b6&0&2#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{91A6805D-1002-48DC-9740-DEF86A797131}]
"SymbolicLink"="\\\\?\\BTH#MS_BTHPAN#7&1bb168b6&0&2#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{91A6805D-1002-48DC-9740-DEF86A797131}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#BTH#MS_BTHPAN#7&1bb168b6&0&2#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{91A6805D-1002-48DC-9740-DEF86A797131}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#BTH#MS_BTHPAN#7&1bb168b6&0&2#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#PCI#VEN_14E4&DEV_1659&SUBSYS_01E61028&REV_11#4&188bd7e4&0&00E4#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="PCI\\VEN_14E4&DEV_1659&SUBSYS_01E61028&REV_11\\4&188bd7e4&0&00E4"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#PCI#VEN_14E4&DEV_1659&SUBSYS_01E61028&REV_11#4&188bd7e4&0&00E4#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{AACF144C-0770-4FE3-B92B-A4BE71D2F9B9}]
"SymbolicLink"="\\\\?\\PCI#VEN_14E4&DEV_1659&SUBSYS_01E61028&REV_11#4&188bd7e4&0&00E4#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{AACF144C-0770-4FE3-B92B-A4BE71D2F9B9}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#PCI#VEN_14E4&DEV_1659&SUBSYS_01E61028&REV_11#4&27c84f55&0&00E4#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="PCI\\VEN_14E4&DEV_1659&SUBSYS_01E61028&REV_11\\4&27c84f55&0&00E4"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#PCI#VEN_14E4&DEV_1659&SUBSYS_01E61028&REV_11#4&27c84f55&0&00E4#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{22D13694-90DB-47B8-815D-1B062FF9D042}]
"SymbolicLink"="\\\\?\\PCI#VEN_14E4&DEV_1659&SUBSYS_01E61028&REV_11#4&27c84f55&0&00E4#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{22D13694-90DB-47B8-815D-1B062FF9D042}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#PCI#VEN_14E4&DEV_432B&SUBSYS_008E106B&REV_01#A9464BFFFF9B002500#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="PCI\\VEN_14E4&DEV_432B&SUBSYS_008E106B&REV_01\\A9464BFFFF9B002500"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#PCI#VEN_14E4&DEV_432B&SUBSYS_008E106B&REV_01#A9464BFFFF9B002500#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{7857D8BE-61B9-4C0A-8699-0623CFCDF9B7}]
"SymbolicLink"="\\\\?\\PCI#VEN_14E4&DEV_432B&SUBSYS_008E106B&REV_01#A9464BFFFF9B002500#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{7857D8BE-61B9-4C0A-8699-0623CFCDF9B7}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#PCI#VEN_14E4&DEV_432B&SUBSYS_008E106B&REV_01#A9464BFFFF9B002500#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{7857D8BE-61B9-4C0A-8699-0623CFCDF9B7}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#PCI#VEN_14E4&DEV_432B&SUBSYS_008E106B&REV_01#A9464BFFFF9B002500#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#PCI#VEN_8086&DEV_100E&SUBSYS_001E8086&REV_02#3&267a616a&0&18#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="PCI\\VEN_8086&DEV_100E&SUBSYS_001E8086&REV_02\\3&267a616a&0&18"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#PCI#VEN_8086&DEV_100E&SUBSYS_001E8086&REV_02#3&267a616a&0&18#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{B0BF74E5-B8F8-4FD8-B3E1-B9360C6ABAA2}]
"SymbolicLink"="\\\\?\\PCI#VEN_8086&DEV_100E&SUBSYS_001E8086&REV_02#3&267a616a&0&18#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{B0BF74E5-B8F8-4FD8-B3E1-B9360C6ABAA2}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\*ISATAP\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{27660F46-48BF-466E-844A-D1FB3D0DDE32}]
"SymbolicLink"="\\\\?\\Root#*ISATAP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{27660F46-48BF-466E-844A-D1FB3D0DDE32}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{27660F46-48BF-466E-844A-D1FB3D0DDE32}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0001#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\*ISATAP\\0001"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0001#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{600EC8A1-C676-4D79-918F-FE130EC9F336}]
"SymbolicLink"="\\\\?\\Root#*ISATAP#0001#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{600EC8A1-C676-4D79-918F-FE130EC9F336}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0001#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{600EC8A1-C676-4D79-918F-FE130EC9F336}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0001#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0002#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\*ISATAP\\0002"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0002#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{872DD157-C7A3-400E-8FD1-539EB0951715}]
"SymbolicLink"="\\\\?\\Root#*ISATAP#0002#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{872DD157-C7A3-400E-8FD1-539EB0951715}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0002#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{872DD157-C7A3-400E-8FD1-539EB0951715}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0002#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0003#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\*ISATAP\\0003"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0003#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{469D2865-5AE0-4A6A-818F-11EE859BA73C}]
"SymbolicLink"="\\\\?\\Root#*ISATAP#0003#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{469D2865-5AE0-4A6A-818F-11EE859BA73C}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0003#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{469D2865-5AE0-4A6A-818F-11EE859BA73C}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0003#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0004#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="ROOT\\*ISATAP\\0004"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0004#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{7B1273F9-62B6-4436-8AAA-57E2DDE36F7D}]
"SymbolicLink"="\\\\?\\ROOT#*ISATAP#0004#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{7B1273F9-62B6-4436-8AAA-57E2DDE36F7D}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0004#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{7B1273F9-62B6-4436-8AAA-57E2DDE36F7D}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0004#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0005#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="ROOT\\*ISATAP\\0005"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0005#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{E3836FEC-53DA-4045-9344-9AE94528CBCE}]
"SymbolicLink"="\\\\?\\ROOT#*ISATAP#0005#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{E3836FEC-53DA-4045-9344-9AE94528CBCE}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0005#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{E3836FEC-53DA-4045-9344-9AE94528CBCE}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0005#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0006#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="ROOT\\*ISATAP\\0006"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0006#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{84DD37E2-005E-46DE-A956-449EDC03DDFB}]
"SymbolicLink"="\\\\?\\ROOT#*ISATAP#0006#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{84DD37E2-005E-46DE-A956-449EDC03DDFB}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0006#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{84DD37E2-005E-46DE-A956-449EDC03DDFB}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#*ISATAP#0006#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_AGILEVPNMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\MS_AGILEVPNMINIPORT\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_AGILEVPNMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{29898C9D-B0A4-4FEF-BDB6-57A562022CEE}]
"SymbolicLink"="\\\\?\\Root#MS_AGILEVPNMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{29898C9D-B0A4-4FEF-BDB6-57A562022CEE}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_AGILEVPNMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{29898C9D-B0A4-4FEF-BDB6-57A562022CEE}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_AGILEVPNMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_L2TPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\MS_L2TPMINIPORT\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_L2TPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{E43D242B-9EAB-4626-A952-46649FBB939A}]
"SymbolicLink"="\\\\?\\Root#MS_L2TPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{E43D242B-9EAB-4626-A952-46649FBB939A}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_L2TPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{E43D242B-9EAB-4626-A952-46649FBB939A}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_L2TPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANBH#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\MS_NDISWANBH\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANBH#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#NDISWANBH]
"SymbolicLink"="\\\\?\\Root#MS_NDISWANBH#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\NDISWANBH"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANBH#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#NDISWANBH\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANBH#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANIP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\MS_NDISWANIP\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANIP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#NDISWANIP]
"SymbolicLink"="\\\\?\\Root#MS_NDISWANIP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\NDISWANIP"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANIP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#NDISWANIP\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANIP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANIPV6#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\MS_NDISWANIPV6\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANIPV6#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#NDISWANIPV6]
"SymbolicLink"="\\\\?\\Root#MS_NDISWANIPV6#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\NDISWANIPV6"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANIPV6#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#NDISWANIPV6\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_NDISWANIPV6#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_PPPOEMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\MS_PPPOEMINIPORT\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_PPPOEMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{8E301A52-AFFA-4F49-B9CA-C79096A1A056}]
"SymbolicLink"="\\\\?\\Root#MS_PPPOEMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{8E301A52-AFFA-4F49-B9CA-C79096A1A056}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_PPPOEMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{8E301A52-AFFA-4F49-B9CA-C79096A1A056}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_PPPOEMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_PPTPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\MS_PPTPMINIPORT\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_PPTPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{DF4A9D2C-8742-4EB1-8703-D395C4183F33}]
"SymbolicLink"="\\\\?\\Root#MS_PPTPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{DF4A9D2C-8742-4EB1-8703-D395C4183F33}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_PPTPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{DF4A9D2C-8742-4EB1-8703-D395C4183F33}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_PPTPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_SSTPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\MS_SSTPMINIPORT\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_SSTPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{71F897D7-EB7C-4D8D-89DB-AC80D9DD2270}]
"SymbolicLink"="\\\\?\\Root#MS_SSTPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{71F897D7-EB7C-4D8D-89DB-AC80D9DD2270}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_SSTPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{71F897D7-EB7C-4D8D-89DB-AC80D9DD2270}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#MS_SSTPMINIPORT#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#Root#SYSTEM#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="Root\\SYSTEM\\0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#Root#SYSTEM#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{eeab7790-c514-11d1-b42b-00805fc1270e}&asyncmac]
"SymbolicLink"="\\\\?\\Root#SYSTEM#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{eeab7790-c514-11d1-b42b-00805fc1270e}&asyncmac"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#Root#SYSTEM#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{eeab7790-c514-11d1-b42b-00805fc1270e}&asyncmac\Device Parameters]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#Root#SYSTEM#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{eeab7790-c514-11d1-b42b-00805fc1270e}&asyncmac\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#Root#SYSTEM#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="SW\\{eeab7790-c514-11d1-b42b-00805fc1270e}\\asyncmac"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{78032B7E-4968-42D3-9F37-287EA86C0AAA}]
"SymbolicLink"="\\\\?\\SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{78032B7E-4968-42D3-9F37-287EA86C0AAA}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{78032B7E-4968-42D3-9F37-287EA86C0AAA}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&166054e7&0&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="USB\\VID_2001&PID_7E41&MI_00\\6&166054e7&0&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&166054e7&0&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{310F4FCA-2253-4F45-AF80-2E5C4CF90909}]
"SymbolicLink"="\\\\?\\USB#VID_2001&PID_7E41&MI_00#6&166054e7&0&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{310F4FCA-2253-4F45-AF80-2E5C4CF90909}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&166054e7&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="USB\\VID_2001&PID_7E41&MI_00\\6&166054e7&1&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&166054e7&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{76C8AC49-E5DC-4BE0-98E4-B3FAA3318C32}]
"SymbolicLink"="\\\\?\\USB#VID_2001&PID_7E41&MI_00#6&166054e7&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{76C8AC49-E5DC-4BE0-98E4-B3FAA3318C32}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&166054e7&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{76C8AC49-E5DC-4BE0-98E4-B3FAA3318C32}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&166054e7&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&1b9d08d4&0&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="USB\\VID_2001&PID_7E41&MI_00\\6&1b9d08d4&0&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&1b9d08d4&0&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{A6DD7F1D-56D6-4CA9-81FB-BC435B50F593}]
"SymbolicLink"="\\\\?\\USB#VID_2001&PID_7E41&MI_00#6&1b9d08d4&0&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{A6DD7F1D-56D6-4CA9-81FB-BC435B50F593}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&235bec5b&0&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="USB\\VID_2001&PID_7E41&MI_00\\6&235bec5b&0&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&235bec5b&0&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{CA3E1BDE-3EE5-4B7D-A144-8455A206440C}]
"SymbolicLink"="\\\\?\\USB#VID_2001&PID_7E41&MI_00#6&235bec5b&0&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{CA3E1BDE-3EE5-4B7D-A144-8455A206440C}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&2fa2efd3&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="USB\\VID_2001&PID_7E41&MI_00\\6&2fa2efd3&1&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&2fa2efd3&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{FE7CD5B7-1FDB-488D-B643-0903109D7D88}]
"SymbolicLink"="\\\\?\\USB#VID_2001&PID_7E41&MI_00#6&2fa2efd3&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{FE7CD5B7-1FDB-488D-B643-0903109D7D88}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&2fa2efd3&2&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="USB\\VID_2001&PID_7E41&MI_00\\6&2fa2efd3&2&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&2fa2efd3&2&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{65BB6BD6-6CDB-43A5-B450-64A2287C70B1}]
"SymbolicLink"="\\\\?\\USB#VID_2001&PID_7E41&MI_00#6&2fa2efd3&2&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{65BB6BD6-6CDB-43A5-B450-64A2287C70B1}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&2fa2efd3&3&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="USB\\VID_2001&PID_7E41&MI_00\\6&2fa2efd3&3&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&2fa2efd3&3&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{D5D28BAA-734F-4885-8C89-F3EAEDFA91F6}]
"SymbolicLink"="\\\\?\\USB#VID_2001&PID_7E41&MI_00#6&2fa2efd3&3&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{D5D28BAA-734F-4885-8C89-F3EAEDFA91F6}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&ca14d76&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="USB\\VID_2001&PID_7E41&MI_00\\6&ca14d76&1&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&ca14d76&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{0BC883D2-DAFB-4202-874A-B9C4C5BB3CCF}]
"SymbolicLink"="\\\\?\\USB#VID_2001&PID_7E41&MI_00#6&ca14d76&1&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{0BC883D2-DAFB-4202-874A-B9C4C5BB3CCF}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&ca14d76&2&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="USB\\VID_2001&PID_7E41&MI_00\\6&ca14d76&2&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#USB#VID_2001&PID_7E41&MI_00#6&ca14d76&2&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{7EB48003-6E25-4C38-B42C-A7CA5B6E1199}]
"SymbolicLink"="\\\\?\\USB#VID_2001&PID_7E41&MI_00#6&ca14d76&2&0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{7EB48003-6E25-4C38-B42C-A7CA5B6E1199}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#{5d624f94-8850-40c3-a3fa-a4fd2080baf3}#vwifimp#5&121f6484&0&01#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="{5d624f94-8850-40c3-a3fa-a4fd2080baf3}\\vwifimp\\5&121f6484&0&01"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#{5d624f94-8850-40c3-a3fa-a4fd2080baf3}#vwifimp#5&121f6484&0&01#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{354168A7-A09C-4934-895B-F89FA3C0BBD4}]
"SymbolicLink"="\\\\?\\{5d624f94-8850-40c3-a3fa-a4fd2080baf3}#vwifimp#5&121f6484&0&01#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{354168A7-A09C-4934-895B-F89FA3C0BBD4}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#{5d624f94-8850-40c3-a3fa-a4fd2080baf3}#vwifimp#5&121f6484&1&02#{ad498944-762f-11d0-8dcb-00c04fc3358c}]
"DeviceInstance"="{5d624f94-8850-40c3-a3fa-a4fd2080baf3}\\vwifimp\\5&121f6484&1&02"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#{5d624f94-8850-40c3-a3fa-a4fd2080baf3}#vwifimp#5&121f6484&1&02#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{D77366DC-8430-4300-B82F-8E84A815186C}]
"SymbolicLink"="\\\\?\\{5d624f94-8850-40c3-a3fa-a4fd2080baf3}#vwifimp#5&121f6484&1&02#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{D77366DC-8430-4300-B82F-8E84A815186C}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#{5d624f94-8850-40c3-a3fa-a4fd2080baf3}#vwifimp#5&121f6484&1&02#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{D77366DC-8430-4300-B82F-8E84A815186C}\Control]
"Linked"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#{5d624f94-8850-40c3-a3fa-a4fd2080baf3}#vwifimp#5&121f6484&1&02#{ad498944-762f-11d0-8dcb-00c04fc3358c}\Control]
"ReferenceCount"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\Descriptions]
"WAN Miniport (SSTP)"=hex(7):31,00,00,00,00,00
"WAN Miniport (IKEv2)"=hex(7):31,00,00,00,00,00
"WAN Miniport (L2TP)"=hex(7):31,00,00,00,00,00
"WAN Miniport (Network Monitor)"=hex(7):31,00,00,00,00,00
"WAN Miniport (IP)"=hex(7):31,00,00,00,00,00
"WAN Miniport (IPv6)"=hex(7):31,00,00,00,00,00
"WAN Miniport (PPPOE)"=hex(7):31,00,00,00,00,00
"WAN Miniport (PPTP)"=hex(7):31,00,00,00,00,00
"RAS Async Adapter"=hex(7):31,00,00,00,00,00
"Microsoft ISATAP Adapter"=hex(7):31,00,00,00,32,00,00,00,33,00,00,00,34,00,00,\
  00,35,00,00,00,36,00,00,00,37,00,00,00,00,00
"Remote NDIS based Internet Sharing Device"=hex(7):31,00,00,00,32,00,00,00,33,\
  00,00,00,34,00,00,00,35,00,00,00,36,00,00,00,37,00,00,00,38,00,00,00,39,00,\
  00,00,00,00
"Microsoft Virtual WiFi Miniport Adapter"=hex(7):31,00,00,00,32,00,00,00,00,00
"Bluetooth Device (RFCOMM Protocol TDI)"=hex(7):31,00,00,00,00,00
"Bluetooth Device (Personal Area Network)"=hex(7):31,00,00,00,00,00
"Broadcom 802.11n Network Adapter"=hex(7):31,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{0BC883D2-DAFB-4202-874A-B9C4C5BB3CCF}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{0BC883D2-DAFB-4202-874A-B9C4C5BB3CCF}\Connection]
"DefaultNameResourceId"=dword:0000070a
"DefaultNameIndex"=dword:00000006
"Name"="Local Area Connection 6"
"PnpInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&CA14D76&1&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{27660F46-48BF-466E-844A-D1FB3D0DDE32}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{27660F46-48BF-466E-844A-D1FB3D0DDE32}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:0000000b
"Name"="isatap.{D77366DC-8430-4300-B82F-8E84A815186C}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{29898C9D-B0A4-4FEF-BDB6-57A562022CEE}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{29898C9D-B0A4-4FEF-BDB6-57A562022CEE}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:00000002
"Name"="Local Area Connection* 2"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{2CAA64ED-BAA3-4473-B637-DEC65A14C8AA}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{2CAA64ED-BAA3-4473-B637-DEC65A14C8AA}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:00000008
"Name"="Local Area Connection* 8"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{310F4FCA-2253-4F45-AF80-2E5C4CF90909}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{310F4FCA-2253-4F45-AF80-2E5C4CF90909}\Connection]
"DefaultNameResourceId"=dword:0000070a
"DefaultNameIndex"=dword:00000008
"Name"="Local Area Connection 8"
"PnpInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&166054E7&0&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{354168A7-A09C-4934-895B-F89FA3C0BBD4}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{354168A7-A09C-4934-895B-F89FA3C0BBD4}\Connection]
"DefaultNameResourceId"=dword:0000070e
"DefaultNameIndex"=dword:00000002
"Name"="Wireless Network Connection 2"
"PnpInstanceID"="{5D624F94-8850-40C3-A3FA-A4FD2080BAF3}\\VWIFIMP\\5&121F6484&0&01"
"MediaSubType"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{469D2865-5AE0-4A6A-818F-11EE859BA73C}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{469D2865-5AE0-4A6A-818F-11EE859BA73C}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:0000000b
"Name"="isatap.{7857D8BE-61B9-4C0A-8699-0623CFCDF9B7}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{5BF54C7E-91DA-457D-80BF-333677D7E316}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{5BF54C7E-91DA-457D-80BF-333677D7E316}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:00000007
"Name"="Local Area Connection* 7"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{600EC8A1-C676-4D79-918F-FE130EC9F336}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{600EC8A1-C676-4D79-918F-FE130EC9F336}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:0000000b
"Name"="isatap.{91A6805D-1002-48DC-9740-DEF86A797131}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{65BB6BD6-6CDB-43A5-B450-64A2287C70B1}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{65BB6BD6-6CDB-43A5-B450-64A2287C70B1}\Connection]
"DefaultNameResourceId"=dword:0000070a
"DefaultNameIndex"=dword:00000004
"Name"="Local Area Connection 4"
"PnpInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&2FA2EFD3&2&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{71F897D7-EB7C-4D8D-89DB-AC80D9DD2270}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{71F897D7-EB7C-4D8D-89DB-AC80D9DD2270}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:00000000
"Name"="Local Area Connection*"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{76C8AC49-E5DC-4BE0-98E4-B3FAA3318C32}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{76C8AC49-E5DC-4BE0-98E4-B3FAA3318C32}\Connection]
"DefaultNameResourceId"=dword:0000070a
"DefaultNameIndex"=dword:00000009
"Name"="Local Area Connection 9"
"PnpInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&166054E7&1&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{78032B7E-4968-42D3-9F37-287EA86C0AAA}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{78032B7E-4968-42D3-9F37-287EA86C0AAA}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:0000000a
"Name"="Local Area Connection* 10"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{7857D8BE-61B9-4C0A-8699-0623CFCDF9B7}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{7857D8BE-61B9-4C0A-8699-0623CFCDF9B7}\Connection]
"DefaultNameResourceId"=dword:0000070e
"DefaultNameIndex"=dword:00000000
"Name"="Wireless Network Connection"
"PnpInstanceID"="PCI\\VEN_14E4&DEV_432B&SUBSYS_008E106B&REV_01\\A9464BFFFF9B002500"
"MediaSubType"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{7B1273F9-62B6-4436-8AAA-57E2DDE36F7D}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{7B1273F9-62B6-4436-8AAA-57E2DDE36F7D}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:0000000b
"Name"="Reusable ISATAP Interface {7B1273F9-62B6-4436-8AAA-57E2DDE36F7D}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{7EB48003-6E25-4C38-B42C-A7CA5B6E1199}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{7EB48003-6E25-4C38-B42C-A7CA5B6E1199}\Connection]
"DefaultNameResourceId"=dword:0000070a
"DefaultNameIndex"=dword:00000007
"Name"="Local Area Connection 7"
"PnpInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&CA14D76&2&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{84DD37E2-005E-46DE-A956-449EDC03DDFB}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{84DD37E2-005E-46DE-A956-449EDC03DDFB}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:0000000b
"Name"="Local Area Connection* 11"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{872DD157-C7A3-400E-8FD1-539EB0951715}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{872DD157-C7A3-400E-8FD1-539EB0951715}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:0000000b
"Name"="isatap.{76C8AC49-E5DC-4BE0-98E4-B3FAA3318C32}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{8D616583-4B43-4EE3-ABEA-D198AE9B7988}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{8D616583-4B43-4EE3-ABEA-D198AE9B7988}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:00000009
"Name"="Local Area Connection* 9"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{8E301A52-AFFA-4F49-B9CA-C79096A1A056}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{8E301A52-AFFA-4F49-B9CA-C79096A1A056}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:00000005
"Name"="Local Area Connection* 5"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{91A6805D-1002-48DC-9740-DEF86A797131}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{91A6805D-1002-48DC-9740-DEF86A797131}\Connection]
"DefaultNameResourceId"=dword:00000710
"DefaultNameIndex"=dword:00000000
"Name"="Bluetooth Network Connection"
"PnpInstanceID"="BTH\\MS_BTHPAN\\7&1BB168B6&0&2"
"MediaSubType"=dword:00000007

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{9A399D81-2EAD-4F23-BCDD-637FC13DCD51}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{9A399D81-2EAD-4F23-BCDD-637FC13DCD51}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:00000006
"Name"="Local Area Connection* 6"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{A6DD7F1D-56D6-4CA9-81FB-BC435B50F593}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{A6DD7F1D-56D6-4CA9-81FB-BC435B50F593}\Connection]
"DefaultNameResourceId"=dword:0000070a
"DefaultNameIndex"=dword:00000002
"Name"="Local Area Connection 2"
"PnpInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&1B9D08D4&0&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{CA3E1BDE-3EE5-4B7D-A144-8455A206440C}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{CA3E1BDE-3EE5-4B7D-A144-8455A206440C}\Connection]
"DefaultNameResourceId"=dword:0000070a
"DefaultNameIndex"=dword:0000000a
"Name"="Local Area Connection 10"
"PnpInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&235BEC5B&0&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{D5D28BAA-734F-4885-8C89-F3EAEDFA91F6}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{D5D28BAA-734F-4885-8C89-F3EAEDFA91F6}\Connection]
"DefaultNameResourceId"=dword:0000070a
"DefaultNameIndex"=dword:00000005
"Name"="Local Area Connection 5"
"PnpInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&2FA2EFD3&3&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{D77366DC-8430-4300-B82F-8E84A815186C}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{D77366DC-8430-4300-B82F-8E84A815186C}\Connection]
"DefaultNameResourceId"=dword:0000070e
"DefaultNameIndex"=dword:00000003
"Name"="Wireless Network Connection 3"
"PnpInstanceID"="{5D624F94-8850-40C3-A3FA-A4FD2080BAF3}\\VWIFIMP\\5&121F6484&1&02"
"MediaSubType"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{DF4A9D2C-8742-4EB1-8703-D395C4183F33}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{DF4A9D2C-8742-4EB1-8703-D395C4183F33}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:00000004
"Name"="Local Area Connection* 4"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{E3836FEC-53DA-4045-9344-9AE94528CBCE}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{E3836FEC-53DA-4045-9344-9AE94528CBCE}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:0000000b
"Name"="Reusable ISATAP Interface {E3836FEC-53DA-4045-9344-9AE94528CBCE}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{E43D242B-9EAB-4626-A952-46649FBB939A}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{E43D242B-9EAB-4626-A952-46649FBB939A}\Connection]
"DefaultNameResourceId"=dword:00000709
"DefaultNameIndex"=dword:00000003
"Name"="Local Area Connection* 3"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{FE7CD5B7-1FDB-488D-B643-0903109D7D88}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{FE7CD5B7-1FDB-488D-B643-0903109D7D88}\Connection]
"DefaultNameResourceId"=dword:0000070a
"DefaultNameIndex"=dword:00000003
"Name"="Local Area Connection 3"
"PnpInstanceID"="USB\\VID_2001&PID_7E41&MI_00\\6&2FA2EFD3&1&0000"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{0EFE03B2-EA87-44C1-B825-9BBEA54F37B4}]
"Characteristics"=dword:00000028
"InfPath"="netrass.inf"
"InfSection"="Ndi-Steelhead"
"LocDescription"="@netrass.inf,%steelhead-dispname%;Steelhead"
"Description"="Steelhead"
"ComponentId"="ms_steelhead"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,2d,00,d2,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{0EFE03B2-EA87-44C1-B825-9BBEA54F37B4}\Ndi]
"ClsID"="{6e65cbc5-926d-11d0-8e27-00c04fc99dcf}"
"ComponentDll"="rascfg.dll"
"Service"="RemoteAccess"
"CoServices"=hex(7):52,00,65,00,6d,00,6f,00,74,00,65,00,41,00,63,00,63,00,65,\
  00,73,00,73,00,00,00,00,00
"ExcludeSetupStartServices"=hex(7):52,00,65,00,6d,00,6f,00,74,00,65,00,41,00,\
  63,00,63,00,65,00,73,00,73,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{0EFE03B2-EA87-44C1-B825-9BBEA54F37B4}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{56494156-6C00-4B77-90D7-A4A435088232}]
"Characteristics"=dword:00000028
"InfPath"="netnb.inf"
"InfSection"="NetBIOS.ndi"
"LocDescription"="@netnb.inf,%netbios_desc%;NetBIOS Interface"
"Description"="NetBIOS Interface"
"ComponentId"="ms_netbios"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,35,00,1e,00,01,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{56494156-6C00-4B77-90D7-A4A435088232}\Ndi]
"Service"="NetBIOS"
"CoServices"=hex(7):4e,00,65,00,74,00,42,00,49,00,4f,00,53,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{56494156-6C00-4B77-90D7-A4A435088232}\Ndi\Interfaces]
"UpperRange"="winnet5"
"LowerRange"="netbios"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{5CBF81BF-5055-47CD-9055-A76B2B4E3698}]
"Characteristics"=dword:00040028
"InfPath"="netvwififlt.inf"
"InfSection"="Install"
"LocDescription"="@netvwififlt.inf,%vwififlt_desc%;Virtual WiFi Filter Driver"
"Description"="Virtual WiFi Filter Driver"
"ComponentId"="ms_vwifi"
"InstallTimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0b,00,2d,00,46,03

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{5CBF81BF-5055-47CD-9055-A76B2B4E3698}\Ndi]
"Service"="vwififlt"
"CoServices"=hex(7):76,00,77,00,69,00,66,00,69,00,66,00,6c,00,74,00,00,00,00,\
  00
"HelpText"="Virtual WiFi Filter Driver"
"FilterClass"="ms_medium_converter_128"
"FilterType"=dword:00000002
"FilterRunType"=dword:00000002
"TimeStamp"=hex:e6,07,01,00,03,00,1a,00,0e,00,0b,00,2d,00,46,03

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{5CBF81BF-5055-47CD-9055-A76B2B4E3698}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"
"FilterMediaTypes"="vwifi"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{6B7E8FF8-E9A2-46EB-A4EA-42CCA2D43C96}]
"Characteristics"=dword:00000000
"InfPath"="netserv.inf"
"InfSection"="Install.ndi"
"LocDescription"="@netserv.inf,%msserver_desc%;File and Printer Sharing for Microsoft Networks"
"Description"="File and Printer Sharing for Microsoft Networks"
"ComponentId"="ms_server"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,35,00,20,00,e8,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{6B7E8FF8-E9A2-46EB-A4EA-42CCA2D43C96}\Ndi]
"ClsID"="{7F368827-9516-11d0-83D9-00A0C911E5DF}"
"Service"="LanmanServer"
"CoServices"=hex(7):4c,00,61,00,6e,00,6d,00,61,00,6e,00,53,00,65,00,72,00,76,\
  00,65,00,72,00,00,00,00,00
"ExcludeSetupStartServices"=hex(7):4c,00,61,00,6e,00,6d,00,61,00,6e,00,53,00,\
  65,00,72,00,76,00,65,00,72,00,00,00,00,00
"HelpText"="@netcfgx.dll,-50003"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{6B7E8FF8-E9A2-46EB-A4EA-42CCA2D43C96}\Ndi\Interfaces]
"UpperRange"="winnet5"
"LowerRange"="tdi,netbios,ipx,netbios_smb"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{B5F4D659-7DAA-4565-8E41-BE220ED60542}]
"Characteristics"=dword:00040000
"InfPath"="netpacer.inf"
"InfSection"="Install"
"LocDescription"="@netpacer.inf,%psched_desc%;QoS Packet Scheduler"
"Description"="QoS Packet Scheduler"
"ComponentId"="ms_pacer"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,35,00,39,00,9a,02

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{B5F4D659-7DAA-4565-8E41-BE220ED60542}\Ndi]
"Service"="Psched"
"CoServices"=hex(7):50,00,73,00,63,00,68,00,65,00,64,00,00,00,00,00
"HelpText"="@%SystemRoot%\\System32\\drivers\\pacer.sys,-100"
"FilterClass"="scheduler"
"FilterType"=dword:00000002
"FilterRunType"=dword:00000002
"TimeStamp"=hex:e5,07,04,00,01,00,13,00,04,00,06,00,0c,00,99,03

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{B5F4D659-7DAA-4565-8E41-BE220ED60542}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"
"FilterMediaTypes"="ethernet, wan"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{B70D6460-3635-4D42-B866-B8AB1A24454C}]
"Characteristics"=dword:00040028
"InfPath"="wfplwf.inf"
"InfSection"="Install"
"LocDescription"="@wfplwf.inf,%wfplwf_desc%;WFP Lightweight Filter"
"Description"="WFP Lightweight Filter"
"ComponentId"="ms_wfplwf"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,30,00,47,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{B70D6460-3635-4D42-B866-B8AB1A24454C}\Ndi]
"Service"="WfpLwf"
"CoServices"=hex(7):57,00,66,00,70,00,4c,00,77,00,66,00,00,00,00,00
"HelpText"="WFP Lightweight Filter"
"FilterClass"="ms_firewall_upper"
"FilterType"=dword:00000002
"FilterRunType"=dword:00000001
"TimeStamp"=hex:e5,07,04,00,01,00,13,00,04,00,06,00,10,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{B70D6460-3635-4D42-B866-B8AB1A24454C}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"
"FilterMediaTypes"="ethernet"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{C9548B78-5743-4E64-9BA1-CD4D974A329F}]
"Characteristics"=dword:00000038
"InfPath"="netrass.inf"
"InfSection"="Ndi-RasSrv"
"LocDescription"="@netrass.inf,%rassrv-dispname%;Dial-Up Server"
"Description"="Dial-Up Server"
"ComponentId"="ms_rassrv"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,2d,00,84,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{C9548B78-5743-4E64-9BA1-CD4D974A329F}\Ndi]
"ClsID"="{6e65cbc1-926d-11d0-8e27-00c04fc99dcf}"
"ComponentDll"="rascfg.dll"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{C9548B78-5743-4E64-9BA1-CD4D974A329F}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{E475CF9A-60CD-4439-A75F-0079CE0E18A1}]
"Characteristics"=dword:00040028
"InfPath"="netnwifi.inf"
"InfSection"="MS_NWIFI.Install"
"LocDescription"="@netnwifi.inf,%ms_nwifi.displayname%;NativeWiFi Filter"
"Description"="NativeWiFi Filter"
"ComponentId"="ms_nativewifip"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,37,00,02,00,58,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{E475CF9A-60CD-4439-A75F-0079CE0E18A1}\Ndi]
"Service"="NativeWifiP"
"CoServices"=hex(7):4e,00,61,00,74,00,69,00,76,00,65,00,57,00,69,00,66,00,69,\
  00,50,00,00,00,00,00
"HelpText"=""
"FilterClass"="ms_medium_converter_top"
"FilterType"=dword:00000002
"FilterRunType"=dword:00000001
"TimeStamp"=hex:e5,07,04,00,01,00,13,00,04,00,06,00,0e,00,a5,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{E475CF9A-60CD-4439-A75F-0079CE0E18A1}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"
"FilterMediaTypes"="wlan"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{EA24CD6C-D17A-4348-9190-09F0D5BE83DD}]
"Characteristics"=dword:00040038
"InfPath"="ndiscap.inf"
"InfSection"="Install"
"LocDescription"="@ndiscap.inf,%ndiscap_desc%;NDIS Capture LightWeight Filter"
"Description"="NDIS Capture LightWeight Filter"
"ComponentId"="MS_NDISCAP"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,36,00,26,00,f2,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{EA24CD6C-D17A-4348-9190-09F0D5BE83DD}\Ndi]
"Service"="NdisCap"
"CoServices"=hex(7):4e,00,64,00,69,00,73,00,43,00,61,00,70,00,00,00,00,00
"HelpText"="Packet Capture Filter Driver"
"FilterClass"="failover"
"FilterType"=dword:00000001
"FilterRunType"=dword:00000002
"ClsID"="{D212B88E-8365-4CA9-BC4E-CFA4251F6B5F}"
"ComponentDll"="ndiscapCfg.dll"
"TimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,36,00,26,00,d3,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{EA24CD6C-D17A-4348-9190-09F0D5BE83DD}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"
"FilterMediaTypes"="ethernet, wlan, ppip"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{F5658C39-CD0D-45B5-A342-E2C037714CE4}]
"Characteristics"=dword:00000028
"InfPath"="netrass.inf"
"InfSection"="Ndi-RasMan"
"LocDescription"="@netrass.inf,%rasman-dispname%;Remote Access Connection Manager"
"Description"="Remote Access Connection Manager"
"ComponentId"="ms_rasman"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,1e,00,f3,02

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{F5658C39-CD0D-45B5-A342-E2C037714CE4}\Ndi]
"Service"="RasMan"
"CoServices"=hex(7):52,00,61,00,73,00,41,00,63,00,64,00,00,00,52,00,61,00,73,\
  00,41,00,75,00,74,00,6f,00,00,00,00,00
"ExcludeSetupStartServices"=hex(7):52,00,61,00,73,00,41,00,63,00,64,00,00,00,\
  52,00,61,00,73,00,41,00,75,00,74,00,6f,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{F5658C39-CD0D-45B5-A342-E2C037714CE4}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{12F2EEA2-EE86-4933-8C0B-346E5E57F332}]
"Characteristics"=dword:00000028
"InfPath"="netrast.inf"
"InfSection"="Ndi-PppoeProtocol"
"LocDescription"="@netrast.inf,%pppoe-dispname%;Point to Point Protocol Over Ethernet"
"Description"="Point to Point Protocol Over Ethernet"
"ComponentId"="ms_pppoe"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,20,00,fd,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{12F2EEA2-EE86-4933-8C0B-346E5E57F332}\Ndi]
"ClsID"="{e949da38-c39d-4460-8ea7-a39152c56836}"
"ComponentDll"="rascfg.dll"
"Service"="RasPppoe"
"HelpText"="@%systemroot%\\system32\\rascfg.dll,-32010"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{12F2EEA2-EE86-4933-8C0B-346E5E57F332}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="ndis4,ndis5"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{234991D1-04CC-47F5-A4A9-29808D68765F}]
"Characteristics"=dword:00000028
"InfPath"="nettcpip.inf"
"InfSection"="MS_WINS.PrimaryInstall"
"LocDescription"="@nettcpip.inf,%ms_wins.displayname%;WINS Client(TCP/IP) Protocol"
"Description"="WINS Client(TCP/IP) Protocol"
"ComponentId"="ms_netbt"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,35,00,14,00,dc,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{234991D1-04CC-47F5-A4A9-29808D68765F}\Ndi]
"Service"="NetBT"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{234991D1-04CC-47F5-A4A9-29808D68765F}\Ndi\Interfaces]
"UpperRange"="netbios"
"LowerRange"="tdi"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{24AB3BC7-8C0C-4389-A4D4-8B8FD6ADEA7A}]
"Characteristics"=dword:00000038
"InfPath"="netrast.inf"
"InfSection"="Ndi-PptpProtocol"
"LocDescription"="@netrast.inf,%pptp-dispname%;Point to Point Tunneling Protocol"
"Description"="Point to Point Tunneling Protocol"
"ComponentId"="ms_pptp"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,1f,00,ba,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{24AB3BC7-8C0C-4389-A4D4-8B8FD6ADEA7A}\Ndi]
"ClsID"="{6e65cbc4-926d-11d0-8e27-00c04fc99dcf}"
"ComponentDll"="rascfg.dll"
"HelpText"="@%systemroot%\\system32\\rascfg.dll,-32009"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{24AB3BC7-8C0C-4389-A4D4-8B8FD6ADEA7A}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{27EE12EA-A6B3-4E15-AF2B-D4B9D989EDFB}]
"Characteristics"=dword:00000028
"InfPath"="nettcpip.inf"
"InfSection"="MS_TCPIP.Tunnel.PrimaryInstall"
"LocDescription"="@nettcpip.inf,%ms_tcpip.tunnel.displayname%;Internet Protocol (TCP/IP) - Tunnels"
"Description"="Internet Protocol (TCP/IP) - Tunnels"
"ComponentId"="ms_tcpip_tunnel"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,36,00,28,00,34,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{27EE12EA-A6B3-4E15-AF2B-D4B9D989EDFB}\Linkage]
"Bind"=hex(7):00,00
"Route"=hex(7):00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,54,00,43,00,50,\
  00,49,00,50,00,54,00,55,00,4e,00,4e,00,45,00,4c,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{27EE12EA-A6B3-4E15-AF2B-D4B9D989EDFB}\Ndi]
"BindForm"="TCPIPTUNNEL"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{27EE12EA-A6B3-4E15-AF2B-D4B9D989EDFB}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="ndis5_tunnel"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2B07FAA1-8217-4E30-B5EC-FD4501E773BB}]
"Characteristics"=dword:00000028
"InfPath"="netip6.inf"
"InfSection"="MS_TCPIP6.Tunnel.Install"
"LocDescription"="@netip6.inf,%ms_tcpip6.tunnel.displayname%;Microsoft TCP/IP version 6 - Tunnels"
"Description"="Microsoft TCP/IP version 6 - Tunnels"
"ComponentId"="ms_tcpip6_tunnel"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,36,00,28,00,dc,03

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2B07FAA1-8217-4E30-B5EC-FD4501E773BB}\Linkage]
"Bind"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,38,00,34,\
  00,44,00,44,00,33,00,37,00,45,00,32,00,2d,00,30,00,30,00,35,00,45,00,2d,00,\
  34,00,36,00,44,00,45,00,2d,00,41,00,39,00,35,00,36,00,2d,00,34,00,34,00,39,\
  00,45,00,44,00,43,00,30,00,33,00,44,00,44,00,46,00,42,00,7d,00,00,00,5c,00,\
  44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,36,00,30,00,30,00,45,00,43,\
  00,38,00,41,00,31,00,2d,00,43,00,36,00,37,00,36,00,2d,00,34,00,44,00,37,00,\
  39,00,2d,00,39,00,31,00,38,00,46,00,2d,00,46,00,45,00,31,00,33,00,30,00,45,\
  00,43,00,39,00,46,00,33,00,33,00,36,00,7d,00,00,00,5c,00,44,00,65,00,76,00,\
  69,00,63,00,65,00,5c,00,7b,00,34,00,36,00,39,00,44,00,32,00,38,00,36,00,35,\
  00,2d,00,35,00,41,00,45,00,30,00,2d,00,34,00,41,00,36,00,41,00,2d,00,38,00,\
  31,00,38,00,46,00,2d,00,31,00,31,00,45,00,45,00,38,00,35,00,39,00,42,00,41,\
  00,37,00,33,00,43,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,\
  5c,00,7b,00,32,00,37,00,36,00,36,00,30,00,46,00,34,00,36,00,2d,00,34,00,38,\
  00,42,00,46,00,2d,00,34,00,36,00,36,00,45,00,2d,00,38,00,34,00,34,00,41,00,\
  2d,00,44,00,31,00,46,00,42,00,33,00,44,00,30,00,44,00,44,00,45,00,33,00,32,\
  00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,7b,00,38,00,\
  37,00,32,00,44,00,44,00,31,00,35,00,37,00,2d,00,43,00,37,00,41,00,33,00,2d,\
  00,34,00,30,00,30,00,45,00,2d,00,38,00,46,00,44,00,31,00,2d,00,35,00,33,00,\
  39,00,45,00,42,00,30,00,39,00,35,00,31,00,37,00,31,00,35,00,7d,00,00,00,00,\
  00
"Route"=hex(7):22,00,7b,00,38,00,34,00,44,00,44,00,33,00,37,00,45,00,32,00,2d,\
  00,30,00,30,00,35,00,45,00,2d,00,34,00,36,00,44,00,45,00,2d,00,41,00,39,00,\
  35,00,36,00,2d,00,34,00,34,00,39,00,45,00,44,00,43,00,30,00,33,00,44,00,44,\
  00,46,00,42,00,7d,00,22,00,00,00,22,00,7b,00,36,00,30,00,30,00,45,00,43,00,\
  38,00,41,00,31,00,2d,00,43,00,36,00,37,00,36,00,2d,00,34,00,44,00,37,00,39,\
  00,2d,00,39,00,31,00,38,00,46,00,2d,00,46,00,45,00,31,00,33,00,30,00,45,00,\
  43,00,39,00,46,00,33,00,33,00,36,00,7d,00,22,00,00,00,22,00,7b,00,34,00,36,\
  00,39,00,44,00,32,00,38,00,36,00,35,00,2d,00,35,00,41,00,45,00,30,00,2d,00,\
  34,00,41,00,36,00,41,00,2d,00,38,00,31,00,38,00,46,00,2d,00,31,00,31,00,45,\
  00,45,00,38,00,35,00,39,00,42,00,41,00,37,00,33,00,43,00,7d,00,22,00,00,00,\
  22,00,7b,00,32,00,37,00,36,00,36,00,30,00,46,00,34,00,36,00,2d,00,34,00,38,\
  00,42,00,46,00,2d,00,34,00,36,00,36,00,45,00,2d,00,38,00,34,00,34,00,41,00,\
  2d,00,44,00,31,00,46,00,42,00,33,00,44,00,30,00,44,00,44,00,45,00,33,00,32,\
  00,7d,00,22,00,00,00,22,00,7b,00,38,00,37,00,32,00,44,00,44,00,31,00,35,00,\
  37,00,2d,00,43,00,37,00,41,00,33,00,2d,00,34,00,30,00,30,00,45,00,2d,00,38,\
  00,46,00,44,00,31,00,2d,00,35,00,33,00,39,00,45,00,42,00,30,00,39,00,35,00,\
  31,00,37,00,31,00,35,00,7d,00,22,00,00,00,00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,54,00,43,00,50,\
  00,49,00,50,00,36,00,54,00,55,00,4e,00,4e,00,45,00,4c,00,5f,00,7b,00,38,00,\
  34,00,44,00,44,00,33,00,37,00,45,00,32,00,2d,00,30,00,30,00,35,00,45,00,2d,\
  00,34,00,36,00,44,00,45,00,2d,00,41,00,39,00,35,00,36,00,2d,00,34,00,34,00,\
  39,00,45,00,44,00,43,00,30,00,33,00,44,00,44,00,46,00,42,00,7d,00,00,00,5c,\
  00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,54,00,43,00,50,00,49,00,50,00,\
  36,00,54,00,55,00,4e,00,4e,00,45,00,4c,00,5f,00,7b,00,36,00,30,00,30,00,45,\
  00,43,00,38,00,41,00,31,00,2d,00,43,00,36,00,37,00,36,00,2d,00,34,00,44,00,\
  37,00,39,00,2d,00,39,00,31,00,38,00,46,00,2d,00,46,00,45,00,31,00,33,00,30,\
  00,45,00,43,00,39,00,46,00,33,00,33,00,36,00,7d,00,00,00,5c,00,44,00,65,00,\
  76,00,69,00,63,00,65,00,5c,00,54,00,43,00,50,00,49,00,50,00,36,00,54,00,55,\
  00,4e,00,4e,00,45,00,4c,00,5f,00,7b,00,34,00,36,00,39,00,44,00,32,00,38,00,\
  36,00,35,00,2d,00,35,00,41,00,45,00,30,00,2d,00,34,00,41,00,36,00,41,00,2d,\
  00,38,00,31,00,38,00,46,00,2d,00,31,00,31,00,45,00,45,00,38,00,35,00,39,00,\
  42,00,41,00,37,00,33,00,43,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,\
  00,65,00,5c,00,54,00,43,00,50,00,49,00,50,00,36,00,54,00,55,00,4e,00,4e,00,\
  45,00,4c,00,5f,00,7b,00,32,00,37,00,36,00,36,00,30,00,46,00,34,00,36,00,2d,\
  00,34,00,38,00,42,00,46,00,2d,00,34,00,36,00,36,00,45,00,2d,00,38,00,34,00,\
  34,00,41,00,2d,00,44,00,31,00,46,00,42,00,33,00,44,00,30,00,44,00,44,00,45,\
  00,33,00,32,00,7d,00,00,00,5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,\
  54,00,43,00,50,00,49,00,50,00,36,00,54,00,55,00,4e,00,4e,00,45,00,4c,00,5f,\
  00,7b,00,38,00,37,00,32,00,44,00,44,00,31,00,35,00,37,00,2d,00,43,00,37,00,\
  41,00,33,00,2d,00,34,00,30,00,30,00,45,00,2d,00,38,00,46,00,44,00,31,00,2d,\
  00,35,00,33,00,39,00,45,00,42,00,30,00,39,00,35,00,31,00,37,00,31,00,35,00,\
  7d,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2B07FAA1-8217-4E30-B5EC-FD4501E773BB}\Ndi]
"BindForm"="TCPIP6TUNNEL"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2B07FAA1-8217-4E30-B5EC-FD4501E773BB}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="ndis5_tunnel,ndis5_ip6_tunnel"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2B4683A7-F97E-478E-BBD6-34EDF0D9DEA8}]
"Characteristics"=dword:00000038
"InfPath"="nettcpip.inf"
"InfSection"="MS_NETBT_SMB.PrimaryInstall"
"LocDescription"="@nettcpip.inf,%ms_netbt_smb.displayname%;Message-oriented TCP/IP Protocol (SMB session)"
"Description"="Message-oriented TCP/IP Protocol (SMB session)"
"ComponentId"="ms_netbt_smb"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,35,00,14,00,2a,02

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2B4683A7-F97E-478E-BBD6-34EDF0D9DEA8}\Linkage]
"Bind"=hex(7):00,00
"Route"=hex(7):00,00
"Export"=hex(7):5c,00,44,00,65,00,76,00,69,00,63,00,65,00,5c,00,4e,00,65,00,74,\
  00,62,00,69,00,6f,00,73,00,53,00,6d,00,62,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2B4683A7-F97E-478E-BBD6-34EDF0D9DEA8}\Ndi]
"BindForm"="NetbiosSmb"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2B4683A7-F97E-478E-BBD6-34EDF0D9DEA8}\Ndi\Interfaces]
"UpperRange"="netbios_smb"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2BE5AF45-DD00-422F-8484-8370DD108A53}]
"Characteristics"=dword:00000028
"InfPath"="ndisuio.inf"
"InfSection"="Install"
"LocDescription"="@ndisuio.inf,%ndisuio_desc%;NDIS Usermode I/O Protocol"
"Description"="NDIS Usermode I/O Protocol"
"ComponentId"="ms_ndisuio"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,17,00,98,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2BE5AF45-DD00-422F-8484-8370DD108A53}\Ndi]
"Service"="Ndisuio"
"HelpText"=""

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2BE5AF45-DD00-422F-8484-8370DD108A53}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="ndis5,ndis4,ndis5_uio,flpp4,flpp6"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2FF8F288-20AD-41F8-A181-321D0659CA4D}]
"Characteristics"=dword:00000000
"InfPath"="rspndr.inf"
"InfSection"="Install"
"LocDescription"="@rspndr.inf,%displayname%;Link-Layer Topology Discovery Responder"
"Description"="Link-Layer Topology Discovery Responder"
"ComponentId"="MS_RSPNDR"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,2b,00,2a,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2FF8F288-20AD-41F8-A181-321D0659CA4D}\Ndi]
"Service"="rspndr"
"HelpText"="@%SystemRoot%\\system32\\lltdres.dll,-3"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{2FF8F288-20AD-41F8-A181-321D0659CA4D}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="ndis5"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{32345029-1B7D-43AF-B504-E71E5660B2F0}]
"Characteristics"=dword:000000a0
"InfPath"="netip6.inf"
"InfSection"="MS_TCPIP6.Install"
"LocDescription"="@netip6.inf,%ms_tcpip6.displayname%;Internet Protocol Version 6 (TCP/IPv6)"
"Description"="Internet Protocol Version 6 (TCP/IPv6)"
"ComponentId"="ms_tcpip6"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,35,00,13,00,c1,03

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{32345029-1B7D-43AF-B504-E71E5660B2F0}\Ndi]
"BindForm"="Tcpip6"
"ClsId"="{0C41D1E6-9D16-41ED-9CDD-D0665039857B}"
"ComponentDll"="tcpipcfg.dll"
"HelpText"="@tcpipcfg.dll,-50002"
"Service"="Tcpip6"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{32345029-1B7D-43AF-B504-E71E5660B2F0}\Ndi\Interfaces]
"UpperRange"="tdi"
"LowerRange"="ndis5,ndis5_tunnel,ndis5_ip6_tunnel,flpp6"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{5D9F4D1D-F5B3-48BA-85AD-9B44176DD0C8}]
"Characteristics"=dword:000000a0
"InfPath"="nettcpip.inf"
"InfSection"="MS_TCPIP.PrimaryInstall"
"LocDescription"="@nettcpip.inf,%ms_tcpip.displayname%;Internet Protocol Version 4 (TCP/IPv4)"
"Description"="Internet Protocol Version 4 (TCP/IPv4)"
"ComponentId"="ms_tcpip"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,35,00,13,00,de,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{5D9F4D1D-F5B3-48BA-85AD-9B44176DD0C8}\Ndi]
"BindForm"="Tcpip"
"ClsId"="{A907657F-6FDF-11D0-8EFB-00C04FD912B2}"
"ComponentDll"="tcpipcfg.dll"
"HelpText"="@%SystemRoot%\\system32\\tcpipcfg.dll,-50001"
"Service"="Tcpip"
"CoServices"=hex(7):54,00,63,00,70,00,69,00,70,00,00,00,4e,00,65,00,74,00,62,\
  00,74,00,00,00,53,00,6d,00,62,00,00,00,4c,00,6d,00,68,00,6f,00,73,00,74,00,\
  73,00,00,00,44,00,68,00,63,00,70,00,00,00,54,00,64,00,78,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{5D9F4D1D-F5B3-48BA-85AD-9B44176DD0C8}\Ndi\Interfaces]
"UpperRange"="tdi"
"LowerRange"="ndis5,ndis5_ip,flpp4"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{633F880E-FFD2-484F-A4CA-EB724F8BC057}]
"Characteristics"=dword:00000000
"InfPath"="lltdio.inf"
"InfSection"="Install"
"LocDescription"="@lltdio.inf,%displayname%;Link-Layer Topology Discovery Mapper I/O Driver"
"Description"="Link-Layer Topology Discovery Mapper I/O Driver"
"ComponentId"="MS_LLTDIO"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,2b,00,3c,03

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{633F880E-FFD2-484F-A4CA-EB724F8BC057}\Ndi]
"Service"="lltdio"
"HelpText"="@%SystemRoot%\\system32\\lltdres.dll,-4"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{633F880E-FFD2-484F-A4CA-EB724F8BC057}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="ndis5"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{69E184C5-2F7C-45D0-8C56-85097BA63C11}]
"Characteristics"=dword:00000028
"InfPath"="netrast.inf"
"InfSection"="Ndi-NdisWan"
"LocDescription"="@netrast.inf,%ndiswan-dispname%;Remote Access NDIS WAN Driver"
"Description"="Remote Access NDIS WAN Driver"
"ComponentId"="ms_ndiswan"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,1e,00,a5,02

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{69E184C5-2F7C-45D0-8C56-85097BA63C11}\Ndi]
"ClsID"="{6e65cbc3-926d-11d0-8e27-00c04fc99dcf}"
"ComponentDll"="rascfg.dll"
"Service"="NdisWan"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{69E184C5-2F7C-45D0-8C56-85097BA63C11}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="ndisatm,ndiscowan,ndiswan,ndiswanasync"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{69E184C5-2F7C-45D0-8C56-85097BA63C11}\Parameters]
"QoSPriorityThreshold"=dword:00000000
"QoSFragmentSize"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{6D9E377D-E19D-47CF-BE5F-D2DA5F99318A}]
"Characteristics"=dword:00000038
"InfPath"="netsstpt.inf"
"InfSection"="Ndi-SstpProtocol"
"LocDescription"="@netsstpt.inf,%sstp-dispname%;SSTP based VPN"
"Description"="SSTP based VPN"
"ComponentId"="ms_sstp"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,1b,00,59,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{6D9E377D-E19D-47CF-BE5F-D2DA5F99318A}\Ndi]
"ClsID"="{0F0C09C5-601E-4396-BCD0-CDB343D7F657}"
"ComponentDll"="rascfg.dll"
"HelpText"="@%systemroot%\\system32\\sstpsvc.dll,-203"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{6D9E377D-E19D-47CF-BE5F-D2DA5F99318A}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{7D857581-4BD0-44AB-B87C-921422A69D39}]
"Characteristics"=dword:00000028
"InfPath"="netrast.inf"
"InfSection"="Ndi-Wanarp"
"LocDescription"="@netrast.inf,%wanarp-dispname%;Remote Access IP ARP Driver"
"Description"="Remote Access IP ARP Driver"
"ComponentId"="MS_wanarp"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,35,00,15,00,6d,01

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{7D857581-4BD0-44AB-B87C-921422A69D39}\Ndi]
"Service"="Wanarp"
"CoServices"=hex(7):57,00,61,00,6e,00,61,00,72,00,70,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{7D857581-4BD0-44AB-B87C-921422A69D39}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="ndiswanip"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{7F218BFD-64B7-4786-8302-9D8A2704B0E2}]
"Characteristics"=dword:00000038
"InfPath"="netavpnt.inf"
"InfSection"="Ndi-AgileVpnProtocol"
"LocDescription"="@netavpnt.inf,%agilevpn-dispname%;AgileVpn based VPN"
"Description"="AgileVpn based VPN"
"ComponentId"="ms_agilevpn"
"InstallTimeStamp"=hex:da,07,0b,00,00,00,15,00,03,00,27,00,37,00,8e,02

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{7F218BFD-64B7-4786-8302-9D8A2704B0E2}\Ndi]
"ClsID"="{7177c4bd-e20a-4140-ad8a-998e7a2d18c0}"
"ComponentDll"="rascfg.dll"
"HelpText"="Allows you to securely connect to a private network using the Internet."

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{7F218BFD-64B7-4786-8302-9D8A2704B0E2}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{92356401-DAAE-49DA-8D29-5B023CCF4CD9}]
"Characteristics"=dword:00000028
"InfPath"="nettcpip.inf"
"InfSection"="MS_SMB.Install"
"LocDescription"="@nettcpip.inf,%ms_smb.displayname%;Microsoft NetbiosSmb"
"Description"="Microsoft NetbiosSmb"
"ComponentId"="MS_SMB"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,35,00,38,00,86,03

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{92356401-DAAE-49DA-8D29-5B023CCF4CD9}\Ndi]
"Service"="Smb"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{92356401-DAAE-49DA-8D29-5B023CCF4CD9}\Ndi\Interfaces]
"UpperRange"="netbios_smb"
"LowerRange"="tdi"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{E7AC61F5-4BFE-4254-8889-98A990D174D5}]
"Characteristics"=dword:00000038
"InfPath"="netrast.inf"
"InfSection"="Ndi-L2tpProtocol"
"LocDescription"="@netrast.inf,%l2tp-dispname%;Layer 2 Tunneling Protocol"
"Description"="Layer 2 Tunneling Protocol"
"ComponentId"="ms_l2tp"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,1e,00,41,03

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{E7AC61F5-4BFE-4254-8889-98A990D174D5}\Ndi]
"ClsID"="{6e65cbc6-926d-11d0-8e27-00c04fc99dcf}"
"ComponentDll"="rascfg.dll"
"HelpText"="@%systemroot%\\system32\\rascfg.dll,-32008"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{E7AC61F5-4BFE-4254-8889-98A990D174D5}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="nolower"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{F27D2AC4-396D-442D-9FD8-05AEF1E98AAB}]
"Characteristics"=dword:00000028
"InfPath"="netrast.inf"
"InfSection"="Ndi-Wanarpv6"
"LocDescription"="@netrast.inf,%wanarpv6-dispname%;Remote Access IPv6 ARP Driver"
"Description"="Remote Access IPv6 ARP Driver"
"ComponentId"="MS_wanarpv6"
"InstallTimeStamp"=hex:d9,07,07,00,02,00,0e,00,04,00,31,00,21,00,cf,02

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{F27D2AC4-396D-442D-9FD8-05AEF1E98AAB}\Ndi]
"Service"="Wanarpv6"
"CoServices"=hex(7):57,00,61,00,6e,00,61,00,72,00,70,00,76,00,36,00,00,00,00,\
  00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E975-E325-11CE-BFC1-08002BE10318}\{F27D2AC4-396D-442D-9FD8-05AEF1E98AAB}\Ndi\Interfaces]
"UpperRange"="noupper"
"LowerRange"="ndiswanipv6"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\LEGACY_NDISTAPI]
"NextInstance"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\LEGACY_RASACD]
"NextInstance"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\LEGACY_RASACD\0000]
"Service"="RasAcd"
"Legacy"=dword:00000001
"ConfigFlags"=dword:00000000
"Class"="LegacyDriver"
"ClassGUID"="{8ECC055D-047F-11D1-A537-0000F8753ED1}"
"DeviceDesc"="Remote Access Auto Connection Driver"
"Capabilities"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\LEGACY_RASACD\0000\Control]
"ActiveService"="RasAcd"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_L2TPMINIPORT]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_L2TPMINIPORT\0000]
"ClassGUID"="{4d36e972-e325-11ce-bfc1-08002be10318}"
"Class"="Net"
"HardwareID"=hex(7):6d,00,73,00,5f,00,6c,00,32,00,74,00,70,00,6d,00,69,00,6e,\
  00,69,00,70,00,6f,00,72,00,74,00,00,00,00,00
"Driver"="{4d36e972-e325-11ce-bfc1-08002be10318}\\0002"
"Mfg"="@netrasa.inf,%msft%;Microsoft"
"Service"="Rasl2tp"
"DeviceDesc"="@netrasa.inf,%mp-l2tp-dispname%;WAN Miniport (L2TP)"
"ConfigFlags"=dword:00000000
"Capabilities"=dword:00000000
"ContainerID"="{00000000-0000-0000-FFFF-FFFFFFFFFFFF}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_L2TPMINIPORT\0000\Device Parameters]
"InstanceIndex"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_L2TPMINIPORT\0000\LogConf]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANBH]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANBH\0000]
"ClassGUID"="{4d36e972-e325-11ce-bfc1-08002be10318}"
"Class"="Net"
"HardwareID"=hex(7):6d,00,73,00,5f,00,6e,00,64,00,69,00,73,00,77,00,61,00,6e,\
  00,62,00,68,00,00,00,00,00
"Driver"="{4d36e972-e325-11ce-bfc1-08002be10318}\\0006"
"Mfg"="@netrasa.inf,%msft%;Microsoft"
"Service"="NdisWan"
"DeviceDesc"="@netrasa.inf,%mp-bh-dispname%;WAN Miniport (Network Monitor)"
"ConfigFlags"=dword:00000000
"Capabilities"=dword:00000000
"ContainerID"="{00000000-0000-0000-FFFF-FFFFFFFFFFFF}"
"LowerFilters"=hex(7):4e,00,64,00,69,00,73,00,54,00,61,00,70,00,69,00,00,00,00,\
  00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANBH\0000\Device Parameters]
"InstanceIndex"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANBH\0000\LogConf]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANIP]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANIP\0000]
"ClassGUID"="{4d36e972-e325-11ce-bfc1-08002be10318}"
"Class"="Net"
"HardwareID"=hex(7):6d,00,73,00,5f,00,6e,00,64,00,69,00,73,00,77,00,61,00,6e,\
  00,69,00,70,00,00,00,00,00
"Driver"="{4d36e972-e325-11ce-bfc1-08002be10318}\\0008"
"Mfg"="@netrasa.inf,%msft%;Microsoft"
"Service"="NdisWan"
"DeviceDesc"="@netrasa.inf,%mp-ip-dispname%;WAN Miniport (IP)"
"ConfigFlags"=dword:00000000
"Capabilities"=dword:00000000
"ContainerID"="{00000000-0000-0000-FFFF-FFFFFFFFFFFF}"
"LowerFilters"=hex(7):4e,00,64,00,69,00,73,00,54,00,61,00,70,00,69,00,00,00,00,\
  00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANIP\0000\Device Parameters]
"InstanceIndex"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANIP\0000\LogConf]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PPPOEMINIPORT]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PPPOEMINIPORT\0000]
"ClassGUID"="{4d36e972-e325-11ce-bfc1-08002be10318}"
"Class"="Net"
"HardwareID"=hex(7):6d,00,73,00,5f,00,70,00,70,00,70,00,6f,00,65,00,6d,00,69,\
  00,6e,00,69,00,70,00,6f,00,72,00,74,00,00,00,00,00
"Driver"="{4d36e972-e325-11ce-bfc1-08002be10318}\\0004"
"Mfg"="@netrasa.inf,%msft%;Microsoft"
"Service"="RasPppoe"
"DeviceDesc"="@netrasa.inf,%mp-pppoe-dispname%;WAN Miniport (PPPOE)"
"ConfigFlags"=dword:00000000
"Capabilities"=dword:00000000
"ContainerID"="{00000000-0000-0000-FFFF-FFFFFFFFFFFF}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PPPOEMINIPORT\0000\Device Parameters]
"InstanceIndex"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PPPOEMINIPORT\0000\LogConf]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PPTPMINIPORT]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PPTPMINIPORT\0000]
"ClassGUID"="{4d36e972-e325-11ce-bfc1-08002be10318}"
"Class"="Net"
"HardwareID"=hex(7):6d,00,73,00,5f,00,70,00,70,00,74,00,70,00,6d,00,69,00,6e,\
  00,69,00,70,00,6f,00,72,00,74,00,00,00,00,00
"Driver"="{4d36e972-e325-11ce-bfc1-08002be10318}\\0003"
"Mfg"="@netrasa.inf,%msft%;Microsoft"
"Service"="PptpMiniport"
"DeviceDesc"="@netrasa.inf,%mp-pptp-dispname%;WAN Miniport (PPTP)"
"ConfigFlags"=dword:00000000
"Capabilities"=dword:00000000
"ContainerID"="{00000000-0000-0000-FFFF-FFFFFFFFFFFF}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PPTPMINIPORT\0000\Device Parameters]
"InstanceIndex"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PPTPMINIPORT\0000\LogConf]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ras]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ras\CurrentVersion]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Router]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Router\CurrentVersion]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Router\CurrentVersion\RouterManagers]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Router\CurrentVersion\RouterManagers\Ip]
"ConfigClsid"="58bdf951-f471-11cf-aa67-00805f0c9232"
"ConfigDll"="ipadmin.dll"
"DllPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,69,\
  00,70,00,72,00,74,00,72,00,6d,00,67,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ProtocolId"=dword:00000021
"Title"="@%Systemroot%\\system32\\iprtrmgr.dll,-200"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Router\CurrentVersion\RouterManagers\Ipv6]
"ConfigClsid"="58bdf951-f471-11cf-aa67-00805f0c9232"
"ConfigDll"="ipadmin.dll"
"DllPath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,69,\
  00,70,00,72,00,74,00,72,00,6d,00,67,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ProtocolId"=dword:00000057
"Title"="@%Systemroot%\\system32\\iprtrmgr.dll,-201"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Router\CurrentVersion\UiConfigDlls]
"58bdf950-f471-11cf-aa67-00805f0c9232"="ifadmin.dll"
"58bdf951-f471-11cf-aa67-00805f0c9232"="ipadmin.dll"
"58bdf953-f471-11cf-aa67-00805f0c9232"="ddmadmin.dll"

The following registry keys were not found:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppleTalk\Parameters\Adapters\NdisWanAtalk
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpInIp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NwlnkFlt
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NwlnkFwd
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NwlnkIpx\Parameters\Adapters\NdisWanIpx
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rasirda
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Raspti
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\NdisWanIp
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\LEGACY_RASMAN
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\LEGACY_WANARP
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_IRDAMINIPORT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_IRMODEMMINIPORT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_L2TPMINIPORT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANATALK
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANBH
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANIP
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_NDISWANIPX
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PPPOEMINIPORT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PPTPMINIPORT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\MS_PTIMINIPORT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\ROOT\SW&{EEAB7790-C514-11D1-B42B-00805FC1270E}
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Connection Manager
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Connection Manager
Installed Devices [ Table Of Contents ]
01 WAN Miniport (SSTP)                           vpn            
02 WAN Miniport (SSTP)                           vpn            
03 WAN Miniport (PPTP)                           vpn            
04 WAN Miniport (PPTP)                           vpn            
05 WAN Miniport (PPPOE)                          pppoe          
06 WAN Miniport (L2TP)                           vpn            
07 WAN Miniport (L2TP)                           vpn            
08 WAN Miniport (IKEv2)                          vpn            
09 WAN Miniport (IKEv2)                          vpn            
Process Information [ Table Of Contents ]
   0 System Process  
   4 System          
 284 smss.exe        
 368 csrss.exe       
 408 wininit.exe     
 420 csrss.exe       Title:  
 456 services.exe    
 472 lsass.exe       Svcs:  EFS,KeyIso,SamSs
 480 lsm.exe         
 528 winlogon.exe    
 632 svchost.exe     Svcs:  PlugPlay,Power
 708 svchost.exe     Svcs:  RpcEptMapper,RpcSs
 792 svchost.exe     Svcs:  eventlog,lmhosts,wscsvc
 860 svchost.exe     Svcs:  hidserv,Netman,PcaSvc,SysMain,TrkWks,UmRdpService,UxSms,Wlansvc,WPDBusEnum,wudfsvc
 908 svchost.exe     Svcs:  EventSystem,fdPHost,FontCache,netprofm,nsi,sppuinotify,SstpSvc,WdiServiceHost,WinHttpAutoProxySvc
 932 svchost.exe     Svcs:  EapHost,IKEEXT,iphlpsvc,LanmanServer,MMCSS,ProfSvc,RasAuto,RasMan,Schedule,SENS,SessionEnv,SharedAccess,ShellHWDetection,Themes,Winmgmt,wuauserv
 112 audiodg.exe     
 300 svchost.exe     Svcs:  gpsvc
1116 svchost.exe     Svcs:  Dnscache,LanmanWorkstation,NlaSvc,TapiSrv,TermService,Wecsvc
1328 spoolsv.exe     Svcs:  Spooler
1356 svchost.exe     Svcs:  DPS,MpsSvc
1472 svchost.exe     
1520 svchost.exe     Svcs:  FDResPub,SSDPSRV,upnphost,wcncsvc
1596 SMSvcHost.exe   Svcs:  NetPipeActivator,NetTcpActivator,NetTcpPortSharing
1692 svchost.exe     Svcs:  stisvc
1752 svchost.exe     Svcs:  W3SVC,WAS
1804 InstallService.exeSvcs:  Wireless Modem Service
1904 svchost.exe     
2236 svchost.exe     Svcs:  PolicyAgent
2260 svchost.exe     Svcs:  WinDefend
2708 WUDFHost.exe    
2876 taskhost.exe    Title:  MCI command handling window
3068 dwm.exe         Title:  DWM Notification Window
1096 explorer.exe    Title:  Program Manager
2592 ehshell.exe     Title:  Windows Media Center
2604 odbcad32.exe    Title:  Microsoft ODBC Administrator
2624 HelpPane.exe    Title:  Windows Help and Support
2772 iexplore.exe    Title:  New tab - Internet Explorer
3036 iexplore.exe    Title:  
 836 SearchIndexer.exeSvcs:  WSearch
3404 GoogleCrashHandler.exe
3428 GoogleCrashHandler64.exe
3652 chrome.exe      Title:  D-Link - DWR-932C - Google Chrome
3712 chrome.exe      Title:  
3924 chrome.exe      
3992 chrome.exe      
2544 chrome.exe      
2568 chrome.exe      
3092 chrome.exe      
2044 SearchProtocolHost.exe
4180 chrome.exe      
4536 chrome.exe      
4648 chrome.exe      
4736 chrome.exe      
4968 chrome.exe      
4144 mscorsvw.exe    
4256 mscorsvw.exe    
3320 sppsvc.exe      Svcs:  sppsvc
3552 wmpnetwk.exe    Svcs:  WMPNetworkSvc
6116 svchost.exe     Svcs:  SDRSVC
5212 DeviceProperties.exeTitle:  CicMarshalWnd
 776 msdt.exe        Title:  Windows Network Diagnostics
6308 sdiagnhost.exe  Title:  C:\Windows\System32\sdiagnhost.exe
5956 conhost.exe     
3936 wuauclt.exe     Title:  Windows Update Taskbar Notification
6048 msconfig.exe    Title:  System Configuration
3492 cmd.exe         Title:  Administrator: C:\Windows\System32\cmd.exe
6708 conhost.exe     Title:  CicMarshalWnd
6496 ehrecvr.exe     Svcs:  ehRecvr
6704 ehsched.exe     Svcs:  ehSched
3172 ehtray.exe      Title:  Windows Media Center
7144 wmplayer.exe    Title:  ms_sqlce_se_notify_wndproc
7240 mmc.exe         Title:  Device Manager
3524 mmc.exe         Title:  Device Manager
3984 msdt.exe        Title:  Windows Network Diagnostics
8596 sdiagnhost.exe  Title:  C:\Windows\System32\sdiagnhost.exe
6276 conhost.exe     
5104 chrome.exe      
8752 notepad.exe     Title:  Untitled - Notepad
7652 wlanext.exe     
5348 conhost.exe     
7872 chrome.exe      
4496 chrome.exe      
3688 chrome.exe      
8864 chrome.exe      
8436 chrome.exe      
8676 chrome.exe      
5228 chrome.exe      
4460 chrome.exe      
 184 chrome.exe      
2464 chrome.exe      
5500 chrome.exe      
8532 chrome.exe      
6820 chrome.exe      
5164 chrome.exe      
6644 alg.exe         
5452 rundll32.exe    Title:  
7272 drvinst.exe     
7296 drvinst.exe     
8072 dinotify.exe    Title:  DINotifyWindowName853
4284 TrustedInstaller.exeSvcs:  TrustedInstaller
3676 regedit.exe     Title:  Registry Editor
7280 rundll32.exe    Title:  
4456 WmiPrvSE.exe    
5636 drvinst.exe     
8388 drvinst.exe     
6992 svchost.exe     Svcs:  WerSvc
 400 SearchFilterHost.exe
7176 dllhost.exe     Title:  OleMainThreadWndName
Command-Line Utilities [ Table Of Contents ]
arp.exe -a [ Table Of Contents ]
Interface: 192.168.0.14 --- 0x1f
  Internet Address      Physical Address      Type
  192.168.0.1           96-66-e6-49-7c-7b     dynamic   
  192.168.0.255         ff-ff-ff-ff-ff-ff     static    
  224.0.0.2             01-00-5e-00-00-02     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  224.0.0.251           01-00-5e-00-00-fb     static    
  224.0.0.252           01-00-5e-00-00-fc     static    
  239.255.255.250       01-00-5e-7f-ff-fa     static    
  255.255.255.255       ff-ff-ff-ff-ff-ff     static    

ipconfig.exe /all [ Table Of Contents ]
Windows IP Configuration

   Host Name . . . . . . . . . . . . : BEHNAMKHANI-PC
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection 9:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Remote NDIS based Internet Sharing Device #8
   Physical Address. . . . . . . . . : 66-64-58-FA-F2-FD
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::a52a:7b1f:870d:1af%31(Preferred) 
   IPv4 Address. . . . . . . . . . . : 192.168.0.14(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Thursday, February 03, 2022 3:51:28 AM
   Lease Expires . . . . . . . . . . : Thursday, February 03, 2022 3:51:28 PM
   Default Gateway . . . . . . . . . : 192.168.0.1
   DHCP Server . . . . . . . . . . . : 192.168.0.1
   DHCPv6 IAID . . . . . . . . . . . : 526804056
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-29-83-0E-D6-00-25-4B-D1-9D-88
   DNS Servers . . . . . . . . . . . : 192.168.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Wireless LAN adapter Wireless Network Connection 3:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft Virtual WiFi Miniport Adapter #2
   Physical Address. . . . . . . . . : 00-25-4B-9B-A9-46
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Wireless LAN adapter Wireless Network Connection:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Broadcom 802.11n Network Adapter
   Physical Address. . . . . . . . . : 00-25-4B-9B-A9-46
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes

Ethernet adapter Bluetooth Network Connection:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Bluetooth Device (Personal Area Network)
   Physical Address. . . . . . . . . : 00-25-BC-65-4C-0E
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter isatap.{D77366DC-8430-4300-B82F-8E84A815186C}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter isatap.{91A6805D-1002-48DC-9740-DEF86A797131}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter isatap.{76C8AC49-E5DC-4BE0-98E4-B3FAA3318C32}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #3
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter isatap.{7857D8BE-61B9-4C0A-8699-0623CFCDF9B7}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #4
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter Local Area Connection* 11:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #7
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

ipconfig.exe /displaydns [ Table Of Contents ]
Windows IP Configuration

    dc.services.visualstudio.com
    ----------------------------------------
    Record Name . . . . . : dc.services.visualstudio.com
    Record Type . . . . . : 5
    Time To Live  . . . . : 181
    Data Length . . . . . : 8
    Section . . . . . . . : Answer
    CNAME Record  . . . . : dc.applicationinsights.microsoft.com


    safebrowsing.googleapis.com
    ----------------------------------------
    Record Name . . . . . : safebrowsing.googleapis.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 160
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 172.217.21.42


    teredo.ipv6.microsoft.com
    ----------------------------------------
    Name does not exist.


    ds.download.windowsupdate.com
    ----------------------------------------
    Record Name . . . . . : ds.download.windowsupdate.com
    Record Type . . . . . : 5
    Time To Live  . . . . : 23
    Data Length . . . . . : 8
    Section . . . . . . . : Answer
    CNAME Record  . . . . : wu-bg-shim.trafficmanager.net


    ing-district.clicktale.net
    ----------------------------------------
    Record Name . . . . . : ing-district.clicktale.net
    Record Type . . . . . : 5
    Time To Live  . . . . : 160
    Data Length . . . . . : 8
    Section . . . . . . . : Answer
    CNAME Record  . . . . : webrecorder-prod-1682395302.us-east-1.elb.amazonaws.com



route.exe print [ Table Of Contents ]
===========================================================================
Interface List
 31...66 64 58 fa f2 fd ......Remote NDIS based Internet Sharing Device #8
 21...00 25 4b 9b a9 46 ......Microsoft Virtual WiFi Miniport Adapter #2
 20...00 25 4b 9b a9 46 ......Broadcom 802.11n Network Adapter
 19...00 25 bc 65 4c 0e ......Bluetooth Device (Personal Area Network)
  1...........................Software Loopback Interface 1
 27...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter
 29...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #2
 23...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #3
 28...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #4
 46...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #7
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.0.1     192.168.0.14     20
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    306
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    306
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    306
      192.168.0.0    255.255.255.0         On-link      192.168.0.14    276
     192.168.0.14  255.255.255.255         On-link      192.168.0.14    276
    192.168.0.255  255.255.255.255         On-link      192.168.0.14    276
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    306
        224.0.0.0        240.0.0.0         On-link      192.168.0.14    276
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    306
  255.255.255.255  255.255.255.255         On-link      192.168.0.14    276
===========================================================================
Persistent Routes:
  None

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    306 ::1/128                  On-link
 31    276 fe80::/64                On-link
 31    276 fe80::a52a:7b1f:870d:1af/128
                                    On-link
  1    306 ff00::/8                 On-link
 31    276 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None

net.exe start [ Table Of Contents ]
These Windows services are started:

   Application Host Helper Service
   Application Layer Gateway Service
   Background Intelligent Transfer Service
   Base Filtering Engine
   Bluetooth Support Service
   Certificate Propagation
   CNG Key Isolation
   COM+ Event System
   Computer Browser
   Cryptographic Services
   DCOM Server Process Launcher
   Desktop Window Manager Session Manager
   DHCP Client
   Diagnostic Policy Service
   Diagnostic Service Host
   Distributed Link Tracking Client
   DNS Client
   Encrypting File System (EFS)
   Extensible Authentication Protocol
   Function Discovery Provider Host
   Function Discovery Resource Publication
   Group Policy Client
   Human Interface Device Access
   IKE and AuthIP IPsec Keying Modules
   Internet Connection Sharing (ICS)
   IP Helper
   IPsec Policy Agent
   Microsoft .NET Framework NGEN v4.0.30319_X64
   Microsoft .NET Framework NGEN v4.0.30319_X86
   Multimedia Class Scheduler
   Net.Pipe Listener Adapter
   Net.Tcp Listener Adapter
   Net.Tcp Port Sharing Service
   Network Connections
   Network List Service
   Network Location Awareness
   Network Store Interface Service
   Offline Files
   Plug and Play
   Portable Device Enumerator Service
   Power
   Print Spooler
   Program Compatibility Assistant Service
   Remote Access Auto Connection Manager
   Remote Access Connection Manager
   Remote Desktop Configuration
   Remote Desktop Services
   Remote Desktop Services UserMode Port Redirector
   Remote Procedure Call (RPC)
   RPC Endpoint Mapper
   Secure Socket Tunneling Protocol Service
   Security Accounts Manager
   Security Center
   Server
   Shell Hardware Detection
   Software Protection
   SPP Notification Service
   SSDP Discovery
   Superfetch
   System Event Notification Service
   Task Scheduler
   TCP/IP NetBIOS Helper
   Telephony
   Themes
   UPnP Device Host
   User Profile Service
   Windows Audio
   Windows Audio Endpoint Builder
   Windows Backup
   Windows Connect Now - Config Registrar
   Windows Defender
   Windows Driver Foundation - User-mode Driver Framework
   Windows Error Reporting Service
   Windows Event Collector
   Windows Event Log
   Windows Firewall
   Windows Font Cache Service
   Windows Image Acquisition (WIA)
   Windows Management Instrumentation
   Windows Media Center Receiver Service
   Windows Media Center Scheduler Service
   Windows Media Player Network Sharing Service
   Windows Modules Installer
   Windows Process Activation Service
   Windows Search
   Windows Update
   WinHTTP Web Proxy Auto-Discovery Service
   Wireless Modem Service
   WLAN AutoConfig
   Workstation
   World Wide Web Publishing Service

The command completed successfully.


netstat.exe -e [ Table Of Contents ]
Interface Statistics

                           Received            Sent

Bytes                     303618852        54987309
Unicast packets              303156          193743
Non-unicast packets            3654            4872
Discards                          0               0
Errors                            0               0
Unknown protocols                 0

netstat.exe -o [ Table Of Contents ]
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:5357         BEHNAMKHANI-PC:54225   TIME_WAIT       0
  TCP    192.168.0.14:52612     wr-in-f188:5228        ESTABLISHED     3924
  TCP    192.168.0.14:54003     13.69.106.217:https    TIME_WAIT       0
  TCP    192.168.0.14:54014     ec2-35-168-171-34:https  TIME_WAIT       0
  TCP    192.168.0.14:54017     ec2-35-168-171-34:https  TIME_WAIT       0
  TCP    192.168.0.14:54127     192.168.0.1:http       TIME_WAIT       0
  TCP    192.168.0.14:54224     192.168.0.1:8201       TIME_WAIT       0

netstat.exe -s [ Table Of Contents ]
IPv4 Statistics

  Packets Received                   = 123408
  Received Header Errors             = 0
  Received Address Errors            = 1
  Datagrams Forwarded                = 0
  Unknown Protocols Received         = 0
  Received Packets Discarded         = 908
  Received Packets Delivered         = 125270
  Output Requests                    = 78866
  Routing Discards                   = 0
  Discarded Output Packets           = 0
  Output Packet No Route             = 13
  Reassembly Required                = 0
  Reassembly Successful              = 0
  Reassembly Failures                = 0
  Datagrams Successfully Fragmented  = 0
  Datagrams Failing Fragmentation    = 0
  Fragments Created                  = 0

IPv6 Statistics

  Packets Received                   = 38
  Received Header Errors             = 0
  Received Address Errors            = 0
  Datagrams Forwarded                = 0
  Unknown Protocols Received         = 0
  Received Packets Discarded         = 538
  Received Packets Delivered         = 1225
  Output Requests                    = 2124
  Routing Discards                   = 0
  Discarded Output Packets           = 0
  Output Packet No Route             = 6
  Reassembly Required                = 0
  Reassembly Successful              = 0
  Reassembly Failures                = 0
  Datagrams Successfully Fragmented  = 0
  Datagrams Failing Fragmentation    = 0
  Fragments Created                  = 0

ICMPv4 Statistics

                            Received    Sent
  Messages                  102         11        
  Errors                    0           0         
  Destination Unreachable   93          2         
  Time Exceeded             0           0         
  Parameter Problems        0           0         
  Source Quenches           0           0         
  Redirects                 0           0         
  Echo Replies              9           0         
  Echos                     0           9         
  Timestamps                0           0         
  Timestamp Replies         0           0         
  Address Masks             0           0         
  Address Mask Replies      0           0         
  Router Solicitations      0           0         
  Router Advertisements     0           0         

ICMPv6 Statistics

                            Received    Sent
  Messages                  216         12        
  Errors                    0           0         
  Destination Unreachable   2           2         
  Packet Too Big            0           0         
  Time Exceeded             0           0         
  Parameter Problems        0           0         
  Echos                     0           0         
  Echo Replies              0           0         
  MLD Queries               38          0         
  MLD Reports               176         0         
  MLD Dones                 0           0         
  Router Solicitations      0           6         
  Router Advertisements     0           0         
  Neighbor Solicitations    0           2         
  Neighbor Advertisements   0           2         
  Redirects                 0           0         
  Router Renumberings       0           0         

TCP Statistics for IPv4

  Active Opens                        = 5084
  Passive Opens                       = 46
  Failed Connection Attempts          = 56
  Reset Connections                   = 72
  Current Connections                 = 3
  Segments Received                   = 116013
  Segments Sent                       = 69661
  Segments Retransmitted              = 617

TCP Statistics for IPv6

  Active Opens                        = 18
  Passive Opens                       = 18
  Failed Connection Attempts          = 0
  Reset Connections                   = 2
  Current Connections                 = 0
  Segments Received                   = 222
  Segments Sent                       = 222
  Segments Retransmitted              = 0

UDP Statistics for IPv4

  Datagrams Received    = 9224
  No Ports              = 813
  Receive Errors        = 0
  Datagrams Sent        = 8448

UDP Statistics for IPv6

  Datagrams Received    = 1011
  No Ports              = 536
  Receive Errors        = 0
  Datagrams Sent        = 1629

netstat.exe -n [ Table Of Contents ]
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    127.0.0.1:5357         127.0.0.1:54225        TIME_WAIT
  TCP    192.168.0.14:52612     108.177.15.188:5228    ESTABLISHED
  TCP    192.168.0.14:54127     192.168.0.1:80         TIME_WAIT
  TCP    192.168.0.14:54224     192.168.0.1:8201       TIME_WAIT
  TCP    192.168.0.14:54244     20.83.81.161:443       ESTABLISHED
  TCP    192.168.0.14:54254     23.58.223.136:80       ESTABLISHED
  TCP    192.168.0.14:54262     192.168.0.1:80         TIME_WAIT

nbtstat.exe -c [ Table Of Contents ]
    
\Device\NetBT_Tcpip_{FA82869E-B721-4157-87AC-D3C15E88AE68}:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache
    
Bluetooth Network Connection:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache
    
Wireless Network Connection:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache
    
Wireless Network Connection 3:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache
    
\Device\NetBT_Tcpip_{761AA1C9-7A27-4D3E-A149-72817A379687}:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache
    
Local Area Connection 9:
Node IpAddress: [192.168.0.14] Scope Id: []

    No names in cache
    
\Device\NetBT_Tcpip_{AC9F360A-1B14-4C56-B97E-AC2108D4006C}:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache

nbtstat.exe -n [ Table Of Contents ]
    
\Device\NetBT_Tcpip_{FA82869E-B721-4157-87AC-D3C15E88AE68}:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache
    
Bluetooth Network Connection:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache
    
Wireless Network Connection:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache
    
Wireless Network Connection 3:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache
    
\Device\NetBT_Tcpip_{761AA1C9-7A27-4D3E-A149-72817A379687}:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache
    
Local Area Connection 9:
Node IpAddress: [192.168.0.14] Scope Id: []

                NetBIOS Local Name Table

       Name               Type         Status
    ---------------------------------------------
    BEHNAMKHANI-PC <20>  UNIQUE      Registered 
    
\Device\NetBT_Tcpip_{AC9F360A-1B14-4C56-B97E-AC2108D4006C}:
Node IpAddress: [0.0.0.0] Scope Id: []

    No names in cache

nbtstat.exe -r [ Table Of Contents ]
    NetBIOS Names Resolution and Registration Statistics
    ----------------------------------------------------

    Resolved By Broadcast     = 0
    Resolved By Name Server   = 0

    Registered By Broadcast   = 2
    Registered By Name Server = 0

nbtstat.exe -S [ Table Of Contents ]
    
\Device\NetBT_Tcpip_{FA82869E-B721-4157-87AC-D3C15E88AE68}:
Node IpAddress: [0.0.0.0] Scope Id: []

    No Connections
    
Bluetooth Network Connection:
Node IpAddress: [0.0.0.0] Scope Id: []

    No Connections
    
Wireless Network Connection:
Node IpAddress: [0.0.0.0] Scope Id: []

    No Connections
    
Wireless Network Connection 3:
Node IpAddress: [0.0.0.0] Scope Id: []

    No Connections
    
\Device\NetBT_Tcpip_{761AA1C9-7A27-4D3E-A149-72817A379687}:
Node IpAddress: [0.0.0.0] Scope Id: []

    No Connections
    
Local Area Connection 9:
Node IpAddress: [192.168.0.14] Scope Id: []

    No Connections
    
\Device\NetBT_Tcpip_{AC9F360A-1B14-4C56-B97E-AC2108D4006C}:
Node IpAddress: [0.0.0.0] Scope Id: []

    No Connections

netsh.exe dump [ Table Of Contents ]
#========================
# Interface configuration
#========================
pushd interface 


popd
# End of interface configuration



# ----------------------------------
# IPHTTPS Configuration
# ----------------------------------
pushd interface httpstunnel

reset


popd
# End of IPHTTPS configuration



# ----------------------------------
# IPv4 Configuration
# ----------------------------------
pushd interface ipv4

reset
add address name="Wireless Network Connection 3" address=192.168.137.1 mask=255.255.255.0


popd
# End of IPv4 configuration



# ----------------------------------
# IPv6 Configuration
# ----------------------------------
pushd interface ipv6

reset


popd
# End of IPv6 configuration



# ----------------------------------
# ISATAP Configuration
# ----------------------------------
pushd interface isatap



popd
# End of ISATAP configuration



# ----------------------------------
# 6to4 Configuration
# ----------------------------------
pushd interface 6to4

reset



popd
# End of 6to4 configuration



# ----------------------------------
# ISATAP Configuration
# ----------------------------------
pushd interface isatap



popd
# End of ISATAP configuration


#========================
# Port Proxy configuration
#========================
pushd interface portproxy

reset


popd

# End of Port Proxy configuration



# ----------------------------------
# TCP Configuration
# ----------------------------------
pushd interface tcp

reset

set global rss=enabled chimney=automatic autotuninglevel=normal congestionprovider=none ecncapability=disabled timestamps=disabled netdma=enabled dca=enabled initialrto=3000 nonsackrttresiliency=disabled maxsynretransmissions=2


popd
# End of TCP configuration



# ----------------------------------
# Teredo Configuration
# ----------------------------------
pushd interface teredo
set state type=client servername=teredo.ipv6.microsoft.com. servervirtualip=0.0.0.0



popd
# End of Teredo configuration



# ----------------------------------
# 6to4 Configuration
# ----------------------------------
pushd interface 6to4

reset



popd
# End of 6to4 configuration


# ------------------------------------
# Bridge configuration (not supported)
# ------------------------------------

# ------------------------------------
# End of Bridge configuration
# ------------------------------------

# ----------------------------------------
# Wired LAN Configuration
# ----------------------------------------
pushd lan


popd

# End of Wired LAN Configuration.


Mobile Broadband configuration dump is not supported

# ========================================================== 
# Health Registration Authority configuration 
# ========================================================== 
pushd nap hra

popd
# End of NAP HRA configuration 

# ========================================================== 
# Network Access Protection client configuration 
# ========================================================== 
pushd nap client

# ---------------------------------------------------------- 
# Trusted server group configuration 
# ---------------------------------------------------------- 

reset trustedservergroup 

# ---------------------------------------------------------- 
# Cryptographic service provider (CSP) configuration 
# ---------------------------------------------------------- 

set csp name = "Microsoft RSA SChannel Cryptographic Provider" keylength = "2048" 

# ---------------------------------------------------------- 
# Hash algorithm configuration 
# ---------------------------------------------------------- 

set hash oid = "1.3.14.3.2.29" 

# ---------------------------------------------------------- 
# Enforcement configuration 
# ---------------------------------------------------------- 

set enforcement id = "79617" admin = "disable" id = "79619" admin = "disable" id = "79621" admin = "disable" id = "79623" admin = "disable" 
# ---------------------------------------------------------- 
# Tracing configuration 
# ---------------------------------------------------------- 

set tracing state = "disable" level = "basic" 

# ---------------------------------------------------------- 
# User interface configuration 
# ---------------------------------------------------------- 

reset userinterface 

popd
# End of NAP client configuration 

                                            
# ----------------------------------------- 
# Remote Access Configuration               
# ----------------------------------------- 
pushd ras

set authmode mode = standard
delete authtype type = PAP
delete authtype type = MD5CHAP
delete authtype type = MSCHAPv2
delete authtype type = EAP
delete authtype type = CERT
add authtype type = MSCHAPv2
delete link type = SWC
delete link type = LCP
add link type = SWC
add link type = LCP
delete multilink type = MULTI
add multilink type = MULTI
set conf confstate = disabled
set type ipv4rtrtype = lananddd ipv6rtrtype = none rastype = ipv4
set wanports device = "WAN Miniport (IKEv2)" rasinonly = disabled ddinout = disabled ddoutonly = disabled maxports = 2 
set wanports device = "WAN Miniport (L2TP)" rasinonly = disabled ddinout = disabled ddoutonly = disabled maxports = 2 
set wanports device = "WAN Miniport (PPPOE)" ddoutonly = disabled
set wanports device = "WAN Miniport (PPTP)" rasinonly = disabled ddinout = disabled ddoutonly = disabled maxports = 2 
set wanports device = "WAN Miniport (SSTP)" rasinonly = disabled ddinout = disabled ddoutonly = disabled maxports = 2 

set user name = BEHNAM dialin = policy cbpolicy = none 
set user name = BEHNAMKHANI dialin = policy cbpolicy = none 
set user name = Guest dialin = policy cbpolicy = none 
set user name = HomeGroupUser$ dialin = policy cbpolicy = none 

set ikev2connection idletimeout = 5 nwoutagetime = 30
set ikev2saexpiry saexpirytime = 480 sadatasizelimit = 100

popd

# End of Remote Access configuration.        
                                             
                                             

                                            
# ----------------------------------------- 
# Remote Access Diagnostics Configuration   
# ----------------------------------------- 
pushd ras diagnostics

set rastracing component = * state = disabled
set rastracing component = "VPNIKE" state = enabled
set rastracing component = "tapisrv" state = enabled
set rastracing component = "tapi32" state = enabled
set rastracing component = "svchost_RASTLS" state = enabled
set rastracing component = "svchost_RASMANCS" state = enabled
set rastracing component = "svchost_RASDLG" state = enabled
set rastracing component = "svchost_RASCHAP" state = enabled
set rastracing component = "svchost_RASAPI32" state = enabled
set rastracing component = "setup_RASMANCS" state = enabled
set rastracing component = "setup_RASAPI32" state = enabled
set rastracing component = "SaRACmd_RASMANCS" state = enabled
set rastracing component = "SaRACmd_RASAPI32" state = enabled
set rastracing component = "rundll32_RASMANCS" state = enabled
set rastracing component = "rundll32_RASGCW" state = enabled
set rastracing component = "rundll32_RASDLG" state = enabled
set rastracing component = "rundll32_RASAPI32" state = enabled
set rastracing component = "RASTAPI" state = enabled
set rastracing component = "RASPLAP" state = enabled
set rastracing component = "rasphone_RASMANCS" state = enabled
set rastracing component = "rasphone_RASDLG" state = enabled
set rastracing component = "rasphone_RASAPI32" state = enabled
set rastracing component = "RASPHONE" state = enabled
set rastracing component = "RASPAP" state = enabled
set rastracing component = "RASMAN" state = enabled
set rastracing component = "RASIPV6CP" state = enabled
set rastracing component = "RASIPHLP" state = enabled
set rastracing component = "RASIPCP" state = enabled
set rastracing component = "RASEAP" state = enabled
set rastracing component = "RASCCP" state = enabled
set rastracing component = "RASAUTO" state = enabled
set rastracing component = "PPP" state = enabled
set rastracing component = "NDPTSP" state = enabled
set rastracing component = "mcupdate_RASMANCS" state = enabled
set rastracing component = "mcupdate_RASAPI32" state = enabled
set rastracing component = "KMDDSP" state = enabled
set rastracing component = "IPNATHLP" state = enabled
set rastracing component = "IpHlpSvc" state = enabled
set rastracing component = "iexplore_RASAPI32" state = enabled
set rastracing component = "ie4uinit_RASAPI32" state = enabled
set rastracing component = "IASSDO_AUX" state = enabled
set rastracing component = "IASRECST_AUX" state = enabled
set rastracing component = "IASDATASTORE_AUX" state = enabled
set rastracing component = "Explorer_RASTLSUI" state = enabled
set rastracing component = "Explorer_RASTLS" state = enabled
set rastracing component = "Explorer_RASMANCS" state = enabled
set rastracing component = "Explorer_RASGCW" state = enabled
set rastracing component = "Explorer_RASDLG" state = enabled
set rastracing component = "Explorer_RASCHAP" state = enabled
set rastracing component = "Explorer_RASAPI32" state = enabled
set rastracing component = "ehshell_RASMANCS" state = enabled
set rastracing component = "ehshell_RASAPI32" state = enabled
set rastracing component = "ehExtHost_RASMANCS" state = enabled
set rastracing component = "ehExtHost_RASAPI32" state = enabled
set rastracing component = "DllHost_RASMANCS" state = enabled
set rastracing component = "DllHost_RASGCW" state = enabled
set rastracing component = "DllHost_RASDLG" state = enabled
set rastracing component = "DllHost_RASCHAP" state = enabled
set rastracing component = "DllHost_RASAPI32" state = enabled
set rastracing component = "dfsvc_RASMANCS" state = enabled
set rastracing component = "dfsvc_RASAPI32" state = enabled
set rastracing component = "CMMON32" state = enabled

set modemtracing state = disabled

set cmtracing state = disabled

set securityeventlog state = enabled

set loglevel events = warn


popd

# End of Remote Access Diagnostics Configuration.
                                                 
                                                 

                                            
# ----------------------------------------- 
# Remote Access IP Configuration            
# ----------------------------------------- 
pushd ras ip

delete pool

set negotiation mode = allow
set access mode = all
set addrreq mode = deny
set broadcastnameresolution mode = enabled
set addrassign method = auto
set preferredadapter 

popd

# End of Remote Access IP configuration.     
                                             

                                            
# ----------------------------------------- 
# Remote Access IPv6 Configuration          
# ----------------------------------------- 
pushd ras ipv6



set negotiation mode = deny
set access mode = all
set routeradvertise mode = enabled

popd

# End of Remote Access IPv6 configuration.   
                                             

                                            
# ----------------------------------------- 
# Remote Access AAAA Configuration          
# ----------------------------------------- 
pushd ras aaaa


popd

# End of Remote Access AAAA configuration.     
                                               
                                               


# -----------------------------------------
# WinHTTP Proxy Configuration
# -----------------------------------------
pushd winhttp

reset proxy

popd

# End of WinHTTP Proxy Configuration

# ----------------------------------------
# Wireless LAN configuration
# ----------------------------------------
pushd wlan

# Allow filter list
# ----------------------------------------


# Block filter list
# ----------------------------------------


popd
# End of Wireless LAN Configuration

Phone Book Files [ Table Of Contents ]
-------------------------------------------------------------------------------
C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk
-------------------------------------------------------------------------------
[VPN Connection]
Encoding=1
PBVersion=1
Type=2
AutoLogon=0
UseRasCredentials=1
LowDateTime=684720160
HighDateTime=30939290
DialParamsUID=6200134
Guid=606BFC65C7F38D4086F3A49272C2AA21
VpnStrategy=0
ExcludedProtocols=0
LcpExtensions=1
DataEncryption=256
SwCompression=1
NegotiateMultilinkAlways=1
SkipDoubleDialDialog=0
DialMode=0
OverridePref=15
RedialAttempts=3
RedialSeconds=60
IdleDisconnectSeconds=0
RedialOnLinkFailure=1
CallbackMode=0
CustomDialDll=
CustomDialFunc=
CustomRasDialDll=
ForceSecureCompartment=0
DisableIKENameEkuCheck=0
AuthenticateServer=0
ShareMsFilePrint=1
BindMsNetClient=1
SharedPhoneNumbers=0
GlobalDeviceSettings=0
PrerequisiteEntry=
PrerequisitePbk=
PreferredPort=VPN1-0
PreferredDevice=WAN Miniport (IKEv2)
PreferredBps=0
PreferredHwFlow=1
PreferredProtocol=1
PreferredCompression=1
PreferredSpeaker=1
PreferredMdmProtocol=0
PreviewUserPw=1
PreviewDomain=1
PreviewPhoneNumber=0
ShowDialingProgress=1
ShowMonitorIconInTaskBar=1
CustomAuthKey=26
CustomAuthData=314442431A00000008000000010000000200000000000000
AuthRestrictions=128
IpPrioritizeRemote=1
IpInterfaceMetric=0
IpHeaderCompression=0
IpAddress=0.0.0.0
IpDnsAddress=0.0.0.0
IpDns2Address=0.0.0.0
IpWinsAddress=0.0.0.0
IpWins2Address=0.0.0.0
IpAssign=1
IpNameAssign=1
IpDnsFlags=0
IpNBTFlags=1
TcpWindowSize=0
UseFlags=2
IpSecFlags=0
IpDnsSuffix=
Ipv6Assign=1
Ipv6Address=::
Ipv6PrefixLength=0
Ipv6PrioritizeRemote=1
Ipv6InterfaceMetric=0
Ipv6NameAssign=1
Ipv6DnsAddress=::
Ipv6Dns2Address=::
Ipv6Prefix=0000000000000000
Ipv6InterfaceId=0000000000000000
DisableClassBasedDefaultRoute=0
DisableMobility=0
NetworkOutageTime=1800
ProvisionType=0
PreSharedKey=

NETCOMPONENTS=
ms_msclient=1
ms_server=1

MEDIA=rastapi
Port=VPN1-0
Device=WAN Miniport (IKEv2)

DEVICE=vpn
PhoneNumber=192.168.0.1
AreaCode=
CountryCode=0
CountryID=0
UseDialingRules=0
Comment=
FriendlyName=
LastSelectedPhone=0
PromoteAlternates=0
TryNextAlternateOnFail=1

