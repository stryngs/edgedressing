
# edgedressing
One day while experimenting with airpwn-ng, I noticed unexpected GET requests on the target node.  The node in question happened to be a Windows 10 laptop and every time it would connect to the AP a GET request was made.  Using [scapy](https://scapy.net/)  I was able to make the Edge browser open up and proceed to a URL of my choosing upon connecting to a wireless access point.

Enter NCSI probing, by Microsoft.

https://docs.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network

The biggest takeaway is that Microsoft for whatever reason chose to use HTTP as one of the mechanisms to determine how NCSI functions.  I suspect it has something to do with how they try to have Windows handle something like a sign-in page for Internet usage.  Think of a coffee shop as it were.  Rather than just give free wifi away, you have to come inside and find out more; hopefully you'll buy a cup.
```
NCSI sends a DNS request to resolve the address of the www.msftconnecttest.com FQDN.

If NCSI receives a valid response from a DNS server, NCSI sends a plain HTTP GET request to http://www.msftconnecttest.com/connecttest.txt.

If NCSI successfully downloads the text file, it makes sure that the file contains Microsoft Connect Test.

NCSI sends another DNS request to resolve the address of the dns.msftncsi.com FQDN.

If any of these requests fails, the network alert appears in the Task Bar (as described in Symptoms). If you hover over the icon, you see a message such as "No connectivity" or "Limited Internet access" (depending on which requests failed).
If all of these requests succeed, the Task Bar shows the usual network icon. If you hover over the icon, you see a message such as "Internet access."
```

The opening of Edge was by design for "user experience" purposes.
```
If the network requires credentials, Windows opens the default browser (such as Internet Explorer or Edge). If the network has a sign-in page, that page appears in the browser.

This behavior was introduced to improve the Windows user experience. In earlier versions of Windows, when you connect to a network that requires you to authenticate, the browser window does not open automatically. You may see a message that states that you must take further action in order to connect fully to the network. To complete the connection, you must click the message to open a browser window (or manually open a browser window) and enter a user name and password.

Because the network does not allow internet access without credentials, the network alert appears in the Task Bar.

In some cases, such as when you connect to a network that uses a proxy server to connect to the internet or when network restrictions prevent NCSI from completing its active probe process, Windows opens the MSN Portal page in the default browser. If you analyze a network trace on the computer, it shows an HTTP connection to http://www.msftconnecttest.com/redirect that is followed by a connection to the MSN Portal. Windows opens this page for the benefit of the passive probe process. If the page loads, NCSI concludes that the computer has internet access. As the different probes fail and then succeed, the network status alert appears and then disappears.
```

Maybe that is what I saw during testing, I'd interacted with the active probing process and created a situation where the browser opened without user intervention.

I now had everything I needed to formulate a set of conditions in scapy that would trigger when the NCSI probing was in use.

edgedressing will open whatever Default Browser the user has set.

## Reasoning for going public
edgedressing is what I like to call a Remote Code Execution Vector.  An RCE, but limited to what a browser can be made to do.  As this is not a direct exploit and I have not included payloads that bypass the Edge sandbox protections, it would take further research to put this into exploit territory.

Microsoft designed the Operating System to behave this way.  It is a feature meant for you, the user.  edgedressing leverages this feature with the ability to produce an outcome that Microsoft may not have intended to happen, but happened anyways because of the HTTP flaw in the NCSI probing implementation.

Knowledge is power and that is why I am making this aspect of Windows known.  This code should not work.  HTTP for a built-in Operating System function that has no signature functionality or other mitigation is absurd.

## The cure is worse than the disease
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\EnableActiveProbing
Key Type: DWORD
Value: Decimal 0 (False)

HKLM\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\NoActiveProbe
Key Type: DWORD
Value: Decimal 1 (True)

HKLM\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\DisablePassivePolling
Key Type: DWORD
Value: Decimal 1 (True)
```
The above does exactly as Microsoft said it would.  It made the user experience worse, but it did prevent edgedressing from working as intended.  No more HTTP, ya'ay.

You are cautioned though against fixing this.
```
Microsoft does not recommend disabling the NCSI probes. Several operating system components and applications rely on NCSI. For example, if NCSI does not function correctly, Microsoft Outlook may not be able to connect to a mail server, or Windows may not be able to download updates even if the computer is connected to the internet.
```

## Requirements
* [Aircrack-NG](https://www.aircrack-ng.org/install.html)
* [Scapy](https://github.com/secdev/scapy)
* [airpwn-ng](https://github.com/ICSec/airpwn-ng)

## Proof of Concept
WPA or WEP
```
airtun-ng -a <BSSID> -e <ESSID> -p <PSK> <Monitoring NIC>
python3 ./poc.py -i at0 -m at0 --tun --injection payloads/demo --trigger "connecttest"
```

Open
```
python3 ./poc.py -i <Injecting NIC> -m <Monitoring NIC> --injection payloads/demo --trigger "connecttest"
```
