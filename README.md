# TestAP

Test Wireless Access Point(Open System Only)


## Summary

I created this tool to learn wireless access point's function, scapy and 802.11.

This tool can do the following.

- wireless access point (Open System)
    - Scan Access Point and create Access Point(Open System Only).
    - Associate Client(Open System)
    - Transfer DHCP Packet
    - Transfer ARP Packet
    - Transfer UDP Packet

<font style="color:red">
I could hardly use a function that transfer TCP Packet. <br>
TCP Retransmission occurs frequently due to qualities of receive data are bad.
</font>


## Cautions

<font style="color:red;font-size:150%">
Do not abuse this tool.<br>
</font>


## Installation

This tool can run Linux Operationg System(e.g. Debian).

Also, You need to install the following packages.

- python 2.7
- sudo
- secdev/scapy Version 2.4.0
- aircrack-ng
- aircrack-ng/rtl8812au v5.1.5
- macchanger
- python-netaddr


## Example

Oracle VM VirtualBox and ELECOM WDC-433DU2H(USB Wi-Fi network Adapter)

1. Create a virtual machine and Install OS(Debian 9).
    - OS: Debian 9 x64
    - Network Adapter: NAT or NAT network(use DNS and DHCP Server of VirtualBox)
    - Enable USB Controller: USB 2.0 (EHCI) Controller
1. Install Packages
    - Update apt repository(sources.list)
    - Install packages(sudo)
        ```
        sudo apt-get install -y sudo vim git
        ```
    - Install Oracle guest Additions
        ```
        sudo apt install -y linux-headers-amd64
        sudo apt build-dep -y linux
        ```
    - Install aircrack-ng
        ```
        sudo apt-get install -y aircrack-ng
        ```
    - Install aircrack-ng/rtl8812au v5.1.5
        ```
        git clone -b v5.1.5 https://github.com/aircrack-ng/rtl8812au.git
        sudo apt-get install -y dkms make build-essential bc libelf-dev linux-headers-`uname -r`
        cd rtl8812au
        make
        sudo make install
        ```
    - Install secdev/scapy Version 2.4.0
        ```
        git clone https://github.com/secdev/scapy.git
        cd scapy
        git checkout -b v2.4.0
        sudo python setup.py install
        sudo apt-get install -y tcpdump
        sudo apt-get install -y python-matplotlib
        sudo apt-get install -y python-pyx
        sudo apt-get install -y python-ipython
        ```
    - Install macchanger
        ```
        sudo apt-get install -y macchanger
        ```
    - Install python-netaddr
        ```
        sudo apt-get install -y python-netaddr
        ```
    - Install wireshark(Optional)
        ```
        sudo apt-get install -y wireshark
        ```
1. Connect USB Wi-Fi network adapter to PC and attach it to Virtual Machine.
    - <font style="color:blue">Note: Check wired interface and wireless interface(e.g. ip command).</font>
1. Copy Program and run
    - Check arguments
        ```
        test@debian:~/testap$ sudo python testap.py -h
        ##### OS Check #####
        Operating System: Linux

        ##### Root Check #####
        You are running this script as root!

        ##### Argument parser #####
        usage: Usage: sudo python testap.py winterface interface [--help]

        positional arguments:
          winterface  wireless interface name
          interface   wired interface name

        optional arguments:
          -h, --help  show this help message and exit
        test@debian:~/testap$
        ```
    - Run
        ```
        test@debian:~/testap$ sudo python testap.py wlxxxxxxxxxxxxx enp0s3
        ##### OS Check #####
        Operating System: Linux

        ##### Root Check #####
        You are running this script as root!

        ##### Argument parser #####
        Interface wlxxxxxxxxxxxxx exist!

        Interface enp0s3 exist!



        ##########################################################################################
        Init Interface           :init
        Get MAC Address          :getmac
        Change MAC Address       :changemac
        Check Channel            :checkchannels
        Set Channel              :setchannel <channel number>
        Run TestAP (OpenSystem)  :runtestap

        Quit                     :quit <interface down:0, up:1>
        ##########################################################################################

        Command > init
        ##### Init Wireless Interface #####
        Interface wlxxxxxxxxxxxxx exist!

        ----- WiFi interface down -----

        ----- rfkill unblock all -----
        0: phy0: Wireless LAN
          Soft blocked: no
          Hard blocked: no

        ----- iw reg set JP -----
        global
        country JP: DFS-JP
          (2402 - 2482 @ 40), (N/A, 20), (N/A)
          (2474 - 2494 @ 20), (N/A, 20), (N/A), NO-OFDM
          (4910 - 4990 @ 40), (N/A, 23), (N/A)
          (5030 - 5090 @ 40), (N/A, 23), (N/A)
          (5170 - 5250 @ 80), (N/A, 20), (N/A), AUTO-BW
          (5250 - 5330 @ 80), (N/A, 20), (0 ms), DFS, AUTO-BW
          (5490 - 5710 @ 160), (N/A, 23), (0 ms), DFS
          (59000 - 66000 @ 2160), (N/A, 10), (N/A)


        ----- airmon-ng check kill -----

        Found 5 processes that could cause trouble.
        If airodump-ng, aireplay-ng or airtun-ng stops working after
        a short period of time, you may want to run 'airmon-ng check kill'

          PID Name
          398 avahi-daemon
          401 avahi-daemon
          427 NetworkManager
          502 dhclient
          700 wpa_supplicant


        Killing these processes:

          PID Name
          502 dhclient
          700 wpa_supplicant




        ----- WiFi interface mode change: monitor -----

        ----- WiFi interface set txpower -----
        wlxxxxxxxxxxxxx  IEEE 802.11  Mode:Monitor  Frequency:2.412 GHz  Tx-Power=5 dBm
                  Retry short limit:7   RTS thr:off   Fragment thr:off
                  Power Management:off


        ----- MAC address change -----
        Current MAC:   xx:xx:xx:xx:xx:xx (unknown)
        Permanent MAC: xx:xx:xx:xx:xx:xx (unknown)
        New MAC:       ww:ww:ww:ww:ww:ww

        ----- IP address set -----

        ----- WiFi interface up -----
        3: wlxxxxxxxxxxxxx: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
            link/ieee802.11/radiotap ww:ww:ww:ww:ww:ww brd ff:ff:ff:ff:ff:ff
            inet 10.0.2.100/24 scope global wlxxxxxxxxxxxxx
               valid_lft forever preferred_lft forever

        Interface wlxxxxxxxxxxxxx exist!

        Actual wlxxxxxxxxxxxxx MAC Address: ww:ww:ww:ww:ww:ww



        ##########################################################################################
        Init Interface           :init
        Get MAC Address          :getmac
        Change MAC Address       :changemac
        Check Channel            :checkchannels
        Set Channel              :setchannel <channel number>
        Run TestAP (OpenSystem)  :runtestap

        Quit                     :quit <interface down:0, up:1>
        ##########################################################################################

        Command > runtestap
        ##### Run TestAP(OpenSystem) #####
        Interface wlxxxxxxxxxxxxx exist!

        ----- check channels -----
        Channel List: [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 10, 12, 13]
        input scan channel number: 6
        ----- WiFi interface channel setting -----
        channel = 6
        wlxxxxxxxxxxxxx  IEEE 802.11  Mode:Monitor  Frequency:2.437 GHz  Tx-Power=5 dBm
                  Retry short limit:7   RTS thr:off   Fragment thr:off
                  Power Management:off


        ----- scan beacon packet -----
        [0] ssid:test, len:4, addr1:ff:ff:ff:ff:ff:ff, addr2:yy:yy:yy:yy:yy:yy, addr3:yy:yy:yy:yy:yy:yy, addr4:None
        [1] ssid:test, len:4, addr1:ff:ff:ff:ff:ff:ff, addr2:yy:yy:yy:yy:yy:yy, addr3:yy:yy:yy:yy:yy:yy, addr4:None
        [2] ssid:test, len:4, addr1:ff:ff:ff:ff:ff:ff, addr2:yy:yy:yy:yy:yy:yy, addr3:yy:yy:yy:yy:yy:yy, addr4:None
        [3] ssid:test, len:4, addr1:ff:ff:ff:ff:ff:ff, addr2:yy:yy:yy:yy:yy:yy, addr3:yy:yy:yy:yy:yy:yy, addr4:None
        [4] ssid:test, len:4, addr1:ff:ff:ff:ff:ff:ff, addr2:yy:yy:yy:yy:yy:yy, addr3:yy:yy:yy:yy:yy:yy, addr4:None
        [5] ssid:test, len:4, addr1:ff:ff:ff:ff:ff:ff, addr2:yy:yy:yy:yy:yy:yy, addr3:yy:yy:yy:yy:yy:yy, addr4:None
        [6] ssid:test, len:4, addr1:ff:ff:ff:ff:ff:ff, addr2:yy:yy:yy:yy:yy:yy, addr3:yy:yy:yy:yy:yy:yy, addr4:None
        [7] ssid:test, len:4, addr1:ff:ff:ff:ff:ff:ff, addr2:yy:yy:yy:yy:yy:yy, addr3:yy:yy:yy:yy:yy:yy, addr4:None
        [8] ssid:test, len:4, addr1:ff:ff:ff:ff:ff:ff, addr2:yy:yy:yy:yy:yy:yy, addr3:yy:yy:yy:yy:yy:yy, addr4:None
        [9] ssid:test, len:4, addr1:ff:ff:ff:ff:ff:ff, addr2:yy:yy:yy:yy:yy:yy, addr3:yy:yy:yy:yy:yy:yy, addr4:None

        select beacon packet number: 1

        ----- start thread sending beacon -----

        ----- start thread wired interface -----

        ----- start thread testap -----

        Use anykey to exit.
        Connect Client: zz:zz:zz:zz:zz:zz.
        <__main__.Client instance at 0x7fe1be116a28>
        Connect Client: zz:zz:zz:zz:zz:zz.
        <__main__.Client instance at 0x7fe1be0dd5a8>
        Connect Client: zz:zz:zz:zz:zz:zz.
        <__main__.Client instance at 0x7fe1be0a33f8>


        ----- stop thread testap -----

        ----- stop thread wired interface -----

        ----- stop thread sending beacon -----



        ##########################################################################################
        Init Interface           :init
        Get MAC Address          :getmac
        Change MAC Address       :changemac
        Check Channel            :checkchannels
        Set Channel              :setchannel <channel number>
        Run TestAP (OpenSystem)  :runtestap

        Quit                     :quit <interface down:0, up:1>
        ##########################################################################################

        Command > quit 0
        ##### Quit #####
        ----- WiFi interface down -----

        ----- IP address del -----

        3: wlxxxxxxxxxxxxx: <BROADCAST,MULTICAST> mtu 1500 qdisc mq state DOWN group default qlen 1000
            link/ieee802.11/radiotap ww:ww:ww:ww:ww:ww brd ff:ff:ff:ff:ff:ff

        test@debian:~/testap$
        ```
