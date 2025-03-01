WiFi Deauthentication Attack Mitigation
=======================================

Project Overview
----------------

This project focuses on analyzing the use of deauthentication messages in WiFi networks and implementing a functionality to prevent attacks based on these messages. The study covers different versions of the IEEE 802.11 protocol and provides a practical approach to mitigate forced disconnections of legitimate devices.

Explanation of Detection and Mitigation System
----------------------------------------------

### 1\. Main System (wifi-deauth-protection)

This Python script uses Scapy to capture and analyze network packets for deauthentication frames.

#### Main Functions:

*   **Detection**: Identifies deauthentication packets and counts them by source.
    
*   **Analysis**: Compares the frequency of deauthentication packets with a configurable threshold.
    
*   **Mitigation**: Sends authentication packets to counteract attacks.
    
*   **Monitoring**: Maintains a log of clients connected to the AP and detects suspicious MAC addresses.
    

### 2\. Alert System (alert-system)

This component enhances the primary detection system by providing multi-channel notifications:

*   **Desktop notifications**: Immediate visual alerts.
    
*   **Email alerts**: Remote notifications for administrators.
    
*   **Telegram notifications**: Alternative communication channel.
    
*   **Severity control**: Categorizes attacks based on intensity.
    
*   **Anti-spam system**: Prevents excessive notifications for the same attack.
    

### 3\. MFP Configuration Script (config-script)

A Bash script to configure **802.11w Management Frame Protection (MFP)**:

*   **AP Configuration**: Modifies hostapd.conf to enable MFP.
    
*   **Client Configuration**: Configures wpa\_supplicant to use MFP.
    
*   **Diagnostics**: Checks hardware support for MFP.
    
*   **Scanning**: Detects nearby networks with MFP enabled.
    

### 4\. Test Cases (test-cases)

A document with detailed procedures to validate each system component:

*   Basic and advanced detection tests.
    
*   Mitigation effectiveness tests.
    
*   Validation of MFP configuration.
    
*   Alert system testing.
    
*   Performance and stability evaluation.
    

Vulnerabilities and IEEE 802.11 Standards
-----------------------------------------

The deauthentication attack is a vulnerability present in:

*   **802.11a/b/g/n/ac**: These versions are vulnerable as management frames are sent without authentication.
    

The definitive solution came with:

*   **802.11w**: Introduced **Management Frame Protection (MFP)**, which authenticates management frames, including deauthentication messages.
    

File Structure
--------------

**FileDescription**sniffer.pyDetects deauthentication attacks using Scapy.mitigation.pyFilters and ignores rogue deauthentication frames.alert\_system.pyLogs and notifies the user when an attack is detected.config.shConfigures **802.11w MFP** to strengthen security.test\_cases.mdContains test scenarios to validate the detection and mitigation functionalities.

Installation & Usage
--------------------

### Installation

Ensure you have **Python 3+** and required dependencies:

`   pip install scapy   `

### Running the Detection System

`   python sniffer.py   `

### Running the Mitigation System

`   python mitigation.py   `

### Enabling Management Frame Protection (MFP) on a Linux System

`   sudo bash config.sh   `

Future Improvements
-------------------

*   Integration with a **GUI Dashboard** for monitoring attacks.
    
*   Real-time countermeasures such as automatic MAC banning.
    
*   Machine learning-based anomaly detection for improved accuracy.
    

Disclaimer
----------

This project is intended **only for educational and research purposes**. Any misuse for unauthorized network attacks is strictly prohibited. The authors are not responsible for any misuse of this software.

License
-------

This project is licensed under the **MIT License**.
