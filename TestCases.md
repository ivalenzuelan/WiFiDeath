**Test Cases: WiFi Deauthentication Attack Detection and Mitigation**
=====================================================================

**1\. Attack Detection Validation**
-----------------------------------

### **Test 1.1: Basic Detection of Deauthentication Packets**

**Objective:** Verify that the system correctly detects deauthentication packets.

**Procedure:**

1.  sudo python3 sniffer.py -i wlan0 -v
    
2.  sudo aireplay-ng --deauth 5 -a \[BSSID\_AP\] wlan0
    
3.  Check that the packets are detected in the logs.
    

**Expected Result:**

*   Deauthentication packets appear in the logs with source and destination information.
    
*   The packet count is accurate.
    

### **Test 1.2: Detection of Massive Attacks**

**Objective:** Verify that the system correctly identifies an attack when the configured threshold is exceeded.

**Procedure:**

1.  sudo python3 sniffer.py -i wlan0 -t 5 -w 30
    
2.  sudo aireplay-ng --deauth 10 -a \[BSSID\_AP\] wlan0
    
3.  Check the system's response.
    

**Expected Result:**

*   The system generates an alert indicating the detection of a possible attack.
    
*   The attacker's MAC address is added to the suspicious addresses list.
    

### **Test 1.3: Filtering by BSSID**

**Objective:** Verify that the system can focus on a specific AP.

**Procedure:**

1.  sudo python3 sniffer.py -i wlan0 -b \[BSSID\_AP\]
    
2.  Generate deauthentications for different BSSIDs, including the specified one.
    
3.  Check that only relevant deauthentications are detected.
    

**Expected Result:**

*   Only packets related to the specified BSSID are reported and counted.
    
*   Packets targeting other APs are ignored.
    

**2\. Mitigation Tests**
------------------------

### **Test 2.1: Activating Mitigation Mode**

**Objective:** Verify that the system responds appropriately when mitigation is activated.

**Procedure:**

1.  sudo python3 sniffer.py -i wlan0 -m
    
2.  Generate a deauthentication attack.
    
3.  Check the system's response.
    

**Expected Result:**

*   The system detects the attack and activates the mitigation response.
    
*   The mitigation action is recorded in the logs.
    

### **Test 2.2: Sending Authentication Packets (Countermeasure)**

**Objective:** Verify that authentication packets are sent correctly.

**Procedure:**

1.  sudo python3 sniffer.py -i wlan0 -m -b \[BSSID\_AP\]
    
2.  Generate a deauthentication attack while capturing traffic with Wireshark.
    
3.  Analyze the packets sent by the system.
    

**Expected Result:**

*   Authentication packets are observed being sent in response to the attack.
    
*   Affected clients receive authentication packets.
    

### **Test 2.3: Mitigation Effectiveness**

**Objective:** Verify that mitigation effectively reduces client disconnections.

**Procedure:**

1.  Set up a client connected to the target AP.
    
2.  Measure disconnection time during an attack without mitigation.
    
3.  Activate mitigation and repeat the attack.
    
4.  Compare disconnection times.
    

**Expected Result:**

*   Disconnection time or attack effectiveness is reduced when mitigation is active.
    
*   The client reconnects more quickly or does not disconnect at all.
    

**3\. MFP (Management Frame Protection) Configuration Tests**
-------------------------------------------------------------

### **Test 3.1: Enabling MFP on the Access Point**

**Objective:** Verify the correct configuration of MFP on the AP.

**Procedure:**

1.  Run sudo ./config.sh and select AP configuration (option 5).
    
2.  Set MFP as mandatory (level 2).
    
3.  Verify the configuration in the hostapd.conf file.
    
4.  Restart the hostapd service.
    

**Expected Result:**

*   The configuration file contains the line ieee80211w=2.
    
*   The hostapd service starts correctly.
    
*   A network scan shows that MFP is enabled.
    

### **Test 3.2: Configuring a Client with MFP Support**

**Objective:** Verify that a client is correctly set up to use MFP.

**Procedure:**

1.  Run sudo ./config.sh and select client configuration (option 6).
    
2.  Configure the connection to the network with mandatory MFP.
    
3.  Attempt to connect to the MFP-enabled AP.
    

**Expected Result:**

*   The wpa\_supplicant.conf file contains the correct MFP settings.
    
*   The client connects successfully to the MFP-protected AP.
    

### **Test 3.3: Resistance to Attacks with MFP Enabled**

**Objective:** Verify that MFP protects against deauthentication attacks.

**Procedure:**

1.  Configure both the AP and client with mandatory MFP.
    
2.  Attempt a deauthentication attack.
    
3.  Monitor if the client disconnects.
    

**Expected Result:**

*   The client does not disconnect despite the attack.
    
*   Deauthentication packets are rejected by the client.
    

**4\. Alert System Tests**
--------------------------

### **Test 4.1: Desktop Notifications**

**Objective:** Verify that desktop notifications are generated when an attack is detected.

**Procedure:**

1.  Configure alert\_system.py with desktop notifications enabled.
    
2.  Run the detector with the alert system.
    
3.  Generate a deauthentication attack.
    

**Expected Result:**

*   A desktop notification appears warning about the attack.
    
*   The notification contains the attacker's MAC address and severity.
    

### **Test 4.2: Email Alerts**

**Objective:** Verify that email alerts are sent when configured.

**Procedure:**

1.  Configure alert\_system.py with email alerts enabled and valid credentials.
    
2.  Run the detector with the alert system.
    
3.  Generate a deauthentication attack.
    

**Expected Result:**

*   An email is sent to the configured recipients.
    
*   The email contains attack details (MAC, severity, time).
    

This document provides detailed test cases to validate the detection and mitigation system for WiFi deauthentication attacks.