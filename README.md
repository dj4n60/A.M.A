# A.M.A

Automated Malware Analysis Using Python v1.0

# Description

This is a script written in python used for "Static Analysis" of malwares. Focus on malware PE Headers, Strings, Image Type, MD5 Hash, VirusTotal Analysis. . Supported on Linux OS .

A.M.A will generate a report folder and in this folder you can find folder with report for each file is on folder where you run the script .
The 4 output files :
*Strings.txt for the extracted strings
*PE Analysis.txt for PE headers
*VT Basic Scan.txt
*VT Scan.txt for virus total analysis.  

# Important

You have to enter your Virus Total API Key inside the program at on line number 51.

           key="" # <= Here Enter Your VT API Key between double quotes


# Example

![alt text](https://github.com/ShilpeshTrivedi/MAUPS/blob/master/VT%20Scan.png)

# Pre-Requesites

pip install -r requirements.txt

# Usage
On the folder with the malwares
python3 ama.py

# Kudos

           M   M   AAAA   U   U   PPPP    SSSSS
           M M M   A  A   U   U   P   P   S
           M M M   AaaA   U   U   PPPP    SSSSS
           M   M   A  A   U   U   P           S
           M   M . A  A .  UUU  . P     . SSSSS v 1.1


        +++++++++++++++++++++++++++++++++++++++++++++++++
        + Auther :- Shilpesh Trivedi                    +
        + Title :- Malware Analysis Using Python Script +
        +++++++++++++++++++++++++++++++++++++++++++++++++

kudos at https://github.com/ShilpeshTrivedi/MAUPS
