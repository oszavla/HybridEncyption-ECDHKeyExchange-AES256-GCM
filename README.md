# HybridEncyption-ECDHKeyExchange-AES256-GCM
A hybrid encryption scheme is a cryptographic technique that combines the speed of symmetric encryption (using AES-256-GCM) with the secure key distribution of asymmetric encryption (using ECDH). This repository is for enrichment courses final project (Cryptography) in odd semester at Information Technology, Faculty of Intelligent Electrical and Information technology, Sepuluh Nopember Institute of Technology.This final project, create an output **ECSErtion**

# ECSErtion: ECCDH Secure Emergency Communication

## Overview
This app is secure emergency communication using **Local Area Network**, without internet connection. This communication application can be effectively used in very critical situations such as disasters, war emergencies, to send confidential files during emergencies, and so on. By simply using a router that is connected to electricity, communication can be carried out very securely through _end-to-end encryption_, in contrast to walkie-talkies or handy talkies which are based on unencrypted radio waves.

The _end-to-end encryption_ used in this communication uses an **elliptic curve cryptography system via Diffie-Hellman key exchange**. This encryption can be computed without requiring high processor capacity, as the keys used are much shorter than those used in the RSA key distribution scheme, which offers the same level of security. 

## How to use
### Prerequisite
1.	The prerequisite for secure communication is that both the sender and receiver **must know each other's IP addresses** if the communication is two-way. 
2.	However, if the communication is one-way, only the receiver's IP address is required.
3.	Because this system can only be used within a local radius (such WIFI) for emergency situations, it requires that the **sender and receiver be connected to the same Local Area Network.**
4.	Messages sent can be in the form of text files, .txt, .png, .jpg, .pdf, .docx, .xlsx, .zip, .rar, .mp3, .mp4, .exe, and .bin.
### Running the Program
1.	To run the program, first download the latest version (in sender's device and receiver's device) available, namely **V8.exe**, then place it in an empty folder and double-click on the application.
2.	Then, if you already know the receiver's IP address, type it in the **IP:** box at the top (by default, the IP is 127.0.0.1).
3.	Next, make sure the **Port:** (second box below **IP:**) used by both the **Sender** and **Receiver** is the same (by default, it's 65432).
4.	Determine the **Mode:** whether you're sending a **File** or a **Text message**.
5.	If you're sending a text message, continue by typing your message in the **Text message** box.
6.	If you're sending a file, click **Browse...** to browse the file you want to send.
7.	**The Save received as:** box allows you to just rename the file you're sending. For example, if you want to send the file named "ProjectDatabase.xlsx" and you want to change it to "SecureFile1.xlsx", type that name in the **Save received as:** box.
8.	Don't forget for each **Sender** and **Receiver**, they can receive each other's messages, if they agreed and determined the **Mode:** which is appropriate to their role (**Receiver** or **Sender**) and then press **Start (send)** on the Sender and press **Start (receive)** on the receiver.

For any problem, fell free to contact me ``bagusalvanza123@gmail.com``






