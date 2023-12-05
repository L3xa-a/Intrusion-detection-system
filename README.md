# Intrusion Detection System (IDS) Project

## Overview

This project is a custom-built Intrusion Detection System (IDS) developed primarily for educational purposes in 2022. The core objective of this project is to gain an in-depth understanding of how intrusion detection systems operate and to explore the fundamental concepts of network security monitoring.

## Disclaimer

**Important: This IDS is not intended for real-world application.** It has been developed as a learning tool and should be used solely for educational purposes. The system may not cover all aspects of security required for a production-grade IDS and might lack the robustness and features of professionally developed software.

## Features

- **Port Scan Detection:** Detects potential port scanning activities, a common reconnaissance technique used by attackers.
- **Signature-Based Detection:** Identifies known attack patterns within network traffic. Note that this analysis only works on unencrypted traffic and includes a limited set of signatures.
- **TCP Traffic Analysis:** Focuses on analyzing TCP packets, particularly paying attention to SYN packets for identifying unusual patterns.

## Usage

This project is built in Go and utilizes libraries such as `gopacket` for packet capture and analysis.

1. **Installation:**
   - Ensure that Go is installed on your system.
   - Clone the repository.
   - Install required dependencies.

2. **Running the IDS:**
   - Modify the source code as needed for your learning purposes.
   - Run the system on a network interface to start monitoring traffic.

## Limitations

Please note that this IDS system is limited in its capabilities:
- It only analyzes unencrypted traffic, which limits its effectiveness in many modern network environments where encryption is prevalent.
- The signature database included is minimal, serving only as a basic example of how signature-based detection can be implemented.

## Project Status

**Ongoing Development:** This project is a work in progress and is not yet complete. Additional features, improvements, and refinements are planned for future updates.

## License

This project is open-sourced under the [MIT License](LICENSE).

## Acknowledgements

Special thanks to the Go programming community and the authors of the libraries used in this project.
