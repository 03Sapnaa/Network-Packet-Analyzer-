# Network-Packet-Analyzer-
Objective:
Develop a Python-based tool that captures and analyzes network packets to help monitor, troubleshoot, and secure network traffic. This tool can be used to detect anomalies, identify potential security threats, and gain insights into the behavior of a network.

Key Features:
Packet Capturing: Capture live network packets using libraries like Scapy or PyShark.
Protocol Analysis: Identify and decode various network protocols (e.g., TCP, UDP, HTTP, DNS).
Traffic Filtering: Apply filters to focus on specific types of traffic (e.g., only HTTP packets or packets from a specific IP address).
Real-Time Monitoring: Display network traffic in real-time, with the option to log data for further analysis.
Statistics and Reporting: Generate summaries and statistics, such as packet count, protocol distribution, and communication patterns.

Explanation:
Packet Capturing:

The tool uses Scapy, a powerful Python library, to capture network packets. You can specify the network interface (e.g., eth0) and the number of packets to capture.
Protocol Analysis:

The tool identifies and prints out basic information about the captured packets, including the IP addresses, protocols (TCP, UDP, ARP), and port numbers.
Real-Time Monitoring:

The captured packets are analyzed and printed in real-time, providing instant visibility into network activity.
Customization:

The tool can be customized to capture only specific types of packets or to perform deeper protocol analysis, such as HTTP request/response analysis.
Statistics and Reporting:

The code can be extended to include statistical analysis, such as counting the number of packets per protocol or generating a summary report of the captured traffic.
