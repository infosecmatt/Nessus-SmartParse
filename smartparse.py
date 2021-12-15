import pandas as pd
import ipaddress as ip

df = pd.read_csv("../scan.csv")
# print(df)

# number of in scope IP addresses
()
IPRange = ip.ip_network('10.5.5.0/24')
print("Number of IP addresses in-scope for scanning:", int(IPRange[-1]) - int(IPRange[0]))

# number of unique hosts identified during scanning
print()
print("Hosts identified during scanning:", df['Host'].nunique())

# number of hosts with at least one vulnerability of Low or greater
vulnerable = df.loc[df['Risk'] != 'None']
print("Hosts with at least one vulnerability:", vulnerable['Host'].nunique())

# number of services identified on the network

UniqueIPPort = df.drop_duplicates(subset=['Host','Protocol','Port'], keep='last')
print(UniqueIPPort)
print("Total number of services identified during scanning:",len(UniqueIPPort.index))

# services identified broken down by protocol/port

# tcp
IsTCP = UniqueIPPort['Protocol'] == 'tcp'
TCPServicePorts = UniqueIPPort[IsTCP]
print(TCPServicePorts)

TCPServicePortCount = [{'Port': k, 'Count': v}for k, v in dict(TCPServicePorts["Port"].value_counts()).items()]
for x in TCPServicePortCount:
    if x["Count"] == 1:
        print(x["Count"],"device identified as having TCP port",x["Port"], "open.")
    else:
        print(x["Count"],"devices identified as having TCP port",x["Port"], "open.")

# udp
IsUDP = UniqueIPPort['Protocol'] == 'udp'
UDPServicePorts = UniqueIPPort[IsUDP]

UDPServicePortCount = [{'Port': k, 'Count': v}for k, v in dict(UDPServicePorts["Port"].value_counts()).items()]
for x in UDPServicePortCount:
    if x["Count"] == 1:
        print(x["Count"],"device identified as having UDP port",x["Port"], "open.")
    else:
        print(x["Count"],"devices identified as having UDP port",x["Port"], "open.")


# Number of vulnerabilities based on criticality
print()
print("Number of vulnerabilities identified during scanning based on criticality:")
VulnSummary = [{'Risk': k, 'Count': v} for k, v in dict(df["Risk"].value_counts()).items()]
for x in VulnSummary:
    print(x["Risk"],":",x["Count"],"vulnerabilities found.")
