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
print("Total number of services identified during scanning:",len(UniqueIPPort.index))

# services identified broken down by protocol/port

# tcp
IsTCP = UniqueIPPort['Protocol'] == 'tcp'
TCPServicePorts = UniqueIPPort[IsTCP]

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

# icmp
IsICMP = UniqueIPPort['Protocol'] == 'icmp'
ICMPHosts = UniqueIPPort[IsICMP]

ICMPHostCount = [{'Port': k, 'Count': v}for k, v in dict(ICMPHosts["Port"].value_counts()).items()]
for x in ICMPHostCount:
    print(x["Count"], "devices were found to respond to ICMP requests.")


# Number of vulnerabilities based on criticality
print()
print("Number of vulnerabilities identified during scanning based on criticality:")
VulnSummary = [{'Risk': k, 'Count': v} for k, v in dict(df["Risk"].value_counts()).items()]
for x in VulnSummary:
    print(x["Risk"],":",x["Count"],"vulnerabilities found.")

# Vulnerabilities broken down by service
print()
print("Vulnerability Summary for each identified open port:")
print()
print("Vulnerabilities on TCP ports:")
print()

# TODO: improve this whole thing. by creating a list of lists I could turn this entire section into one big nested for loop.

# tcp
for x in TCPServicePortCount:
    print("Vulnerability Summary for TCP port",x["Port"],":")
    IsPort = df['Port'] == x["Port"]
    PortVulnResults = df[IsPort]
    PortVulnSummary = [{'Risk': k, 'Count': v} for k, v in dict(PortVulnResults["Risk"].value_counts()).items()]
    for y in PortVulnSummary:
        print(y["Risk"],":",y["Count"],"vulnerabilities found.")
    print()

# udp
print()
print("Vulnerabilities on UDP ports:")
print()
for x in UDPServicePortCount:
    print("Vulnerability Summary for UDP port",x["Port"],":")
    IsPort = df['Port'] == x["Port"]
    PortVulnResults = df[IsPort]
    PortVulnSummary = [{'Risk': k, 'Count': v} for k, v in dict(PortVulnResults["Risk"].value_counts()).items()]
    for y in PortVulnSummary:
        print(y["Risk"],":",y["Count"],"vulnerabilities found.")
    print()

#icmp
print()
print("Vulnerabilities related to ICMP services:")
print()
ICMPVulnSummary = [{"Risk":k,"Count":v} for k,v in dict(ICMPHosts["Risk"].value_counts()).items()]
for x in ICMPVulnSummary:
    print(x["Risk"],":",x["Count"],"vulnerabilities found.")



# get count of unique vulnerabilities for each criticality level
RiskRatings = df["Risk"].unique()
for x in RiskRatings:
    print("Aggregated vulnerability counts based on NessusID for the risk rating",x,":")
    MatchesRisk = df['Risk'] == x
    RiskGroupVulns = df[MatchesRisk]
    AggregatedVulnCount = [{'Plugin ID':k,'Count':v} for k,v in dict(RiskGroupVulns["Plugin ID"].value_counts()).items()]
    print(len(AggregatedVulnCount),"unique vulnerabilities with the risk rating",x,"were identified.")
    AggregatedVulns = pd.DataFrame(AggregatedVulnCount)
    print(RiskGroupVulns.merge(AggregatedVulns, on='Plugin ID', how='left').drop_duplicates(subset=['Plugin ID']))
    print()
