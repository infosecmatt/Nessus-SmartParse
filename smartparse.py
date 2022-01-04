import pandas as pd
import numpy as np
import ipaddress as ip

df = pd.read_csv("../scan.csv")

# high level summary
print("High level observations:")
HighLevel = []

# number of in scope IP addresses
IPRange = ip.ip_network('10.5.5.0/24')
InScopeAddresses = {'Observation':'# In-Scope IP Addresses','Count':int(IPRange[-1]) - int(IPRange[0])}
HighLevel.append(InScopeAddresses)
# number of unique hosts identified during scanning
print()
AvailableHosts = {'Observation':"Hosts identified during scanning",'Count':df['Host'].nunique()}
HighLevel.append(AvailableHosts)

# number of hosts with at least one vulnerability of Low or greater
vulnerable = df.loc[df['Risk'] != 'None']
VulnerableHosts = {'Observation':"Hosts with at least one vulnerability",'Count':vulnerable['Host'].nunique()}
HighLevel.append(VulnerableHosts)
# number of services identified on the network

UniqueIPPort = df.drop_duplicates(subset=['Host','Protocol','Port'], keep='last')
TotalServices = {'Observation':"Total number of services identified during scanning",'Count':len(UniqueIPPort.index)}
HighLevel.append(TotalServices)
dfHighLevel = pd.DataFrame(HighLevel, columns=['Observation','Count'])
print(dfHighLevel)
# services identified broken down by protocol/port

# tcp hosts
IsTCP = UniqueIPPort['Protocol'] == 'tcp'
TCPServicePorts = UniqueIPPort[IsTCP]
TCPServicePortCount = [{'Port': k, 'Count': v}for k, v in dict(TCPServicePorts["Port"].value_counts()).items()]

# udp hosts
IsUDP = UniqueIPPort['Protocol'] == 'udp'
UDPServicePorts = UniqueIPPort[IsUDP]
UDPServicePortCount = [{'Port': k, 'Count': v}for k, v in dict(UDPServicePorts["Port"].value_counts()).items()]

# icmp hosts
IsICMP = UniqueIPPort['Protocol'] == 'icmp'
ICMPHosts = UniqueIPPort[IsICMP]
ICMPHostCount = [{'Port': k, 'Count': v}for k, v in dict(ICMPHosts["Port"].value_counts()).items()]

# Number of vulnerabilities based on criticality
print()
print("Number of vulnerabilities identified during scanning based on criticality:")
VulnSummary = [{'Risk': k, 'Count': v} for k, v in dict(df["Risk"].value_counts()).items()]
dfVulnSummary = pd.DataFrame(VulnSummary)
print(dfVulnSummary)

# Vulnerabilities broken down by service
print()
print("Vulnerability Summary for each identified open port:")
print()

PortVulnList = []

# tcp
for x in TCPServicePortCount:
    IsPort = df['Port'] == x["Port"]
    PortVulnResults = df[IsPort]
    PortVulnCount = [{'Risk': k, 'Count': v} for k, v in dict(PortVulnResults["Risk"].value_counts()).items()]
    d = {"Port":x["Port"], "PortCount":x["Count"], "Protocol":"tcp"}
    RiskScore = 0
    for y in PortVulnCount:
        if y["Risk"] == "Critical":
            RiskScore += y["Count"]
        elif y["Risk"] == "High":
            RiskScore += y["Count"] / 10
        elif y["Risk"] == "Medium":
            RiskScore += y["Count"] / 100
        elif y["Risk"] == "Low":
            RiskScore += y["Count"] / 10000
        d[y["Risk"]] = y["Count"]
    d["RiskScore"] = RiskScore 
    PortVulnList.append(d)

# udp
for x in UDPServicePortCount:
    IsPort = df['Port'] == x["Port"]
    PortVulnResults = df[IsPort]
    PortVulnCount = [{'Risk': k, 'Count': v} for k, v in dict(PortVulnResults["Risk"].value_counts()).items()]
    d = {"Port":x["Port"], "PortCount":x["Count"], "Protocol":"udp"}
    RiskScore = 0
    for y in PortVulnCount:
        if y["Risk"] == "Critical":
            RiskScore += y["Count"]
        elif y["Risk"] == "High":
            RiskScore += y["Count"] / 10
        elif y["Risk"] == "Medium":
            RiskScore += y["Count"] / 100
        elif y["Risk"] == "Low":
            RiskScore += y["Count"] / 10000
        d[y["Risk"]] = y["Count"]
    d["RiskScore"] = RiskScore
    PortVulnList.append(d)

#icmp
ICMPVulnSummary = [{"Risk":k,"Count":v} for k,v in dict(ICMPHosts["Risk"].value_counts()).items()]
ICMPVulnList = {"PortCount":ICMPHostCount[0]['Count'],"Protocol":"icmp"}
ICMPRiskScore = 0
for x in ICMPVulnSummary:
    if x["Risk"] == "Critical":
        ICMPRiskScore += x["Count"]
    elif x["Risk"] == "High":
        ICMPRiskScore += x["Count"] / 10
    elif x["Risk"] == "Medium":
        ICMPRiskScore += x["Count"] / 100
    elif x["Risk"] == "Low":
        ICMPRiskScore += x["Count"] / 10000
    ICMPVulnList[x["Risk"]] = x["Count"]
ICMPVulnList["RiskScore"] = ICMPRiskScore
PortVulnList.append(ICMPVulnList)

dfPortVulnList = pd.DataFrame(PortVulnList)
print(dfPortVulnList)
# get count of unique vulnerabilities for each criticality level as well as environment risk rating for each individual Nessus ID
RiskRatings = df["Risk"].unique()
for x in RiskRatings:
    print("Aggregated vulnerability counts based on NessusID for the risk rating",x,":")
    MatchesRisk = df['Risk'] == x
    RiskGroupVulns = df[MatchesRisk]
    AggregatedVulnCount = [{'Plugin ID':k,'Count':v} for k,v in dict(RiskGroupVulns["Plugin ID"].value_counts()).items()]
    xyz = []
    d = {}
    print(len(AggregatedVulnCount),"unique vulnerabilities with the risk rating",x,"were identified.")
    AggregatedVulns = pd.DataFrame(AggregatedVulnCount)
    IDVulnSummary = RiskGroupVulns.merge(AggregatedVulns, on='Plugin ID', how='left').drop_duplicates(subset=['Plugin ID'])
    IDVulnSummary["RiskScore"] = np.nan
    for index,row in IDVulnSummary.iterrows():
        if row["Risk"] == "Critical":
            IDVulnSummary["RiskScore"] = IDVulnSummary["Count"]
        elif row["Risk"] == "High":
            IDVulnSummary["RiskScore"] = IDVulnSummary["Count"] / 10
        elif row["Risk"] == "Medium":
            IDVulnSummary["RiskScore"] = IDVulnSummary["Count"] / 100
        elif row["Risk"] == "Low":
            IDVulnSummary["RiskScore"] = IDVulnSummary["Count"] / 10000
        else:
            IDVulnSummary["RiskScore"] = 0
    print(IDVulnSummary.sort_values(by='RiskScore',ascending=False, ignore_index=True))
    print()
    
# get count vulnerabilities by Risk rating for each scanned host
print()
print("Getting vulnerability summary and a weighted risk rating for each host:")
Hosts = df["Host"].unique()
HostVulnSummary = []
for x in Hosts:
    MatchesHost = df["Host"] == x
    HostVulns = df[MatchesHost]
    AggregatedVulnCount = [{'Risk':k,'Count':v} for k,v in dict(HostVulns['Risk'].value_counts()).items()]
    AggregatedVulns = pd.DataFrame(AggregatedVulnCount)
    d = {"Host":x}
    RiskScore = 0
    for y in AggregatedVulnCount:
        #updating risk score
        if y["Risk"] == "Critical":
            RiskScore += y["Count"]
        elif y["Risk"] == "High":
            RiskScore += y["Count"] / 10
        elif y["Risk"] == "Medium":
            RiskScore += y["Count"] / 100
        elif y["Risk"] == "Low":
            RiskScore += y["Count"] / 10000

        d[y["Risk"]] = y["Count"]
        d["RiskScore"] = RiskScore

    HostVulnSummary.append(d)
dfHostVulnSummary = pd.DataFrame(HostVulnSummary)
print(dfHostVulnSummary.sort_values(by=['RiskScore', 'Critical', 'High', 'Medium', 'Low', 'None'], ascending=False, ignore_index=True))

