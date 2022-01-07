import pandas as pd
import numpy as np
import ipaddress as ip
import argparse as ap
import os
import csv

#argparse
parser = ap.ArgumentParser(description='Take a supplied Nessus scan .csv output, perform useful permutations to the data to reveal insights into vulnerability management, and use those insights to provide meaningful reporting metrics.')
parser.add_argument('-f','--input-file', required=True, help='The Nessus .csv file to be analyzed.', dest='path')
group = parser.add_mutually_exclusive_group()
group.add_argument('-r','--ip-range', required=False, help='In-scope IP range used for scanning. If multiple subnets are used, use -rf instead.',dest='iprange')
group.add_argument('-rf','--range-file', required=False, help='File containing list of in-scope IPs, separated by newline characters',dest='rangefile')
parser.add_argument('-o','--out-path',default=__file__, help='Directory where permutated data will be output.',dest='outpath')
args = parser.parse_args()

# making directory for reporting / output
path = ""
if os.path.isdir(args.outpath):
    path = os.path.join(args.outpath,"output")
    try:
        os.makedirs(path)
        os.chmod(path,0o755)
    except FileExistsError:
        exit("Directory "+path+" already exists.")
    except:
        exit("Unable to create folder for output. Do you have write permissions to "+args.outpath+"?")
else:
    path = os.path.join(os.path.dirname(args.outpath),"output")
    try:
        os.makedirs(path)
        os.chmod(path,0o755)
    except FileExistsError:
        exit("Directory "+path+" already exists.")
    except:
        exit("Unable to create folder for output. Do you have write permissions to "+os.path.dirname(args.outpath)+"?")
# checking if supplied file exists
if os.path.isfile(args.path):
    try:
        df = pd.read_csv(args.path, engine='python',encoding='utf-8',error_bad_lines=False)
    except Exception as e:
        print(e)
        exit("ERROR: Supplied file " + args.path + " is not a csv. Exiting...")
else:
	exit("Invalid file or path: " + args.path)

#high level analysis
HighLevel = []
# checking if supplied IP range is valid and counting in-scope addresses if valid
if args.iprange is not None:
    try:
        IPRange = ip.ip_network(args.iprange)
        #number of in scope IP addresses
        InScopeAddresses = {'Observation':'# In-Scope IP Addresses','Count':int(IPRange[-1]) - int(IPRange[0])}
        HighLevel.append(InScopeAddresses)
    except:
    	exit("Invalid IP range. Please ensure that the provided range uses slash notation.")
# checking if supplied IP range file is valid
elif args.rangefile is not None: 
    if os.path.isfile(args.rangefile):
        with open(args.rangefile, 'r') as scope:
            InScopeAddressCount = 0
            for line in scope:
                value = line.strip()
                try:
                    ip.ip_address(value)
                    InScopeAddressCount += 1
                except:
                    try:
                        subnet = ip.ip_network(value)
                        IpsInRange = int(subnet[-1]) - int(subnet[0])
                        InScopeAddressCount += IpsInRange
                    except:
                        exit("Error encountered with IP range file. " + value + " is not a valid IP address or range.")
            InScopeAddresses = {'Observation':'# In-Scope IP Addresses','Count':InScopeAddressCount}
            HighLevel.append(InScopeAddresses)
    else:
        exit("Provided range file "+args.rangefile+" does not exist.")

# number of unique hosts identified during scanning
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
dfHighLevel.to_csv(path + '/' + "HighLevelSummary.csv",quoting=csv.QUOTE_NONNUMERIC,escapechar="\\",doublequote=True, encoding='utf-8', index=False)
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
VulnSummary = [{'Risk': k, 'Count': v} for k, v in dict(df["Risk"].value_counts()).items()]
dfVulnSummary = pd.DataFrame(VulnSummary)
dfVulnSummary.to_csv(path + '/' + "VulnCriticalitySummary.csv",quoting=csv.QUOTE_NONNUMERIC,escapechar="\\",doublequote=True, encoding='utf-8', index=False)

# Vulnerabilities broken down by service / each open port

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
dfPortVulnList.to_csv(path + '/' + "PortVulnList.csv",quoting=csv.QUOTE_NONNUMERIC,escapechar="\\",doublequote=True, encoding='utf-8', index=False)
# get count of unique vulnerabilities for each criticality level as well as environment risk rating for each individual Nessus ID
RiskRatings = df["Risk"].unique()
UniqueVulnsPerRisk = []
for x in RiskRatings:
    # print("Aggregated vulnerability counts based on NessusID for the risk rating",x,":")
    MatchesRisk = df['Risk'] == x
    RiskGroupVulns = df[MatchesRisk]
    AggregatedVulnCount = [{'Plugin ID':k,'Count':v} for k,v in dict(RiskGroupVulns["Plugin ID"].value_counts()).items()]
    d = {"Risk":x,"Unique Count": len(AggregatedVulnCount)}
    UniqueVulnsPerRisk.append(d)
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
    IDVulnSummary = IDVulnSummary.sort_values(by='RiskScore',ascending=False, ignore_index=True)
    IDVulnSummary.to_csv(path + '/' + x +"-NessusIDVulnSummary.csv",quoting=csv.QUOTE_NONNUMERIC,escapechar="\\",doublequote=True, encoding='utf-8', index=False)
dfUniqueVulnsPerRisk = pd.DataFrame(UniqueVulnsPerRisk)
dfUniqueVulnsPerRisk.to_csv(path+'/'+'UniqueVulnsPerRisk.csv',quoting=csv.QUOTE_NONNUMERIC,escapechar="\\",doublequote=True,encoding='utf-8',index=False)
# get count vulnerabilities by Risk rating for each scanned host
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
dfHostVulnSummary = dfHostVulnSummary.sort_values(by=['RiskScore', 'Critical', 'High', 'Medium', 'Low', 'None'], ascending=False, ignore_index=True)
dfHostVulnSummary.to_csv(path + '/' + "HostBasedSummary.csv",quoting=csv.QUOTE_NONNUMERIC,escapechar="\\",doublequote=True, encoding='utf-8', index=False)

