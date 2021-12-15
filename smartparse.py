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
UniqueIPPort = df.drop_duplicates(subset=['Host', 'Protocol', 'Port'], keep='last')

UniqueIPPort = df.groupby(['Host', 'Protocol', 'Port']).first()
print("Total number of services identified during scanning:",len(UniqueIPPort.index))



# Number of vulnerabilities based on criticality
print()
print("Number of vulnerabilities identified during scanning based on criticality:")
VulnSummary = [{'Risk': k, 'Count': v} for k, v in dict(df["Risk"].value_counts()).items()]
for x in VulnSummary:
    print(x["Risk"],":",x["Count"],"vulnerabilities found.")
