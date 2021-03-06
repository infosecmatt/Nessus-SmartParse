# TODO

- (DONE) Count of in-scope IP addresses
- (DONE) Count of active hosts (unique hosts that returned a result)
- (DONE) Count of hosts with at least one vulnerability (i.e. ones that returned a Low or higher)
- Total services (e.g., SMB, HTTP)
	- (DONE) broken down by service (count each SMB, HTTP, etc.)
		- Identify services by mapping ports to probably protocols
- (DONE) Total vulnerabilities
	- (DONE) broken down by criticality
	- (DONE) broken down by service/port
	- broken down by OS
	- broken down by network segment
- (DONE) distinct vulnerabilities
	- (DONE) broken down by criticality
- (DONE) most vulnerable hosts
	- (DONE) using weighted CVSS scores
		- 10000 lows = 1 critical
		- 100  mediums = 1 critical
		- 10 highs = 1 critical
		- 1 critical = 1 critical
		- subject to change
		- Actually, I do want to change it. Need to move to CVSS in the future as the severity range is too wide to just use's Nessus' Risk attribute, especially in the High Risk range
			- to that end, I stole the Department of Homeland Security's Risk Rating formula for their Cyber Hygiene Assessment Report (https://www.cisa.gov/uscert/sites/default/files/resources/ncats/CyHy%20Sample%20Report_508C.pdf). It's as follows: Risk Rating = (CVSS ^ 7) / (10^6)
	- For each host, divide the RiskScore by the total RiskScore of all devices to get a percentage of risk that each host is resposible for. will open things up to analysis such as "These 5 hosts represent over 70% of risk in the organization."
- (DONE) most severe vulnerabilities
	- (DONE) combination of frequency found + weighted CVSS score
- average vulnerability age by criticality
- percent vulnerabilities younger than 30 days by criticality
	- for critical, break down further using 0-15, 16-30, 31-90, 90+
- celebrity CVEs
- top 25 vulnerabilities by criticality
- make the initial codebase less ugly and more efficient
- (DONE) make sure everything gets outputted as csv
- Add flag for excluded IPs or IP ranges from scope
- for all try/excepts, be sure to include original error message by writing something to the effect of 'except Exception as e' followed by print(e)
- create a cleanup function to run whenever part of the script fails. for example, deleting the output folder or any data run thus far
- for IP ranges provided, documentation should specify that the ranges should be logical groupings such as office locations, departments, etc.. that way in the future the tool can break vulnerabilities down by network segment and provide insight like "40% of all vulnerabilities are located within the Austin datacenter."
- Need to create documentation for usage
	- Nessus CSV output should ideally be outputted with all columns (may require custom output) in order to use vulnerability age analysis
- Use .nessus scan configuration XML files in lieu of IP ranges and potentially to gather other relevant scan information.
- Determine unmanaged assets formulaically. Take the average Risk Score of all hosts, multiply by 10. Any asset with a Risk Score greater than that number may be considered unmanaged.
	- this could yield unreliable results for organizations with no assets that are truly unmanaged, so some additional checks will have to be in place to ensure that things aren't falsely labeled as unmanaged.
- create an output naming format that doesn't error out every time the folder already exists (e.g., using timestamps). at the end of the script, if successful, print message to user describing where they can find the results.
- PortVulnList:
	- create concatenation of protocol and port to get unique ID.
		- e.g., for tcp port 0, the ID would be tcp/0; for udp port 0, the ID would be udp/0
Long term ideas:
- incorporate visualization / pretty output of everything
- develop mechanism for trend monitoring
