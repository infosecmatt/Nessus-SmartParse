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

Long term ideas:
- incorporate visualization / pretty output of everything
- develop mechanism for trend monitoring
