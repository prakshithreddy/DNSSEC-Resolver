# DNSSEC-Resolver

External Libraries Used: dnspython(has dependencies on pcrypto and Mircosoft Visual Studio C++ 9.x for python)


Instructions to run the programs:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PART-A(mydig.py - Non Secure resolver):
~~~~~~

	python mydig.py www.google.com	A

	python mydig.py	www.google.com MX

	python mydig.py	www.google.com NS

	python mydig.py	www.google.com

----------------------------------------------

PART-B(mydnssecresolver.py - Secure resolver):
~~~~~~

	python mydnssecresolver.py www.google.com
	
	Implementation of secure resolver is documented in PartB_implementation.txt .
	
----------------------------------------------
	
PART-C(Analysis):
~~~~~~
	
	My DNS Resolver is compared with the local DNS resolver and Google DNS Resolver(8.8.8.8) and CDF is plotted for analysis as CDF.png.
	Obeservations from the CDF are documented in PartC_results.txt.
	
Other Useful Resources:
~~~~~~~~~~~~~~~~~~~~~~

	Understand how DNSSEC works - https://www.cloudflare.com/dns/dnssec/how-dnssec-works/

	Check correctness of each website using - https://dnssec-debugger.verisignlabs.com/
	
	
	
