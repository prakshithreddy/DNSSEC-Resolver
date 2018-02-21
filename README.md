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
