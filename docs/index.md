# The impacket Programming Manual

**Author: Lu Ping (鲁平)**

Personal WeChat blog: Security丨Art — corrections and feedback are welcome.

impacket is a widely used "domain penetration toolkit". Its `examples` folder ships plenty of scripts that operate against domain controllers and covers most routine domain-penetration needs. Precisely because of that, most articles online focus on how to *use* those example scripts, while almost nothing has been written about *developing your own scripts* with impacket for real domain-penetration scenarios. The opposite would be more useful: many exploitation scripts for later domain vulnerabilities were built directly on top of impacket modules (e.g. sam-the-admin, CVE-2022-33679). This manual fills that gap, so that when the next vulnerability appears you can quickly write your own PoC with impacket.
