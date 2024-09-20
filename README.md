# A Zeek Based QuasarRAT Malware Detector

Malware often hides communications with its command and control (C2) server over HTTPS. 
The encryption in HTTPS usually conceals the compromise long enough for the malware to 
accomplish its goal. This makes detecting malware that uses HTTPS challenging, but once 
in a while, you will catch a break, as in the case here with QuasarRAT, a Windows remote 
access tool that has been deployed over the past year to target organizations that manage 
critical infrastructure in the United States.

### Example Notice.log Output

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2024-09-20-00-36-35
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
1723831638.402474	CABkjv381UgODCw5Cc	192.168.100.7	49744	86.136.67.231	1337	-	-	-	tcp	QuasarRAT::C2_Traffic_Observed	Potential QuasarRAT C2 discovered via a default SSL certificate.	-	192.168.100.7	86.136.67.231	1337	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
#close	2024-09-20-00-36-35
```

### Suricata Rules

You can find Suricata rules in the "suri" directory.

### PCAP Sources

- QuasarRAT
  - https://app.any.run/tasks/09ffabf7-774a-43a3-8c97-68f2046fd385#
