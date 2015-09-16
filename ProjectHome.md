## Packetforward ##
Packetforward is an IP packet capture and forward tool based on libpcap and libnet. It is a command line tool that listens on one network interface for UDP and TCP packets and then injects them on the same or another network interface. It has options for packet capture filtering and changing destination address.


## Todo ##
Support for more than one destination address.<br>
Compiled as a Universal Binary<br>
<br>
<br>
<h2>Version History</h2>
<u>0.8.1:</u> (2008-12-19)<br>
Changed the makefile for easy configuration.<br>
Corrected minor errors in the readme file related to getting libnet.<br>
<br>
<u>0.8:</u> (2008-01-13)<br>
New option to set Packetforward in packet capture mode only.<br>
<br>
<u>0.7.1:</u> 2007-02-23<br>
The makefile now uses the libpcap that is preinstalled on Mac OS X.<br>
The distributed Mac OS X (Intel) binary is now compiled to use the libpcap that is preinstalled on Mac OS X.<br>
Corrected minor errors in the readme file related to usage of Packetforward.<br>
Added a script to ease usage of Packetforward.<br>
<br>
<u>0.7:</u> (2007-02-18)<br>
New code for injecting packets using libnet.<br>
New command line options handling.<br>
New options to hide headers and payload.<br>
Fixed minor bugs related to signedness warnings when compiling.<br>
Fixed minor bugs where wrong IP and TCP packet lengths were calculated.<br>
<br>
<u>0.5.1:</u> (2007-02-16)<br>
Fixed a serius bug where the payload file for Nemesis was saved in a wrong directory.<br>
<br>
<u>0.5:</u> (2007-02-15)<br>
First public release.<br>
Capture code is using libpcap.<br>
Dependent on Nemesis to inject packets.