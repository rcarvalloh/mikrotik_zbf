# mikrotik_zbf

Mikrotik script for zone based firewall implementations 

#                                          WARNING                                                        #
# I PROVIDE THIS SCRIPT "AS IS", WITHOUT ANY KIND OF GUARANTEE THAT IT'll WORK IN YOUR PARTICULAR SETUP  #
#           I AM NOT RESPONSIBLE FOR ANY DOWNTIME YOU MAY INCUR BY USING THIS SCRIPT                      #


This script is to create a set of custom rules to enable a Mikrotik box firewall to behave as a Zone Based Firewall (read here for more information: http://ciscoskills.net/2011/03/18/understanding-zone-based-firewalls/) 

This is a kind of firewall methodology that's available in Cisco and other manufacturers (like OpenWrt, Juniper, etc.). Sadly in Mikrotik it isn't implemented, however by using custom chains one can create a firewall that behaves like a ZBF. 

This scripts creates 4 different zones:

INSIDE: Trusted traffic
OUTSIDE: Not trusted traffic 
DMZ: Partially trusted traffic 
FIREWALL: Traffic that starts or ends inside the router itself 

It'll also create the following chains (Inzone-to-Outzone):
Inside-to-Outside, Inside-to-Dmz, Inside-to-Firewall, Outside-to-Inside, Outside-to-Dmz, Outside-to-Firewall, Dmz-to-Inside, Dmz-to-Outside, Dmz-to-Firewall, Intra-Zone-Traffic-Inside, Intra-Zone-Traffic-Outside, Intra-Zone-Traffic-Dmz, Firewall-to-Inside, Firewall-to-Outside, Firewall-to-Dmz

Please read the script's description before running it. 
The script also installs a function inside the router that you can call via console with the command:

#  THIS VERSION ONLY WORKS WITH ROS >= 6.36  #

The reason being it uses "interface-lists" to classify traffic instead of the old method which used a lot of jumps, this is more cleaner and easier to maintain, in order to add or remove interfaces from a zone all you've got to do is add or remove the interface from the corresponding list (located at interfaces -> interface list from winbox)

For the old version check release 1.0


#   DEFAULT BEHAVIOR FOR NEW CONNECTIONS   #


IN ZONE - OUT ZONE - ACTION

Inside - Outside - Accept
Inside - Inside - Accept
Inside - Dmz- Accept
Inside - Firewall - Accept 

Outside - Inside - Deny
Outside - Outside - Accept
Outside - Dmz - Deny
Outside - Firewall - Deny

Dmz - Inside - Deny
Dmz - Dmz - Accept
Dmz - Outside - Accept
Dmz - Firewall - Deny

Firewall - Outside - Deny
Firewall - Inside - Deny
Firewall - Dmz - Deny

Traffic coming from an interface with no security context in either forward, input and output is automatically dropped 

#  KNOWN ISSUES  #

Currently, if the router's got a service running that tries to access another service running inside it, the firewall will block the connection (for instance, hotspot trying to do a request to user manager in the same device), this is because the connection won't have any interface associated (it'll appear as coming from an Unknown interface and going to an Unknown interface).

If this is your case disable the rules that block traffic from UNKNOWN interfaces in chains INPUT and OUTPUT and it'll work. 

#   NOTES   #

This is a really restrictive firewall, please study it first before implementing, for instance by default traffic from the router to the outside zone (your ISP for example) is dropped, this will cause a problem with your routes if you're using "check-gateway", you need to allow ICMP messages to the gateway being tested in the "Firewall-to-Outside" chain.

The chains follow an specific pattern, don't mess with it, if you want to add a rule for a specific traffic path do so at the specific chain (ie. traffic from inside to outside must be managed in the Inside-to-Outside chain...) Also MAKE SURE, you add the rule before the rule tagged as "DEFAULT-RULE" for that particular chain. 

An easy way to do this is in winbox go to: IP -> FIREWALL - FILTER and filter based on chains (using the button in the top right corner) then just copy the default rule, modify it to your needs and drag it upwards. If you want to add more rules don't copy the DEFAULT-RULE just the ones preceding it and they'll be automatically on top of it. 

# AUTHOR: ING. RAFAEL CARVALLO
# VERSION: 2.0
