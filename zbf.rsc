#ZONE BASED FIREWALL SCRIPT
#DEFINING SECURITY ZONES (SZ) MEMBERS 
#PLACE THE INTERFACES BELONGING TO A ZONE SEPARATED BY COMMAS AND INSIDE ""
#IF YOU DON'T WANT MEMBER INSIDE A PARTICULAR ZONE JUST LEAVE THE VARIABLE INITIALIZED (AS IN REMOVE {} AND EVERYTHING INSIDE)
#THE RULES THAT ACTIVATE THE FIREWALL ARE BY DEFAULT DISABLED YOU MUST ENABLE THEM MANUALLY
#AUTHOR: ING. RAFAEL CARVALLO
#DATE: 11/08/2017
#VERSION: 2.0
###THIS VERSION USES INTERFACE LISTS THIS FEATURE IS ONLY AVAILABLE IN ROS >= 6.36
:local INSIDE {"bridge-local";"wlan1"}
:local OUTSIDE {"ether1"}
:local DMZ 
#CREATING THE INTERFACE LISTS
/interface list
add comment="INSIDE ZONE" name=INSIDE
add comment="OUTSIDE ZONE" name=OUTSIDE
add comment="DMZ" name=DMZ

#ADDING THE INTERFACES TO LISTS 
#INSIDE
:foreach x in $INSIDE do={
	/interface list member
	add interface=$x list=INSIDE
}

#OUTSIDE
:foreach x in $OUTSIDE do={
	/interface list member
	add interface=$x list=OUTSIDE
}

#DMZ
:foreach x in $DMZ do={
	/interface list member
	add interface=$x list=DMZ
}

#SETTING UP THE FIREWALL CONTEXT 
/ip firewall filter 
#REMOVING ALL THE PREVIOUS RULES INSTALLED
remove [find where !dynamic]
#SETTING THE INITIAL RULES
add chain=forward connection-state=established,related
add chain=input connection-state=established,related
add chain=output connection-state=established,related
:do {
	#FROM-INSIDE JUMP RULES 
		add chain=forward action=jump jump-target=From-Inside in-interface-list=INSIDE disabled=yes
		add chain=input action=jump jump-target=Inside-to-Firewall in-interface-list=INSIDE disabled=yes
		add chain=output action=jump jump-target=Firewall-to-Inside out-interface-list=INSIDE disabled=yes
	
	#FROM-OUTSIDE JUMP RULES 
		add chain=forward action=jump jump-target=From-Outside in-interface-list=OUTSIDE disabled=yes
		add chain=input action=jump jump-target=Outside-to-Firewall in-interface-list=OUTSIDE disabled=yes
		add chain=output action=jump jump-target=Firewall-to-Outside out-interface-list=OUTSIDE disabled=yes
	
	#FROM-DMZ JUMP RULES 
		add chain=forward action=jump jump-target=From-Dmz in-interface-list=DMZ disabled=yes
		add chain=input action=jump jump-target=Dmz-to-Firewall in-interface-list=DMZ disabled=yes
		add chain=output action=jump jump-target=Firewall-to-Dmz out-interface-list=DMZ disabled=yes
	
	#FROM-INSIDE CHAIN 
		add chain=From-Inside action=jump jump-target=Inside-to-Outside out-interface-list=OUTSIDE 
		add chain=From-Inside action=jump jump-target=Inside-to-Dmz out-interface-list=DMZ 
		add chain=From-Inside action=jump jump-target=Intra-Zone-Traffic-Inside out-interface-list=INSIDE 

	add chain=From-Inside action=drop comment="DEFAULT-RULE" 
	
	#FROM-OUTSIDE CHAIN 
		add chain=From-Outside action=jump jump-target=Outside-to-Inside out-interface-list=INSIDE 
		add chain=From-Outside action=jump jump-target=Outside-to-Dmz out-interface-list=DMZ 
		add chain=From-Outside action=jump jump-target=Intra-Zone-Traffic-Outside out-interface-list=OUTSIDE
	
	add chain=From-Outside action=drop comment="DEFAULT-RULE"
	
	#FROM-DMZ CHAIN 
		add chain=From-Dmz action=jump jump-target=Dmz-to-Outside out-interface-list=OUTSIDE 
		add chain=From-Dmz action=jump jump-target=Dmz-to-Inside out-interface-list=INSIDE
		add chain=From-Dmz action=jump jump-target=Intra-Zone-Traffic-Dmz out-interface-list=DMZ 
	
	add chain=From-Dmz action=drop comment="DEFAULT-RULE"
		
} on-error={
	:error "Can't create initial jump rules, please check the interfaces names"
}
#DEFAULT FOR INTERFACES NOT LISTED INSIDE A SECURITY ZONE 
add chain=forward action=drop comment="DROP ALL TRAFFIC IN FORWARD COMMING FROM AN INTERFACE WITH NO SECURITY ZONE DEFINED" disabled=yes
add chain=input action=drop comment="DROP ALL TRAFFIC IN INPUT COMMING FROM AN INTERFACE WITH NO SECURITY ZONE DEFINED" disabled=yes
add chain=output action=drop comment="DROP ALL TRAFFIC IN OUTPUT GOING TO AN INTERFACE WITH NO SECURITY ZONE DEFINED" disabled=yes
#INTRA SECURITY ZONE TRAFFIC 
add action=passthrough chain=Intra-Zone-Traffic-Inside comment="TRAFFIC THAT TRAVERSE THE SAME SECURITY ZONE (INSIDE) - DEFAULT ACTION: ACCEPT"
add chain=Intra-Zone-Traffic-Inside
add action=passthrough chain=Intra-Zone-Traffic-Outside comment="TRAFFIC THAT TRAVERSE THE SAME SECURITY ZONE (OUTSIDE) - DEFAULT ACTION: ACCEPT"
add chain=Intra-Zone-Traffic-Outside
add action=passthrough chain=Intra-Zone-Traffic-Dmz comment="TRAFFIC THAT TRAVERSE THE SAME SECURITY ZONE (DMZ) - DEFAULT ACTION: ACCEPT"
add chain=Intra-Zone-Traffic-Dmz
#INTER SECURITY ZONE DEFAULT TRAFFIC RULES 
add action=passthrough chain=Inside-to-Outside comment="FROM SZ:INSIDE TO SZ:OUTSIDE - DEFAULT ACTION: ACCEPT"
add chain=Inside-to-Outside comment="DEFAULT-RULE"
add action=passthrough chain=Inside-to-Dmz comment="SZ:INSIDE TO SZ:DMZ - DEFAULT ACTION: ACCEPT"
add chain=Inside-to-Dmz comment="DEFAULT-RULE"
add action=passthrough chain=Outside-to-Inside comment="FROM SZ:OUTSIDE TO SZ:INSIDE - DEFAULT ACTION: DROP"
add action=drop chain=Outside-to-Inside
add action=passthrough chain=Outside-to-Dmz comment="FROM SZ:OUTSIDE TO SZ:DMZ - DEFAULT ACTION: ACCEPT"
add chain=Outside-to-Dmz comment="DEFAULT-RULE" 
add action=passthrough chain=Dmz-to-Inside comment="FROM SZ:DMZ TO SZ:INSIDE - DEFAULT ACTION: DROP"
add action=drop chain=Dmz-to-Inside comment="DEFAULT-RULE"
add action=passthrough chain=Dmz-to-Outside comment="SZ:DMZ TO SZ:OUTSIDE - DEFAULT ACTION: DROP"
add action=drop chain=Dmz-to-Outside comment="DEFAULT-RULE"
add action=passthrough chain=Inside-to-Firewall comment="SZ:INSIDE TO SZ:FIREWALL - DEFAULT ACTION: ACCEPT"
add chain=Inside-to-Firewall comment="DEFAULT-RULE"
add action=passthrough chain=Outside-to-Firewall comment="SZ:OUTSIDE TO SZ:FIREWALL - DEFAULT ACTION: DROP"
add action=drop chain=Outside-to-Firewall comment="DEFAULT-RULE"
add action=passthrough chain=Dmz-to-Firewall comment="SZ:DMZ TO SZ:FIREWALL - DEFAULT ACTION: DROP"
add action=drop chain=Dmz-to-Firewall comment="DEFAULT-RULE"
add action=passthrough chain=Firewall-to-Inside comment="SZ:FIREWALL TO SZ:INSIDE - DEFAULT ACTION: ACCEPT"
add chain=Firewall-to-Inside comment="DEFAULT-RULE"
add action=passthrough chain=Firewall-to-Outside comment="SZ:FIREWALL TO SZ:OUTSIDE - DEFAULT ACTION: DROP"
add action=drop chain=Firewall-to-Outside comment="DEFAULT-RULE"
add action=passthrough chain=Firewall-to-Dmz comment="SZ:FIREWALL TO SZ:DMZ - DEFAULT ACTION: DROP"
add action=drop chain=Firewall-to-Dmz comment="DEFAULT-RULE"
