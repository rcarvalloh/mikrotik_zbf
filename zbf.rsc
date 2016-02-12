#ZONE BASED FIREWALL SCRIPT
#DEFINING SECURITY ZONES (SZ) MEMBERS 
#PLACE THE INTERFACES BELONGING TO A ZONE SEPARATED BY COMMAS AND INSIDE ""
#IF YOU DON'T WANT MEMBER INSIDE A PARTICULAR ZONE JUST LEAVE THE VARIABLE INITIALIZED (AS IN REMOVE {} AND EVERYTHING INSIDE)
#THE RULES THAT ACTIVATE THE FIREWALL ARE BY DEFAULT DISABLED YOU MUST ENABLE THEM MANUALLY
#AUTHOR: ING. RAFAEL CARVALLo
#DATE: 03/02/2016
#VERSION: 1.0

:local INSIDE {"bridge-local";"wlan1"}
:local OUTSIDE {"ether1"}
:local DMZ 

#SETTING UP THE CONTEXT 
/ip firewall filter 

#REMOVING ALL THE PREVIOUS RULES INSTALLED
remove [find where !dynamic]

#SETTING THE INITIAL RULES
add chain=forward connection-state=established,related
add chain=input connection-state=established,related
add chain=output connection-state=established,related

:do {
	#FROM-INSIDE JUMP RULES 
	:foreach x in $INSIDE do={
		add chain=forward action=jump jump-target=From-Inside in-interface=$x disabled=yes
		add chain=input action=jump jump-target=Inside-to-Firewall in-interface=$x disabled=yes
		add chain=output action=jump jump-target=Firewall-to-Inside out-interface=$x disabled=yes
	}	
	
	#FROM-OUTSIDE JUMP RULES 
	:foreach x in $OUTSIDE do={
		add chain=forward action=jump jump-target=From-Outside in-interface=$x disabled=yes
		add chain=input action=jump jump-target=Outside-to-Firewall in-interface=$x disabled=yes
		add chain=output action=jump jump-target=Firewall-to-Outside out-interface=$x disabled=yes
	}
	
	#FROM-DMZ JUMP RULES 
	:foreach x in $DMZ do={
		add chain=forward action=jump jump-target=From-Dmz in-interface=$x disabled=yes
		add chain=input action=jump jump-target=Dmz-to-Firewall in-interface=$x disabled=yes
		add chain=output action=jump jump-target=Firewall-to-Dmz out-interface=$x disabled=yes
	}
	
	#FROM-INSIDE CHAIN 
	:foreach x in $OUTSIDE do={
		add chain=From-Inside action=jump jump-target=Inside-to-Outside out-interface=$x 
	}
	:foreach x in $DMZ do={
		add chain=From-Inside action=jump jump-target=Inside-to-Dmz out-interface=$x 
	}
	
	:foreach x in $INSIDE do={
		add chain=From-Inside action=jump jump-target=Intra-Zone-Traffic-Inside out-interface=$x 
	}
	
	add chain=From-Inside action=drop comment="DEFAULT-RULE" 
	
	#FROM-OUTSIDE CHAIN 
	:foreach x in $INSIDE do={
		add chain=From-Outside action=jump jump-target=Outside-to-Inside out-interface=$x 
	}
	:foreach x in $DMZ do={
		add chain=From-Outside action=jump jump-target=Outside-to-Dmz out-interface=$x 
	}
	
	:foreach x in $OUTSIDE do={
		add chain=From-Outside action=jump jump-target=Intra-Zone-Traffic-Outside out-interface=$x
	}
	
	add chain=From-Outside action=drop comment="DEFAULT-RULE"
	
	#FROM-DMZ CHAIN 
	:foreach x in $OUTSIDE do={
		add chain=From-Dmz action=jump jump-target=Dmz-to-Outside out-interface=$x 
	}
	:foreach x in $INSIDE do={
		add chain=From-Dmz action=jump jump-target=Dmz-to-Inside out-interface=$x 
	}
	
	:foreach x in $DMZ do={
		add chain=From-Dmz action=jump jump-target=Intra-Zone-Traffic-Dmz out-interface=$x 
	}
	
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

/system script
add name=zbfFunctions owner=admin policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive source="###############################################################################\r\
    \n#THIS SCRIPTS HELP YOU ADD INTERFACES TO AN SPECIFIC ZONE                                                                #\r\
    \n#IT'S INSTALLED AS A SCRIPT INSIDE THE ROUTER                                                                                            #\r\
    \n#THIS ASSUMES YOU HAVEN'T CHANGED THE FIREWALL INITIAL SCHEME \"AS PER ZBF.RSC\"                   #\r\
    \n###############################################################################\r\
    \n\r\
    \n#DO NOT TOUCH THIS\r\
    \n:local oppositeZone\r\
    \n:local currentDate [/system clock get date]\r\
    \n\r\
    \n#SETTING UP HELPER VARIABLES \r\
    \n:if (\$1!=\"add\" and \$1!=\"remove\" ) do={ \r\
    \n:error \"Error, bad parameters, usage: zbf add zoneNumber interface OR zbf remove interface\"\r\
    \n} \r\
    \n\r\
    \n:if (\$1=\"add\") do={\r\
    \n:local zone [:put \$2]\r\
    \n:if (\$zone=\"1\" or \$zone=\"2\" or \$zone=\"3\") do={\r\
    \n\t:if (\$zone=\"1\") do={\r\
    \n\t\t:set zone \"Inside\"\r\
    \n\t\t:set oppositeZone {\"Outside\";\"Dmz\"}\r\
    \n\t}\r\
    \n\t:if (\$zone=\"2\") do={\r\
    \n\t\t:set zone \"Outside\"\r\
    \n\t\t:set oppositeZone {\"Inside\";\"Dmz\"}\r\
    \n\t}\r\
    \n\t:if (\$zone=\"3\") do={\r\
    \n\t\t:set zone \"Dmz\"\r\
    \n\t\t:set oppositeZone {\"Inside\";\"Outside\"}\r\
    \n\t}\r\
    \n} else={\r\
    \n\t:error \"Invalid zone set, please check again 1.- INSIDE, 2.- OUTSIDE, 3.- DMZ\"\r\
    \n}\r\
    \n\r\
    \n#DATE VARIABLE FOR BACKUP\r\
    \n:local currentDATE [/system clock get date]\r\
    \n# extract month from currentDATE\r\
    \n:local currentDATEmonth [ :pick \$currentDATE 0 3 ];\r\
    \n# extract day\r\
    \n:local currentDATEday [ :pick \$currentDATE 4 6 ];\r\
    \n# extract year\r\
    \n:local currentDATEyear [ :pick \$currentDATE 7 11 ];\r\
    \n# get position of our month in the array = month number\r\
    \n:local mm ([ :find \$months \$currentDATEmonth -1 ] + 1);\r\
    \n# if month number is less than 10 (a single digit), then add a leading 0\r\
    \n:if (\$mm < 10) do={\r\
    \n    :set currentDATEmonth (\"0\" . \$mm);\r\
    \n# otherwise, just set currentDATEmonth as the number\r\
    \n} else={\r\
    \n    :set currentDATEmonth \$mm;\r\
    \n}\r\
    \n# combine year, month, and day\r\
    \n:local currentDATEvalue (\$currentDATEday.\"-\".\$currentDATEmonth.\"-\".\$currentDATEyear);\r\
    \n\r\
    \n/ip firewall filter\r\
    \n\r\
    \n:if ([:len \$3] = 0) do={\r\
    \n\t:error \"You must specify an interface as the third parameter\"\r\
    \n}\r\
    \n\r\
    \n#making a backup\r\
    \nexport file=(\"ZBF at \".\$currentDATEvalue.\".rsc\")\r\
    \n:put \"A backup has been made previous to adding the interface - ZBF at \$currentDATEvalue\"\r\
    \n\r\
    \n:local interfacesToAdd [:put \$3]\r\
    \n\r\
    \n:do {\r\
    \n                #REMOVING ALL THE PREVIOUS RULES FOR THE SELECTED INTERFACE (IF ANY)\r\
    \n                :foreach x in \$interfacesToAdd do={\r\
    \n                                 remove [find where in-interface=\$x]\r\
    \n                                 remove [find where out-interface=\$x]\r\
    \n               }\r\
    \n            \r\
    \n\t:foreach x in \$interfacesToAdd do={\r\
    \n\t\t#BASE JUMP RULES\r\
    \n\t\tadd chain=forward action=jump jump-target=\"From-\$zone\" in-interface=\$x place-before=3 disabled=yes\r\
    \n\t\tadd chain=input action=jump jump-target=\"\$zone-to-Firewall\" in-interface=\$x place-before=3 disabled=yes\r\
    \n\t\tadd chain=output action=jump jump-target=\"Firewall-to-\$zone\" out-interface=\$x place-before=3 disabled=yes\r\
    \n\t\t#JUMP RULE FOR INTRA ZONE TRAFFIC\r\
    \n\t\tadd chain=\"From-\$zone\" action=jump out-interface=\$x jump-target=\"Intra-Zone-Traffic-\$zone\" place-before=[find where chain=\"From-\$zone\" comment=\"DEFAULT-RULE\"]\r\
    \n\t\t#JUMP RULES FOR TRAFFIC GOING TO OPPOSITE ZONES \r\
    \n\t\t:foreach y in \$oppositeZone do={\r\
    \n\t\t\tadd chain=\"From-\$y\" action=jump out-interface=\$x jump-target=(\$y.\"-to-\".\$zone) place-before=[find where chain=\"From-\$y\" comment=\"DEFAULT-RULE\"]\r\
    \n\t\t}\r\
    \n\t}\r\
    \n} on-error={\r\
    \n\t:error \"Can't include interface to zone, please check interface name\"\r\
    \n}\r\
    \n\r\
    \n}\r\
    \n\r\
    \n:if (\$1=\"remove\") do={\r\
    \n\r\
    \n:if ([:len \$2] = 0) do={\r\
    \n\t:error \"You must specify an interface as the second parameter\"\r\
    \n}\r\
    \n\r\
    \n/ip firewall filter \r\
    \n\r\
    \n#DATE VARIABLE FOR BACKUP\r\
    \n:local currentDATE [/system clock get date]\r\
    \n# extract month from currentDATE\r\
    \n:local currentDATEmonth [ :pick \$currentDATE 0 3 ];\r\
    \n# extract day\r\
    \n:local currentDATEday [ :pick \$currentDATE 4 6 ];\r\
    \n# extract year\r\
    \n:local currentDATEyear [ :pick \$currentDATE 7 11 ];\r\
    \n# get position of our month in the array = month number\r\
    \n:local mm ([ :find \$months \$currentDATEmonth -1 ] + 1);\r\
    \n# if month number is less than 10 (a single digit), then add a leading 0\r\
    \n:if (\$mm < 10) do={\r\
    \n    :set currentDATEmonth (\"0\" . \$mm);\r\
    \n# otherwise, just set currentDATEmonth as the number\r\
    \n} else={\r\
    \n    :set currentDATEmonth \$mm;\r\
    \n}\r\
    \n# combine year, month, and day\r\
    \n:local currentDATEvalue (\$currentDATEday.\"-\".\$currentDATEmonth.\"-\".\$currentDATEyear);\r\
    \n\r\
    \n#making a backup\r\
    \nexport file=(\"ZBF at \".\$currentDATEvalue.\".rsc\")\r\
    \n:put \"A backup has been made previous to adding the interface - ZBF at \$currentDATEvalue\"\r\
    \n\r\
    \n:local interfacesToRemove [:put \$2]\r\
    \n\r\
    \n:do {\r\
    \n                #REMOVING ALL THE RULES FOR THE SELECTED INTERFACE (IF ANY)\r\
    \n                :foreach x in \$interfacesToRemove do={\r\
    \n                                 remove [find where in-interface=\$x]\r\
    \n                                 remove [find where out-interface=\$x]\r\
    \n               }\r\
    \n\t} on-error={\r\
    \n\t\t:error \"Can't remove interface, please check interface name\"\r\
    \n\t}\r\
    \n}"

/system scheduler
add name=setZbfFunction on-event=":global zbf [:parse [/system script get zbfFunctions  source]]\r\
    \n" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive start-time=startup

:global zbf [:parse [/system script get zbfFunctions  source]]

:put "Firewall Setup Correctly"
