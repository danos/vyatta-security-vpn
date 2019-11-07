#!/opt/vyatta/bin/cliexec
vyatta-validate-type ipv4 $VAR(@) || vyatta-validate-type ipv6 $VAR(@) || [ $VAR(@) = 'any' ]
