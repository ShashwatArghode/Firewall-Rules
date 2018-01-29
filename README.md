# Firewall-Rules


# Implementation Details:
	As firewall rules are changed often and used always during transmitting or receiving all the network packets it is important to
	
	have O(1) time complexity for checking if the packet is allowed by the existing firewall rules. Therefore, a hash is created for
	
	storing all the firewall rules to check if a network packet having particular ip address, port, protocol and direction is be
	
	allowed or blocked. All port and all ips case is handled separately to save on space. This solution has more space complexity but
	
	less time complexity.
	
	
# Testing:
	Tested code with different test cases for the rules provided in the description. Have checked most of the edge cases like start/end ip and port in a particular range. Have also checked code for all ips and all port case as that is handled seperately in the code.

# Refinement and Optimizations:
	I would have tried using different data structure to reduce on space complexity by adjusting the tadeoff between space and time complexity. Using a tree like data structure would have reduced space but hampered time complexity. Also would have handled ranged ips/ports effectively if more time was offered. Actually, this decision is based on the input i.e if more input are direct ips/port or ranges and what we can compromise on in terms of complexity i.e space or time.
	
# Team interests:
	1. Platform Team.
	2. Data Team.
