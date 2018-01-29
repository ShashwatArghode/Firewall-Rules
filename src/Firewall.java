import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class Firewall {

	protected Set<Long> firewallRulesHash = new HashSet<>();
	protected Set<String> allPortIpsSet = new HashSet<>();
	public Firewall(String file) throws FileNotFoundException, IOException {
		BufferedReader br = new BufferedReader(new FileReader(file));
		String rule = "";
		while((rule=br.readLine()) != null) {
			populateFirewallRules(rule);
		}
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			//Please modify the path to your csv input file.
			Firewall firewall = new Firewall("C:\\Users\\dell\\eclipse-workspace\\FirewallRules\\src\\Firewall_Rules.csv");
			//Few testcases
			System.out.println(firewall.accessPacket("inbound", "tcp", 80, "192.168.1.2"));
			System.out.println(firewall.accessPacket("inbound", "udp", 53, "192.168.2.1"));
			System.out.println(firewall.accessPacket("outbound", "tcp", 10234, "192.168.10.11"));
			System.out.println(firewall.accessPacket("inbound", "tcp", 81, "192.168.1.2"));
			System.out.println(firewall.accessPacket("inbound", "udp", 24, "52.12.48.92"));
			System.out.println(firewall.accessPacket("inbound", "tcp", 24, "52.12.48.92"));
			System.out.println(firewall.accessPacket("inbound", "udp", 53, "192.168.2.5"));
			System.out.println(firewall.accessPacket("inbound", "udp", 53, "192.168.2.6"));
			System.out.println(firewall.accessPacket("outbound", "tcp", 20000, "192.168.10.11"));
			System.out.println(firewall.accessPacket("outbound", "tcp", 20001, "192.168.10.11"));
		}
		catch(Exception e) {
			System.out.println("Exception: "+ e.getLocalizedMessage());
		}
	}
	
	public void populateFirewallRules(String rule){
		String[] ruleArr = rule.split(",");
		int minPort = 0;
		int maxPort = 0;
		long minIP = 0;
		long maxIP = 0;
		
		//Handling all port and all ips case seperately
		if(ruleArr[2].equals("1-65535") && ruleArr[3].equals("0.0.0.0-255.255.255.255")){
			allPortIpsSet.add(ruleArr[0]+"-"+ruleArr[1]);
			return;
		}
		
		//Checking for port ranges
		if(ruleArr[2].contains("-")) {
			String[] portRange = ruleArr[2].split("-");
			minPort = Integer.parseInt(portRange[0]);
			maxPort = Integer.parseInt(portRange[1]);
		}
		else {
			minPort = Integer.parseInt(ruleArr[2]);
			maxPort = Integer.parseInt(ruleArr[2]);
		}
		
		//Checking for ip ranges
		if(ruleArr[3].contains("-")) {
			String[] ipRange = ruleArr[3].split("-");
			minIP = Long.parseLong(ipRange[0].replaceAll("\\.", ""));
			maxIP = Long.parseLong(ipRange[1].replaceAll("\\.", ""));
		}
		else {
			minIP = Long.parseLong(ruleArr[3].replaceAll("\\.", ""));
			maxIP = Long.parseLong(ruleArr[3].replaceAll("\\.", ""));
		}
		
		//Adding all ips and ports allowed mapping to hashset
		for(int i = minPort;i<=maxPort;i++) {
			for(long j = minIP;j<=maxIP;j++) {
				firewallRulesHash.add(new FirewallRule(ruleArr[0], ruleArr[1], i, j).hashCode);
			}
		}
	}
	
	public boolean accessPacket(String direction, String protocol, int port,String ip) {
		if(allPortIpsSet.contains(direction+"-"+protocol)){
			return true;
		}
		
		FirewallRule fr = new FirewallRule(direction, protocol, port, Long.parseLong(ip.replaceAll("\\.", "")));
		if(firewallRulesHash.contains(fr.hashCode))
			return true;
		return false;
	}
	
	public class FirewallRule{
		String direction;
		String protocol;
		int port;
		long ip;
		long hashCode;
		
		public FirewallRule(String direction, String protocol, int port,long ip) {
			this.direction = direction;
			this.protocol = protocol;
			this.port = port;
			this.ip = ip;
			this.hashCode = 31 * getHashCode(direction,protocol,port,ip); 
		}
		
		//Generating hashcode for Firewall rules
		public long getHashCode(String direction, String protocol, int port, long ip) {
			int hash =  1;
			int prime = 31;
			hash = prime * hash + direction.hashCode();
			hash = prime * hash + protocol.hashCode();
			hash = prime * hash + port;
			hash = prime * hash + Long.valueOf(ip).hashCode();
	        return hash;
		}
	}

}
