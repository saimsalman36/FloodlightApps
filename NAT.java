package net.floodlightcontroller.nat;

/**
 * @author Brendan Tschaen
 * 
 * date: 9/16/2015
 * 
 * NAT Application: This application is a Network Address Translation (NAT)
 * module for floodlight. The module takes control of a single switch within
 * the topology and creates/installs NAT rules at this switch. This module attempts
 * to handle ARP by ignoring all ARP requests initiated from outside of the NAT.
 * ARP requests sent from within the NAT are translated so that external hosts
 * believe they are talking to the NAT's IP Address.
 * 
 * 
 * Requirements:
 * 		PATH_IN file: list of internal ip addresses
 * 		PATH_OUT file: single ip address to be viewed external.
 * 						needs to be one of the internal ip addresses
 * 		NAT_INFO file:	tells app info about NAT
 * 						format:
 * 				switch_id, internalport1 internalport2 ... internalportn, externalport1 externalport2 ... externalportn
 * 
 *	Usage: put this module before the packet installation rule (e.g., learning switch).
 *			Modify the files described above, and ensure their paths are correct in the code.
 *
 *	Testing in Mininet: Because this module is designed for TCP connections, we
 *			must create a TCP connection in Mininet. One way to do so is through
 *			iperf.
 *			1) set up an iperf server *outside* the NAT
 *					e.g. mininet> h4 iperf -s &
 *			2) run the iperf client from *within* the NAT
 *					e.g. mininet> h1 iperf -c h4 
 *
 */

import com.google.common.collect.HashBiMap;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFPacketIn;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.DatapathId;
// import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.TransportPort;

public class NAT implements IFloodlightModule, IOFMessageListener {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger log = LoggerFactory.getLogger( NAT.class );

    protected String insideIPsFile;
    protected String externalIPFile;
    protected String natInfoFile;

	protected ArrayList<IPv4Address> inside_ip = new ArrayList<IPv4Address>();
	protected IPv4Address external_ip = null;
	
	private DatapathId nat_swId = null;
	//switch ports facing inside of nat
	private ArrayList<TransportPort> nat_internal_ports = new ArrayList<TransportPort>();
	//switch ports facing outside of nat
	private ArrayList<TransportPort> nat_external_ports = new ArrayList<TransportPort>();

	HashBiMap<String,String> internal2external = HashBiMap.create();
	//TCP ports already in use
	ArrayList<TransportPort> usedPorts = new ArrayList<TransportPort>();
	
	HashMap<Long, Integer> internalMAC2ip = new HashMap<Long, Integer>(); 
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "NAT";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// not the NAT switch, continue processing as normal
		if( sw.getId()!=this.nat_swId ){
			return Command.CONTINUE;
		}
		
		
		OFPacketIn pi = (OFPacketIn) msg;
    	Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

    	if( eth.getEtherType()==EthType.IPv4 || eth.getEtherType()==EthType.ARP)
    		System.err.println( "Switch " +sw.getId() + ":" + eth.toString() );
    	if( eth.getEtherType() == EthType.IPv4 ){
            /* We got an IPv4 packet; get the payload from Ethernet */
            IPv4 ipv4 = (IPv4) eth.getPayload();
            short[] ports = networkTranslator( ipv4, sw, pi, cntx );
            // if(ports!=null){
            	// installFlowMods(sw, pi, cntx, ipv4.getSourceAddress(), ports[0], ports[1]);
            // }
        }
    	// else if( eth.getEtherType()== Ethernet.TYPE_ARP ){
    	// 	handleARP( sw, pi, cntx );
    	// }
    	// else{
    	// 	//log.info( "Unsupported packet type: " + Integer.toHexString(eth.getEtherType() & 0xffff) );
    	// }
		return Command.STOP;
	}

// 	private void handleARP( IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx ){

// 		Ethernet eth = new Ethernet();
// 		eth.deserialize(pi.getPacketData(), 0, pi.getPacketData().length);
// 		//Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
// 		ARP arp = (ARP) eth.getPayload();
// 		System.err.println( arp.toString() );
// 		if( inside_ip.contains(IPv4.fromIPv4Address(IPv4.toIPv4Address( arp.getSenderProtocolAddress()))) ){
			
// 			internalMAC2ip.put( Ethernet.toLong(arp.getSenderHardwareAddress()), IPv4.toIPv4Address(arp.getSenderProtocolAddress()) );
// 			arp.setSenderProtocolAddress( IPv4.toIPv4Address(external_ip) );
// 			if( Ethernet.toLong(arp.getTargetHardwareAddress())==0 ){
// 				arp.setTargetHardwareAddress( eth.getDestinationMACAddress() );//Ethernet.toMACAddress("ff:ff:ff:ff:ff:ff") );
// 			}
// 			// generate ARP request
// 			IPacket arpRequest = new Ethernet()
// 				.setSourceMACAddress(arp.getSenderHardwareAddress())
// 				.setDestinationMACAddress(arp.getTargetHardwareAddress())
// 				.setEtherType(Ethernet.TYPE_ARP)
// 				.setPriorityCode(eth.getPriorityCode())
// 				.setPayload( arp );

// 			//make packet out action
// 	        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
// 	                .getMessage(OFType.PACKET_OUT);    
// 	        po.setBufferId(OFPacketOut.BUFFER_ID_NONE).setInPort(pi.getInPort());
	        
// 	        ArrayList<OFAction> actions = new ArrayList<OFAction>();
// 	        for( Short externalNATSwitchPort: this.nat_external_ports ){
// 	        	OFActionOutput action = new OFActionOutput();
// 	        	action.setPort( externalNATSwitchPort );
// 	        	actions.add( action );
// 	        }       
// 	        po.setActions(actions);
// 	        po.setActionsLength( (short) (nat_external_ports.size()*OFActionOutput.MINIMUM_LENGTH) );
// 	        byte[] packetData = arpRequest.serialize();
//             po.setPacketData(packetData);
//             po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
//                     + po.getActionsLength() + packetData.length));
//             System.out.println( po.toString() );
// 	        try {
// 	            sw.write(po, null);
// 	            sw.flush();
// 	        } catch (IOException e) {
// 	            log.error("Failure writing PacketOut", e);
// 	        }
			
// 		}
// 		else if(IPv4.fromIPv4Address(IPv4.toIPv4Address(arp.getTargetProtocolAddress())).equals(external_ip)){
// 			log.info( "Not originating from within NAT, target IP is NAT IP\n");
// 			long dstMAC = Ethernet.toLong(eth.getDestinationMACAddress());
// 			if( !internalMAC2ip.containsKey( dstMAC) ){
// 				log.info( "Not forwarding. Outside host trying to initiate contact to inside host" );
// 				return;
// 			}
// 			int dstTrueIP = internalMAC2ip.get( dstMAC );
// 			arp.setTargetProtocolAddress( dstTrueIP );

// 			log.info( arp.toString() );
// 			// generate ARP request
// 			IPacket arpReply = new Ethernet()
// 				.setSourceMACAddress(arp.getSenderHardwareAddress())
// 				.setDestinationMACAddress(arp.getTargetHardwareAddress())
// 				.setEtherType(Ethernet.TYPE_ARP)
// 				.setPriorityCode(eth.getPriorityCode())
// 				.setPayload( arp );

// 			//make packet out action
// 			OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
// 					.getMessage(OFType.PACKET_OUT);    
// 			po.setBufferId(OFPacketOut.BUFFER_ID_NONE).setInPort(pi.getInPort());

// 			ArrayList<OFAction> actions = new ArrayList<OFAction>();
// 			for( Short internalNATSwitchPort: this.nat_internal_ports ){
// 				OFActionOutput action = new OFActionOutput();
// 				action.setPort( internalNATSwitchPort );
// 				actions.add( action );
// 			}       
// 			po.setActions(actions);
// 			po.setActionsLength( (short) (nat_internal_ports.size()*OFActionOutput.MINIMUM_LENGTH) );
// 			byte[] packetData = arpReply.serialize();
// 			po.setPacketData(pi.getPacketData());
// 			po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
// 					+ po.getActionsLength() + packetData.length));

// 			try {
// 				sw.write(po, null);
// 				sw.flush();
// 			} catch (IOException e) {
// 				log.error("Failure writing PacketOut", e);
// 			}
// 		}
		
		
// 	}
	
	
	private short[] networkTranslator( IPv4 ipv4, IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx ){
        if( ipv4.getProtocol()!=IpProtocol.TCP ){
        	log.info( "Dropping non-TCP packet" );
        	return null;
        }
    	TCP tcp = (TCP) ipv4.getPayload();
        IPv4Address srcIp = ipv4.getSourceAddress();
        IPv4Address dstIp = ipv4.getDestinationAddress();

    	TransportPort srcPort = tcp.getSourcePort();
    	TransportPort dstPort = tcp.getDestinationPort();

    	// if( inside_ip.contains(IPv4.fromIPv4Address(srcIp)) ){
     //    	System.err.println( "headed out of the NAT" );
     //    	short natPort = getExternalPort( srcIp, srcPort );
     //    	return new short[]{srcPort,natPort};
     //    }
    	// else if( IPv4.fromIPv4Address(dstIp).equals(external_ip) ){
     //    	System.err.println( "headed behind the NAT" );
     //    	//should never reach here, all connections should be initiated from within NAT
     //    	return null;
     //    }
     //    else{
     //    	//should never reach here
     //    	log.error( "Should never reach here, but it reached here..." );
     //    	log.error( "Source IP Adress:" + IPv4.fromIPv4Address(srcIp) );
     //    	log.error( "Destination IP Address:" + IPv4.fromIPv4Address(dstIp) );
     //    	return null;
     //    }

        return null; // TODO: SAIM - REMOVE THIS
	}
	
	// /**
	//  * Gets the external port for an internal <IP Address, Source Port>.
	//  * If a port has already been allocated, returns that port. Otherwise,
	//  * allocates a new, unused port for this address/port combo.
	//  * @param srcIp
	//  * @param srcPort
	//  * @return
	//  */
	// private short getExternalPort( IPv4Address srcIp, short srcPort ){
 //    	short natPort;
 //    	String key = IPv4.fromIPv4Address(srcIp) + ":" + srcPort;
 //    	if( internal2external.containsKey(key) ){
 //    		natPort = Short.parseShort( internal2external.get( key ).split(":")[1] );
 //    	}
 //    	else{
 //    		Random random = new Random();
 //    		natPort = (short) (random.nextInt(1000)+1024);
 //    		while( usedPorts.contains(natPort) ){
 //    			natPort = (short) (random.nextInt(1000)+1024);
 //    		}
 //    		usedPorts.add( natPort );
 //    		String value = external_ip + ":" + natPort;
 //        	this.internal2external.put( key, value );
 //    	}
 //    	return natPort;
	// }
	
// 	private void installFlowMods(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx,
// 			int internalAddress, short internalPort, short externalPort){
// 		Ethernet eth = new Ethernet();
// 		eth.deserialize(msg.getPacketData(), 0, msg.getPacketData().length);
// 		//Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
// 		if( eth.getEtherType()!=Ethernet.TYPE_IPv4){
// 			return;
// 		}
		
// 		IPv4 ipv4 = (IPv4) eth.getPayload();
// 		ipv4.setSourceAddress( external_ip );
// 		TCP tcp = (TCP) ipv4.getPayload();
// 		tcp.setSourcePort( externalPort );
// 		ipv4.setPayload(tcp);
		
//         OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
//                 .getMessage(OFType.PACKET_OUT);
//         po.setInPort(msg.getInPort());

//         // set actions
//         ArrayList<OFAction> actions = new ArrayList<OFAction>();
//         for( Short externalNATSwitchPort: this.nat_external_ports ){
//         	OFActionOutput action = new OFActionOutput();
//         	action.setPort( externalNATSwitchPort );
//         	actions.add( action );
//         }
// 		po.setActions(actions);
//         po.setActionsLength( (short) (nat_external_ports.size()*OFActionOutput.MINIMUM_LENGTH));

//         // set data if is is included in the packetin
//         byte[] packetData = eth.serialize();
//         po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
//                 + po.getActionsLength() + packetData.length));
//         po.setPacketData(packetData);
//         try {
//             sw.write(po, cntx);
//             sw.flush();
//         } catch (IOException e) {
//             log.error("Failure writing PacketOut", e);
//         }
		
//         //set forward translation
//         OFMatch match = new OFMatch();
//     	match.setWildcards( Wildcards.FULL.matchOn(Flag.DL_TYPE).matchOn(Flag.NW_SRC).matchOn(Flag.NW_PROTO).matchOn(Flag.TP_SRC).withNwSrcMask(32) );
//     	match.setDataLayerType( Ethernet.TYPE_IPv4 );
//     	match.setNetworkSource( internalAddress );
//     	match.setNetworkProtocol( IPv4.PROTOCOL_TCP );
//     	match.setTransportSource( internalPort );
    	
//     	actions.clear();
//         OFActionNetworkLayerSource ofanls = new OFActionNetworkLayerSource();
//         ofanls.setNetworkAddress( IPv4.toIPv4Address(external_ip) );
//         actions.add( ofanls );
//         OFActionTransportLayerSource ofatls = new OFActionTransportLayerSource();
//         ofatls.setTransportPort(externalPort);
//         actions.add( ofatls );
//         for( Short externalNATSwitchPort: this.nat_external_ports ){
//         	OFActionOutput action = new OFActionOutput();
//         	action.setPort( externalNATSwitchPort );
//         	actions.add( action );
//         }

// 		OFFlowMod flowMod = new OFFlowMod();
//     	flowMod.setMatch( match );
//     	flowMod.setBufferId(OFPacketOut.BUFFER_ID_NONE);
//         flowMod.setLength( (short) (OFFlowMod.MINIMUM_LENGTH + 
//         		nat_external_ports.size()*OFActionOutput.MINIMUM_LENGTH +
//         		OFActionNetworkLayerSource.MINIMUM_LENGTH +
//         		OFActionTransportLayerSource.MINIMUM_LENGTH) );
//         flowMod.setActions( actions );
        
//         try {
//             sw.write(flowMod, cntx);
//             sw.flush();
//         } catch (IOException e) {
//             log.error("Failure writing flowMod1", e);
//         }

//         //set reverse translation
//         match = new OFMatch();
//         match.setWildcards( Wildcards.FULL.matchOn(Flag.DL_TYPE).matchOn(Flag.NW_DST).matchOn(Flag.NW_PROTO).matchOn(Flag.TP_DST).withNwDstMask(32) );
//     	match.setDataLayerType( Ethernet.TYPE_IPv4 );
//         match.setNetworkDestination( IPv4.toIPv4Address(external_ip) );
//         match.setNetworkProtocol( IPv4.PROTOCOL_TCP );
//     	match.setTransportDestination( externalPort );
    	
//     	actions.clear();
//         OFActionNetworkLayerDestination ofanld = new OFActionNetworkLayerDestination();
//         ofanld.setNetworkAddress( internalAddress );
//         actions.add( ofanld );
//         OFActionTransportLayerDestination ofatld = new OFActionTransportLayerDestination();
//         ofatld.setTransportPort( internalPort );
//         actions.add( ofatld );
//     	for( Short externalNATSwitchPort: this.nat_internal_ports ){
//         	OFActionOutput action = new OFActionOutput();
//         	action.setPort( externalNATSwitchPort );
//         	actions.add( action );
//         }
    	
//     	flowMod = new OFFlowMod();
//     	flowMod.setMatch( match );
//     	flowMod.setBufferId(OFPacketOut.BUFFER_ID_NONE);
//         flowMod.setLength( (short) (OFFlowMod.MINIMUM_LENGTH +
//         		 this.nat_internal_ports.size()*OFActionOutput.MINIMUM_LENGTH + 
//         		OFActionNetworkLayerDestination.MINIMUM_LENGTH +
// 				OFActionTransportLayerDestination.MINIMUM_LENGTH) );
//         flowMod.setActions( actions );

//         try {
//             sw.write(flowMod, cntx);
//             sw.flush();
//         } catch (IOException e) {
//             log.error("Failure writing flowMod2", e);
//         }
// 	}
	
	
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		final Map<String, String> modConf = context.getConfigParams(this);

		// File containing inside IPs
		this.insideIPsFile = modConf.get("inside_ips_file");
		if (this.insideIPsFile == null) {
			throw new RuntimeException("No value for configuration parameter 'inside_ips_file'!");
		}

		// File containing external IP
		this.externalIPFile = modConf.get("external_ip_file");
		if (this.externalIPFile == null) {
			throw new RuntimeException("No value for configuration parameter 'external_ip_file'!");
		}

		// File containing NAT info
		this.natInfoFile = modConf.get("nat_info_file");
		if (this.natInfoFile == null) {
			throw new RuntimeException("No value for configuration parameter 'nat_info_file'!");
		}

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		System.out.println( "Starting up NAT module" );
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		
		BufferedReader reader;
		try
		{
			//read in internal ip addresses
			reader = new BufferedReader(new FileReader(new File(this.insideIPsFile)));
			String temp = null;
			while ((temp = reader.readLine()) != null)
			{
				if( !temp.startsWith("//") ){
					inside_ip.add(IPv4Address.of(temp));
				}
			}
			reader.close();

			//read in externally visible ip addresses
			reader = new BufferedReader(new FileReader(new File(this.externalIPFile)));
			temp = null;
			while ((temp = reader.readLine()) != null)
			{
				if( !temp.startsWith("//") ){
					external_ip = IPv4Address.of(temp);
					// assume one line and at the first line
					break;
				}
			}
			reader.close();
			
			//read in NAT switch id, inside ports, outside ports
			reader = new BufferedReader(new FileReader(new File(this.natInfoFile)));
			temp = null;
			System.out.println( "NAT info:" );
			while ((temp = reader.readLine()) != null)
			{
				if( !temp.startsWith("//") ){
					String[] nat_info = temp.split( "," );
					
					nat_swId = DatapathId.of(Long.valueOf( nat_info[0] ));
					System.out.println( "\tSwitchID: " + nat_swId );
					
					for( String internal_port: nat_info[1].trim().split(" ") ){
						nat_internal_ports.add( TransportPort.of( Integer.parseInt(internal_port)) );
					}
					System.out.println( "\tInternal ports: " + nat_internal_ports.toString() );
					
					for( String external_port: nat_info[2].trim().split(" ") ){
						nat_external_ports.add( TransportPort.of( Integer.parseInt(external_port)) );
					}
					System.out.println( "\tExternal ports:" + nat_external_ports.toString() );
					// assume one line and at the first line
					break;
				}
			}
			reader.close();
			
		} catch (IOException e)
		{
			e.printStackTrace();
		}
		
		
	}

// 	/**
// 	 * @param args
// 	 */
// 	public static void main(String[] args) {
// 		// TODO Auto-generated method stub

// 	}

}
