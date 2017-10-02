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
import org.projectfloodlight.openflow.protocol.OFPacketOut;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.MacAddress;

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

    HashMap<MacAddress, IPv4Address> internalMAC2ip = new HashMap<MacAddress, IPv4Address>(); 

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
        if( !sw.getId().equals(this.nat_swId) ){
            return Command.CONTINUE;
        }		

        OFPacketIn pi = (OFPacketIn) msg;
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if( eth.getEtherType()==EthType.IPv4 || eth.getEtherType()==EthType.ARP)
            // System.err.println( "Switch " +sw.getId() + ":" + eth.toString() );
        if( eth.getEtherType() == EthType.IPv4 ){
            /* We got an IPv4 packet; get the payload from Ethernet */
            IPv4 ipv4 = (IPv4) eth.getPayload();
            TransportPort[] ports = networkTranslator( ipv4, sw, pi, cntx );
            if(ports!=null){
                installFlowMods(sw, pi, cntx, ipv4.getSourceAddress(), ports[0], ports[1]);
            }
        }
        else if( eth.getEtherType()== EthType.ARP ){
        	handleARP( sw, pi, cntx );
        }
        else{
        	// log.info( "Unsupported packet type: " + Integer.toHexString(eth.getEtherType() & 0xffff) );
        }
        return Command.STOP;
    }


    private TransportPort[] networkTranslator( IPv4 ipv4, IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx ){
        if( ipv4.getProtocol()!=IpProtocol.TCP ){
            log.info( "Dropping non-TCP packet" );
            return null;
        }
        TCP tcp = (TCP) ipv4.getPayload();
        IPv4Address srcIp = ipv4.getSourceAddress();
        IPv4Address dstIp = ipv4.getDestinationAddress();

        TransportPort srcPort = tcp.getSourcePort();
        TransportPort dstPort = tcp.getDestinationPort();

        if( inside_ip.contains(srcIp) ){
            System.err.println( "headed out of the NAT" );
            TransportPort natPort = getExternalPort( srcIp, srcPort );
            return new TransportPort[]{srcPort,natPort};
        }
        else if( dstIp.equals(external_ip) ){
            System.err.println( "headed behind the NAT" );
//should never reach here, all connections should be initiated from within NAT
            return null;
        }
        else{
//should never reach here
            log.error( "Should never reach here, but it reached here..." );
            log.error( "Source IP Adress:" + srcIp );
            log.error( "Destination IP Address:" + dstIp );
            return null;
        }
    }

    /**
    * Gets the external port for an internal <IP Address, Source Port>.
    * If a port has already been allocated, returns that port. Otherwise,
    * allocates a new, unused port for this address/port combo.
    * @param srcIp
    * @param srcPort
    * @return
    */
    private TransportPort getExternalPort( IPv4Address srcIp, TransportPort srcPort ){
        TransportPort natPort;
        String key =srcIp.toString() + ":" + srcPort.toString();
        if( internal2external.containsKey(key) ){
            natPort = TransportPort.of( Integer.parseInt(internal2external.get( key ).split(":")[1]) );
        }
        else{
            Random random = new Random();
            natPort = TransportPort.of (random.nextInt(1000)+1024);
            while( usedPorts.contains(natPort) ){
                natPort = TransportPort.of (random.nextInt(1000)+1024);
            }
            usedPorts.add( natPort );
            String value = this.external_ip + ":" + natPort;
            this.internal2external.put( key, value );
        }
        return natPort;
    }

    private void installFlowMods(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx,
        IPv4Address internalAddress, TransportPort internalPort, TransportPort externalPort){
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        if( eth.getEtherType()!=EthType.IPv4){
            return;
        }

        OFFactory myFactory = sw.getOFFactory();

    // set actions
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        OFActions actions = myFactory.actions();

    //set forward translation
        Match match = myFactory.buildMatch()
        .setExact(MatchField.ETH_TYPE, EthType.IPv4)
        .setExact(MatchField.IPV4_SRC, internalAddress)
        .setExact(MatchField.IP_PROTO, IpProtocol.TCP)
        .setExact(MatchField.TCP_SRC, internalPort)
        .build();

        actionList.clear();
        actionList.add(sw.getOFFactory().actions().setNwSrc(external_ip));
        actionList.add(sw.getOFFactory().actions().setTpSrc(externalPort));

        for( TransportPort externalNATSwitchPort: this.nat_external_ports ){
            OFActionOutput action = actions.buildOutput()
            .setPort( OFPort.of(externalNATSwitchPort.getPort()) )
            .build();
            actionList.add( action );
        }

        OFFlowMod flowMod = myFactory.buildFlowModify()
        .setBufferId(OFBufferId.NO_BUFFER)
        .setMatch(match)
        .setActions(actionList)
        .build();

        sw.write(flowMod);

    //set reverse translation //

        OFFactory myFactoryReverse = sw.getOFFactory();
        ArrayList<OFAction> actionListReverse = new ArrayList<OFAction>();
        OFActions actionsReverse = myFactoryReverse.actions();

        Match matchReverse = myFactoryReverse.buildMatch()
        .setExact(MatchField.ETH_TYPE, EthType.IPv4)
        .setExact(MatchField.IPV4_DST, external_ip)
        .setExact(MatchField.IP_PROTO, IpProtocol.TCP)
        .setExact(MatchField.TCP_DST, externalPort)
        .build();

        actionListReverse.clear();
        actionListReverse.add(sw.getOFFactory().actions().setNwDst(internalAddress));
        actionListReverse.add(sw.getOFFactory().actions().setTpDst(internalPort));

        for( TransportPort internalNATSwitchPort: this.nat_internal_ports ){
            OFActionOutput action = actionsReverse.buildOutput()
            .setPort( OFPort.of(internalNATSwitchPort.getPort()) )
            .build();
            actionListReverse.add( action );
        }

        OFFlowMod flowModReverse = myFactoryReverse.buildFlowModify()
        .setBufferId(OFBufferId.NO_BUFFER)
        .setMatch(matchReverse)
        .setActions(actionListReverse)
        .build();

        sw.write(flowModReverse);
    }

    private void handleARP( IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx ){

        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        ARP arp = (ARP) eth.getPayload();
        OFFactory myFactory = sw.getOFFactory();

        System.err.println("ARP PACKET: " + arp);

        if (!((arp.getTargetProtocolAddress()).equals(external_ip))) {
            if (this.nat_external_ports.contains(TransportPort.of(pi.getInPort().getPortNumber()))) {
                log.info( "Not forwarding. Outside host trying to initiate contact to inside host" );
                return;
            }

            internalMAC2ip.put( arp.getSenderHardwareAddress(), arp.getSenderProtocolAddress() );
            arp.setSenderProtocolAddress( external_ip );
            System.err.println(arp.getTargetHardwareAddress());
            if( arp.getTargetHardwareAddress().getLong()==0 ){
                System.err.println(eth.getDestinationMACAddress());
                arp.setTargetHardwareAddress( eth.getDestinationMACAddress() );//Ethernet.toMACAddress("ff:ff:ff:ff:ff:ff") );
            }

            IPacket arpRequest = new Ethernet()
                .setSourceMACAddress(arp.getSenderHardwareAddress())
                .setDestinationMACAddress(arp.getTargetHardwareAddress())
                .setEtherType(EthType.ARP)
                .setPriorityCode(eth.getPriorityCode())
                .setPayload( arp );

            ArrayList<OFAction> actionList = new ArrayList<OFAction>();
            OFActions actions = myFactory.actions();

            for( TransportPort externalNATSwitchPort: this.nat_external_ports ){
                OFActionOutput action = actions.buildOutput()
                .setPort( OFPort.of(externalNATSwitchPort.getPort()) )
                .build();
                actionList.add( action );
            }

            OFPacketOut po = myFactory.buildPacketOut()
            .setBufferId(OFBufferId.NO_BUFFER)
            .setInPort(pi.getInPort())
            .setData(arpRequest.serialize())
            .setActions(actionList)
            .build();

            sw.write(po);

        }
        else if((arp.getTargetProtocolAddress()).equals(external_ip)) {
            MacAddress dstMAC = eth.getDestinationMACAddress();

            if( arp.getTargetHardwareAddress().getLong()==0 ){
                System.err.println(eth.getDestinationMACAddress());
                arp.setTargetHardwareAddress( eth.getDestinationMACAddress() );//Ethernet.toMACAddress("ff:ff:ff:ff:ff:ff") );
            }

            IPv4Address dstTrueIP = internalMAC2ip.get( dstMAC );
            arp.setTargetProtocolAddress( dstTrueIP );

            // generate ARP request
            IPacket arpReply = new Ethernet()
                .setSourceMACAddress(arp.getSenderHardwareAddress())
                .setDestinationMACAddress(arp.getTargetHardwareAddress())
                .setEtherType(EthType.ARP)
                .setPriorityCode(eth.getPriorityCode())
                .setPayload( arp );

            ArrayList<OFAction> actionList = new ArrayList<OFAction>();
            OFActions actions = myFactory.actions();

            for( TransportPort internalNATSwitchPort: this.nat_internal_ports ){
                OFActionOutput action = actions.buildOutput()
                .setPort( OFPort.of(internalNATSwitchPort.getPort()) )
                .build();
                actionList.add( action );
            }

            OFPacketOut po = myFactory.buildPacketOut()
            .setBufferId(OFBufferId.NO_BUFFER)
            .setInPort(pi.getInPort())
            .setData(arpReply.serialize())
            .setActions(actionList)
            .build();

            sw.write(po);
        }
    }



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
                    System.out.println (IPv4Address.of(temp));
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
                    System.out.println (external_ip);
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
}