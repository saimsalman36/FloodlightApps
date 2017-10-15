package net.floodlightcontroller.hedera;

import edu.duke.cs.legosdn.core.Defaults;
import edu.duke.cs.legosdn.core.cache.IMsgMaskCli;
import edu.duke.cs.legosdn.core.state.NSQuery;
import edu.duke.cs.legosdn.core.state.StateLayerAwareApp;
import edu.duke.cs.legosdn.core.state.StateLayerQuery;
import edu.duke.cs.legosdn.core.state.TypeDeserializers;
import edu.duke.cs.legosdn.core.state.TypeSerializers;
import edu.duke.cs.legosdn.core.state.faults.NoActiveTransactionFault;
import edu.duke.cs.legosdn.core.util.Util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListSet;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
// import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;


import net.floodlightcontroller.packet.Ethernet;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFStatisticsReply;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.Wildcards;
import org.projectfloodlight.openflow.protocol.Wildcards.Flag;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.projectfloodlight.openflow.protocol.statistics.OFStatistics;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;

import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.projectfloodlight.openflow.types.DatapathId;

/**
 * Implementation of Hedera.
 */
public class Hedera implements IFloodlightModule, IOFMessageListener, IOFSwitchListener,
    ILinkDiscoveryListener, StateLayerAwareApp, IMsgMaskCli {

  private static final Logger LOG = LoggerFactory.getLogger(Hedera.class);

  // --->[ Interactions with the state layer ]<---
  //
  private StateLayerQuery slq;
  
  public static int BUG = -1;
  
  // 1: enable; 0: disable
  protected static int ENABLE_WILDCARD = -1;
  
  // 0: no cache; 1: cache without fingerprint; 2: both
  private static int ENABLE_CACHE = -1;
  
  private int idx_bug = -1;
  
  	protected static final Random r;
    protected double rd;
	protected static final double CRASH_PROB = 1 - 0.8;
  
	protected static final TypeSerializers typeSer;
	protected static final TypeDeserializers typeDeser;

	static
	{
		typeSer = new TypeSerializers();
		typeDeser = new TypeDeserializers();
		r = new Random();
	}
	
	enum State
	{
		has_port_1, counter_port_2
	};
  
	@Override
	public int getMsgWildcard()
	{
		if (ENABLE_WILDCARD == 1)
		{
			try
			{
				BufferedReader reader = new BufferedReader(new FileReader(
						new File(getInputMappingPath())));
				String temp = null;

				while ((temp = reader.readLine()) != null)
				{
					if (temp.length() == 0)
						continue;

					String[] equalTokens = temp.split("=");
					if (equalTokens.length != 2)
					{
						LOG.error("getMsgWildcard> Invalid input mapping format: "
								+ temp);
						reader.close();
					}
					String key = equalTokens[0].trim();
					// TODO: Support more wildcards
					// TODO: Flexible with variable name such as pi
					// TODO: add wildcard by "ret |= OFMatch.OFPFW_IN_PORT"
					if (key.equals("pi.inPort"))
					{
						return OFMatch.OFPFW_IN_PORT;
					}
				}
				reader.close();

			} catch (IOException ioe)
			{
				ioe.printStackTrace();
				return -1;
			}
		}
		return -1;
	}
	
	@Override
	public void writeWildcard() throws IOException
	{
		String path = String.format("%s%s%s", Defaults.MASK_PATH,
				File.separator, this.ns);
		Util.writeFile(path, Integer.toString(getMsgWildcard()));
	}
	
	private String getInputMappingPath()
	{
		return String.format("%s%s%s", Defaults.INPUT_MAPPING_PATH,
				File.separator, getNameSpace());
	}
	
	@Override
	public String getNameSpace()
	{
		return "edu.duke.cs.legosdn.tests.apps.hedera.Hedera";
	}

  @Override
  public void setQueryProvider(StateLayerQuery queryProvider) {
    this.slq = queryProvider;
  }

  @Override
  public void writeStateVars() throws IOException {

  }
  //
  // ---<[ Interactions with the state layer ]>---

  // --->[ Interactions with the AppVisor for NS-related queries ]<---
  //
  private NSQuery nsq;

  // Namespace and its numeric identifier.
  private String ns;
  private int nsID;

  @Override
  public void setNSQueryProvider(NSQuery nsQueryProvider) {
    this.nsq = nsQueryProvider;
    this.ns = this.nsq.getNS();
    this.nsID = this.nsq.fromNS(this.ns);

    if (LOG.isInfoEnabled()) {
      LOG.info("setNSQueryProvider> NS: {}<{}>", this.ns, this.nsID);
    }
  }
  //
  // ---<[ Interactions with the AppVisor for NS-related queries ]>---

  // --->[ Application State ]<---
  //
  // Expected number of switches in the topology.
  static final int DEF_NUM_SWS = 8;

  // Frequency (in seconds) at which configuration changes happen.
  static final short CONFIG_INTERVAL = 1;
  // Idle timeout for rules
  static final short FLOW_IDLE_TIMEOUT = CONFIG_INTERVAL * 10;
  // Default idle timeout (in seconds) for FlowMods.
  static final short FMOD_IDLE_TIMEOUT = 5;
  // Default hard timeout (in seconds) for FlowMods; 0 => no-expiry
  static final short FMOD_HARD_TIMEOUT = 0;
  // Default priority for FlowMods.
  static final short FMOD_PRIORITY = 100;

  // IPv6 Ethernet multicast address; 33-33-xx-xx-xx-xx
  private static final byte[] MULTICAST_DNS =
      HexString.fromHexString("33:33:00:00:00:fb");

  // Address uses to infer the connectivity of switches to controller.
  static final byte[] FAKE_DST_ETH =
      HexString.fromHexString("ee:ee:ee:ee:ee:ee");

  static final short SIGNAL_VLAN_ID = Short.MAX_VALUE;
  static final String FAKE_SRC_IP = "255.255.255.255";
  static final int FAKE_DST_IP = Integer.MAX_VALUE;

  // Network topology
  private final NetTopo netTopo;
  // Set of MACs we have learned about.
  private final ConcurrentSkipListSet<MacAddress> knownMacs;
  // Switch ID to packet match mappings.
  private final ConcurrentMap<DatapathId, LinkedList<OFMatch>> swMatchMap;
  // Host MAC address to Switch ID mappings.
  private final ConcurrentMap<MacAddress, DatapathId> hostMacToSwMap;
  // Edge switches (i.e., switches connected to hosts).
  private final ConcurrentSkipListSet<DatapathId> edgeSws;
  // Flow-demand estimator.
  private final DemandEstimator demandEst;
  // Statistics (number of bytes delivered) for each flow match.
  private final ConcurrentMap<OFMatch, Long> flowStatMap;
  private final PathUtil pathUtil;
  // Per-flow byte counts.
  private final ConcurrentMap<String, ConcurrentMap<String, FlowStatsWrapper>> perFlowStats;
  // Switches associated with the STATS_REPLY.
  private final ConcurrentSkipListSet<DatapathId> statSrcs;
  // Threshold rate for detecting elephant flows.
  private static double elephantRate;
  // Last time when we load-balanced elephant flows in the network.
  private static long lastRuntime;
  //
  // ---<[ Application State ]>---

  private IFloodlightProviderService flProvider;

  public Hedera() {
    this.netTopo = new NetTopo();
    this.knownMacs = new ConcurrentSkipListSet<>();
    this.swMatchMap = new ConcurrentHashMap<>(Hedera.DEF_NUM_SWS);
    this.hostMacToSwMap = new ConcurrentHashMap<>(Hedera.DEF_NUM_SWS);
    this.edgeSws = new ConcurrentSkipListSet<>();
    this.demandEst = new DemandEstimator();
    // NOTE: Let's assume one flow originating from each port on the switch.
    this.flowStatMap = new ConcurrentHashMap<>(Hedera.DEF_NUM_SWS * 4);
    this.pathUtil = new PathUtil(this.netTopo);
    this.perFlowStats = new ConcurrentHashMap<>(Hedera.DEF_NUM_SWS * 4);
    this.statSrcs = new ConcurrentSkipListSet<>();
    lastRuntime = System.currentTimeMillis();
  }

  @Override
  public String getName() {
    return Hedera.class.getCanonicalName();
  }

  @Override
  public boolean isCallbackOrderingPrereq(OFType type, String name) {
    return false;
  }

  @Override
  public boolean isCallbackOrderingPostreq(OFType type, String name) {
    return false;
  }

  @Override
  public Collection<Class<? extends IFloodlightService>> getModuleServices() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("getModuleServices> Hedera does not expose any services!");
    }
    return null;
  }

  @Override
  public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("getModuleServices> Hedera does not implement any services!");
    }
    return null;
  }

  @Override
  public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
    final Collection<Class<? extends IFloodlightService>> deps =
        new ArrayList<Class<? extends IFloodlightService>>(1);
    deps.add(IFloodlightProviderService.class);
    return deps;
  }

  @Override
  public void init(FloodlightModuleContext context) throws FloodlightModuleException {
    this.flProvider = context.getServiceImpl(IFloodlightProviderService.class);
    this.pathUtil.init(this.flProvider);
    final Map<String, String> configParams = context.getConfigParams(this);
    try {
    	Hedera.elephantRate = Double.parseDouble(configParams.get("elephant.rate"));
    } catch(NullPointerException npe) 
    { Hedera.elephantRate = 5; } // TODO: Is this a reasonable value?

    if (LOG.isDebugEnabled()) {
      LOG.debug("init> Hedera: initialized");
    }
  }

  @Override
  public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
    this.flProvider.addOFMessageListener(OFType.PACKET_IN, this);

    // NOTE: It is important to subscribe to OFStatisticsReply messages!
    //  AppVisor, otherwise, will have no clue that the app. is interested in the message.
    this.flProvider.addOFMessageListener(OFType.STATS_REPLY, this);
    
	try
	{
		writeStateVars();
		if (BUG == -1)
		{
			BUG = Util.config(Util.CONFIG_PATH, "bug");
			LOG.info("BUG: " + BUG);
		}
		if (ENABLE_WILDCARD == -1)
		{
			// ENABLE_WILDCARD = Util.config(Util.CONFIG_PATH,
			// "enable_wildcard");
			ENABLE_CACHE = Util.config(Util.CONFIG_PATH, "enable_cache");
			if (ENABLE_CACHE < 2)
				ENABLE_WILDCARD = 0;
			else
				ENABLE_WILDCARD = 1;
			LOG.info("ENABLE_WILDCARD: " + ENABLE_WILDCARD);
		}
		// Write after setting ENABLE_WILDCARD
		writeWildcard();

	} catch (IOException e)
	{
		e.printStackTrace(System.err);
		// Crash and burn; no point in continuing!
		throw new RuntimeException(e);
	}

	if (BUG == 9)
	{
		Thread worker = new Thread(new Worker());
		worker.start();
	}

    if (LOG.isDebugEnabled()) {
      LOG.debug("startUp> Hedera: started!");
    }
  }

  @Override
  public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(String.format("receive> Sw<%s> => %s", sw.getStringId(), msg.getType()));
    }

    if (msg.getType().equals(OFType.PACKET_IN)) {
      return this.handlePacketIn(sw, (OFPacketIn) msg, cntx);
    }

    if (msg.getType().equals(OFType.STATS_REPLY)) {
      return this.handleStatsReply(sw, (OFStatisticsReply) msg, cntx);
    }

    return Command.CONTINUE;
  }

  /**
   * Handle PACKET_IN messages.
   *
   * @param sw Switch
   * @param pi PACKET_IN message
   * @param cntx Floodlight context
   * @return CONTINUE or STOP
   */
  private Command handlePacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		if (BUG == 1)
		{
			try
			{
				if (pi.getInPort().getPortNumber() == 1)
				{
					LOG.info("Set state " + State.has_port_1.ordinal());
					this.slq.set(this.nsID, State.has_port_1.ordinal(),
							typeSer.valueOf(true));
				}
				else if (pi.getInPort().getPortNumber() == 2)
				{
					LOG.info("Get state " + State.counter_port_2.ordinal());
					int pkt_counter = typeDeser.toInteger(this.slq.get(
							this.nsID, State.counter_port_2.ordinal())) + 1;
					LOG.info("pkt_counter: " + pkt_counter);
					this.slq.set(this.nsID, State.counter_port_2.ordinal(),
							typeSer.valueOf(pkt_counter));
					LOG.info("Set state " + State.counter_port_2.ordinal());

					boolean has_port_1 = typeDeser.toBoolean(this.slq.get(
							this.nsID, State.has_port_1.ordinal()));
					LOG.info("Get state " + State.has_port_1.ordinal());
					LOG.info("[Learning SW] has_port_1: " + has_port_1);

					if (pkt_counter > 2)
						if (has_port_1)
							throw new RuntimeException("counter 2!");
				}
			} catch (NoActiveTransactionFault e) // zzy: do nothing now
			{
			}
		}
		else if (BUG == 2)
		{
			try
			{
				if (pi.getInPort().getPortNumber() == 1)
				{
					LOG.info("Set state " + State.has_port_1.ordinal());
					this.slq.set(this.nsID, State.has_port_1.ordinal(),
							typeSer.valueOf(true));
				}
				else
				{
					boolean has_port_1 = typeDeser.toBoolean(this.slq.get(
							this.nsID, State.has_port_1.ordinal()));
					if (has_port_1)
					{
						byte[] buf = pi.getPacketData();
						LOG.trace("buf len: " + buf.length);
						byte b = buf[99];
					}
				}
			} catch (NoActiveTransactionFault e) // zzy: do nothing now
			{
			}
		}
		else if (BUG == 3)
		{
			try
			{
				if (pi.getInPort().getPortNumber() > 1)
				{
					// Don't set the state.
					// The state only keeps a non-empty array for
					// rollBackVersion.
					LOG.info("Get state " + State.counter_port_2.ordinal());
					int pkt_counter = typeDeser.toInteger(this.slq.get(
							this.nsID, State.counter_port_2.ordinal())) + 1;
					LOG.info("pkt_counter: " + pkt_counter);
					throw new RuntimeException("Invalid port!");
				}
			} catch (NoActiveTransactionFault e) // zzy: do nothing now
			{
			}
		}
		else if (BUG == 4)
		{
			try
			{
				if (pi.getInPort().getPortNumber() == 1)
				{
					LOG.info("Set state " + State.has_port_1.ordinal());
					this.slq.set(this.nsID, State.has_port_1.ordinal(),
							typeSer.valueOf(true));
				}
				else if (pi.getInPort().getPortNumber() == 2)
				{
					LOG.info("Get state " + State.counter_port_2.ordinal());
					int pkt_counter = typeDeser.toInteger(this.slq.get(
							this.nsID, State.counter_port_2.ordinal())) + 1;
					LOG.info("pkt_counter: " + pkt_counter);
					this.slq.set(this.nsID, State.counter_port_2.ordinal(),
							typeSer.valueOf(pkt_counter));
					LOG.info("Set state " + State.counter_port_2.ordinal());

					boolean has_port_1 = typeDeser.toBoolean(this.slq.get(
							this.nsID, State.has_port_1.ordinal()));
					LOG.info("Get state " + State.has_port_1.ordinal());
					LOG.info("[Learning SW] has_port_1: " + has_port_1);

					r.nextDouble();
					if (pkt_counter == 2)
						if (has_port_1 && rd > 0.2)
							throw new RuntimeException("counter 2!");
				}
			} catch (NoActiveTransactionFault e) // zzy: do nothing now
			{
			}
		}
		else if (BUG == 5)
		{
			try
			{
				if (pi.getInPort().getPortNumber() == 1)
				{
					LOG.info("Set state " + State.has_port_1.ordinal());
					this.slq.set(this.nsID, State.has_port_1.ordinal(),
							typeSer.valueOf(true));
				}
				else if (pi.getInPort().getPortNumber() == 2)
				{
					LOG.info("Get state " + State.counter_port_2.ordinal());
					int pkt_counter = typeDeser.toInteger(this.slq.get(
							this.nsID, State.counter_port_2.ordinal())) + 1;
					LOG.info("pkt_counter: " + pkt_counter);
					this.slq.set(this.nsID, State.counter_port_2.ordinal(),
							typeSer.valueOf(pkt_counter));
					LOG.info("Set state " + State.counter_port_2.ordinal());

					boolean has_port_1 = typeDeser.toBoolean(this.slq.get(
							this.nsID, State.has_port_1.ordinal()));
					LOG.info("Get state " + State.has_port_1.ordinal());
					LOG.info("[Learning SW] has_port_1: " + has_port_1);

					if (pkt_counter == 2)
						if (has_port_1)
						{
							OFFlowMod flowMod = (OFFlowMod) flProvider
									.getOFMessageFactory().getMessage(
											OFType.FLOW_MOD);
							flowMod.setCommand(OFFlowMod.OFPFC_ADD);
							// no action for dropping
							ArrayList<OFAction> actions = new ArrayList<OFAction>();
							OFMatch match_bug = new OFMatch();
							match_bug.setWildcards(Wildcards.FULL);
							flowMod.setMatch(match_bug);
							flowMod.setActions(actions);
							flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
							flowMod.setBufferId(OFPacketOut.BUFFER_ID_NONE);

							try
							{
								sw.write(flowMod, null);
								sw.flush();
								System.out.println("Installed!!!!");
							} catch (IOException e)
							{
								LOG.error("zzy: Failure flowMod", e);
							}
						}
				}
			} catch (NoActiveTransactionFault e) // zzy: do nothing now
			{
			}
		}
		else if (BUG == 6)
		{
			try
			{
				if (pi.getInPort().getPortNumber() == 1)
				{
					LOG.info("Set state " + State.has_port_1.ordinal());
					this.slq.set(this.nsID, State.has_port_1.ordinal(),
							typeSer.valueOf(true));
				}
				else
				{
					boolean has_port_1 = typeDeser.toBoolean(this.slq.get(
							this.nsID, State.has_port_1.ordinal()));
					if (has_port_1)
					{
						byte[] buf = new byte[100];
						byte b = buf[99];
						buf = pi.getPacketData();
						LOG.trace("buf len: " + buf.length);
						// copy & paste
						b = buf[99];
					}
				}
			} catch (NoActiveTransactionFault e) // zzy: do nothing now
			{
			}
		}
		else if (BUG == 7)
		{
			try
			{
				// Don't set the state.
				// The state only keeps a non-empty array for
				// rollBackVersion.
				LOG.info("Get state " + State.counter_port_2.ordinal());
				int pkt_counter;
				pkt_counter = typeDeser.toInteger(this.slq.get(
						this.nsID, State.counter_port_2.ordinal())) + 1;
				LOG.info("pkt_counter: " + pkt_counter);
			} catch (NoActiveTransactionFault e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else if (BUG == 9)
		{
			try
			{
				if (pi.getInPort().getPortNumber() == 1)
				{
					LOG.info("Set state " + State.has_port_1.ordinal());
					this.slq.set(this.nsID, State.has_port_1.ordinal(),
							typeSer.valueOf(true));
				}
				else
				{
					boolean has_port_1 = typeDeser.toBoolean(this.slq.get(
							this.nsID, State.has_port_1.ordinal()));
					if (has_port_1)
					{
						byte[] buf = pi.getPacketData();
						LOG.trace("buf len: " + buf.length);
						idx_bug = 99;
						Thread.sleep(100);
						byte b = buf[idx_bug];
						idx_bug = -1;
					}
				}
			} catch (NoActiveTransactionFault | InterruptedException e) 
			{
			}
		}
	  
	  
    final OFMatch pktMatch = new OFMatch();
    pktMatch.loadFromPacket(pi.getPacketData(), pi.getInPort());

    if (LOG.isDebugEnabled()) {
      LOG.debug("receive> Match on sw<{}>; {}", sw.getId(), pktMatch);
    }

    final MacAddress dstLong = pktMatch.getDataLayerDestination();
    if (dstLong.equals(Ethernet.toLong(MULTICAST_DNS))) {
      return Command.CONTINUE;
    }

    final Ethernet eth =
        IFloodlightProviderService.bcStore.get(cntx,
                                               IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
    if(eth == null)
    {
    	return Command.CONTINUE;
    }
    final MacAddress srcMac = eth.getSourceMACAddress();
    if (dstLong.equals(Ethernet.toLong(FAKE_DST_ETH))) {
      // Emulating LLDP.
      if (LOG.isInfoEnabled()) {
        LOG.info("receive> pkt to fake dst; VLAN: {}  src: {}", eth.getVlanID(),
                 srcMac.toString());
      }
      // Received this packet (to a fake destination) from a real switch.
      // Use the ingress port on the switch and the switch ID to infer connectivity in the network.
      MacAddress peerPortMac = dstLong;
      if (!this.netTopo.addSwToSwLink(peerPortMac, sw.getId(), pi.getInPort())) {
        // Not a new link!
        this.knownMacs.add(peerPortMac);
      }
      return Command.CONTINUE;
    }

    if (!(this.swMatchMap.containsKey(sw.getId()) &&
        this.swMatchMap.get(sw.getId()).contains(pktMatch))) {
      return Command.CONTINUE;
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("receive> new pkt match from Sw<{}>!", sw.toString());
    }

    this.addHostToSw(srcMac, sw.getId(), pi.getInPort());

    final OFMatch flowMatch = pktMatch.clone().setInputPort(Short.MAX_VALUE);
    this.flowStatMap.putIfAbsent(flowMatch, 0L);

    if (LOG.isInfoEnabled()) {
      LOG.info("receive> finding a path for flow {} with {} wild cards", flowMatch,
               flowMatch.getWildcards());
    }

    final Path p = this.pathUtil.findPath(flowMatch);
    try {
      this.pathUtil.installPath(p, false);
    } catch (IOException e) {
      e.printStackTrace();
      LOG.error("receive> failed to install path; {}", e.getLocalizedMessage());
    }
    return Command.CONTINUE;
  }

  /**
   * Handle STATS_REPLY messages.
   *
   * @param sw Switch
   * @param pi STATS_REPLY message
   * @param cntx Floodlight context
   * @return CONTINUE or STOP
   */
  private Command handleStatsReply(IOFSwitch sw, OFStatisticsReply pi, FloodlightContext cntx) {
    if (!this.statSrcs.add(sw.getId())) {
      // WARNING: Assume that when we receive a second STATS_REPLY from a switch,
      //  it implies that a new stat. collection cycle has started.

      // Clear prior stat. computations.
      this.flowStatMap.clear();
    }

    for (OFStatistics stat : pi.getStatistics()) {
      // Only interested in flow statistics.
      if (!(stat instanceof OFFlowStatisticsReply)) {
        continue;
      }

      final OFFlowStatisticsReply flowStat = (OFFlowStatisticsReply) stat;
      final OFMatch match = flowStat.getMatch().clone().setInputPort(Short.MAX_VALUE);
      this.flowStatMap.put(match, flowStat.getByteCount());
    }

    final Map<String, ConcurrentMap<String, FlowStatsWrapper>> flowBytesMap =
        DemandEstimator.getFlowBytes(pi.getStatistics());
    this.perFlowStats.putAll(flowBytesMap);

    try {
      this.pathUtil.bcastPortMac(sw.getId());
    } catch (IOException e) {
      e.printStackTrace();
      LOG.error("receive> failed to broadcast port mac on all ports; {}", e.getLocalizedMessage());
    }
    this.loadBalanceFlows();
    return Command.CONTINUE;
  }

    /**
     * Learn the host to switch link, and mark the switch as an edge switch.
     *
     * @param host Host MAC
     * @param sw Switch ID
     * @param port Port number
     */
  private void addHostToSw(MacAddress host, DatapathId sw, OFPort port) {
    //upon detecting a host connected to a switch, mark the switch as an edge

    if (this.hostMacToSwMap.containsKey(host)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("addHostToSw> Host<{}> to Sw<{}> mapping already known!", host, sw);
      }

      return;
    }

    this.hostMacToSwMap.putIfAbsent(host, sw);
    this.edgeSws.add(sw);
    this.demandEst.addEntry(sw);
    this.netTopo.addHostToSw(host, sw, port);
  }

  @Override
  public void switchAdded(DatapathId switchId) {
    if (LOG.isInfoEnabled()) {
      LOG.info("switchAdded> Sw<{}>", switchId);
    }
  }

  @Override
  public void switchRemoved(DatapathId switchId) {
    this.pathUtil.removeSw(switchId);

    if (LOG.isInfoEnabled()) {
      LOG.info("switchRemoved> Sw<{}>", switchId);
    }
  }

  @Override
  public void switchDeactivated(DatapathId switchId) {

  }

  @Override
  public void switchActivated(DatapathId switchId) {
    this.netTopo.addSw(switchId);
    final IOFSwitch sw = this.flProvider.getSwitch(switchId);
    if(sw.getPorts() != null)
    {
      for(ImmutablePort port : sw.getPorts()) {
        final Long addr = Ethernet.toLong(port.getHardwareAddress());
        this.netTopo.addSwPortToMac(sw.getId(), port.getPortNumber(), HexString.toHexString(addr));
      }
    }

    this.pathUtil.addSw(switchId);

    if (LOG.isInfoEnabled()) {
      LOG.info("switchActivated> Sw<{}>", switchId);
    }
  }

  @Override
  public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {
    if (LOG.isInfoEnabled()) {
      LOG.info("switchPortChanged> Sw<{}> {}", switchId, type);
    }
  }

  @Override
  public void switchChanged(DatapathId switchId) {
    if (LOG.isInfoEnabled()) {
      LOG.info("switchChanged> Sw<{}>", switchId);
    }
  }

  @Override
  public void linkDiscoveryUpdate(LDUpdate update) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(String.format("linkDiscoveryUpdate> %s  src: %d  dst: %d", update.getType(),
                              update.getSrc(), update.getDst()));
    }
  }

  @Override
  public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
    for(LDUpdate u : updateList) {
      this.netTopo.addSwToSwLink(u.getSrc(), u.getSrcPort(), u.getDst(), u.getDstPort());
    }
  }

  private void loadBalanceFlows() {
    synchronized (Hedera.class) {
      final long currTime = System.currentTimeMillis();

      if ((currTime - lastRuntime) <= CONFIG_INTERVAL * 1000) {
        // Do not run too often!
        return;
      }

      lastRuntime = currTime;
    }

    final Map<Long, Long> totalBytesFromSrc =
        new HashMap<Long, Long>(DEF_NUM_SWS);
    final Map<Long, Map<Long, Long>> flowByteCounts =
        new HashMap<Long, Map<Long, Long>>(DEF_NUM_SWS);

    for (String srcMAC : this.perFlowStats.keySet()) {
      final ConcurrentMap<String, FlowStatsWrapper> dstFlowStats = this.perFlowStats.get(srcMAC);

      for (String dstMAC : dstFlowStats.keySet()) {
        final FlowStatsWrapper fStats = dstFlowStats.get(dstMAC);
        final long bytes = fStats.bytes;

        final long srcSwId = this.hostMacToSwMap.get(srcMAC);
        final long dstSwId = this.hostMacToSwMap.get(dstMAC);

        this.demandEst.setEntryMatchCount(srcSwId, dstSwId,
                                          fStats.match.setInputPort(Short.MAX_VALUE), fStats.bytes);

        if (!flowByteCounts.containsKey(srcSwId)) {
          // No byte counts for either the src or the dst!
          Map<Long, Long> bytesToDst = new HashMap<Long, Long>();
          bytesToDst.put(dstSwId, bytes);
          flowByteCounts.put(srcSwId, bytesToDst);
        } else {
          // Byte count map contains src!

          if (!flowByteCounts.get(srcSwId).containsKey(dstSwId)) {
            // No byte counts for dst!
            flowByteCounts.get(srcSwId).put(dstSwId, bytes);
          } else {
            // Byte counts for <src, dst> is present; update the count!
            flowByteCounts.get(srcSwId).put(dstSwId,
                                            flowByteCounts.get(srcSwId).get(dstSwId) + bytes);
          }
        } // Update byte counts.

        if (totalBytesFromSrc.containsKey(srcSwId)) {
          totalBytesFromSrc.put(srcSwId, totalBytesFromSrc.get(srcSwId) + bytes);
        } else {
          totalBytesFromSrc.put(srcSwId, bytes);
        }
      }
    }

    if (LOG.isDebugEnabled()) {
      final StringBuilder buf = new StringBuilder("");
      for (long src : flowByteCounts.keySet()) {
        for (long dst : flowByteCounts.get(src).keySet()) {
          buf.append("  >> ");
          buf.append(src);
          buf.append(" -> ");
          buf.append(src);
          buf.append(" : ");
          buf.append(flowByteCounts.get(src).get(dst));
          buf.append("\n");
        }
      }
      buf.append("\n");
      for (long src : totalBytesFromSrc.keySet()) {
        buf.append("  >> ");
        buf.append(src);
        buf.append("  - ");
        buf.append(totalBytesFromSrc.get(src));
      }

      LOG.debug("loadBalanceFlows> {}", buf.toString());
    }

    for (long srcSwId : flowByteCounts.keySet()) {
      final Map<Long, Long> dstMap = flowByteCounts.get(srcSwId);
      for (long dstSwId : dstMap.keySet()) {
        if (totalBytesFromSrc.get(srcSwId) == 0) {
          if (LOG.isWarnEnabled()) {
            LOG.warn("loadBalanceFlows> invalid data; %d => %d = 0", srcSwId, dstSwId);
          }

          continue;
        }

        // Demand is defined as the ratio of
        //  the bytes received at a dst. to the total bytes generated at src.
        final double demand = (double) dstMap.get(dstSwId) / totalBytesFromSrc.get(srcSwId);
        this.demandEst.setEntryDemand(srcSwId, dstSwId, demand);
      }
    }

    this.perFlowStats.clear();

    if (LOG.isInfoEnabled()) {
      LOG.info("loadBalanceFlows> [current demands]  {}", this.demandEst.matrixToString());
    }

    if (this.demandEst.hasData()) {
      this.demandEst.estimateDemand();
    }

    List<OFMatch> elephants = this.demandEst.getElephants(Hedera.elephantRate);

    if (LOG.isInfoEnabled()) {
      LOG.info("loadBalanceFlows> [elephant flows]  {}", elephants);
    }

    // Update topology to reflect occupied count.
    for (OFMatch match : elephants) {
      match.setWildcards(0);

      Path currFwdPath = this.pathUtil.getFwdPath(match);
      if (currFwdPath == null) {
        if (LOG.isDebugEnabled()) {
          final StringBuilder buf = new StringBuilder("");
          for (OFMatch m : this.pathUtil.getFwdPathMatches()) {
            buf.append("  OFMatch-\n");
            buf.append(m);
            buf.append("\n");
          }

          LOG.debug("loadBalanceFlows> [forward path cache]\n{}", buf.toString());
        }

        if (LOG.isDebugEnabled()) {
          final StringBuilder buf = new StringBuilder("");
          for (OFMatch m : this.pathUtil.getRevPathMatches()) {
            buf.append("  OFMatch-\n");
            buf.append(m);
            buf.append("\n");
          }

          LOG.debug("loadBalanceFlows> [reverse path cache]\n{}", buf.toString());
        }

        currFwdPath = this.pathUtil.getRevPath(match);
        if (currFwdPath == null) {
          if (LOG.isWarnEnabled()) {
            LOG.warn("loadBalanceFlows> no path for elephant flow!"
                         + " match {} with wild cards {}", match, match.getWildcards());
          }
        } else {
          if (LOG.isWarnEnabled()) {
            LOG.warn("loadBalanceFlows> path for elephant flow found in the rev direction!"
                         + " match {}  path> {}", match, currFwdPath);
          }
        }

        continue;
      }

      if (LOG.isInfoEnabled()) {
        LOG.info("loadBalanceFlows> found path {} for elephant flow {}", currFwdPath, match);
      }

      this.netTopo.incLinksOccupyCount(currFwdPath.getLinkIds());
    } // Process all elephant flows.

    if (LOG.isDebugEnabled()) {
      final StringBuilder buf = new StringBuilder("");
      for (Link link : this.netTopo.getAllLinks()) {
        buf.append("  > ");
        buf.append(link.toString());
        buf.append("  occupy-count: ");
        buf.append(link.getOccupied());
        buf.append("\n");
      }

      LOG.debug("loadBalanceFlows> occupy counts-\n{}", buf.toString());
    }

    for (int i = 0; i < elephants.size(); i++) {
      for (int j = i + 1; j < elephants.size(); j++) {
        final OFMatch eFlowX = elephants.get(i);
        final OFMatch eFlowY = elephants.get(j);

        if (eFlowY.equals(eFlowX)) {
          if (LOG.isWarnEnabled()) {
            LOG.warn("loadBalanceFlows> elephants are same! X: {}  Y: {}", eFlowX, eFlowY);
          }

          continue;
        }

        final Path pathX = this.pathUtil.getFwdPath(eFlowX);
        final Path pathY = this.pathUtil.getFwdPath(eFlowY);

        if (pathX == null || pathY == null) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("loadBalanceFlows> missing paths; X-null? %b  Y-null? %b",
                      pathX == null, pathY == null);
          }

          continue;
        }

        if (!pathX.overlaps(pathY)) {
          // Non-overlapping paths; no action required!

          continue;
        }

        if (LOG.isInfoEnabled()) {
          LOG.info(String.format("loadBalanceFlows> overlapping elephant flows!"
                                     + " %s on path %s, and %s on path %s",
                                 eFlowX, pathX, eFlowY, pathY));
        }

        // NOTE: Arbitrarily picking one of the two flows to move!
        final Path altPath = this.netTopo.findUsablePath(eFlowY);

        if (LOG.isInfoEnabled()) {
          LOG.info("loadBalanceFlows> alt. path for {} is {}", eFlowY, altPath);
        }

        this.setNewPath(eFlowY, pathY, altPath);
        this.pathUtil.updateFwdPathCache(eFlowY.setInputPort(Short.MAX_VALUE).clone(), altPath);

//        // WARNING: Assuming the following block from Chen's implementation can be ignored.
//        //  The code block below seems to requesting all local controllers
//        //   to re-route the flow safely.
//        for (Integer id : allLocals.keySet()) {
//          LocalController client = null;
//          if (allLocalHandlers.containsKey(id)) {
//            client = allLocalHandlers.get(id);
//          } else {
//            LocalHandler handler = allLocals.get(id);
//            client = handler.lc;
//            allLocalHandlers.put(id, client);
//          }
//          // NOTE: The call below has been ported over.
//          this.setNewPath(eFlowY, pathY, altPath);
//          // NOTE: The call below has been ported over.
//          this.pathUtil.updateFwdPathCache(eFlowY.setInputPort(Short.MAX_VALUE).clone(), altPath);
//        }

        if (LOG.isDebugEnabled()) {
          LOG.debug("loadBalanceFlows> re-routed flow- wild cards: {}  in-port: {}",
                    eFlowY.getWildcards(), eFlowY.getInputPort());
        }
      }
    } // Process all elephant flows.

    this.demandEst.clearCurrrent();
    this.netTopo.clearOccupyCount();
  }

  /**
   * Find switch associated with the host MAC address.
   *
   * @param mac Host's MAC address
   * @return Switch ID
   */
  private Long getSwByHostMac(String mac) {
    if (!this.hostMacToSwMap.containsKey(mac)) {
      return null;
    }
    return this.hostMacToSwMap.get(mac);
  }

  private void setNewPath(OFMatch flowMatch, Path oldPath, Path newPath) {
    final long dst = Ethernet.toLong(flowMatch.getDataLayerDestination());
    final Long dstSw = this.getSwByHostMac(HexString.toHexString(dst));

    final long src = Ethernet.toLong(flowMatch.getDataLayerSource());
    Long srcSwitch = this.getSwByHostMac(HexString.toHexString(src));

    final OFMatch newFMatch = new OFMatch();
    newFMatch
        .setWildcards(flowMatch.getWildcards())
        .setDataLayerDestination(flowMatch.getDataLayerDestination())
        .setDataLayerSource(flowMatch.getDataLayerSource())
        .setInputPort(Short.MAX_VALUE)
        .setDataLayerVirtualLan((short) 0)
        .setWildcards(Wildcards.FULL
                          .matchOn(Flag.IN_PORT)
                          .matchOn(Flag.DL_DST)
                          .matchOn(Flag.DL_SRC)
                          .withNwDstMask(0)
                          .withNwSrcMask(0));

    if (LOG.isInfoEnabled()) {
      LOG.info(String.format("setNewPath> Flow %s changing from (old) %s to (new) %s with wild cards %d",
                             flowMatch, oldPath, newPath, newFMatch.getWildcards()));
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("setNewPath> (new) {}  (old) {}", newPath.getMatch(), oldPath.getMatch());
    }

    // Uninstall old path first
    final Iterator<Long> oldSwIds = oldPath.getDpids();
    while (oldSwIds.hasNext()) {
      final long dpid = oldSwIds.next();
      if (!this.pathUtil.isSwInCache(dpid)) {
        continue;
      }

      newFMatch.setInputPort(oldPath.getIngressPort(dpid));

      if (LOG.isDebugEnabled()) {
        LOG.debug("setNewPath> trying to delete flow on {} for match {}", dpid, newFMatch);
      }

      final OFFlowMod flowMod =
          this.pathUtil.createFlowMod(newFMatch.clone(),
                                      OFFlowMod.OFPFC_DELETE,
                                      FLOW_IDLE_TIMEOUT,
                                      oldPath.getEgressPort(dpid),
                                      OFPacketOut.BUFFER_ID_NONE);

      // WARNING: Chen's implementation passes the FlowMod to Mimir.
      //  Assuming Mimir writes it out to the network, we will do the same here.
      //  In any case, we do not want to route the flow over the old path in the network.
      try {
        final IOFSwitch sw = this.flProvider.getSwitch(dpid);
        sw.write(flowMod, null);
        // 'flush' can be costly, if writes are frequent!
        sw.flush();
      } catch (IOException e) {
        String msg = String.format("Failed to delete old path from Sw<{}>", dpid);
        LOG.warn("setNewPath> {}; {}", msg, e.getLocalizedMessage());
        throw new RuntimeException(msg, e);
      }
    }

    // Install new (or alternate) path
    Iterator<Long> newSwIds = newPath.getDpids();
    while (newSwIds.hasNext()) {
      final long dpid = newSwIds.next();
      if (!this.pathUtil.isSwInCache(dpid)) {
        continue;
      }

      newFMatch.setInputPort(newPath.getIngressPort(dpid));

      if (LOG.isDebugEnabled()) {
        LOG.debug("setNewPath> trying to add flow on {} for match {}", dpid, newFMatch);
      }

      final OFFlowMod flowMod =
          this.pathUtil.createFlowMod(newFMatch.clone(),
                                      OFFlowMod.OFPFC_ADD,
                                      FLOW_IDLE_TIMEOUT,
                                      oldPath.getEgressPort(dpid),
                                      OFPacketOut.BUFFER_ID_NONE);

      try {
        final IOFSwitch sw = this.flProvider.getSwitch(dpid);
        sw.write(flowMod, null);
        // 'flush' can be costly, if writes are frequent!
        sw.flush();
      } catch (IOException e) {
        String msg = String.format("Failed to add new path from Sw<{}>", dpid);
        LOG.warn("setNewPath> {}; {}", msg, e.getLocalizedMessage());
        throw new RuntimeException(msg, e);
      }
    }
  }
  
	class Worker implements Runnable
	{
		@Override
		public void run()
		{
			while (true)
			{
				System.out.println("worker");
				try
				{
					Thread.sleep(200);
				} catch (InterruptedException e)
				{
					e.printStackTrace();
				}
				if (idx_bug > 0)
				{
					idx_bug = 0;
				}
			}
		}
	}
	
	protected void touchState()
	{
    	// touch
    	try
		{
			int pkt_counter = typeDeser.toInteger(this.slq.get(
					this.nsID, State.counter_port_2.ordinal()));
			LOG.info("pkt_counter: " + pkt_counter);
		} catch (NoActiveTransactionFault e)
		{
			e.printStackTrace();
		}
	}

}
