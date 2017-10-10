
package edu.duke.cs.legosdn.tests.apps.rf;

import edu.duke.cs.legosdn.core.DefaultWildcard;
import edu.duke.cs.legosdn.core.Defaults;
import edu.duke.cs.legosdn.core.cache.IMsgMaskCli;
import edu.duke.cs.legosdn.core.log.FileRecorder;
import edu.duke.cs.legosdn.core.log.NullRecorder;
import edu.duke.cs.legosdn.core.log.Recorder;
import edu.duke.cs.legosdn.core.se.util.Type;
import edu.duke.cs.legosdn.core.state.NSQuery;
import edu.duke.cs.legosdn.core.state.StateLayerAwareApp;
import edu.duke.cs.legosdn.core.state.StateLayerQuery;
import edu.duke.cs.legosdn.core.state.TypeDeserializers;
import edu.duke.cs.legosdn.core.state.TypeSerializers;
import edu.duke.cs.legosdn.core.state.faults.NoActiveTransactionFault;
import edu.duke.cs.legosdn.core.util.StateUtil;
import edu.duke.cs.legosdn.core.util.Util;
import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;

import org.openflow.protocol.*;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class RouteFlow implements IFloodlightModule, IOFMessageListener, IOFSwitchListener, ILinkDiscoveryListener,
								StateLayerAwareApp, IMsgMaskCli{

    protected static Logger logger = LoggerFactory.getLogger(RouteFlow.class);

    private static final int DEF_NUM_SWS   = 16;
    private static final int DEF_NUM_LINKS = DEF_NUM_SWS * 2;

    // Hosts are always assumed to be at the first port of a switch.
    public static final short SW_HOST_PORT = 1;

    // Default cost of links
    public static final int UNIT_DIST_COST = 1;

    // Value indicating unknown distance between two switches
    public static final int UNKNOWN_DIST     = Integer.MAX_VALUE;
    // Value indicating unknown next hop to move from source to destination
    public static final int UNKNOWN_NEXT_HOP = 0;

    private static final File NUM_RT_WR = new File(String.format("%s/%s-num-rt-writes.txt",
                                                                 Defaults.APP_LOGS_PATH,
                                                                 RouteFlow.class.getCanonicalName()));
    private final File ROUTES_LOG = new File(String.format("%s/%s-routes.txt",
                                                           Defaults.APP_LOGS_PATH,
                                                           RouteFlow.class.getCanonicalName()));
    protected Recorder recorder;

    protected IFloodlightProviderService flProvider;
    protected ILinkDiscoveryService      linkDiscoverySrvc;

    protected final AtomicInteger               numSws;
    protected final Set<Long>                   activeSws;
    // Mapping from host-ip to sw-port
    protected final Map<Integer, Long>          hostToSw;
    // Network links.
    protected final Map<Link, LinkInfo>         netwLinks;
    // Network routes.
    protected final Map<Long, Map<Long, Short>> netwRoutes;
    
    protected StateLayerQuery slq;
    protected NSQuery nsq;
	
	protected static final TypeSerializers typeSer;
	protected static final TypeDeserializers typeDeser;
	
	protected static final Random r;
	protected double rd;
	protected static final double CRASH_PROB = 1 - 0.8;

	static
	{
		typeSer = new TypeSerializers();
		typeDeser = new TypeDeserializers();
		r = new Random();
	}

	// Namespace and its numeric identifier.
	protected String ns;
	protected int nsID;
	
	// A random state that keeps the version available (from the state list)
	protected enum State
	{
		counter
	};
	
	// 1: has_port_1 & counter_port_2
	// 2: buffer overflow
	// 3: port > 5
	// 4: random
	// 5: blackhole
	// 6: copy & paste
	// 7: wrong action
	// 8: forgot packet
	// 9: race condition
	protected static int BUG = -1;
	
	// 0: no cache; 1: cache without fingerprint; 2: both
	protected static int ENABLE_CACHE = -1;
	// 1: enable; 0: disable
	protected static int ENABLE_WILDCARD = -1;

    public RouteFlow() {
        this.numSws = new AtomicInteger(0);
        this.activeSws = new HashSet<Long>(DEF_NUM_SWS);
        this.hostToSw = new HashMap<Integer, Long>(DEF_NUM_SWS);
        this.netwLinks = new HashMap<Link, LinkInfo>(DEF_NUM_LINKS);
        this.netwRoutes = new HashMap<Long, Map<Long, Short>>(DEF_NUM_SWS);
        this.rd = r.nextDouble();

        if (!getNUM_RT_WR().exists()) {
            try {
            	getNUM_RT_WR().createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e.getCause());
            }
        }
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        if (getLogger().isDebugEnabled()) {
        	getLogger().debug("getModuleServices> module does not expose any services!");
        }
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        if (getLogger().isDebugEnabled()) {
        	getLogger().debug("getServiceImpls> module does not implement any services!");
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
        final Map<String, String> modConf = context.getConfigParams(this);

        final boolean enableMLog =
                Boolean.parseBoolean(modConf.get("enable_msglog") == null ? "false" :
                                             modConf.get("enable_msglog"));
        if (enableMLog)
            this.recorder = FileRecorder.getInstance();
        else
            this.recorder = NullRecorder.getInstance();

        // File containing host-to-switch mappings.
        final String hostToSwMapFile = modConf.get("host_to_sw_mappings");
        if (hostToSwMapFile == null) {
            throw new RuntimeException("No value for configuration parameter 'host_to_sw_mappings'!");
        }
        this.loadHostToSwMappings(hostToSwMapFile);

        this.flProvider = context.getServiceImpl(IFloodlightProviderService.class);
        this.linkDiscoverySrvc = context.getServiceImpl(ILinkDiscoveryService.class);

        if (getLogger().isDebugEnabled()) {
        	getLogger().debug("init> initialized");
        }
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        this.flProvider.addOFSwitchListener(this);
        this.linkDiscoverySrvc.addListener(this);

        if (getLogger().isDebugEnabled()) {
        	getLogger().debug("startUp> started");
        }
		try
		{
			writeStateVars();
			if (BUG == -1)
			{
				BUG = Util.config(Util.CONFIG_PATH, "bug");
				getLogger().info("BUG: " + BUG);
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
				getLogger().info("ENABLE_WILDCARD: " + ENABLE_WILDCARD);
			}
			// Write after setting ENABLE_WILDCARD
			writeWildcard();
		} catch (IOException ioe)
		{
		}
    }

    @Override
    public String getName() {
        return RouteFlow.class.getCanonicalName();
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
    public void switchAdded(long switchId) {
        final int numSws = this.numSws.incrementAndGet();
        final int numActiveSws = this.activeSws.size();

        if (getLogger().isTraceEnabled()) {
        	getLogger().trace(String.format("switchAdded> [%d] %s; #switches: %d, #active: %d",
                                       switchId, Long.toHexString(switchId), numSws, numActiveSws));
        }
    }

    @Override
    public void switchRemoved(long switchId) {
        synchronized (this.activeSws) {
            this.activeSws.remove(switchId);
        }
        final int numActiveSws = this.activeSws.size();
        final int numSws = this.numSws.decrementAndGet();

        if (getLogger().isTraceEnabled()) {
        	getLogger().trace(String.format("switchRemoved> [%d] %s; #switches: %d, #active: %s",
                                       switchId, Long.toHexString(switchId), numSws, numActiveSws));
        }

        this.recorder.logInMsg(String.format("Sw-%d removed.", switchId), getROUTES_LOG());

        synchronized (this.activeSws) {
            if (this.processLinkUpdates(this.linkDiscoverySrvc.getLinks())) {
                this.computeRoutes(this.netwLinks);
            }
        }
    }

    @Override
    public void switchActivated(long switchId) {
        synchronized (this.activeSws) {
            this.activeSws.add(switchId);
            this.floodARP(switchId);
        }
        final int numActiveSws = this.activeSws.size();
        final int numSws = this.numSws.get();

        if (getLogger().isTraceEnabled()) {
        	getLogger().trace(String.format("switchActivated> [%d] %s; #switches: %d, #active: %d",
                                       switchId, Long.toHexString(switchId), numSws, numActiveSws));
        }

        this.recorder.logInMsg(String.format("Sw-%d activated.", switchId), getROUTES_LOG());

        synchronized (this.activeSws) {
            if (this.processLinkUpdates(this.linkDiscoverySrvc.getLinks())) {
                this.computeRoutes(this.netwLinks);
            }
        }
    }

    @Override
    public void switchPortChanged(long switchId, ImmutablePort port, IOFSwitch.PortChangeType type) {
        if (getLogger().isTraceEnabled()) {
        	getLogger().trace(String.format("switchPortChanged> [%d] %s: %s (%s)",
                                       switchId, Long.toHexString(switchId), port.toString(), type.toString()));
        }

        this.recorder.logInMsg(String.format("Sw-%d:%d %s.",
                                             switchId, port.getPortNumber(), type.toString()),
                                             getROUTES_LOG());

        synchronized (this.activeSws) {
            if (this.processLinkUpdates(this.linkDiscoverySrvc.getLinks())) {
                this.computeRoutes(this.netwLinks);
            }
        }
    }

    @Override
    public void switchChanged(long switchId) {
        if (getLogger().isTraceEnabled()) {
        	getLogger().trace(String.format("switchChanged> [%d] %s", switchId, Long.toHexString(switchId)));
        }
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (getLogger().isTraceEnabled()) {
        	getLogger().trace(String.format("receive> %s => %s", sw.getStringId(), msg.getType()));
        }
        return Command.CONTINUE;
    }

    /**
     * Delete links associated with unknown switches.
     *
     * @param links Links.
     */
    private void delLinksOfUnknownSws(Map<Link, LinkInfo> links) {
        final List<Link> delLinks = new ArrayList<Link>(DEF_NUM_LINKS);

        // Remove existing links associated with unknown switches.
        for (Link link : links.keySet()) {
            if (this.activeSws.contains(link.getSrc()) &&
                this.activeSws.contains(link.getDst())) {
                continue;
            }
            delLinks.add(link);

            this.recorder.logInMsg(String.format("Ignoring link %s Sw-%d:%d Sw-%d:%d",
                                                 links.get(link).getLinkType().toString(),
                                                 link.getSrc(),
                                                 link.getSrcPort(),
                                                 link.getDst(),
                                                 link.getDstPort()),
                                                 getROUTES_LOG());

        }
        for (Link link : delLinks) {
            links.remove(link);
        }
    }

    /**
     * Process link updates and indicate if the topology has changed.
     *
     * @param links Network links.
     * @return True, if topology has changed; false, otherwise
     */
    private boolean processLinkUpdates(Map<Link, LinkInfo> links) {
    	// touch
    	try
		{
			int pkt_counter = typeDeser.toInteger(this.slq.get(
					this.nsID, State.counter.ordinal()));
			getLogger().info("pkt_counter: " + pkt_counter);
			this.slq.set(this.nsID, State.counter.ordinal(),
					typeSer.valueOf(pkt_counter));
			getLogger().info("Set state " + State.counter.ordinal());
		} catch (NoActiveTransactionFault e)
		{
			e.printStackTrace();
		}
    	
        this.delLinksOfUnknownSws(links);

        final Set<Link> oldLinks = this.netwLinks.keySet();
        final Set<Link> newLinks = links.keySet();

        final boolean hasAdditions = !oldLinks.containsAll(newLinks);
        final boolean hasDeletions = !newLinks.containsAll(oldLinks);
        if (!hasAdditions && !hasDeletions) {
            this.recorder.logInMsg("No links added or deleted!", getROUTES_LOG());

            return false;
        }

        if (hasAdditions) {
            final Set<Link> additions = new HashSet<Link>(newLinks);
            additions.removeAll(oldLinks);
            for (Link link : additions) {
                this.netwLinks.put(link, links.get(link));
            }

            this.recorder.logInMsg(String.format("#link-additions: %d.", additions.size()), getROUTES_LOG());
        }

        if (hasDeletions) {
            final Set<Link> deletions = new HashSet<Link>(oldLinks);
            deletions.removeAll(newLinks);
            for (Link link : deletions) {
                this.netwLinks.remove(link);
            }

            this.recorder.logInMsg(String.format("#link-deletions: %d.", deletions.size()), getROUTES_LOG());
        }

        return true;
    }

    @Override
    public void linkDiscoveryUpdate(LDUpdate update) {
        if (getLogger().isTraceEnabled()) {
        	getLogger().trace(String.format("linkDiscoveryUpdate> (%s) %s - src: %d => dst: %d",
                                       update.getType().toString(),
                                       update.getOperation().toString(),
                                       update.getSrc(),
                                       update.getDst()));
        }

        this.recorder.logInMsg(String.format("LDUpdate %s %s Sw-%d:%d Sw-%d:%d",
                                             update.getOperation().toString(),
                                             update.getType().toString(),
                                             update.getSrc(),
                                             update.getSrcPort(),
                                             update.getDst(),
                                             update.getDstPort()),
                                             getROUTES_LOG());

        synchronized (this.activeSws) {
            if (this.processLinkUpdates(this.linkDiscoverySrvc.getLinks())) {
                this.computeRoutes(this.netwLinks);
            }
        }
    }

    @Override
    public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
        if (getLogger().isTraceEnabled()) {
        	getLogger().trace(String.format("linkDiscoveryUpdate> received %d updates", updateList.size()));
        }

        this.recorder.logInMsg(String.format("#LDUpdates: %d", updateList.size()),
        		getROUTES_LOG());

        synchronized (this.activeSws) {
            if (this.processLinkUpdates(this.linkDiscoverySrvc.getLinks())) {
                this.computeRoutes(this.netwLinks);
            }
        }
    }

    public static final class LinkEnds {

        public final long src;
        public final long dst;
        private final int hashCode;

        public LinkEnds(long src, long dst) {
            this.src = src;
            this.dst = dst;
            this.hashCode = String.format("%d,%d", this.src, this.dst).hashCode();
        }

        @Override
        public int hashCode() {
            return this.hashCode;
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof LinkEnds)) {
                throw new RuntimeException("Comparing apples and oranges!");
            }
            final LinkEnds that = (LinkEnds) obj;
            return this.src == that.src && this.dst == that.dst;
        }

    }

    /**
     * Compute routes between different switches.
     *
     * @param nwLinks Map of known links and associated metadata.
     */
    protected synchronized void computeRoutes(Map<Link, LinkInfo> nwLinks) {
        this.recorder.logMsg(String.format("#links: %d", nwLinks.size()), "-", getROUTES_LOG());

        if (getLogger().isTraceEnabled()) {
        	getLogger().trace(String.format("computeRoutes> #links: %d", nwLinks.size()));
        }

        final Map<LinkEnds, Short> linkDetails = new HashMap<LinkEnds, Short>(DEF_NUM_LINKS);
        for (Map.Entry<Link, LinkInfo> linkEntry : nwLinks.entrySet()) {
            final Link link = linkEntry.getKey();
            final short srcPort = link.getSrcPort();
            final LinkEnds le = new LinkEnds(link.getSrc(), link.getDst());
            linkDetails.put(le, srcPort);

            if (getLogger().isDebugEnabled()) {
            	getLogger().debug(String.format("computeRoutes> link: %d:%d => %d", le.src, srcPort, le.dst));
            }
        }
        final Map<Long, Map<Long, Long>> routes = this.calcShortestPaths(linkDetails.keySet());
        this.setupRoutes(routes, linkDetails);
    }

    /**
     * Initialize distance and next-hop matrices.
     *
     * @param distance Distance matrix
     * @param nextHop Next hop matrix
     */
    private void initMatrices(int[][] distance, int[][] nextHop) {
        // NOTE: Matrices are square.
        final int N = distance.length;
        for (int i = 0; i < N; i++) {
            // Distance to unknown destination is some very large value.
            Arrays.fill(distance[i], UNKNOWN_DIST);
            // Distance to self is zero.
            distance[i][i] = 0;
            // Next hop is unknown.
            Arrays.fill(nextHop[i], UNKNOWN_NEXT_HOP);
        }
    }

    /**
     * Calculate shortest path between any two switches.
     *
     * @param links Set of known switch links
     * @return Shortest routes between switches
     */
    protected Map<Long, Map<Long, Long>> calcShortestPaths(Set<LinkEnds> links) {
        final int N;
        // Switch IDs to array indices.
        final Map<Long, Integer> swToIndex;
        final long[] swIDs;
        synchronized (this.activeSws) {
            N = this.activeSws.size();

            swToIndex = new HashMap<Long, Integer>(N);
            swIDs = new long[N];

            // Map switches IDs to array indices.
            int index = 0;
            for (Long sw : this.activeSws) {
                swToIndex.put(sw, index);
                swIDs[index] = sw;
                index++;
            }
        }

        if (getLogger().isDebugEnabled()) {
        	getLogger().debug(String.format("calcShortestPaths> #switches: %d", N));
            StringBuilder buf = new StringBuilder("calcShortestPaths>");
            for (int s = 0; s < N; s++) {
                buf.append(" ");
                buf.append(swIDs[s]);
            }
            getLogger().debug(buf.toString());
        }

        // NOTE: Links are bi-directional
        final int[][] distance = new int[N][N];
        // Port on the source that connects it to the corresponding next hop.
        final int[][] nextHop = new int[N][N];
        // Initialize matrices.
        this.initMatrices(distance, nextHop);

        // Update distances of known links
        for (LinkEnds le : links) {
            if (!swToIndex.containsKey(le.src) || !swToIndex.containsKey(le.dst)) {
                // We have not seen activations of these switches, yet!
                continue;
            }

            // Convert switch IDs to zero-based indices.
            final int u = swToIndex.get(le.src);
            final int v = swToIndex.get(le.dst);
            distance[u][v] = UNIT_DIST_COST;
            // To go from 'u' to 'v', use the given port on the source 'u'.
            nextHop[u][v] = v;

            if (getLogger().isTraceEnabled()) {
            	getLogger().trace(String.format("calcShortestPaths> using link from %d<%d> to %d<%d>",
                                           le.src, u, le.dst, v));
            }
        }

        // Compute all pairs shortest paths using the Floyd-Warshall algorithm.
        for (int k = 0; k < N; k++) {
            for (int i = 0; i < N; i++) {
                for (int j = 0; j < N; j++) {
                    if (distance[i][k] == UNKNOWN_DIST || distance[k][j] == UNKNOWN_DIST)
                        continue;

                    final int newDist = distance[i][k] + distance[k][j];
                    final int oldDist = distance[i][j];
                    if (newDist < oldDist) {
                        distance[i][j] = newDist;
                        nextHop[i][j] = nextHop[i][k];

                        if (getLogger().isDebugEnabled()) {
                        	getLogger().debug(String.format("calcShortestPaths>" +
                                                       " new: %d[%d] => %d[%d] via %d[%d] (d: %d => %d)",
                                                       swIDs[i], i, swIDs[j], j, swIDs[nextHop[i][k]], nextHop[i][k],
                                                       oldDist, newDist));
                        }
                    }
                }
            }
        }

        int numRoutes = 0;
        final Map<Long, Map<Long, Long>> routes = new HashMap<Long, Map<Long, Long>>(DEF_NUM_SWS);
        for (int u = 0; u < N; u++) {
            for (int v = 0; v < N; v++) {
                final Long src = swIDs[u];
                final Long dst = swIDs[v];
                final Long nxt = swIDs[nextHop[u][v]];

                if (distance[u][v] == UNKNOWN_DIST) {
                    continue;
                }

                // No routes to self.
                if (u == v) {
                    continue;
                }

                if (!routes.containsKey(src)) {
                    routes.put(src, new HashMap<Long, Long>(DEF_NUM_SWS));
                }
                routes.get(src).put(dst, nxt);
                numRoutes++;

                if (getLogger().isDebugEnabled()) {
                	getLogger().debug(String.format("calcShortestPaths>  %02d => %02d via %02d  (dist: %2d)",
                                               src, dst, nxt, distance[u][v]));
                }
            }
        }

        if (getLogger().isDebugEnabled()) {
        	getLogger().debug(String.format("calcShortestPaths> calculated %d routes", numRoutes));
        }

        return routes;
    }

    /**
     * Setup the routes between different switches.
     *
     * @param routes Next hop matrix
     * @param links Known links in the network
     */
    protected void setupRoutes(final Map<Long, Map<Long, Long>> routes, Map<LinkEnds, Short> links) {
        int numWr = 0;
        synchronized (this.activeSws) {
            List<Integer> hosts = new ArrayList<Integer>(this.hostToSw.keySet());
            Collections.sort(hosts);
            for (Integer host : hosts) {
                // Switch to which the host is connected to.
                final Long dst = this.hostToSw.get(host);

                if (!this.netwRoutes.containsKey(dst)) {
                    this.netwRoutes.put(dst, new HashMap<Long, Short>(DEF_NUM_SWS));
                }

                // Establish at each switch the route to reach the different hosts.
                List<Long> sws = new ArrayList<Long>(this.activeSws);
                Collections.sort(sws);
                for (Long src : sws) {
                    final short outPort;
                    if (src.equals(dst)) {
                        outPort = SW_HOST_PORT;
                    } else {
                        if (!routes.containsKey(src)) {
                            // We do not know the routes to this switch, yet!
                            continue;
                        }

                        if (!routes.get(src).containsKey(dst)) {
                            // We do not know the routes to this switch, yet!
                            continue;
                        }

                        // Next hop towards the destination
                        final Long nxt = routes.get(src).get(dst);

                        final LinkEnds le = new LinkEnds(src, nxt);
                        outPort = links.get(le);
                    }

                    if (getLogger().isDebugEnabled()) {
                    	getLogger().debug(String.format("setupRoutes> Use port %d on %d to go to %d", outPort, src, dst));
                    }

                    if (!this.netwRoutes.get(dst).containsKey(src) ||
                        this.netwRoutes.get(dst).get(src) != outPort) {
                        this.netwRoutes.get(dst).put(src, outPort);
                        this.writeRoute(host, src, outPort, (short) 0);
                        numWr++;
                    }
                }
            }
        }

        if (getLogger().isInfoEnabled()) {
        	getLogger().info(String.format("setupRoutes> wrote %d rules to setup routes", numWr));
        }
        recordNumRtWrites(numWr);
    }

    /**
     * Record number of route writes.
     *
     * @param numWr Number of route writes
     */
    private synchronized void recordNumRtWrites(int numWr) {
        PrintWriter pw = null;
        try {
            pw = new PrintWriter(new FileWriter(getNUM_RT_WR(), true));
            pw.println(String.format("%d  %d", System.currentTimeMillis(), numWr));
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (pw != null) {
                pw.close();
            }
        }
    }
    
    protected File getNUM_RT_WR()
    {
    	return NUM_RT_WR;
    }
    
    protected File getROUTES_LOG()
    {
    	return ROUTES_LOG;
    }
    
    protected Logger getLogger()
    {
    	return logger;
    }

    /**
     * Write flow rule to switch to setup route.
     *
     * @param host Host for which route is being setup
     * @param sw Switch at which route is being setup
     * @param outPort Output port on the switch through which flows will be routed towards the host
     * @param prio Rule priority
     */
    protected void writeRoute(Integer host, Long sw, short outPort, short prio) {
        final OFMatch ofMatch = new OFMatch();
        ofMatch.setNetworkDestination(host);
        ofMatch.setDataLayerType(Ethernet.TYPE_IPv4);
        // For setting up a rule to only allow ICMP protocol.
//        ofMatch.setWildcards(Wildcards.FULL
//                                     .matchOn(Wildcards.Flag.NW_DST)
//                                     .matchOn(Wildcards.Flag.DL_TYPE)
//                                     .matchOn(Wildcards.Flag.NW_PROTO)
//                                     .withNwDstMask(32));
//        ofMatch.setNetworkProtocol(IPv4.PROTOCOL_ICMP);
        // For setting up a rule to allow all protocols.
        ofMatch.setWildcards(Wildcards.FULL
                                     .matchOn(Wildcards.Flag.NW_DST)
                                     .matchOn(Wildcards.Flag.DL_TYPE)
                                     .withNwDstMask(32));

        final OFActionOutput action = new OFActionOutput();
        action.setPort(outPort);

        final OFFlowMod ofFlowMod = (OFFlowMod) this.flProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
        ofFlowMod.setCommand(OFFlowMod.OFPFC_ADD);
        ofFlowMod.setActions(Collections.singletonList((OFAction) action));
        ofFlowMod.setMatch(ofMatch);
        ofFlowMod.setBufferId(OFPacketOut.BUFFER_ID_NONE);
        ofFlowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
        ofFlowMod.setPriority(prio);

        try {
            final IOFSwitch iofSwitch = this.flProvider.getSwitch(sw);
            iofSwitch.write(ofFlowMod, null);
            iofSwitch.flush();
        } catch (IOException e) {
        	getLogger().error(String.format("writeRoute> failed to write route! %s", e.getLocalizedMessage()));
            e.printStackTrace();
        }

        this.recorder.logOutMsg(String.format("Sw-%d:%d => %s ",
                                              sw, outPort, IPv4.fromIPv4Address(host)),
                                              getROUTES_LOG());
    }

    /**
     * Load host-to-switch mappings from file.
     * @param mapFile File containing the mappings
     * @throws FloodlightModuleException
     */
    private void loadHostToSwMappings(String mapFile) throws FloodlightModuleException {
        FileReader inFile = null;
        BufferedReader reader = null;
        try {
            inFile = new FileReader(mapFile);
            reader = new BufferedReader(inFile);
            String line = reader.readLine();
            while (line != null) {
                final String data = line.trim();
                line = reader.readLine();
                if (data.length() == 0) {
                    continue;
                }

                // <host IP>, <switch address>
                final String[] parts = data.split("\\s*,\\s*");
                final Integer host = IPv4.toIPv4Address(parts[0]);
                final Long sw = HexString.toLong(parts[1]);
                this.hostToSw.put(host, sw);
            }

            if (getLogger().isInfoEnabled()) {
            	getLogger().info(String.format("loadHostToSwMappings> loaded %d host-to-switch mappings", this.hostToSw.size()));
            }
        } catch (IOException e) {
        	getLogger().error(String.format("loadHostToSwMappings> failed to load host-to-switch mappings! %s",
                                       e.getLocalizedMessage()));
            throw new FloodlightModuleException(e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    // Ignore error!
                }
            }

            if (inFile != null) {
                try {
                    inFile.close();
                } catch (IOException e) {
                    // Ignore error!
                }
            }
        }
    }

    /**
     * Flood ARP requests received on the given switch.
     *
     * @param sw Switch ID
     */
    private void floodARP(long sw) {
        if (getLogger().isDebugEnabled()) {
        	getLogger().debug(String.format("floodARP> flood ARP for %d", sw));
        }

        final OFMatch ofMatch = new OFMatch().setDataLayerType(Ethernet.TYPE_ARP);
        ofMatch.setWildcards(Wildcards.FULL.matchOn(Wildcards.Flag.DL_TYPE));

        final OFActionOutput ofActionOut = new OFActionOutput().setPort(OFPort.OFPP_FLOOD.getValue());

        final OFFlowMod ofFlowMod = (OFFlowMod) this.flProvider
                .getOFMessageFactory()
                .getMessage(OFType.FLOW_MOD);
        ofFlowMod.setCommand(OFFlowMod.OFPFC_ADD);
        ofFlowMod.setMatch(ofMatch);
        ofFlowMod.setActions(Collections.singletonList((OFAction) ofActionOut));
        ofFlowMod.setLength((short) (OFActionOutput.MINIMUM_LENGTH + OFFlowMod.MINIMUM_LENGTH));
        ofFlowMod.setBufferId(OFPacketOut.BUFFER_ID_NONE);

        try {
            final IOFSwitch iofSwitch = this.flProvider.getSwitch(sw);
            iofSwitch.write(ofFlowMod, null);
            iofSwitch.flush();
        } catch (IOException e) {
        	getLogger().error(String.format("floodARP> failed to setup rule! %s", e.getLocalizedMessage()));
            e.printStackTrace();
        }
    }

	@Override
	public void setNSQueryProvider(NSQuery nsQueryProvider)
	{
		this.nsq = nsQueryProvider;
		this.ns = this.nsq.getNS();
		this.nsID = this.nsq.fromNS(this.ns);
		if (getLogger().isInfoEnabled())
		{
			getLogger().info("Using namespace {}<{}>", this.ns, this.nsID);
		}
	}

	@Override
	public String getNameSpace()
	{
		return "edu.duke.cs.legosdn.tests.apps.rf.RouteFlow";
	}

	@Override
	public int getMsgWildcard()
	{
		// TODO: The fingerprint might be too violent
		if (ENABLE_WILDCARD == 1)
		{
			return DefaultWildcard.LINK_NOTIF_SW
					| DefaultWildcard.PORT_NOTIF_SW
					| DefaultWildcard.SW_NOTIF_ID;
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

	@Override
	public void setQueryProvider(StateLayerQuery queryProvider)
	{
		this.slq = queryProvider;
	}

	@Override
	public void writeStateVars() throws IOException
	{
		final File path = new File(String.format("%s%s%s",
				Defaults.STATE_LIST_PATH, File.separator, this.nsq.getNS()));
		Type[] types = { Type.Int };
		StateUtil.writeStateList(path,
				RouteFlow.State.class.getEnumConstants(), types, this.ns);
	}

}
