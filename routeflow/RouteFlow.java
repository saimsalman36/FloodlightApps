
package net.floodlightcontroller.rf;

// import edu.duke.cs.legosdn.core.Defaults;
// import edu.duke.cs.legosdn.core.log.FileRecorder;
// import edu.duke.cs.legosdn.core.log.NullRecorder;
// import edu.duke.cs.legosdn.core.log.Recorder;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.internal.IOFSwitchService;

import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.Link;
import net.floodlightcontroller.linkdiscovery.internal.LinkInfo;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import org.projectfloodlight.openflow.types.IPv4Address;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.DatapathId;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;

// import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
// import org.projectfloodlight.openflow.protocol.action.OFActions;
// import org.openflow.util.HexString;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class RouteFlow implements IFloodlightModule, IOFMessageListener, IOFSwitchListener, ILinkDiscoveryListener {

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
    private Recorder recorder;

    protected IFloodlightProviderService flProvider;
    protected IOFSwitchService switchService;
    protected ILinkDiscoveryService      linkDiscoverySrvc;

    protected final AtomicInteger               numSws;
    protected final Set<DatapathId>                   activeSws;
    // Mapping from host-ip to sw-port
    protected final Map<IPv4Address, DatapathId>          hostToSw;
    // Network links.
    protected final Map<Link, LinkInfo>         netwLinks;
    // Network routes.
    protected final Map<DatapathId, Map<DatapathId, OFPort>> netwRoutes;

    public RouteFlow() {
        this.numSws = new AtomicInteger(0);
        this.activeSws = new HashSet<DatapathId>(DEF_NUM_SWS);
        this.hostToSw = new HashMap<IPv4Address, DatapathId>(DEF_NUM_SWS);
        this.netwLinks = new HashMap<Link, LinkInfo>(DEF_NUM_LINKS);
        this.netwRoutes = new HashMap<DatapathId, Map<DatapathId, OFPort>>(DEF_NUM_SWS);

        if (!NUM_RT_WR.exists()) {
            try {
                NUM_RT_WR.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e.getCause());
            }
        }
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        if (logger.isDebugEnabled()) {
            logger.debug("getModuleServices> module does not expose any services!");
        }
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        if (logger.isDebugEnabled()) {
            logger.debug("getServiceImpls> module does not implement any services!");
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
        this.switchService = context.getServiceImpl(IOFSwitchService.class);
        this.linkDiscoverySrvc = context.getServiceImpl(ILinkDiscoveryService.class);
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

        if (logger.isDebugEnabled()) {
            logger.debug("init> initialized");
        }
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        switchService.addOFSwitchListener(this);
        linkDiscoverySrvc.addListener(this);

        if (logger.isDebugEnabled()) {
            logger.debug("startUp> started");
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
    public void switchAdded(DatapathId switchId) {
        final int numSws = this.numSws.incrementAndGet();
        final int numActiveSws = this.activeSws.size();

        if (logger.isTraceEnabled()) {
            logger.trace(String.format("switchAdded> %s; #switches: %d, #active: %d",
                                       switchId.toString(), numSws, numActiveSws));
        }
    }

    @Override
    public void switchRemoved(DatapathId switchId) {
        synchronized (this.activeSws) {
            this.activeSws.remove(switchId);
        }
        final int numActiveSws = this.activeSws.size();
        final int numSws = this.numSws.decrementAndGet();

        if (logger.isTraceEnabled()) {
            logger.trace(String.format("switchRemoved> %s; #switches: %d, #active: %s",
                                       switchId.toString(), numSws, numActiveSws));
        }

        this.recorder.logInMsg(String.format("Sw-%d removed.", switchId), ROUTES_LOG);

        synchronized (this.activeSws) {
            if (this.processLinkUpdates(this.linkDiscoverySrvc.getLinks())) {
                this.computeRoutes(this.netwLinks);
            }
        }
    }

    @Override
    public void switchDeactivated(DatapathId switchId) {

    }


    @Override
    public void switchActivated(DatapathId switchId) {
        synchronized (this.activeSws) {
            this.activeSws.add(switchId);
            this.floodARP(switchId);
        }
        final int numActiveSws = this.activeSws.size();
        final int numSws = this.numSws.get();

        if (logger.isTraceEnabled()) {
            logger.trace(String.format("switchActivated> %s; #switches: %d, #active: %d",
                                       switchId.toString(), numSws, numActiveSws));
        }

        this.recorder.logInMsg(String.format("Sw-%d activated.", switchId), ROUTES_LOG);

        synchronized (this.activeSws) {
            if (this.processLinkUpdates(this.linkDiscoverySrvc.getLinks())) {
                this.computeRoutes(this.netwLinks);
            }
        }
    }

    @Override
    public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {
        if (logger.isTraceEnabled()) {
            logger.trace(String.format("switchPortChanged> %s: %s (%s)",
                                       switchId.toString(), port.toString(), type.toString()));
        }

        this.recorder.logInMsg(String.format("Sw-%d:%d %s.",
                                             switchId, port, type.toString()),
                               ROUTES_LOG);

        synchronized (this.activeSws) {
            if (this.processLinkUpdates(this.linkDiscoverySrvc.getLinks())) {
                this.computeRoutes(this.netwLinks);
            }
        }
    }

    @Override
    public void switchChanged(DatapathId switchId) {
        if (logger.isTraceEnabled()) {
            logger.trace(String.format("switchChanged> %s", switchId.toString()));
        }
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (logger.isTraceEnabled()) {
            logger.trace(String.format("receive> %s => %s", sw.toString(), msg.getType()));
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
                                   ROUTES_LOG);

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
        this.delLinksOfUnknownSws(links);

        final Set<Link> oldLinks = this.netwLinks.keySet();
        final Set<Link> newLinks = links.keySet();

        final boolean hasAdditions = !oldLinks.containsAll(newLinks);
        final boolean hasDeletions = !newLinks.containsAll(oldLinks);
        if (!hasAdditions && !hasDeletions) {
            this.recorder.logInMsg("No links added or deleted!", ROUTES_LOG);

            return false;
        }

        if (hasAdditions) {
            final Set<Link> additions = new HashSet<Link>(newLinks);
            additions.removeAll(oldLinks);
            for (Link link : additions) {
                this.netwLinks.put(link, links.get(link));
            }

            this.recorder.logInMsg(String.format("#link-additions: %d.", additions.size()), ROUTES_LOG);
        }

        if (hasDeletions) {
            final Set<Link> deletions = new HashSet<Link>(oldLinks);
            deletions.removeAll(newLinks);
            for (Link link : deletions) {
                this.netwLinks.remove(link);
            }

            this.recorder.logInMsg(String.format("#link-deletions: %d.", deletions.size()), ROUTES_LOG);
        }

        return true;
    }

    // TODO: Correct This!
    // @Override
    // public void linkDiscoveryUpdate(LDUpdate update) {
    //     if (logger.isTraceEnabled()) {
    //         logger.trace(String.format("linkDiscoveryUpdate> (%s) %s - src: %d => dst: %d",
    //                                    update.getType().toString(),
    //                                    update.getOperation().toString(),
    //                                    update.getSrc(),
    //                                    update.getDst()));
    //     }

    //     this.recorder.logInMsg(String.format("LDUpdate %s %s Sw-%d:%d Sw-%d:%d",
    //                                          update.getOperation().toString(),
    //                                          update.getType().toString(),
    //                                          update.getSrc(),
    //                                          update.getSrcPort(),
    //                                          update.getDst(),
    //                                          update.getDstPort()),
    //                            ROUTES_LOG);

    //     synchronized (this.activeSws) {
    //         if (this.processLinkUpdates(this.linkDiscoverySrvc.getLinks())) {
    //             this.computeRoutes(this.netwLinks);
    //         }
    //     }
    // }

    @Override
    public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
        if (logger.isTraceEnabled()) {
            logger.trace(String.format("linkDiscoveryUpdate> received %d updates", updateList.size()));
        }

        this.recorder.logInMsg(String.format("#LDUpdates: %d", updateList.size()),
                               ROUTES_LOG);

        synchronized (this.activeSws) {
            if (this.processLinkUpdates(this.linkDiscoverySrvc.getLinks())) {
                this.computeRoutes(this.netwLinks);
            }
        }
    }

    public static final class LinkEnds {

        public final DatapathId src;
        public final DatapathId dst;
        private final int hashCode;

        public LinkEnds(DatapathId src, DatapathId dst) {
            this.src = src;
            this.dst = dst;
            this.hashCode = String.format("%s,%s", this.src, this.dst).hashCode();
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
        this.recorder.logMsg(String.format("#links: %d", nwLinks.size()), "-", ROUTES_LOG);

        if (logger.isTraceEnabled()) {
            logger.trace(String.format("computeRoutes> #links: %d", nwLinks.size()));
        }

        final Map<LinkEnds, OFPort> linkDetails = new HashMap<LinkEnds, OFPort>(DEF_NUM_LINKS);
        for (Map.Entry<Link, LinkInfo> linkEntry : nwLinks.entrySet()) {
            final Link link = linkEntry.getKey();
            final OFPort srcPort = link.getSrcPort();
            final LinkEnds le = new LinkEnds(link.getSrc(), link.getDst());
            linkDetails.put(le, srcPort);

            if (logger.isDebugEnabled()) {
                logger.debug(String.format("computeRoutes> link: %d:%d => %d", le.src, srcPort, le.dst));
            }
        }
        final Map<DatapathId, Map<DatapathId, DatapathId>> routes = this.calcShortestPaths(linkDetails.keySet());
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
    protected Map<DatapathId, Map<DatapathId, DatapathId>> calcShortestPaths(Set<LinkEnds> links) {
        final int N;
        // Switch IDs to array indices.
        final Map<DatapathId, Integer> swToIndex;
        final DatapathId[] swIDs;
        synchronized (this.activeSws) {
            N = this.activeSws.size();

            swToIndex = new HashMap<DatapathId, Integer>(N);
            swIDs = new DatapathId[N];

            // Map switches IDs to array indices.
            int index = 0;
            for (DatapathId sw : this.activeSws) {
                swToIndex.put(sw, index);
                swIDs[index] = sw;
                index++;
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("calcShortestPaths> #switches: %d", N));
            StringBuilder buf = new StringBuilder("calcShortestPaths>");
            for (int s = 0; s < N; s++) {
                buf.append(" ");
                buf.append(swIDs[s]);
            }
            logger.debug(buf.toString());
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

            if (logger.isTraceEnabled()) {
                logger.trace(String.format("calcShortestPaths> using link from %d<%d> to %d<%d>",
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

                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("calcShortestPaths>" +
                                                       " new: %d[%d] => %d[%d] via %d[%d] (d: %d => %d)",
                                                       swIDs[i], i, swIDs[j], j, swIDs[nextHop[i][k]], nextHop[i][k],
                                                       oldDist, newDist));
                        }
                    }
                }
            }
        }

        int numRoutes = 0;
        final Map<DatapathId, Map<DatapathId, DatapathId>> routes = new HashMap<DatapathId, Map<DatapathId, DatapathId>>(DEF_NUM_SWS);
        for (int u = 0; u < N; u++) {
            for (int v = 0; v < N; v++) {
                final DatapathId src = swIDs[u];
                final DatapathId dst = swIDs[v];
                final DatapathId nxt = swIDs[nextHop[u][v]];

                if (distance[u][v] == UNKNOWN_DIST) {
                    continue;
                }

                // No routes to self.
                if (u == v) {
                    continue;
                }

                if (!routes.containsKey(src)) {
                    routes.put(src, new HashMap<DatapathId, DatapathId>(DEF_NUM_SWS));
                }
                routes.get(src).put(dst, nxt);
                numRoutes++;

                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("calcShortestPaths>  %02d => %02d via %02d  (dist: %2d)",
                                               src, dst, nxt, distance[u][v]));
                }
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("calcShortestPaths> calculated %d routes", numRoutes));
        }

        return routes;
    }

    /**
     * Setup the routes between different switches.
     *
     * @param routes Next hop matrix
     * @param links Known links in the network
     */
    protected void setupRoutes(final Map<DatapathId, Map<DatapathId, DatapathId>> routes, Map<LinkEnds, OFPort> links) {
        int numWr = 0;
        synchronized (this.activeSws) {
            List<IPv4Address> hosts = new ArrayList<IPv4Address>(this.hostToSw.keySet());
            Collections.sort(hosts);
            for (IPv4Address host : hosts) {
                // Switch to which the host is connected to.
                final DatapathId dst = this.hostToSw.get(host);

                if (!this.netwRoutes.containsKey(dst)) {
                    this.netwRoutes.put(dst, new HashMap<DatapathId, OFPort>(DEF_NUM_SWS));
                }

                // Establish at each switch the route to reach the different hosts.
                List<DatapathId> sws = new ArrayList<DatapathId>(this.activeSws);
                Collections.sort(sws);
                for (DatapathId src : sws) {
                    final OFPort outPort;
                    if (src.equals(dst)) {
                        outPort = OFPort.of(SW_HOST_PORT);
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
                        final DatapathId nxt = routes.get(src).get(dst);

                        final LinkEnds le = new LinkEnds(src, nxt);
                        outPort = links.get(le);
                    }

                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("setupRoutes> Use port %d on %d to go to %d", outPort, src, dst));
                    }

                    if (!this.netwRoutes.get(dst).containsKey(src) ||
                        this.netwRoutes.get(dst).get(src) != outPort) {
                        this.netwRoutes.get(dst).put(src, outPort);
                        this.writeRoute(host, src, outPort, 0);
                        numWr++;
                    }
                }
            }
        }

        if (logger.isInfoEnabled()) {
            logger.info(String.format("setupRoutes> wrote %d rules to setup routes", numWr));
        }
        recordNumRtWrites(numWr);
    }

    /**
     * Record number of route writes.
     *
     * @param numWr Number of route writes
     */
    private static synchronized void recordNumRtWrites(int numWr) {
        PrintWriter pw = null;
        try {
            pw = new PrintWriter(new FileWriter(NUM_RT_WR, true));
            pw.println(String.format("%d  %d", System.currentTimeMillis(), numWr));
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (pw != null) {
                pw.close();
            }
        }
    }

    /**
     * Write flow rule to switch to setup route.
     *
     * @param host Host for which route is being setup
     * @param sw Switch at which route is being setup
     * @param outPort Output port on the switch through which flows will be routed towards the host
     * @param prio Rule priority
     */
    protected void writeRoute(IPv4Address host, DatapathId swID, OFPort outPort, int prio) {
        IOFSwitch sw = switchService.getActiveSwitch(swID);
        OFFactory myFactory = sw.getOFFactory();

    // set actions
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        OFActions actions = myFactory.actions();

    //set forward translation
        Match match = myFactory.buildMatch()
        .setExact(MatchField.ETH_TYPE, EthType.IPv4)
        .setExact(MatchField.IPV4_DST, host)
        .build();

        actionList.clear();
        OFActionOutput action = actions.buildOutput()
            .setPort(outPort)
            .build();
        actionList.add( action );
        // actionList.add(sw.getOFFactory().actions().setOutport(outPort));

        OFFlowAdd flowAdd = myFactory.buildFlowAdd()
        .setBufferId(OFBufferId.NO_BUFFER)
        .setMatch(match)
        .setPriority(prio)
        .setActions(actionList)
        .build();

        sw.write(flowAdd);

        this.recorder.logOutMsg(String.format("Sw-%d:%d => %s ",
                                              sw, outPort, host),
                                ROUTES_LOG);
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
                final IPv4Address host = IPv4Address.of(parts[0]);
                final DatapathId sw = DatapathId.of(parts[1]);
                this.hostToSw.put(host, sw);
            }

            if (logger.isInfoEnabled()) {
                logger.info(String.format("loadHostToSwMappings> loaded %d host-to-switch mappings", this.hostToSw.size()));
            }
        } catch (IOException e) {
            logger.error(String.format("loadHostToSwMappings> failed to load host-to-switch mappings! %s",
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
    private void floodARP(DatapathId swID) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("floodARP> flood ARP for %s", swID.toString()));
        }

        IOFSwitch sw = switchService.getActiveSwitch(swID);
        OFFactory myFactory = sw.getOFFactory();

    // set actions
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        OFActions actions = myFactory.actions();

    //set forward translation
        Match match = myFactory.buildMatch()
        .setExact(MatchField.ETH_TYPE, EthType.ARP)
        // .setExact(MatchField.IPV4_DST, host)
        .build();

        actionList.clear();
        OFActionOutput action = actions.buildOutput()
            .setPort(OFPort.FLOOD)
            .build();
        actionList.add( action );

        OFFlowAdd flowAdd = myFactory.buildFlowAdd()
        .setBufferId(OFBufferId.NO_BUFFER)
        .setMatch(match)
        .setActions(actionList)
        .build();

        sw.write(flowAdd);
    }

}
