
package net.floodlightcontroller.routeflow;

// import edu.duke.cs.legosdn.core.appvisor.dplane.DPlaneMsg;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.types.DatapathId;

import java.io.File;

/**
 * Allows quick logging of messages to file. The file/output handles are not not kept open forever.
 */
public interface Recorder {

    /**
     * Log inbound message to file for debugging.
     *
     * @param m Message
     * @param f Log file
     */
    void logInMsg(String m, File f);

    /**
     * Log outbound message to file for debugging.
     *
     * @param m Message
     * @param f Log file
     */
    void logOutMsg(String m, File f);

    /**
     * Log message to file for debugging.
     *
     * @param m Message
     * @param d Direction of message (for debugging)
     * @param f Log file
     */
    void logMsg(String m, String d, File f);

    /**
     * Log message to file for debugging.
     *
     * @param m Inbound data-plane message.
     * @param f Log file
     */
    // void logMsg(DPlaneMsg m, File f);

    /**
     * Log outbound message to file for debugging.
     *
     * @param m Inbound data-plane message.
     * @param f Log file
     */
    // void logOutMsg(DPlaneMsg m, File f);

    /**
     * Log inbound message to file for debugging.
     *
     * @param m Inbound data-plane message.
     * @param f Log file
     */
    // void logInMsg(DPlaneMsg m, File f);

    /**
     * Log message to file for debugging.
     *
     * @param m Inbound data-plane message.
     * @param d Direction of message (for debugging)
     * @param f Log file
     */
    // void logMsg(DPlaneMsg m, String d, File f);

    /**
     * Log inbound message to file for debugging.
     *
     * @param s Switch Identifier.
     * @param m Inbound data-plane message.
     * @param f Log file
     */
    void logInMsg(DatapathId s, OFMessage m, File f);

    /**
     * Log outbound message to file for debugging.
     *
     * @param s Switch Identifier.
     * @param m Inbound data-plane message.
     * @param f Log file
     */
    void logOutMsg(DatapathId s, OFMessage m, File f);

    /**
     * Log message to file for debugging.
     *
     * @param s Switch Identifier.
     * @param m Inbound data-plane message.
     * @param d Direction of message (for debugging)
     * @param f Log file
     */
    void logMsg(DatapathId s, OFMessage m, String d, File f);

}
