
package net.floodlightcontroller.routeflow;

// import edu.duke.cs.legosdn.core.appvisor.dplane.DPlaneMsg;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.types.DatapathId;
import java.io.File;

public class NullRecorder implements Recorder {

    private static final NullRecorder INSTANCE;

    static {
        INSTANCE = new NullRecorder();
    }

    private NullRecorder() {
        /* Avoid explicitly instantiating class. */
    }

    public static Recorder getInstance() {
        return INSTANCE;
    }

    @Override
    public void logInMsg(String m, File f) {

    }

    @Override
    public void logOutMsg(String m, File f) {

    }

    @Override
    public void logMsg(String m, String d, File f) {

    }

    // @Override
    // public void logMsg(DPlaneMsg m, File f) {

    // }

    // @Override
    // public void logOutMsg(DPlaneMsg m, File f) {

    // }

    // @Override
    // public void logInMsg(DPlaneMsg m, File f) {

    // }

    // @Override
    // public void logMsg(DPlaneMsg m, String d, File f) {

    // }

    @Override
    public void logInMsg(DatapathId s, OFMessage m, File f) {

    }

    @Override
    public void logOutMsg(DatapathId s, OFMessage m, File f) {

    }

    @Override
    public void logMsg(DatapathId s, OFMessage m, String d, File f) {

    }

}
