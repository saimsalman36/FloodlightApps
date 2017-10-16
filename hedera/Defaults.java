/** -*- mode: java; coding: utf-8; fill-column: 80; -*-
 * Created by Balakrishnan Chandrasekaran on 2014-07-21 17:53
 * Copyright (c) 2014 Balakrishnan Chandrasekaran <balakrishnan.c@gmail.com>.
 */
package net.floodlightcontroller.hedera;

public interface Defaults {
    // Custom mount point for maintaining configurations, logs, ...
    String LEGOSDN_MOUNT_PT = "/legosdn";

    // Runtime directory path
    String BASE_RUNTIME_PATH = LEGOSDN_MOUNT_PT + "/runtime";

    // Path to app. runtime data
    String APP_RUNTIME_PATH = BASE_RUNTIME_PATH + "/app";

    // Path to app. logs
    String APP_LOGS_PATH = APP_RUNTIME_PATH + "/logs";
}

// public interface Defaults {

//     // Port on which AppVisor listens for connections from apps.
//     int PROXY_PORT = 8833;

//     // NetLog listener port.
//     int NETLOG_PORT = 9933;

//     // Port on which app. listens in for communication from the controller.
//     int STUB_PORT = 9901;

//     // Channel buffer size (in bytes); 128 KB
//     int CHANNEL_BUF_SZ = 128 * 1024;

//     // Time to wait (in ms) for service call responses from controller (to app.)
//     long APP_CP_RESP_WAIT_TIME = 15;

//     // Time to wait (in ms) for message responses from app. (to controller)
//     long APP_DP_RESP_WAIT_TIME = 30;

//     // Time to wait (in ms) for checkpoint/restore operation to complete
//     long CR_RESP_WAIT_TIME = 250;

//     // Time to wait (in ms) to connect to the controller (from the app.)
//     long CONN_WAIT_TIMEOUT = 30;

//     // Time to wait (in ms) for the app. registration with the controller to complete
//     long APP_REGN_TIMEOUT = 10;

//     // Time to wait (in ms) for checkpoint/restore service to shutdown
//     long APP_SHUTDOWN_WAIT = 6000;

//     // Periodic interval (in ms) at which to check if apps. are still alive
//     long APP_HEALTH_CHECK_INTVAL = 10;

//     // Periodic interval (messages/app.) at which to generate checkpoints of app. state
//     int APP_CHKPT_FREQ = 10;

//     // Maximum number of times an app. can attempt to process an inbound message
//     int MAX_RETRY_ATTEMPTS = 3;

//     // By default, do not revert transforms (even if required)
//     boolean INVERT_XFORMS = false;

//     // By default, enable event transformations
//     boolean DISABLE_XFORMS = false;

//     // By default, enable per-app network state management
//     boolean DISABLE_PER_APP_NS = false;

//     // By default, do not log inbound (outbound) messages to (from) the app.
//     //  (NOTE: enable this for debugging)
//     boolean ENABLE_MLOG = false;

//     // By default, replay messages prior to the crash-inducing input (after recovery)
//     boolean DISABLE_REPLAY = false;

//     // By default, enable NetLog
//     boolean DISABLE_NETLOG = false;

//     // By default, run NetLog as a separate process
//     boolean USE_LOCAL_NETLOG = false;

//     // By default, disable logging time taken for controller reboots
//     boolean LOG_CTRLR_REBOOTS = false;

//     // By default, disable logging time taken for app. reboots
//     boolean LOG_APP_REBOOTS = false;

//     // By default, do not log time taken for app. restoration
//     boolean LOG_APP_RESTORES = false;

//     // Checkpoint/restore service listener port
//     int CR_DEF_SERVICE_PORT = 9080;

//     // Custom mount point for maintaining configurations, logs, ...
//     String LEGOSDN_MOUNT_PT = "/legosdn";

//     // Runtime directory path
//     String BASE_RUNTIME_PATH = LEGOSDN_MOUNT_PT + "/runtime";

//     // Path for app. PID files
//     String APP_PID_DIR_PATH = BASE_RUNTIME_PATH + "/stubs";

//     // Path to runtime tools
//     String TOOLS_PATH = BASE_RUNTIME_PATH + "/tools";

//     // Shell-script to restart app. in the background
//     String RESTART_WRAPPER = TOOLS_PATH + "/daemonize.sh";

//     // Shell-script to launch app.
//     String STUB_LAUNCHER = TOOLS_PATH + "/apploader-lomem.sh";

//     // Path to app. timer logs
//     String TIMERS_PATH = BASE_RUNTIME_PATH + "/timers";

//     // Path to app. perf. counter logs
//     String COUNTERS_PATH = BASE_RUNTIME_PATH + "/counters";

//     // Path to app. crash logs
//     String CRASH_IND_BASE_DIR = BASE_RUNTIME_PATH + "/crash-indicators";
//     String CRASH_FLAGS_PATH = BASE_RUNTIME_PATH + "/crash-flags";

//     // Path to app. runtime data
//     String APP_RUNTIME_PATH = BASE_RUNTIME_PATH + "/app";

//     // Path to app. resources
//     String APP_RESOURCES_DIR = APP_RUNTIME_PATH + "/resources";

//     // Path to app. logs
//     String APP_LOGS_PATH = APP_RUNTIME_PATH + "/logs";

//     // State-store service listener port
//     int STATE_SERVICE_PORT = 59090;

//     // Symbolic-execution service listener port
//     int SE_SERVICE_PORT = 59990;

// }
