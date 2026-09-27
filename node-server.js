/**
 * Legacy entry point. If your host's start command still says `node-server.js`,
 * this shim keeps it working: it loads the real adapter, which is node-server.cjs.
 * New deployments should point at node-server.cjs (see README).
 */
import './node-server.cjs';
/* __NODE_SERVER_EOF__ */

