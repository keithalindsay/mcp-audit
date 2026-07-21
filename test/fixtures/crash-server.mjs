// Chaos-QA fixture: a server that crashes immediately, before any MCP handshake.
// Models a config entry that isn't launchable on this machine.
process.stderr.write("fatal: cannot start\n");
process.exit(1);
