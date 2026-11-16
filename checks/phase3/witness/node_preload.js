'use strict'
// Part C. Loaded with NODE_OPTIONS=--require, outside the host file. NODE_V8_COVERAGE writes its counts only when the
// process exits normally, so a stop signal is turned into a normal exit. Nothing else is changed.
process.on('SIGTERM', () => process.exit(0))
