// Alternative frontend for hosts without a native herd7 package. Both the
// solver and the included AArch64 model come from the supplied upstream bundle.
const fs = require("node:fs");
const path = require("node:path");
global.herd_output = text => process.stdout.write(text);
global.herd_stderr = text => { process.stderr.write(text); process.exitCode = 1; };
require(path.resolve(process.argv[2]));
for (const file of process.argv.slice(3))
    global.runHerd("", 'include "aarch64.cat"\n', fs.readFileSync(file, "utf8"), "show none\n");
