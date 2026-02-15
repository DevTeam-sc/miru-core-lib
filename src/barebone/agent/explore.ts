console.log("Agent loading");
const cm = new CModule(File.readAllBytes("./target/aarch64-unknown-none/release/miru-barebone-agent"));
//const cm = new CModule(File.readAllBytes("./target/aarch64-unknown-none/debug/miru-barebone-agent"));

const start = new NativeFunction(cm._start, "pointer", []);
const bufferPhysicalAddress = start();
console.log("Ready! Buffer is at physical address:", bufferPhysicalAddress);
$mdb.continue();

Object.assign(globalThis, { cm, start });
