/**
 * Custom Jest environment that pins TypedArray constructors to the real
 * Node.js globals. Required for onnxruntime-node's native addon, which
 * creates TypedArrays in the main V8 context. Jest's vm.createContext
 * creates a sandbox with its own constructors, making `instanceof` checks
 * in onnxruntime-common's tensor-impl fail at inference output time.
 *
 * Only needed for tests that use onnxruntime-node.
 */
const NodeEnvironment =
  require("jest-environment-node").default ?? require("jest-environment-node");

class OrtNodeEnvironment extends NodeEnvironment {
  constructor(config, context) {
    super(config, context);
    // Pin TypedArray constructors used by onnxruntime-node ONNX outputs.
    // These are set on this.global (the vm context object) so all module
    // code loaded inside Jest sees the same constructors as the native addon.
    this.global.Float32Array = Float32Array;
    this.global.Float64Array = Float64Array;
    this.global.Int8Array = Int8Array;
    this.global.Int16Array = Int16Array;
    this.global.Int32Array = Int32Array;
    this.global.Uint8Array = Uint8Array;
    this.global.Uint16Array = Uint16Array;
    this.global.Uint32Array = Uint32Array;
    this.global.BigInt64Array = BigInt64Array;
    this.global.BigUint64Array = BigUint64Array;
  }
}

module.exports = OrtNodeEnvironment;
