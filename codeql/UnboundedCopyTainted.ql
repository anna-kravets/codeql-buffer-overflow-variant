/**
 * @name Attacker-controlled length copied into a fixed-size buffer
 * @description A memcpy-family call writes into a fixed-size stack buffer using a
 *              length that is derived from attacker-controlled input and is never
 *              compared against that buffer's size. This is CVE-2020-8597 (pppd EAP
 *              `rhostname`, CWE-120, CVSS 3.1 9.8): the bounds check at `eap.c:1423`
 *              exists but constrains `vallen`, while the copy length is `len - vallen`.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id sp/tainted-copy-fixed-buffer
 * @tags security
 *       external/cwe/cwe-120
 *       external/cwe/cwe-121
 *       external/cwe/cwe-787
 */

import cpp
// The `new` dataflow library lives under `semmle/code/cpp/dataflow/`, not under
// `semmle/code/cpp/ir/dataflow/`. It forwards to the IR implementation.
//
// `semmle.code.cpp.security.FlowSources` is deliberately *not* imported. In the bundle
// on the VM it is built on a different dataflow library, so importing both makes the
// name `DataFlow` ambiguous. `SourceProbe.ql` imports it in isolation instead, which is
// where the question it answers belongs anyway.
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking
import CopyToFixedBuffer

/**
 * Taint from attacker input to the length operand of an otherwise-unguarded copy.
 *
 * Taint tracking rather than plain data flow, because the write-up's §5 point is that
 * the value does not survive: `get_input()` computes `len` from `read()`'s return,
 * `eap_input()` throws that away and re-reads a length field out of the packet body,
 * and `eap_request()` finally copies `len - vallen`. Every hop is a new value built
 * from attacker bytes, which is influence, not identity — exactly the distinction
 * drawn in `lectures/12. Static Analysis.md`.
 */
module UnboundedCopyConfig implements DataFlow::ConfigSig {
  /**
   * The parameters of any function whose address is stored in a function-pointer
   * table.
   *
   * This is what makes the query work on both targets. Neither program calls the
   * vulnerable handler by name — pppd dispatches through `protent.input`, the variant
   * through `ops[i].handle` — so if the pack's inter-procedural model does not resolve
   * the indirect call, taint from the real `read()` never arrives at the sink and the
   * query finds nothing. Treating a handler's own parameters as tainted picks taint up
   * on the far side of that edge, and `dispatchTableTarget()` names neither table, so
   * the same rule covers both call chains.
   *
   * Two honest caveats for the write-up.
   *
   * It is an over-approximation: it assumes a function reachable only through a
   * function-pointer table is reachable with attacker-supplied arguments. For a
   * protocol dispatcher that is precisely true; in general it is not.
   *
   * It is also the *only* source here. `RemoteFlowSource`, the pack's own model of
   * network input, would be the better starting point, but it cannot be imported
   * alongside this dataflow library in the bundle on the VM — see the import comment.
   * Run `SourceProbe.ql` to see what it would have contributed.
   */
  predicate isSource(DataFlow::Node source) {
    exists(Function handler |
      handler = dispatchTableTarget() and
      source.asParameter(_) = handler.getAParameter()
    )
  }

  /**
   * The length operand of a copy that already failed the sink-side test. Restricting
   * the sink set here rather than in the `where` clause keeps the flow computation
   * small, which matters on the 1.3 GB heap the VM gives the evaluator.
   */
  predicate isSink(DataFlow::Node sink) {
    exists(CopyCall call |
      sink.asExpr() = call.getLengthArg() and
      exists(LocalVariable dest, int destSize | unguardedCopy(call, dest, destSize))
    )
  }
}

module UnboundedCopyFlow = TaintTracking::Global<UnboundedCopyConfig>;

import UnboundedCopyFlow::PathGraph

from
  UnboundedCopyFlow::PathNode source, UnboundedCopyFlow::PathNode sink, CopyCall call,
  LocalVariable dest, int destSize
where
  unguardedCopy(call, dest, destSize) and
  sink.getNode().asExpr() = call.getLengthArg() and
  UnboundedCopyFlow::flowPath(source, sink)
select call, source, sink,
  alertMessage(call, dest, destSize) + " The length is derived from $@.", source.getNode(),
  "attacker-controlled input"
