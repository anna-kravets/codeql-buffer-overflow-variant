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
import semmle.code.cpp.ir.dataflow.new.DataFlow
import semmle.code.cpp.ir.dataflow.new.TaintTracking
import semmle.code.cpp.security.FlowSources
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
   * Two kinds of source.
   *
   * `RemoteFlowSource` is the C/C++ pack's own model of network input. It is the
   * right answer when it fires.
   *
   * Parameters of dispatch-table handlers are the second kind, and they are what
   * makes this query work on both targets. Neither pppd nor the variant calls the
   * vulnerable handler by name — pppd goes through `protent.input`, the variant
   * through `ops[i].handle` — so if the pack's inter-procedural model does not
   * resolve the indirect call, taint from the real `read()` never arrives. Treating
   * a handler's own parameters as tainted starts tracking on the far side of that
   * edge. It is an over-approximation, and the write-up should say so: it assumes a
   * function reachable only through a function-pointer table is reachable with
   * attacker-supplied arguments. For a protocol dispatcher that is precisely true.
   */
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
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
