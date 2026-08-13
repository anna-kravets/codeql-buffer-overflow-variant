/**
 * @name Diagnostic: what the taint query can use as a source
 * @description Lists every function containing a `RemoteFlowSource` node, and every
 *              function whose address is stored in a function-pointer table. Run this
 *              before `UnboundedCopyTainted.ql`: it answers the one open technical
 *              question in the Part 3 plan — whether the C/C++ pack's default source
 *              model sees pppd's PPP `read()`, and whether the dispatch-table fallback
 *              has anything to hold on to. Cheap, and it makes an empty result from the
 *              taint query diagnosable instead of mysterious. It is also the only place
 *              `RemoteFlowSource` can be used, since the taint query had to drop it to
 *              avoid a library conflict.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id sp/source-probe
 * @tags diagnostic
 */

import cpp
// `FlowSources` is imported alone, with no other dataflow library alongside it, because
// in this bundle it is built on a different one and the two make the name `DataFlow`
// ambiguous. Nothing here needs to name `DataFlow`, so the conflict simply does not
// arise — which is also why `UnboundedCopyTainted.ql` delegates this question here.
import semmle.code.cpp.security.FlowSources
import CopyToFixedBuffer

from Function f, string msg
where
  exists(RemoteFlowSource s | s.getFunction() = f) and
  msg =
    "RemoteFlowSource x" + count(RemoteFlowSource s | s.getFunction() = f | s).toString() +
      " in " + f.getName() + "()"
  or
  f = dispatchTableTarget() and
  msg = "dispatch-table handler: " + f.getName() + "() is reached through a function pointer"
select f, msg
