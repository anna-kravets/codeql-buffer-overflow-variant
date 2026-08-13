/**
 * @name Diagnostic: what the taint query can use as a source
 * @description Lists every function containing a `RemoteFlowSource` node, and every
 *              function whose address is stored in a function-pointer table. Run this
 *              before `UnboundedCopyTainted.ql`: it answers the one open technical
 *              question in the Part 3 plan — whether the C/C++ pack's default source
 *              model sees pppd's PPP `read()`, and whether the dispatch-table fallback
 *              has anything to hold on to. Cheap, and it makes an empty result from the
 *              taint query diagnosable instead of mysterious.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id sp/source-probe
 * @tags diagnostic
 */

import cpp
import semmle.code.cpp.ir.dataflow.new.DataFlow
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
