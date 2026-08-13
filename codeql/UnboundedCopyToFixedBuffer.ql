/**
 * @name Copy into a fixed-size buffer with an unchecked length
 * @description A memcpy-family call writes into a fixed-size stack buffer using a
 *              length operand that is never compared against that buffer's size.
 *              This is the defect behind CVE-2020-8597 (pppd EAP `rhostname`,
 *              CWE-120): a bounds check exists, but it compares the wrong operand.
 *              This version tests the sink shape only — see UnboundedCopyTainted.ql
 *              for the version that also requires the length to be attacker-derived.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id sp/unbounded-copy-fixed-buffer
 * @tags security
 *       external/cwe/cwe-120
 *       external/cwe/cwe-121
 *       external/cwe/cwe-787
 */

import cpp
import CopyToFixedBuffer

from CopyCall call, LocalVariable dest, int destSize
where unguardedCopy(call, dest, destSize)
select call, alertMessage(call, dest, destSize)
