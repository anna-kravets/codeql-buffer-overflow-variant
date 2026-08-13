/**
 * @name Copy into a fixed-size buffer with an unchecked length
 * @description A memcpy-family call writes into a fixed-size stack buffer using a
 *              length operand that is never compared against that buffer's size.
 *              This is the defect behind CVE-2020-8597 (pppd EAP `rhostname`,
 *              CWE-120): a bounds check exists, but it compares the wrong operand.
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
import semmle.code.cpp.valuenumbering.GlobalValueNumbering

/**
 * A call to a `memcpy`-family function, with the argument order
 * `(dest, source, length)`.
 *
 * `bcopy` is deliberately excluded: its destination is argument 1, not 0. pppd's
 * `BCOPY(s, d, l)` macro expands to `memcpy(d, s, l)` (`pppd/pppd.h:816`), so the
 * database records a plain `memcpy` with the arguments already in this order.
 */
class CopyCall extends FunctionCall {
  CopyCall() {
    this.getTarget().getName() =
      [
        "memcpy", "memmove", "strncpy", "__builtin_memcpy", "__builtin_memmove",
        "__builtin___memcpy_chk", "__builtin___memmove_chk", "__builtin_strncpy"
      ]
  }

  Expr getDestArg() { result = this.getArgument(0) }

  Expr getLengthArg() { result = this.getArgument(2) }
}

/**
 * Holds if `v` is an array of a known size, `size` bytes — a fixed-size stack
 * buffer such as pppd's `char rhostname[256]` (`eap.c:1319`).
 *
 * This is the one place `size` is computed from `dest`, so every predicate that
 * mentions both can bind them here.
 */
predicate fixedSizeArray(LocalVariable v, int size) {
  size = v.getType().getUnspecifiedType().(ArrayType).getSize() and
  size > 0
}

/** Holds if `call` writes into the fixed-size local array `dest` of `destSize` bytes. */
predicate copiesIntoFixedBuffer(CopyCall call, LocalVariable dest, int destSize) {
  fixedSizeArray(dest, destSize) and
  exists(VariableAccess va |
    va = call.getDestArg().getAChild*() and
    dest = va.getTarget()
  )
}

/**
 * Holds if `e` denotes the size of `dest`, written either as `sizeof(dest)` or as
 * the literal `destSize`.
 *
 * `e` must *be* that expression, not merely contain it. pppd's check compares
 * against `len + sizeof (rhostname)`, an addition, which therefore does not
 * qualify — the first of two reasons the dead check is not accepted as a guard.
 */
predicate denotesDestSize(Expr e, LocalVariable dest, int destSize) {
  fixedSizeArray(dest, destSize) and
  (
    e.(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget() = dest
    or
    e.(Literal).getValue().toInt() = destSize
  )
}

/**
 * Holds if `call` copies a compile-time constant `n` bytes, e.g. the trimming
 * branch's `BCOPY(..., sizeof (rhostname) - 1)` at `eap.c:1425`. Such a copy is
 * safe by construction when `n` fits the destination.
 */
predicate constantLength(CopyCall call, int n) { n = call.getLengthArg().getValue().toInt() }

/**
 * Holds if some comparison in the enclosing function bounds *the copy length
 * itself* against the size of `dest`.
 *
 * The value-number equality is the crux of the query. pppd compares `vallen`
 * against `len + sizeof (rhostname)`, while the copy length is `len - vallen` —
 * a different value — so the check is correctly *not* treated as a guard and the
 * CVE is still reported. The patch (`8d7970b8`) changes the comparison to
 * `len - vallen >= sizeof (rhostname)`, which is the copy length, so the patched
 * tree goes quiet. Same predicate, opposite verdicts: that is the negative
 * control for Phase 4.
 */
predicate lengthCheckedAgainstDestSize(CopyCall call, LocalVariable dest, int destSize) {
  exists(ComparisonOperation cmp, Expr checked, Expr bound |
    cmp.getEnclosingFunction() = call.getEnclosingFunction() and
    checked = cmp.getAnOperand() and
    bound = cmp.getAnOperand() and
    checked != bound and
    globalValueNumber(checked) = globalValueNumber(call.getLengthArg()) and
    denotesDestSize(bound, dest, destSize)
  )
}

/**
 * A readable rendering of the copy length.
 *
 * `Expr.toString()` prints any binary operation as `... - ...`, which hides the
 * whole point of this query — that pppd's length is `len - vallen` while its check
 * constrains `vallen`. Spelling out the operands makes the finding self-explanatory
 * in the terminal and on a slide.
 */
string describeLength(Expr e) {
  exists(BinaryOperation b | b = e |
    result =
      b.getLeftOperand().toString() + " " + b.getOperator() + " " +
        b.getRightOperand().toString()
  )
  or
  not e instanceof BinaryOperation and result = e.toString()
}

from CopyCall call, LocalVariable dest, int destSize
where
  copiesIntoFixedBuffer(call, dest, destSize) and
  not exists(int n | constantLength(call, n) and n <= destSize) and
  not lengthCheckedAgainstDestSize(call, dest, destSize)
select call,
  call.getLocation().getFile().getBaseName() + ":" +
    call.getLocation().getStartLine().toString() + " in " +
    call.getEnclosingFunction().getName() + "() - copy into fixed-size buffer '" +
    dest.getName() + "' (" + destSize.toString() + " bytes) with length '" +
    describeLength(call.getLengthArg()) +
    "', which is never compared against the buffer's size."
