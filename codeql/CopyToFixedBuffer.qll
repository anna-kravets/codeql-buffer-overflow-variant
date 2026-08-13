/**
 * Shared definitions for the Part 3 queries on CVE-2020-8597 (pppd EAP `rhostname`).
 *
 * Both `UnboundedCopyToFixedBuffer.ql` (sink-shape only) and `UnboundedCopyTainted.ql`
 * (sink shape + taint from attacker input) import this file, so the only difference
 * between their results is the taint condition. That is what makes the before/after
 * comparison meaningful.
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
 * tree goes quiet. Same predicate, opposite verdicts: that is the negative control.
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
 * Holds if `call` copies into the fixed-size local array `dest` with a length that is
 * neither a safe constant nor bounded by the buffer's size. This is the complete
 * sink-side condition, shared by both queries.
 */
predicate unguardedCopy(CopyCall call, LocalVariable dest, int destSize) {
  copiesIntoFixedBuffer(call, dest, destSize) and
  not exists(int n | constantLength(call, n) and n <= destSize) and
  not lengthCheckedAgainstDestSize(call, dest, destSize)
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

/**
 * The alert message, shared so both queries report findings identically.
 *
 * The `unguardedCopy` conjunct is not redundant. `destSize` is an `int`, an infinite
 * domain, so it has to be bound by a generative conjunct inside this predicate — the
 * class-typed parameters bind from their own types, but a primitive one does not. It
 * also restricts the message to actual findings.
 */
string alertMessage(CopyCall call, LocalVariable dest, int destSize) {
  unguardedCopy(call, dest, destSize) and
  result =
    call.getLocation().getFile().getBaseName() + ":" +
      call.getLocation().getStartLine().toString() + " in " +
      call.getEnclosingFunction().getName() + "() - copy into fixed-size buffer '" +
      dest.getName() + "' (" + destSize.toString() + " bytes) with length '" +
      describeLength(call.getLengthArg()) +
      "', which is never compared against the buffer's size."
}

/**
 * A function whose address is stored in a function-pointer table — either in an
 * aggregate initialiser or assigned into a struct field.
 *
 * This is the general answer to the call-graph problem in the write-up (§5): pppd
 * reaches `eap_input` only through `struct protent eap_protent = { ..., eap_input,
 * ... }`, and the variant reaches `handle_hello` only through
 * `static const struct op ops[] = { {1, handle_hello}, ... }`. Neither call site
 * mentions the callee by name. The predicate names neither table, so it generalises
 * to any dispatch-table design — which is what the assignment's "different structure
 * and call chain" requirement is testing.
 *
 * Such a function's parameters carry whatever the dispatcher was handed, so when the
 * default source model cannot see through the indirect call, they are the honest
 * place to start tracking taint.
 */
Function dispatchTableTarget() {
  exists(FunctionAccess fa |
    fa.getTarget() = result and
    fa.getParent+() instanceof AggregateLiteral
  )
  or
  exists(Assignment a, FunctionAccess fa |
    fa.getTarget() = result and
    a.getRValue() = fa and
    a.getLValue() instanceof FieldAccess
  )
}
