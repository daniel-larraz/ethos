(include "Arith-rules.smt2")

(declare-fun x () Int)
(declare-fun y () Int)
(declare-fun z () Int)
(declare-fun w () Int)

(assume @p0 (< x (* 2 y)))
(assume @p1 (< y z))
(assume @p2 (<= w 0))


(step @p3 :rule arith_sum_ub :premises (@p0 @p1 @p2))
(step @p4 (=> (and (> 4 0) (> y z)) (> (* 4 y) (* 4 z))) :rule arith_mult_pos :args (4 (> y z)))
(step @p5 :rule arith_mult_neg :args ((alf.neg 4) (> y z)))
