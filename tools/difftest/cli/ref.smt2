; Reference for ref-proof.cpc and ref-bad.cpc: run with --reference=ref.smt2.
(set-logic ALL)
(declare-fun x () Int)
(assert (< x 0))
(assert (> x 0))
(check-sat)
