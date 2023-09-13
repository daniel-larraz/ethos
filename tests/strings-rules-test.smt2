(include "Strings-programs.smt2")

; the PfRule::CONCAT_EQ rule
(declare-rule concat_eq ((U Type) (s U) (t U) (rev Bool))
  :premises ((= s t))
  :args (U rev)
  :conclusion
    (alf.match ((ss U) (ts U))
      (strip_prefix
           (string_to_flat_form U s rev)
           (string_to_flat_form U t rev))
      ((@pair ss ts)
        (=
          (string_from_flat_form U ss rev)
          (string_from_flat_form U ts rev))))
)

(declare-fun x () String)
(declare-fun y () String)
(declare-fun z () String)
(declare-fun w () String)

(assume @p0 (= (str.++ x y) (str.++ x z)))
(step @q0 (= y z) :rule concat_eq :premises (@p0) :args (String false))

(assume @p1 (= (str.++ x y) x))
(step @q1 (= y "") :rule concat_eq :premises (@p1) :args (String false))

(assume @p2 (= (str.++ x y) y))
(step @q2 (= x "") :rule concat_eq :premises (@p2) :args (String true))



(assume @p3 (= (str.++ "ABC" y) "ABCDEF"))
(step @q3 (= y "DEF") :rule concat_eq :premises (@p3) :args (String false))

(assume @p4 (= (str.++ "ABC" y) (str.++ "AB" z)))
(step @q4 (= (str.++ "C" y) z) :rule concat_eq :premises (@p4) :args (String false))
