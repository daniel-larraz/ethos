(declare-sort Int 0)

(declare-consts <numeral> Int)


(declare-const = (-> (! Type :var T :implicit) T T Bool))

(declare-const + (-> Int Int Int) :right-assoc)


(program run_evaluate ((a Int) (b Int))
    (Int) Int
    (
      ((run_evaluate (+ a b)) (eval.+ (run_evaluate a) (run_evaluate b)))
      ((run_evaluate a) a)
    )
)


(declare-rule eval
   ((a Int))
   :premises ()
   :args (a)
   :conclusion (= a (run_evaluate a))
)

(step a1 (= (+ 5 3) 8) :rule eval :args ((+ 5 3)))


(step a2 (= (+ 500000000000000000000000000000000000000000000000000000000000000000000000000000 3 1) 500000000000000000000000000000000000000000000000000000000000000000000000000004) :rule eval :args ((+ 500000000000000000000000000000000000000000000000000000000000000000000000000000 3 1)))
