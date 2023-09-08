(include "../programs/Nary.smt2")

(declare-const UnitTuple Type)
(declare-const Tuple (-> Type Type Type) :right-assoc-nil UnitTuple)

(declare-const tuple.unit UnitTuple)
(declare-const tuple (-> (! Type :var T :implicit)
                         (! Type :var U :implicit)
                         T U (alf.cons Tuple T U)) :right-assoc-nil tuple.unit)
(declare-const tuple.select
    (-> (! Type :var T :implicit)
        (! Int :var i) T (nary.at Tuple UnitTuple i T)))
(declare-const tuple.update
    (-> (! Type :var T :implicit) (! Type :var S :implicit)
        Int T S T))
(declare-const is-tuple (-> (! Type :var T :implicit) T Bool))
