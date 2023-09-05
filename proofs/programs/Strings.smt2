
(include "../theories/Builtin.smt2")
(include "../programs/Nary.smt2")

(include "../theories/Arith.smt2")
(include "../theories/Strings.smt2")


; This signature is used for both strings and sequences, where we often
; write "string" in the documentation to refer to a string or sequence.

; Make empty string of the given string-like sort U.
(program mk_emptystr ((U Type))
  (Type) U
  (
    ((mk_emptystr (Seq U)) (seq.empty (Seq U)))
    ((mk_emptystr String) "")
  )
)

; Return true if s is the empty string or sequence.
(program string_is_empty ((U Type) (x U))
  (U) Bool
  (
    ((string_is_empty (seq.empty U)) true)
    ((string_is_empty "") true)
    ((string_is_empty x) false)
  )
)

;;-------------------- Skolem terms
; The following side conditions are used for computing terms that define
; Skolems, which are used in reductions. Notice that Skolem terms may use
; terms that are not in original form, meaning that the definitions of Skolems
; may themselves contain Skolems. This is to avoid the use of a side condition
; for computing the original form of a term in the LFSC signature, which
; naively is exponential.

; Get the term corresponding to the prefix of term s of fixed length n.
(define skolem_prefix ((U Type) (s U) (n Int))
  (str.substr s 0 n)
)

; Get the term corresponding to the suffix of term s of fixed length n.
(define skolem_suffix_rem ((U Type) (s U) (n Int))
  (str.substr s n (- (str.len s) n))
)

; Get the term corresponding to the prefix of s before the first occurrence of
; t in s.
(define skolem_first_ctn_pre ((U Type) (s U) (t U))
  (skolem_prefix U s (str.indexof s t 0)))

; Get the term corresponding to the suffix of s after the first occurrence of
; t in s.
(define skolem_first_ctn_post ((U Type) (s U) (t U))
  (skolem_suffix_rem U s (+ (str.len (skolem (skolem_first_ctn_pre U s t))) (str.len t))))

;;-------------------- Utilities

; Head and tail for string concatenation. Fails if not a concatentation term.
;(program string_head ((t term)) term (nary.head str.++ t))
;(program string_tail ((t term)) term (nary.tail str.++ t))

; Concatenation str.++ applications t1 and t2. Note this side condition requires
; taking the sort u of t1 for constructing the empty string.
(program string_concat ((T Type) (t1 T) (t2 T))
  (T T) T
  (((string_concat t1 t2) (nary.concat str.++ t1 t2)))
)

; Decompose str.++ term t of sort u into a head and tail.
;(program string_decompose ((t term) (u sort)) termPair (nary.decompose str.++ t (mk_emptystr u)))

; Insert a string into str.++ term t of sort u.
;(program string_insert ((elem term) (t term) (u sort)) term (nary.insert str.++ elem t))

; Return reverse of t if rev = tt, return t unchanged otherwise.
(define string_rev ((U Type) (rev Bool) (t U)) (alf.ite rev (nary.reverse str.++ t) t))

;;-------------------- Reductions

; In the following, a "reduction predicate" refers to a formula that is used
; to axiomatize an extended string program in terms of (simpler) programs.

; Compute the reduction predicate for (str.substr x n m) of sort U.
(program string_reduction_substr ((U Type) (x U) (n Int) (m Int))
  (U Int Int Type) Bool
  (
    ((string_reduction_substr x n m U)
      (let ((k (skolem (str.substr x n m))))
      (let ((npm (+ n m)))
      (let ((k1 (skolem (skolem_prefix U x n))))
      (let ((k2 (skolem (skolem_suffix_rem U x npm))))
      (ite
        ; condition
        (and (>= n 0)(> (str.len x) n) (> m 0))
        ; if branch
        (and (= x (str.++ k1 k k2))
            (= (str.len k1) n)
            (or (= (str.len k2) (- (str.len x) npm))
                (= (str.len k2) 0))
            (<= (str.len k) m))
        ; else branch
        (= k (mk_emptystr U))
        ))))))
  )
)

; Compute the reduction predicate for (str.indexof x y n) of sort U.
(program string_reduction_indexof ((U Type) (x U) (y U) (n Int))
  (U U Int Type) Bool
  (
    ((string_reduction_indexof x y n U)
      (let ((k (skolem (str.indexof x y n))))
      (let ((xn (str.substr x n (- (str.len x) n))))
      (let ((k1 (skolem (skolem_first_ctn_pre U xn y))))
      (let ((k2 (skolem (skolem_first_ctn_post U xn y))))
      (ite
        (or (not (str.contains xn y)) (> n (str.len x)) (> 0 n))
        (= k (alf.neg 1))
        (ite
          (= y (mk_emptystr U))
          (= k n)
          (and (= xn (str.++ k1 y k2))
              (not (str.contains
                        (str.++ k1 (str.substr y 0 (- (str.len y) 1))) y))
              (= k (+ n (str.len k1)))))))))))
  )
)

; Compute the reduction predicate for term t of sort s. Note that the operators
; listed in comments are missing from the signature currently.
(program string_reduction_pred ((U Type) (x U) (y U) (n Int) (m Int))
  (U Type) Bool
  (
    ((string_reduction_pred (str.substr x n m) U) (string_reduction_substr x n m U))
    ((string_reduction_pred (str.indexof x y n) U) (string_reduction_indexof x y n U))
    ; str.update
    ; str.from_int
    ; str.to_int
    ; seq.nth
    ; str.replaceall
    ; str.replace_re
    ; str.replace_re_all
    ; str.to_lower
    ; str.to_upper
    ; str.rev
    ; str.leq
  )
)

; Compute the eager reduction predicate for (str.contains t r) where s
; is the sort of t and r.
; This is the formula:
;    (ite (str.contains t r) (= t (str.++ sk1 r sk2)) (not (= t r)))
(program string_eager_reduction_contains ((U Type) (t U) (r U))
  (U U Type) Bool
  (
    ((string_eager_reduction_contains t r U)
        (let ((k1 (skolem (skolem_first_ctn_pre U t r))))
        (let ((k2 (skolem (skolem_first_ctn_post U t r))))
        (ite
          (str.contains t r)
          (= t (str.++ k1 r k2))
          (not (= t r)))
        )))
  )
)

; Compute the eager reduction predicate for (str.code s)
(define-fun string_eager_reduction_to_code ((s String)) Bool
  (let ((t (str.to_code s)))
  (ite
    (= (str.len s) 1)
    (and (>= t 0) (< t 196608))
    (= t (alf.neg 1))))
)

; Compute the eager reduction predicate for (str.indexof x y n)
(program string_eager_reduction_indexof ((U Type) (x U) (y U) (n Int))
  (U U Int) Bool
  (
    ((string_eager_reduction_indexof x y n)
        (let ((t (str.indexof x y n)))
        (and (or (= t (alf.neg 1)) (>= t n))
             (<= t (str.len x)))))
  )
)

; `string_eager_reduction t U`
; Compute the eager reduction predicate of term t of type U.
(program mk_string_eager_reduction ((U Type) (x U) (y U) (n Int) (m Int))
  (U Type) Bool
  (
    ((mk_string_eager_reduction (str.to_code x) U) (string_eager_reduction_to_code x))
    ((mk_string_eager_reduction (str.contains x y) U) (string_eager_reduction_contains x y U))
    ((mk_string_eager_reduction (str.indexof x y n) U) (string_eager_reduction_indexof x y n))
  )
)

; re_unfold_pos_concat t R
; A helper method for computing the conclusion of PfRule::RE_UNFOLD_POS.
; For a regular expression (re.++ R1 ... Rn), re_unfold_pos_concat returns a pair of terms
; where the first term is a concatentation (str.++ t1 ... tn) and the second
; is a conjunction M of literals of the form (str.in_re ti Ri), such that
;   (str.in_re x (re.++ R1 ... Rn))
; is equivalent to
;   (and (= x (str.++ t1 ... tn)) M)
; We use the optimization that Rj may be (str.to_re tj); otherwise tj is an
; application of the unfolding skolem program @k.RE_UNFOLD_POS_COMPONENT.
(program re_unfold_pos_concat_rec ((t String) (r1 RegLan) (r2 RegLan :list) (ro RegLan) (i Int))
  (String RegLan RegLan Int) (@Pair String Bool)
  (
    ((re_unfold_pos_concat_rec t alf.nil ro i)       (@pair alf.nil alf.nil))
    ((re_unfold_pos_concat_rec t (re.++ r1 r2) ro i)
      ; match recursive call
      (alf.match ((c String :list) (M Bool :list))
        (re_unfold_pos_concat_rec t r2 ro (alf.add i 1))
        ((@pair c M)
          ; match on what r1 is
          (alf.match ((s String) (r RegLan))
            r1
            ; a constant regular expression, append s
            ((str.to_re s) (@pair (str.++ s c) M))
            ; otherwise, make the skolem and append with constraint
            (r             (let ((k (skolem (@k.RE_UNFOLD_POS_COMPONENT t ro i))))
                           (@pair (str.++ k c) (and (str.in_re k r) M)))))))
    )
  )
)
(define-fun re_unfold_pos_concat ((t String) (r RegLan)) (@Pair String Bool)
  (re_unfold_pos_concat_rec t r r 0))

; Returns a formula corresponding to a conjunction saying that each of the
; elements of str.++ application t is empty. For example for
;   (str.++ x (str.++ y ""))
; this returns:
;  (and (= x "") (and (= y "") true))
(program non_empty_concats ((U Type) (t U) (s U :list))
  (U Type) Bool
  (
    ((non_empty_concats alf.nil U)       alf.nil)
    ((non_empty_concats (str.++ t s) U)  (alf.cons and (= t (mk_emptystr U)) (non_empty_concats s U)))
  )
)

; Returns true if the length of s evaluates to one, false otherwise.
(define check_length_one ((s String)) (check_true (alf.is_eq (alf.len s) 1)))

; Returns true if the length of s evaluates to greater than one, false otherwise.
(define check_length_gt_one ((s String)) (check_true (alf.is_neg (alf.add 1 (alf.neg (alf.len s))))))

; Get first character or empty string from term t.
; If t is of the form (str.++ "A" ...), return "A".
; If t is of the form alf.nil, return alf.nil.
; Otherwise, this side condition fails
(program string_first_char_or_empty ((U Type) (T Type) (t U) (tail U :list) (s T))
  (U) U
  (
    ((string_first_char_or_empty alf.nil)                    alf.nil)
    ; Required for sequences
    ((string_first_char_or_empty (str.++ (seq.unit s) tail)) (seq.unit s))
    ; Check if the length of t evaluates to one.
    ((string_first_char_or_empty (str.++ t tail))            (alf.ite (check_length_one t) t alf.fail))
  )
)

; Flatten constants in str.++ application s. Notice that the rewritten form
; of strings in cvc5 are such that constants are grouped into constants of
; length >=1 which we call "word" constants. For example, the cvc5 rewritten
; form of (str.++ "A" "B" x) is (str.++ "AB" x). Similarly for sequences,
; the rewriten form of (str.++ (seq.unit 0) (seq.unit 1) x) is
; (str.++ (str.++ (seq.unit 0) (seq.unit 1)) x).
; Many string rules rely on processing the prefix of strings, which
; involves reasoning about the characters one-by-one. Since the above term
; has a level of nesting when word constants of size > 1 are involved, this
; method is used to "flatten" str.++ applications so that we have a uniform
; way of reasoning about them in proof rules. In this method, we take a
; str.++ application corresponding to a string term in cvc5 rewritten form.
; It returns the flattened form such that there are no nested applications of
; str.++. For example, given input:
;    (str.++ "AB" (str.++ x alf.nil))
; we return:
;    (str.++ "A" (str.++ "B" (str.++ x alf.nil)))
; Notice that this is done for all word constants in the chain recursively.
; It does not insist that the nested concatenations are over characters only.
; This rule may fail if s is not a str.++ application corresponding to a term
; in cvc5 rewritten form.

; Helper for below, assumes t is a non-empty word constant.
; For example, given "AB", this returns (str.++ "A" (str.++ "B" alf.nil)).
(program string_flatten_word ((t String))
  (String) String
  (
    ((string_flatten_word t) 
      (alf.ite (check_length_one t) 
        (alf.cons str.++ t alf.nil)
        (alf.cons str.++ (alf.extract 0 1 t) (string_flatten_word (alf.extract 1 (alf.len t) t)))))
  )
)
(program string_flatten ((U Type) (t U) (tail U :list) (tail2 U :list))
  (U) U
  (
    ((string_flatten alf.nil) alf.nil)
    ; required for sequences
    ((string_flatten (str.++ (str.++ t tail2) tail)) 
        (nary.concat str.++ (str.++ t tail2) (string_flatten tail)))
    ((string_flatten (str.++ t tail))
        ; otherwise, check whether t is a word constant of length greater than one
        (alf.ite (check_length_gt_one t)
          ; if so, we flatten the word using the method above and concatenate it.
          (nary.concat str.++ (string_flatten_word t) (string_flatten tail))
          ; if not, we just append it to the result of the recursive call
          (alf.cons str.++ t (string_flatten tail))))
  )
)

; Helper for collecting adjacent constants. This side condition takes as input
; a str.++ application s. It returns a pair whose concatenation is equal to s,
; whose first component corresponds to a word constant, and whose second
; component is a str.++ application whose first element is not a character.
; For example, for:
;   (str.++ "A" (str.++ "B" (str.++ x alf.nil)))
; We return:
;   (@pair "AB" (str.++ x alf.nil))
(program string_collect_acc ((U Type) (t U) (tail String :list))
  (U) (@Pair U U)
  (
    ; TODO: sequences
    ; Check if t is a word constant
    ((string_collect_acc (str.++ t tail))
      (alf.ite (check_length_one t)
        (alf.match ((s1 U) (s2 U)) 
          (string_collect_acc tail)
          ((@pair alf.nil s2)  (@pair t s2))
          ((@pair s1 s2)       (@pair (alf.concat t s1) s2))    ; concatentate the constant
        )
        (@pair alf.nil (str.++ t tail))))
    ((string_collect_acc alf.nil)            (@pair alf.nil alf.nil))
  )
)

; Collect adjacent constants for the prefix of string s. For example:
;    (str.++ "A" (str.++ "B" (str.++ x alf.nil)))
; we return:
;    (str.++ (str.++ "A" (str.++ "B" alf.nil)) (str.++ x alf.nil))
; This side condition may fail if s is not a str.++ application.
; Notice that the collection of constants is done for all word constants in the
; term s recursively.
(program string_collect ((U Type) (t U) (s U :list))
  (U) U
  (
    ((string_collect alf.nil)       alf.nil)
    ((string_collect (str.++ t s))
      (alf.match ((s1 U) (s2 U))
        (string_collect_acc (str.++ t s))
        ; did not strip a constant prefix, just append t to the result of processing s
        ((@pair alf.nil s2)
          (alf.cons str.++ t (string_collect s)))
        ; stripped a constant prefix, append it to second term in the pair
        ((@pair s1 s2)
          (alf.cons str.++ s1 (string_collect s2)))
      )
    )
  )
)

; Strip equal prefix of s and t. This returns the pair corresponding to s and
; t after dropping the maximal equal prefix removed. For example, for:
;   (str.++ x (str.++ y (str.++ z "")))
;   (str.++ x (str.++ w ""))
; This method will return:
;   (pair (str.++ y (str.++ z "")) (str.++ w ""))
; This side condition may fail if s or t is not a str.++ application.
(program strip_prefix ((U Type) (t U) (s U) (t2 U :list) (s2 U :list))
  (U U) (@Pair U U)
  (
    ((strip_prefix (str.++ t t2) (str.++ t s2)) (strip_prefix t2 s2))
    ((strip_prefix t s)                         (@pair t s))
  )
)

; Converts a str.++ application into "flat form" so that we are ready to
; process its prefix. This consists of the following steps:
; (1) convert s to n-ary form if it is not already a str.++ application,
; (2) flatten so that its constant prefix,
; (3) (optionally) reverse.
(define string_to_flat_form ((U Type) (s U) (rev Bool))
  ; intro, flatten, reverse
  (string_rev U rev (string_flatten (nary.intro str.++ (mk_emptystr U) s))))

; Converts a term in "flat form" to a term that is in a form that corresponds
; to one in cvc5 rewritten form. This is the dual method to
; string_to_flat_form. This consists of the following steps:
; (1) (optionally) reverse,
; (2) collect constants
; (3) eliminate n-ary form to its element if the term is a singleton list.
(define string_from_flat_form ((U Type) (s U) (rev Bool))
  ; reverse, collect, elim
  (nary.elim str.++ (mk_emptystr U) (string_collect (string_rev U rev s))))
