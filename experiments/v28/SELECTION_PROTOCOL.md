# Frozen selection rule, before inspecting online results

1. Run A–E as specified in the requested v17-based ablation.
2. Also test clean F (representation + contrast), G (representation only), H (neither), I (contrast only). This completes the 2×2 clean-runtime factorial; I was registered before clean-profile scoring/selection and before holdout. No question-specific source or rule was added.
3. No per-question rule, threshold or source changes after inspecting validation.
4. A clean profile is retrieval-eligible when its validation candidate recall@3 is at least A's. If none is eligible, record that the non-regression criterion failed rather than hiding it.
5. Among eligible profiles, maximize strict target-control accuracy, then final semantic accuracy. Exact ties choose H, then I, then G, then F (fewer inference stages and no redundant query step). If none is eligible, apply the same ranking to all four and explicitly report the failed criterion.
6. Freeze that global profile. Evaluate A and the selected profile once on the held-out split. Do not change selection after viewing holdout.
7. Run the safety contracts and one classroom submission. Report negative or inconclusive results honestly. A 27-question subset is not evidence of statistical significance.

The profile JSON is an explicit public configuration, separate from the algorithm fingerprint. Submission gating checks both the algorithm hash and the effective evaluated flags.
