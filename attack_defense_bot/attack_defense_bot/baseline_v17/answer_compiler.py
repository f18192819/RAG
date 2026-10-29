"""Re-export answer_compiler for baseline_v17 compatibility."""
try:
    from ..answer_compiler import (
        CANONICAL_CONTROL_METADATA,
        CONTROL_NAME_ALIASES,
        NEGLECT_CONSEQUENCE_ZH,
        append_verified_course_support,
        build_deterministic_evidence_fallback,
        canonical_terms,
        classify_short_answer_template,
        compile_answer,
        compile_response_json,
        ensure_neglect_consequence,
        extract_question_anchors,
        resolve_control_id,
    )
except ImportError:
    from answer_compiler import (
        CANONICAL_CONTROL_METADATA,
        CONTROL_NAME_ALIASES,
        NEGLECT_CONSEQUENCE_ZH,
        append_verified_course_support,
        build_deterministic_evidence_fallback,
        canonical_terms,
        classify_short_answer_template,
        compile_answer,
        compile_response_json,
        ensure_neglect_consequence,
        extract_question_anchors,
        resolve_control_id,
    )
