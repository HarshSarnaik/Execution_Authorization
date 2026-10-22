#pragma once

enum class AuthState {
    TRUSTED,
    OBSERVED,
    RESTRICTED,
    QUARANTINED
};

class TrustScorer {
public:
    static constexpr int MAX_SCORE = 10000;
    static constexpr int MIN_SCORE = 0;

    // Implements the Schmitt Trigger Hysteresis logic
    static AuthState evaluate_transition(AuthState current_state, int current_score);
    
    // Applies contextual penalties securely
    static int apply_penalty(int current_score, int base_penalty, float contextual_multiplier = 1.0f);
};
