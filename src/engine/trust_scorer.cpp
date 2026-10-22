#include "engine/trust_scorer.h"
#include <algorithm>

AuthState TrustScorer::evaluate_transition(AuthState current_state, int current_score) {
    if (current_score <= MIN_SCORE) return AuthState::QUARANTINED;

    switch (current_state) {
        case AuthState::TRUSTED:
            if (current_score < 7500) return AuthState::OBSERVED; // Demotion Threshold
            break;
        case AuthState::OBSERVED:
            if (current_score > 9000) return AuthState::TRUSTED;  // Promotion Threshold
            if (current_score < 3000) return AuthState::RESTRICTED; // Demotion Threshold
            break;
        case AuthState::RESTRICTED:
            if (current_score > 6000) return AuthState::OBSERVED; // Promotion Threshold
            break;
        case AuthState::QUARANTINED:
            break; // Terminal state, no escape
    }
    return current_state;
}

int TrustScorer::apply_penalty(int current_score, int base_penalty, float contextual_multiplier) {
    int penalty = static_cast<int>(base_penalty * contextual_multiplier);
    return std::max(MIN_SCORE, current_score - penalty);
}
