import json
import os
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

# 1. Setup NLP engine (spaCy)
provider = NlpEngineProvider(nlp_configuration={
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_md"}]
})
nlp_engine = provider.create_engine()

# 2. Load Custom Patterns from JSON
def load_patterns_from_json():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pattern_path = os.path.join(base_dir, "..", "Security", "patterns.json")
    
    try:
        with open(pattern_path, 'r') as f:
            data = json.load(f)
            patterns = data.get("patterns", [])
            print(f"✅ SUCCESS: Loaded {len(patterns)} custom patterns from {pattern_path}")
            return patterns
    except FileNotFoundError:
        print(f"❌ ERROR: Could not find patterns file at {pattern_path}")
        return []
    except json.JSONDecodeError:
        print(f"❌ ERROR: patterns.json is not valid JSON.")
        return []

# 3. Initialize Analyzer
analyzer = AnalyzerEngine(nlp_engine = nlp_engine, supported_languages = ["en"])

# 4. Register Custom Recognizers
custom_patterns_data = load_patterns_from_json()

for p in custom_patterns_data:
    score_map = {"CRITICAL": 0.95, "HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.4}
    confidence = score_map.get(p.get("risk_level", "MEDIUM"), 0.6)

    regex_pattern = f"(?i){p['regex']}"

    # The Presidio Pattern object
    pattern_obj = Pattern(
        name = p["id"], 
        regex = regex_pattern, 
        score = confidence
    )

    # Create the Recognizer
    recognizer = PatternRecognizer(
        supported_entity = p["id"],     # This becomes the 'entity_type' in results
        patterns = [pattern_obj],
        name = f"{p['id']}_recognizer"
    )

    # Add to the analyzer's registry
    analyzer.registry.add_recognizer(recognizer)

# 5. Analysis Function
def analyze_text(text: str):
    '''
    Analyzes text using both default Presidio recognizers 
    AND the custom patterns loaded from JSON.
    '''
    results = analyzer.analyze(text=text, language="en")

    # Filter out low-score noise from default recognizers
    filtered_results = []
    for r in results:
        # Check if this result matches one of our custom IDs
        custom_match = next((item for item in custom_patterns_data if item["id"] == r.entity_type), None)

        if custom_match:
            # It is a custom match
            filtered_results.append({
                "entity_type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": r.score,
                "risk_level": custom_match['risk_level']
            })
        else:
            # It is a default Presidio match (like that False Positive Bank Number)
            # Only keep if score is very high, otherwise ignore noise
            if r.score > 0.4:
                filtered_results.append({
                    "entity_type": r.entity_type,
                    "start": r.start,
                    "end": r.end,
                    "score": r.score,
                    "risk_level": "UNKNOWN" 
                })

    return filtered_results

# Quick test block (only runs if this file is executed directly)
if __name__ == "__main__":
    test_prompt = "Here is our API key: sk-test-123456789, store it safely"
    print(f"Testing: {test_prompt}")
    print(analyze_text(test_prompt))