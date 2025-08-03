import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

# Load the dataset
df_dataset = pd.read_csv("CEAS_08.csv")

# Drop rows with missing values
df_dataset_clean = df_dataset.dropna(subset=["subject", "body", "urls", "label"])

print(f"📊 Using full dataset: {len(df_dataset_clean)} samples for training")

#Sender address pattern feature extractor
class SenderPatternFeatures(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        features = []
        for s in X:
            s = str(s)
            
            # Basic structural features
            num_dots = s.count('.')
            has_hyphen = int('-' in s)
            has_digits = int(any(char.isdigit() for char in s))
            length = len(s)
            at_count = s.count('@')
            starts_with_digit = int(s[0].isdigit()) if s else 0
            
            # Suspicious pattern features
            has_repeated_chars = int(self._has_repeated_characters(s))
            has_suspicious_words = int(self._has_suspicious_words(s))
            domain_length = self._get_domain_length(s)
            has_mixed_case = int(self._has_mixed_case(s))
            has_special_chars = int(self._has_special_characters(s))
            
            features.append([
                num_dots,
                has_hyphen,
                has_digits,
                length,
                at_count,
                starts_with_digit,
                has_repeated_chars,
                has_suspicious_words,
                domain_length,
                has_mixed_case,
                has_special_chars
            ])
        return np.array(features)
    
    def _has_repeated_characters(self, s):
        """Check for repeated characters like 'goooogle'"""
        for i in range(len(s) - 2):
            if s[i] == s[i+1] == s[i+2]:
                return True
        return False
    
    def _has_suspicious_words(self, s):
        """Check for suspicious words in sender address"""
        suspicious_words = ['support', 'security', 'admin', 'service', 'help', 'info', 'contact']
        s_lower = s.lower()
        return any(word in s_lower for word in suspicious_words)
    
    def _get_domain_length(self, s):
        """Get the length of the domain part"""
        if '@' in s:
            domain = s.split('@')[-1].split('>')[0]
            return len(domain)
        return 0
    
    def _has_mixed_case(self, s):
        """Check if sender has mixed case (suspicious)"""
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        return has_upper and has_lower
    
    def _has_special_characters(self, s):
        """Check for special characters beyond dots and hyphens"""
        special_chars = ['_', '+', '=', '!', '#', '$', '%', '&', '*', '(', ')']
        return any(char in s for char in special_chars)


#Transformer to extract URL patterns and count
class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self
    def transform(self, X):
        # Extract URL count and create features
        if hasattr(X, 'values'):
            url_counts = X.values.reshape(-1, 1)  # Handle pandas Series
        else:
            url_counts = X.reshape(-1, 1)  # Handle numpy array
        return url_counts

# Select input features and target - ADD SENDER BACK FOR PATTERN ANALYSIS
X = df_dataset_clean[["subject", "body", "sender", "urls"]]     # Added "sender" back for pattern analysis
y = df_dataset_clean["label"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y  # Added stratification for balanced split
)

print("=== FIXED MODEL - WITH SENDER PATTERN FEATURES ===")
print(f"Training set size: {len(X_train)}")
print(f"Test set size: {len(X_test)}")
print(f"Label distribution in training: {y_train.value_counts().to_dict()}")
print(f"Label distribution in test: {y_test.value_counts().to_dict()}")

print("\nSample training entries:")
print(X_train.head())

# Build the feature preprocessor - INCLUDING SENDER PATTERNS
preprocessor = ColumnTransformer(transformers=[
    ("subject_tfidf", TfidfVectorizer(
        stop_words='english', 
        max_features=500,  # Back to original features
        ngram_range=(1, 2),  # Use bigrams too
        min_df=2,  # Minimum document frequency
        max_df=0.95  # Maximum document frequency
    ), "subject"),
    ("body_tfidf", TfidfVectorizer(
        stop_words='english', 
        max_features=1000,  # Back to original features
        ngram_range=(1, 2),  # Use bigrams too
        min_df=2,
        max_df=0.95
    ), "body"),
    ("sender_patterns", SenderPatternFeatures(), "sender"),  # Add sender pattern features
    ("url_features", Pipeline([
        ("extract", URLFeatureExtractor()),
        ("encode", OneHotEncoder(handle_unknown='ignore'))
    ]), "urls")
])

# Build the full pipeline with better parameters
model_pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("classifier", RandomForestClassifier(
        n_estimators=200,  # Back to original parameters
        max_depth=15,  # Back to original depth
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42
    ))
])

print("\nTraining the model...")
# Train the model
model_pipeline.fit(X_train, y_train)

# Evaluate the model
y_pred = model_pipeline.predict(X_test)

print("\n=== REALISTIC RESULTS ===")
print("Accuracy: ", accuracy_score(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred, digits=4))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save the fixed model
joblib.dump(model_pipeline, "phishing_email_model_fixed.pkl")
print("\nModel saved as 'phishing_email_model_fixed.pkl'")

# Additional analysis
print("\n=== FEATURE IMPORTANCE ANALYSIS ===")
feature_names = []
for name, trans, cols in preprocessor.transformers_:
    if name == "url_features":
        # Custom handling for URLFeatureExtractor + OneHotEncoder
        # Get feature names from OneHotEncoder
        encoder = trans.named_steps["encode"]
        if hasattr(encoder, 'get_feature_names_out'):
            url_feature_names = encoder.get_feature_names_out(["urls"])
            feature_names.extend([f"url_features_{f}" for f in url_feature_names])
        else:
            feature_names.extend([f"url_features_{i}" for i in range(len(cols))])
    elif name == "sender_patterns":
        # Custom handling for SenderPatternFeatures
        sender_pattern_names = ["num_dots", "has_hyphen", "has_digits", "length", "at_count", "starts_with_digit", "has_repeated_chars", "has_suspicious_words", "domain_length", "has_mixed_case", "has_special_chars"]
        feature_names.extend([f"sender_patterns_{f}" for f in sender_pattern_names])
    elif hasattr(trans, 'get_feature_names_out'):
        feature_names.extend([f"{name}_{f}" for f in trans.get_feature_names_out()])
    else:
        feature_names.extend([f"{name}_{i}" for i in range(len(cols))])

# Get feature importance
if hasattr(model_pipeline.named_steps['classifier'], 'feature_importances_'):
    importances = model_pipeline.named_steps['classifier'].feature_importances_
    feature_importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': importances
    }).sort_values('importance', ascending=False)
    print("Top 10 most important features:")
    print(feature_importance_df.head(10))
    
    # Also show sender pattern features specifically
    sender_pattern_features = feature_importance_df[feature_importance_df['feature'].str.startswith('sender_patterns')]
    if not sender_pattern_features.empty:
        print("\nSender pattern features importance:")
        print(sender_pattern_features) 