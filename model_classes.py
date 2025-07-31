import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

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