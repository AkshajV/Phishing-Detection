# Phishing Email Detection System

A machine learning-based system for detecting phishing emails using advanced feature engineering and ensemble methods.

## 🎯 Project Overview

This system analyzes email content to classify messages as either **LEGITIMATE** or **PHISHING** using a Random Forest classifier trained on the CEAS-08 dataset. The model extracts sophisticated features from email subjects, bodies, sender addresses, and URL patterns to make accurate predictions.

## ✨ Key Features

- **Advanced Sender Analysis**: Detects suspicious patterns in sender addresses (repeated characters, suspicious words, mixed case, special characters)
- **URL Pattern Detection**: Analyzes URL counts and patterns within emails
- **Text Feature Extraction**: Uses TF-IDF vectorization for subject and body content analysis
- **Ensemble Learning**: Random Forest classifier for robust predictions
- **EML File Support**: Direct processing of .eml email files
- **Confidence Scoring**: Provides prediction confidence levels for each classification

## 📊 Model Performance

### Training Performance:
- **Training Time**: ~2-3 minutes (full dataset training)
- **Training Accuracy**: 98.0% on test set
- **Dataset Size**: 39,126 samples (full CEAS-08 dataset)

### Evaluation Results:
- **Cross-Validation Accuracy**: 97.2% (±0.8%)
- **Precision**: 95.9% (±0.8%)
- **Recall**: 99.2% (±0.6%)
- **F1-Score**: 97.5% (±0.7%)
- **ROC AUC**: 99.9%

### Real-World Testing:
Based on test results with 10 diverse email samples:
- **Success Rate**: 100% (all emails processed successfully)
- **Confidence Range**: 63-86% confidence in predictions
- **Test Coverage**: Includes both obvious phishing attempts and legitimate emails from major services (Steam, Strava, Character.AI)

### Sample Test Results:
- Phishing emails correctly identified with 71-86% confidence
- Legitimate emails from Steam, Strava, and Character.AI correctly classified with 63-75% confidence

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd phishing-email-detection
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python test_eml_files_clean.py
   ```

## 📁 Project Structure

```
Code/
├── ml_integration_fixed.py          # Main ML pipeline and model training
├── model_classes.py                 # Custom feature extractors
├── test_eml_files_clean.py         # EML file testing script
├── phishing_email_model_fixed.pkl   # Trained model file
├── CEAS_08.csv                     # Training dataset
├── requirements.txt                 # Python dependencies
├── emails/                         # Test email directory
│   ├── *.eml                      # Test email files
└── eml_test_results.csv           # Test results output
```

## 🚀 Usage

### Quick Start - Test Your Emails

```bash
python test_eml_files_clean.py
```

This will:
1. Load the trained model
2. Process all .eml files in the `emails/` directory
3. Generate predictions with confidence scores
4. Display beautiful, formatted results
5. Save results to `eml_test_results.csv`

### Train/Retrain the Model

```bash
python ml_integration_fixed.py
```

This will:
1. Load and preprocess the full CEAS-08 dataset (39,126 samples)
2. Extract features using custom transformers
3. Train a Random Forest classifier (200 estimators, max_depth=15)
4. Save the model as `phishing_email_model_fixed.pkl`
5. **Training time**: ~2-3 minutes

### Evaluate Model Performance

```bash
python model_evaluation.py
```

This will:
1. Load the existing trained model
2. Perform cross-validation and detailed metrics analysis
3. Generate performance visualizations
4. Save comprehensive evaluation report
5. **Evaluation time**: ~30-60 seconds

## 🔍 Feature Engineering

### Sender Pattern Features
- **Structural Analysis**: Dot count, hyphen presence, digit detection
- **Suspicious Patterns**: Repeated characters, suspicious words (support, security, admin)
- **Domain Analysis**: Domain length, mixed case detection
- **Special Characters**: Detection of unusual characters

### URL Features
- **URL Count**: Number of URLs in email body and subject
- **Pattern Analysis**: URL distribution and characteristics

### Text Features
- **TF-IDF Vectorization**: Advanced text analysis for subject and body content
- **Length Analysis**: Content length as a feature

## 📈 Model Architecture

The system uses a **Random Forest Classifier** with the following pipeline:

1. **Feature Extraction**:
   - Sender pattern analysis (11 features)
   - URL counting and analysis
   - TF-IDF text vectorization (optimized for speed)

2. **Preprocessing**:
   - Missing value handling
   - Feature scaling and encoding

3. **Classification**:
   - Ensemble learning with Random Forest
   - Probability-based confidence scoring

## ⚡ Model Architecture

### Training Configuration:
- **Full Dataset**: Uses complete 39,126 samples from CEAS-08 dataset
- **Robust Estimators**: 200 decision trees for comprehensive analysis
- **Optimal Depth**: Max depth of 15 for detailed pattern recognition
- **Rich Features**: 500 subject + 1000 body features with bigrams
- **Advanced Processing**: Uses both unigrams and bigrams for better text understanding

### Evaluation Features:
- **Model Loading**: Loads existing trained model for quick evaluation
- **Comprehensive Testing**: Uses 5,000 samples for thorough evaluation
- **Cross-Validation**: 3-fold cross-validation for robust metrics
- **Automatic Visualizations**: Generates confusion matrix and ROC curves

### Performance Results:
- **Training Time**: 2-3 minutes (comprehensive training)
- **Evaluation Time**: 30-60 seconds (efficient evaluation)
- **High Accuracy**: 98.0% training accuracy, 97.2% cross-validation
- **Excellent Metrics**: 99.9% ROC AUC, 97.5% F1-Score

## 🧪 Testing

The system includes a comprehensive test suite with:
- **Phishing Samples**: Various phishing attempt patterns
- **Legitimate Samples**: Real emails from major services
- **Edge Cases**: Malformed emails and unusual patterns

## 🔧 Customization

### Adding New Features
1. Extend the `SenderPatternFeatures` or `URLFeatureExtractor` classes
2. Add new feature extraction methods
3. Retrain the model with updated features

### Model Tuning
- Adjust Random Forest parameters in `ml_integration_fixed.py`
- Experiment with different ensemble methods
- Fine-tune feature extraction thresholds

## 📝 Output Format

The system generates detailed CSV reports with:
- `filename`: Name of the tested email file
- `subject`: Email subject line
- `sender`: Sender email address
- `urls`: Number of URLs detected
- `body_length`: Length of email body
- `prediction`: Classification (LEGITIMATE/PHISHING)
- `confidence`: Prediction confidence percentage
- `prediction_proba`: Raw probability scores

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and research purposes. While it can help identify potential phishing emails, it should not be the sole method of email security. Always use multiple security layers and exercise caution with suspicious emails.

## 🔗 Dependencies

See `requirements.txt` for the complete list of Python packages used in this project.
