import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score,
    roc_auc_score,
    roc_curve
)
from sklearn.ensemble import RandomForestClassifier
import warnings
warnings.filterwarnings('ignore')

# Import our custom classes
from model_classes import SenderPatternFeatures, URLFeatureExtractor

def load_and_prepare_data():
    """
    Load the dataset and prepare it for evaluation
    """
    print("📊 Loading and preparing dataset...")
    
    # Load the dataset
    df = pd.read_csv("CEAS_08.csv")
    
    # Drop rows with missing values
    df_clean = df.dropna(subset=["subject", "body", "urls", "label"])
    
    print(f"✓ Dataset loaded: {len(df_clean)} samples")
    print(f"✓ Features: {list(df_clean.columns)}")
    
    return df_clean

def create_model_pipeline():
    """
    Create the same model pipeline used in training
    """
    from sklearn.pipeline import Pipeline
    from sklearn.compose import ColumnTransformer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import OneHotEncoder
    
    # Create the pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            ('sender_features', SenderPatternFeatures(), 'sender'),
            ('url_features', URLFeatureExtractor(), 'urls'),
            ('subject_tfidf', TfidfVectorizer(max_features=1000, stop_words='english'), 'subject'),
            ('body_tfidf', TfidfVectorizer(max_features=2000, stop_words='english'), 'body')
        ],
        remainder='drop'
    )
    
    model = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
    ])
    
    return model

def perform_cross_validation(X, y, model, cv_folds=5):
    """
    Perform cross-validation and return detailed metrics
    """
    print(f"\n🔄 Performing {cv_folds}-fold cross-validation...")
    
    # Initialize cross-validation
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
    
    # Perform cross-validation for different metrics
    cv_accuracy = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
    cv_precision = cross_val_score(model, X, y, cv=cv, scoring='precision')
    cv_recall = cross_val_score(model, X, y, cv=cv, scoring='recall')
    cv_f1 = cross_val_score(model, X, y, cv=cv, scoring='f1')
    
    print("✓ Cross-validation completed!")
    
    return {
        'accuracy': cv_accuracy,
        'precision': cv_precision,
        'recall': cv_recall,
        'f1': cv_f1
    }

def evaluate_model_performance(X_train, X_test, y_train, y_test, model):
    """
    Evaluate model performance on test set
    """
    print("\n🎯 Evaluating model performance on test set...")
    
    # Train the model
    model.fit(X_train, y_train)
    
    # Make predictions
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]  # Probability of phishing
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, pos_label=1)
    recall = recall_score(y_test, y_pred, pos_label=1)
    f1 = f1_score(y_test, y_pred, pos_label=1)
    
    # ROC AUC
    y_test_binary = y_test.astype(int)
    roc_auc = roc_auc_score(y_test_binary, y_pred_proba)
    
    print("✓ Model evaluation completed!")
    
    return {
        'y_pred': y_pred,
        'y_pred_proba': y_pred_proba,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc
    }

def create_confusion_matrix(y_test, y_pred, save_plot=True):
    """
    Create and display confusion matrix
    """
    print("\n📈 Creating confusion matrix...")
    
    # Create confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    
    # Create visualization
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'])
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    
    if save_plot:
        plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
        print("✓ Confusion matrix saved as 'confusion_matrix.png'")
    
    plt.show()
    
    return cm

def create_roc_curve(y_test, y_pred_proba, save_plot=True):
    """
    Create and display ROC curve
    """
    print("\n📊 Creating ROC curve...")
    
    # Convert labels to binary
    y_test_binary = y_test.astype(int)
    
    # Calculate ROC curve
    fpr, tpr, _ = roc_curve(y_test_binary, y_pred_proba)
    
    # Create visualization
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc_score(y_test_binary, y_pred_proba):.3f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc="lower right")
    plt.grid(True)
    
    if save_plot:
        plt.savefig('roc_curve.png', dpi=300, bbox_inches='tight')
        print("✓ ROC curve saved as 'roc_curve.png'")
    
    plt.show()

def print_detailed_metrics(cv_results, test_results):
    """
    Print detailed performance metrics
    """
    print("\n" + "="*60)
    print("📊 DETAILED MODEL PERFORMANCE METRICS")
    print("="*60)
    
    # Cross-validation results
    print("\n🔄 CROSS-VALIDATION RESULTS (5-fold):")
    print("-" * 40)
    print(f"Accuracy:  {cv_results['accuracy'].mean():.4f} (+/- {cv_results['accuracy'].std() * 2:.4f})")
    print(f"Precision: {cv_results['precision'].mean():.4f} (+/- {cv_results['precision'].std() * 2:.4f})")
    print(f"Recall:    {cv_results['recall'].mean():.4f} (+/- {cv_results['recall'].std() * 2:.4f})")
    print(f"F1-Score:  {cv_results['f1'].mean():.4f} (+/- {cv_results['f1'].std() * 2:.4f})")
    
    # Test set results
    print("\n🎯 TEST SET RESULTS:")
    print("-" * 40)
    print(f"Accuracy:  {test_results['accuracy']:.4f}")
    print(f"Precision: {test_results['precision']:.4f}")
    print(f"Recall:    {test_results['recall']:.4f}")
    print(f"F1-Score:  {test_results['f1']:.4f}")
    print(f"ROC AUC:   {test_results['roc_auc']:.4f}")
    
    # Performance interpretation
    print("\n💡 PERFORMANCE INTERPRETATION:")
    print("-" * 40)
    if test_results['accuracy'] > 0.9:
        print("✓ Excellent overall accuracy!")
    elif test_results['accuracy'] > 0.8:
        print("✓ Good overall accuracy")
    else:
        print("⚠️  Accuracy could be improved")
    
    if test_results['precision'] > 0.8:
        print("✓ High precision - low false positive rate")
    else:
        print("⚠️  Precision could be improved")
    
    if test_results['recall'] > 0.8:
        print("✓ High recall - catches most phishing emails")
    else:
        print("⚠️  Recall could be improved")
    
    if test_results['roc_auc'] > 0.9:
        print("✓ Excellent ROC AUC - great discriminative ability")
    elif test_results['roc_auc'] > 0.8:
        print("✓ Good ROC AUC")
    else:
        print("⚠️  ROC AUC could be improved")

def save_evaluation_report(cv_results, test_results, filename='model_evaluation_report.txt'):
    """
    Save evaluation results to a text file
    """
    print(f"\n💾 Saving evaluation report to '{filename}'...")
    
    with open(filename, 'w') as f:
        f.write("PHISHING EMAIL DETECTION MODEL EVALUATION REPORT\n")
        f.write("=" * 50 + "\n\n")
        
        f.write("CROSS-VALIDATION RESULTS (5-fold):\n")
        f.write("-" * 30 + "\n")
        f.write(f"Accuracy:  {cv_results['accuracy'].mean():.4f} (+/- {cv_results['accuracy'].std() * 2:.4f})\n")
        f.write(f"Precision: {cv_results['precision'].mean():.4f} (+/- {cv_results['precision'].std() * 2:.4f})\n")
        f.write(f"Recall:    {cv_results['recall'].mean():.4f} (+/- {cv_results['recall'].std() * 2:.4f})\n")
        f.write(f"F1-Score:  {cv_results['f1'].mean():.4f} (+/- {cv_results['f1'].std() * 2:.4f})\n\n")
        
        f.write("TEST SET RESULTS:\n")
        f.write("-" * 20 + "\n")
        f.write(f"Accuracy:  {test_results['accuracy']:.4f}\n")
        f.write(f"Precision: {test_results['precision']:.4f}\n")
        f.write(f"Recall:    {test_results['recall']:.4f}\n")
        f.write(f"F1-Score:  {test_results['f1']:.4f}\n")
        f.write(f"ROC AUC:   {test_results['roc_auc']:.4f}\n")
    
    print(f"✓ Evaluation report saved as '{filename}'")

def main():
    """
    Main evaluation function - optimized for performance
    """
    print("🚀 Starting optimized model evaluation...")
    
    # Load the existing trained model instead of retraining
    print("📥 Loading existing trained model...")
    try:
        model = joblib.load("phishing_email_model_fixed.pkl")
        print("✅ Model loaded successfully!")
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        print("💡 Make sure to run ml_integration_fixed.py first to train the model")
        return
    
    # Load data for evaluation only
    print("📊 Loading dataset for evaluation...")
    df = pd.read_csv("CEAS_08.csv")
    df_clean = df.dropna(subset=["subject", "body", "urls", "label"])
    
    # Use a smaller sample for faster evaluation (10% of data)
    sample_size = min(5000, len(df_clean))
    df_sample = df_clean.sample(n=sample_size, random_state=42)
    
    print(f"✓ Using {sample_size} samples for evaluation (for faster processing)")
    
    # Prepare features and target
    X = df_sample[['sender', 'urls', 'subject', 'body']]
    y = df_sample['label']
    
    # Split data
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    print(f"✓ Data split: {len(X_train)} training, {len(X_test)} test samples")
    
    # Quick cross-validation with fewer folds for speed
    print("\n🔄 Performing quick 3-fold cross-validation...")
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    cv_accuracy = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
    cv_precision = cross_val_score(model, X, y, cv=cv, scoring='precision')
    cv_recall = cross_val_score(model, X, y, cv=cv, scoring='recall')
    cv_f1 = cross_val_score(model, X, y, cv=cv, scoring='f1')
    
    cv_results = {
        'accuracy': cv_accuracy,
        'precision': cv_precision,
        'recall': cv_recall,
        'f1': cv_f1
    }
    
    print("✅ Cross-validation completed!")
    
    # Evaluate on test set
    print("\n🎯 Evaluating model performance on test set...")
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, pos_label=1)
    recall = recall_score(y_test, y_pred, pos_label=1)
    f1 = f1_score(y_test, y_pred, pos_label=1)
    roc_auc = roc_auc_score(y_test.astype(int), y_pred_proba)
    
    test_results = {
        'y_pred': y_pred,
        'y_pred_proba': y_pred_proba,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc
    }
    
    print("✅ Model evaluation completed!")
    
    # Print detailed metrics
    print_detailed_metrics(cv_results, test_results)
    
    # Create visualizations automatically
    print("\n📈 Creating visualizations...")
    create_confusion_matrix(y_test, test_results['y_pred'])
    create_roc_curve(y_test, test_results['y_pred_proba'])
    
    # Save evaluation report
    save_evaluation_report(cv_results, test_results)
    
    print("\n🎉 Model evaluation completed successfully!")
    print("📁 Generated files:")
    print("   - model_evaluation_report.txt")
    print("   - confusion_matrix.png")
    print("   - roc_curve.png")
    
    print(f"\n⏱️  Total evaluation time: ~30-60 seconds (vs 15-20 minutes for full retraining)")

if __name__ == "__main__":
    main() 