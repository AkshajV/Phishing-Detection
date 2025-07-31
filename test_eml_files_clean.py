import pandas as pd
import numpy as np
import joblib
import email
import re
import os
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Import the custom classes from the separate file
from model_classes import SenderPatternFeatures, URLFeatureExtractor

def parse_eml_file(eml_path):
    """
    Parse an .eml file and extract the features needed for the model:
    - subject
    - body
    - sender
    - urls
    """
    try:
        with open(eml_path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f)
        
        # Extract subject
        subject = msg.get('subject', '')
        if subject is None:
            subject = ''
        
        # Extract sender
        sender = msg.get('from', '')
        if sender is None:
            sender = ''
        
        # Extract body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        body += str(part.get_payload())
        else:
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body = str(msg.get_payload())
        
        # Extract URLs from body and subject
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls_in_body = re.findall(url_pattern, body)
        urls_in_subject = re.findall(url_pattern, subject)
        all_urls = urls_in_body + urls_in_subject
        
        # Count URLs
        url_count = len(all_urls)
        
        return {
            'subject': subject,
            'body': body,
            'sender': sender,
            'urls': url_count
        }
    
    except Exception as e:
        print(f"Error parsing {eml_path}: {e}")
        return {
            'subject': '',
            'body': '',
            'sender': '',
            'urls': 0
        }

def test_eml_files():
    """
    Test all .eml files in the emails folder against the trained model
    """
    # Load the trained model
    print("Loading the trained model...")
    try:
        model = joblib.load("phishing_email_model_fixed.pkl")
        print("✓ Model loaded successfully!")
    except Exception as e:
        print(f"✗ Error loading model: {e}")
        return
    
    # Get all .eml files
    emails_dir = Path("emails")
    eml_files = list(emails_dir.glob("*.eml"))
    
    if not eml_files:
        print("No .eml files found in the emails directory!")
        return
    
    print(f"\nFound {len(eml_files)} .eml files to test:")
    for eml_file in eml_files:
        print(f"  - {eml_file.name}")
    
    # Parse and test each file
    results = []
    
    print(f"\n{'='*80}")
    print("TESTING EMAIL FILES")
    print(f"{'='*80}")
    
    for eml_file in eml_files:
        print(f"\n📧 Testing: {eml_file.name}")
        print("-" * 50)
        
        # Parse the email
        email_data = parse_eml_file(eml_file)
        
        # Create a DataFrame for prediction
        test_df = pd.DataFrame([email_data])
        
        # Make prediction
        try:
            prediction = model.predict(test_df)[0]
            prediction_proba = model.predict_proba(test_df)[0]
            
            # Get confidence scores
            confidence = max(prediction_proba)
            
            # Determine result
            result = "PHISHING" if prediction == 1 else "LEGITIMATE"
            confidence_pct = confidence * 100
            
            print(f"Subject: {email_data['subject'][:100]}{'...' if len(email_data['subject']) > 100 else ''}")
            print(f"Sender: {email_data['sender'][:100]}{'...' if len(email_data['sender']) > 100 else ''}")
            print(f"URLs found: {email_data['urls']}")
            print(f"Body length: {len(email_data['body'])} characters")
            print(f"Prediction: {result}")
            print(f"Confidence: {confidence_pct:.2f}%")
            
            # Store results
            results.append({
                'filename': eml_file.name,
                'subject': email_data['subject'],
                'sender': email_data['sender'],
                'urls': email_data['urls'],
                'body_length': len(email_data['body']),
                'prediction': result,
                'confidence': confidence_pct,
                'prediction_proba': prediction_proba
            })
            
        except Exception as e:
            print(f"✗ Error predicting: {e}")
            results.append({
                'filename': eml_file.name,
                'subject': email_data['subject'],
                'sender': email_data['sender'],
                'urls': email_data['urls'],
                'body_length': len(email_data['body']),
                'prediction': 'ERROR',
                'confidence': 0,
                'prediction_proba': [0, 0]
            })
    
    # Summary
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    
    results_df = pd.DataFrame(results)
    
    # Count predictions
    phishing_count = len(results_df[results_df['prediction'] == 'PHISHING'])
    legitimate_count = len(results_df[results_df['prediction'] == 'LEGITIMATE'])
    error_count = len(results_df[results_df['prediction'] == 'ERROR'])
    
    print(f"Total emails tested: {len(results_df)}")
    print(f"Predicted as PHISHING: {phishing_count}")
    print(f"Predicted as LEGITIMATE: {legitimate_count}")
    if error_count > 0:
        print(f"Errors: {error_count}")
    
    print(f"\nDetailed Results:")
    print(results_df[['filename', 'prediction', 'confidence', 'urls']].to_string(index=False))
    
    # Save results to CSV
    results_df.to_csv('eml_test_results.csv', index=False)
    print(f"\nResults saved to 'eml_test_results.csv'")
    
    return results_df

if __name__ == "__main__":
    test_eml_files() 