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
    print("🔍 Loading the trained model...")
    try:
        model = joblib.load("phishing_email_model_fixed.pkl")
        print("✅ Model loaded successfully!")
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return
    
    # Get all .eml files
    emails_dir = Path("emails")
    eml_files = list(emails_dir.glob("*.eml"))
    
    if not eml_files:
        print("❌ No .eml files found in the emails directory!")
        return
    
    print(f"\n📁 Found {len(eml_files)} .eml files to test:")
    for eml_file in eml_files:
        print(f"   📧 {eml_file.name}")
    
    # Parse and test each file
    results = []
    
    print(f"\n{'='*80}")
    print("🚀 TESTING EMAIL FILES")
    print(f"{'='*80}")
    
    for i, eml_file in enumerate(eml_files, 1):
        print(f"\n📧 Testing ({i}/{len(eml_files)}): {eml_file.name}")
        print("─" * 60)
        
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
            
            # Color-coded output based on prediction
            if result == "PHISHING":
                result_icon = "🚨"
                result_color = "RED"
            else:
                result_icon = "✅"
                result_color = "GREEN"
            
            # Format confidence level
            if confidence_pct >= 80:
                confidence_level = "HIGH"
            elif confidence_pct >= 60:
                confidence_level = "MEDIUM"
            else:
                confidence_level = "LOW"
            
            print(f"📋 Subject: {email_data['subject'][:80]}{'...' if len(email_data['subject']) > 80 else ''}")
            print(f"👤 Sender: {email_data['sender'][:60]}{'...' if len(email_data['sender']) > 60 else ''}")
            print(f"🔗 URLs found: {email_data['urls']}")
            print(f"📏 Body length: {len(email_data['body']):,} characters")
            print(f"🎯 Prediction: {result_icon} {result}")
            print(f"📊 Confidence: {confidence_pct:.1f}% ({confidence_level})")
            
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
            print(f"❌ Error predicting: {e}")
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
    
    # Summary with better formatting
    print(f"\n{'='*80}")
    print("📊 SUMMARY REPORT")
    print(f"{'='*80}")
    
    results_df = pd.DataFrame(results)
    
    # Count predictions
    phishing_count = len(results_df[results_df['prediction'] == 'PHISHING'])
    legitimate_count = len(results_df[results_df['prediction'] == 'LEGITIMATE'])
    error_count = len(results_df[results_df['prediction'] == 'ERROR'])
    
    print(f"📈 Total emails tested: {len(results_df)}")
    print(f"🚨 Predicted as PHISHING: {phishing_count}")
    print(f"✅ Predicted as LEGITIMATE: {legitimate_count}")
    if error_count > 0:
        print(f"❌ Errors: {error_count}")
    
    # Calculate success rate
    success_rate = ((len(results_df) - error_count) / len(results_df)) * 100
    print(f"📊 Success rate: {success_rate:.1f}%")
    
    # Show detailed results in a clean table
    print(f"\n📋 DETAILED RESULTS:")
    print("─" * 80)
    
    # Create a formatted table
    print(f"{'Filename':<30} {'Prediction':<12} {'Confidence':<12} {'URLs':<6}")
    print("─" * 80)
    
    for _, row in results_df.iterrows():
        filename = row['filename'][:28] + ".." if len(row['filename']) > 30 else row['filename']
        prediction = row['prediction']
        confidence = f"{row['confidence']:.1f}%" if row['confidence'] > 0 else "N/A"
        urls = row['urls']
        
        # Add icons based on prediction
        if prediction == "PHISHING":
            icon = "🚨"
        elif prediction == "LEGITIMATE":
            icon = "✅"
        else:
            icon = "❌"
        
        print(f"{filename:<30} {icon} {prediction:<10} {confidence:<12} {urls:<6}")
    
    # Save results to CSV
    results_df.to_csv('eml_test_results.csv', index=False)
    print(f"\n💾 Results saved to 'eml_test_results.csv'")
    
    # Final status
    if error_count == 0:
        print("🎉 All emails processed successfully!")
    else:
        print(f"⚠️  {error_count} email(s) had processing errors")
    
    return results_df

if __name__ == "__main__":
    test_eml_files() 