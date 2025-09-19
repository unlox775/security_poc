#!/usr/bin/env python3
"""
AWS CloudTrail Event Data Analyzer

This script analyzes AWS CloudTrail events from CSV files to identify
unclassified events and provide classification recommendations.

Usage:
    python3 analyze_data.py --dev-csv path/to/dev.csv --prod-csv path/to/prod.csv

Author: AI Assistant
Date: 2025-01-27
"""

import argparse
import pandas as pd
import os
import sys
from collections import Counter
from event_classifier import EventClassifier


def load_and_combine_data(dev_file, prod_file):
    """
    Load and combine data from dev and prod CSV files
    
    Args:
        dev_file (str): Path to dev CSV file
        prod_file (str): Path to prod CSV file
        
    Returns:
        pd.DataFrame: Combined dataframe
    """
    print(f"Loading data from {dev_file} and {prod_file}...")
    
    # Check if files exist
    if not os.path.exists(dev_file):
        raise FileNotFoundError(f"Dev CSV file not found: {dev_file}")
    if not os.path.exists(prod_file):
        raise FileNotFoundError(f"Prod CSV file not found: {prod_file}")
    
    # Load dev data
    dev_df = pd.read_csv(dev_file)
    dev_df['source_file'] = 'dev'
    
    # Load prod data  
    prod_df = pd.read_csv(prod_file)
    prod_df['source_file'] = 'prod'
    
    # Combine dataframes
    combined_df = pd.concat([dev_df, prod_df], ignore_index=True)
    
    print(f"Loaded {len(dev_df)} dev events and {len(prod_df)} prod events")
    print(f"Total events: {len(combined_df)}")
    
    return combined_df


def analyze_event_classifications(df, classifier):
    """
    Analyze event classifications using the EventClassifier
    
    Args:
        df (pd.DataFrame): Combined dataframe with events
        classifier (EventClassifier): The event classifier
    """
    print(f"\n" + "="*80)
    print("DATA ANALYSIS - EVENT CLASSIFICATION RESULTS")
    print("="*80)
    
    # Convert eventTime to datetime if not already
    if not pd.api.types.is_datetime64_any_dtype(df['eventTime']):
        df['eventTime'] = pd.to_datetime(df['eventTime'])
    
    # Get unique event combinations
    event_combinations = df[['eventSource', 'eventName']].drop_duplicates()
    event_combinations = [(row['eventSource'], row['eventName']) for _, row in event_combinations.iterrows()]
    
    print(f"\nTotal unique event types: {len(event_combinations)}")
    
    # Get classification summary
    summary = classifier.get_classification_summary(event_combinations)
    
    print(f"\nClassification Summary:")
    print("-" * 40)
    for category, count in summary.items():
        percentage = (count / len(event_combinations)) * 100
        print(f"{category:<20}: {count:>4} events ({percentage:>5.1f}%)")
    
    # Get unclassified events
    unclassified = classifier.get_unclassified_events(event_combinations)
    
    print(f"\n📋 UNCLASSIFIED EVENTS ({len(unclassified)} total):")
    print("-" * 80)
    
    if unclassified:
        # Sort unclassified events for easier review
        sorted_unclassified = sorted(unclassified, key=lambda x: (x[0], x[1]))
        
        # Group by service for easier reading and count distinct dates
        by_service = {}
        for event_source, event_name in sorted_unclassified:
            service = event_source.replace('.amazonaws.com', '')
            if service not in by_service:
                by_service[service] = []
            
            # Count distinct dates for this event
            event_data = df[(df['eventSource'] == event_source) & (df['eventName'] == event_name)]
            distinct_dates = event_data['eventTime'].dt.date.nunique()
            total_occurrences = len(event_data)
            
            by_service[service].append((event_name, distinct_dates, total_occurrences))
        
        for service in sorted(by_service.keys()):
            print(f"\n{service}:")
            for event_name, distinct_dates, total_occurrences in sorted(by_service[service]):
                print(f"  - {event_name} ({distinct_dates} days, {total_occurrences} occurrences)")
    else:
        print("✅ All events have been classified!")
    
    # Show some examples of classified events
    print(f"\n📊 CLASSIFIED EVENTS SAMPLE:")
    print("-" * 80)
    
    # Show examples from each category
    for category in ["SAFE_READ_ONLY", "SENSITIVE_READ_ONLY", "SENSITIVE_WRITE", "HACKING_READS", "STRANGE_READS", "INFRA_READS", "DASHBOARD_READS"]:
        print(f"\n{category} Examples:")
        count = 0
        for event_source, event_name in event_combinations:
            if classifier.classify_event(event_source, event_name) == category and count < 5:
                service = event_source.replace('.amazonaws.com', '')
                print(f"  - {service}: {event_name}")
                count += 1
    
    # Analyze by source file
    print(f"\n📈 CLASSIFICATION BY SOURCE FILE:")
    print("-" * 80)
    
    for source_file in ['dev', 'prod']:
        source_events = df[df['source_file'] == source_file][['eventSource', 'eventName']].drop_duplicates()
        source_event_list = [(row['eventSource'], row['eventName']) for _, row in source_events.iterrows()]
        source_summary = classifier.get_classification_summary(source_event_list)
        
        print(f"\n{source_file.upper()} Events:")
        for category, count in source_summary.items():
            percentage = (count / len(source_event_list)) * 100 if len(source_event_list) > 0 else 0
            print(f"  {category:<20}: {count:>4} events ({percentage:>5.1f}%)")
    
    return unclassified


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Analyze AWS CloudTrail events from CSV files')
    parser.add_argument('--dev-csv', required=True, help='Path to dev CSV file')
    parser.add_argument('--prod-csv', required=True, help='Path to prod CSV file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Load data
        combined_df = load_and_combine_data(args.dev_csv, args.prod_csv)
        
        # Initialize classifier
        classifier = EventClassifier()
        
        # Run data analysis
        unclassified = analyze_event_classifications(combined_df, classifier)
        
        print(f"\n" + "="*80)
        print("DATA ANALYSIS COMPLETE")
        print("="*80)
        
        if unclassified:
            print(f"\nNext steps:")
            print(f"1. Review the {len(unclassified)} unclassified events above")
            print(f"2. Add rules to event_classifier.py for events that need classification")
            print(f"3. Run 'make audit' to check classifier structure")
            print(f"4. Re-run this script to verify classifications")
        else:
            print(f"\n✅ All events are now classified!")
            print(f"Consider reviewing the classifications to ensure they're accurate.")
        
        print(f"\n💡 To audit classifier structure, run: make audit")
        
        return 0 if len(unclassified) == 0 else 1
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
