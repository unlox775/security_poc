#!/usr/bin/env python3
"""
Integration tests for AWS CloudTrail Event Classifier.

These tests validate the classifier works with actual data files.

Author: AI Assistant
Date: 2025-01-27
"""

import unittest
import sys
import os
import pandas as pd

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from event_classifier import EventClassifier


class TestClassifierIntegration(unittest.TestCase):
    """Integration tests for the event classifier with real data."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.classifier = EventClassifier()
        
        # Paths to test data files (use fixtures if available, otherwise environment variables)
        self.dev_csv = os.environ.get('TEST_DEV_CSV', os.path.join(os.path.dirname(__file__), 'test_data', 'standard_format.csv'))
        self.prod_csv = os.environ.get('TEST_PROD_CSV', os.path.join(os.path.dirname(__file__), 'test_data', 'alternate_format.csv'))
    
    def test_classifier_imports(self):
        """Test that the classifier can be imported and initialized."""
        self.assertIsNotNone(self.classifier)
        self.assertIsNotNone(self.classifier.classifiers)
        self.assertIsNotNone(self.classifier.dashboard_reads)
    
    def test_classify_known_events(self):
        """Test classification of known events."""
        # Test some known events
        test_cases = [
            ("ec2.amazonaws.com", "DescribeRegions", "DASHBOARD_READS"),
            ("iam.amazonaws.com", "GetUser", "SENSITIVE_READ_ONLY"),
            ("s3.amazonaws.com", "ListBuckets", "SAFE_READ_ONLY"),
        ]
        
        for event_source, event_name, expected_class in test_cases:
            result = self.classifier.classify_event(event_source, event_name)
            self.assertEqual(result, expected_class, 
                           f"Expected {expected_class} for {event_source}:{event_name}, got {result}")
    
    def test_unclassified_events_are_detected(self):
        """Test that unclassified events are properly detected."""
        # Test with a made-up event that shouldn't be classified
        result = self.classifier.classify_event("fake-service.amazonaws.com", "FakeAction")
        self.assertEqual(result, "UNCLASSIFIED")
    
    def test_data_files_exist(self):
        """Test that the data files exist and can be read."""
        if os.path.exists(self.dev_csv):
            df = pd.read_csv(self.dev_csv)
            self.assertGreater(len(df), 0, "Dev CSV file is empty")
            # Test flexible column detection - should have either standard or alternate column names
            has_event_source = any(col in df.columns for col in ['eventSource', 'service', 'source'])
            has_event_name = any(col in df.columns for col in ['eventName', 'operation', 'action'])
            self.assertTrue(has_event_source, "Dev CSV missing event source column (eventSource/service/source)")
            self.assertTrue(has_event_name, "Dev CSV missing event name column (eventName/operation/action)")
        
        if os.path.exists(self.prod_csv):
            df = pd.read_csv(self.prod_csv)
            self.assertGreater(len(df), 0, "Prod CSV file is empty")
            # Test flexible column detection - should have either standard or alternate column names
            has_event_source = any(col in df.columns for col in ['eventSource', 'service', 'source'])
            has_event_name = any(col in df.columns for col in ['eventName', 'operation', 'action'])
            self.assertTrue(has_event_source, "Prod CSV missing event source column (eventSource/service/source)")
            self.assertTrue(has_event_name, "Prod CSV missing event name column (eventName/operation/action)")
    
    def test_classification_summary(self):
        """Test that classification summary works."""
        # Create some test events
        test_events = [
            ("ec2.amazonaws.com", "DescribeRegions"),
            ("iam.amazonaws.com", "GetUser"),
            ("s3.amazonaws.com", "ListBuckets"),
            ("fake-service.amazonaws.com", "FakeAction"),
        ]
        
        summary = self.classifier.get_classification_summary(test_events)
        
        # Check that summary contains expected categories
        expected_categories = ["SAFE_READ_ONLY", "SENSITIVE_READ_ONLY", "SENSITIVE_WRITE", 
                             "HACKING_READS", "STRANGE_READS", "INFRA_READS", "DASHBOARD_READS", "UNCLASSIFIED"]
        
        for category in expected_categories:
            self.assertIn(category, summary, f"Summary missing category: {category}")
        
        # Check that counts are non-negative
        for category, count in summary.items():
            self.assertGreaterEqual(count, 0, f"Negative count for {category}: {count}")
        
        # Check that total adds up
        total = sum(summary.values())
        self.assertEqual(total, len(test_events), 
                        f"Summary total {total} doesn't match event count {len(test_events)}")
    
    def test_unclassified_events_extraction(self):
        """Test that unclassified events are properly extracted."""
        # Create some test events with known classifications
        test_events = [
            ("ec2.amazonaws.com", "DescribeRegions"),  # Should be classified
            ("iam.amazonaws.com", "GetUser"),          # Should be classified
            ("fake-service.amazonaws.com", "FakeAction"),  # Should be unclassified
            ("another-fake.amazonaws.com", "AnotherFake"),  # Should be unclassified
        ]
        
        unclassified = self.classifier.get_unclassified_events(test_events)
        
        # Should contain the fake events
        fake_events = [
            ("fake-service.amazonaws.com", "FakeAction"),
            ("another-fake.amazonaws.com", "AnotherFake"),
        ]
        
        for fake_event in fake_events:
            self.assertIn(fake_event, unclassified, 
                         f"Expected unclassified event {fake_event} not found")
        
        # Should not contain the real events
        real_events = [
            ("ec2.amazonaws.com", "DescribeRegions"),
            ("iam.amazonaws.com", "GetUser"),
        ]
        
        for real_event in real_events:
            self.assertNotIn(real_event, unclassified, 
                           f"Real event {real_event} incorrectly marked as unclassified")


if __name__ == '__main__':
    unittest.main()
