#!/usr/bin/env python3
"""
Tests for session clustering analysis with flexible CSV format support.

These tests validate that the session clustering tool works with different CSV formats
and properly detects columns.

Author: AI Assistant
Date: 2025-01-27
"""

import unittest
import sys
import os
import tempfile
import shutil
import pandas as pd

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from session_clustering_analysis import SessionClusteringAnalyzer


class TestSessionClustering(unittest.TestCase):
    """Test session clustering with different CSV formats."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = SessionClusteringAnalyzer(gap_hours=1)  # 1 hour gap for testing
        self.test_data_dir = os.path.join(os.path.dirname(__file__), 'test_data')
        self.temp_dir = None
    
    def tearDown(self):
        """Clean up temporary files."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_column_detection_standard_format(self):
        """Test column detection with standard CloudTrail format."""
        csv_file = os.path.join(self.test_data_dir, 'standard_format.csv')
        
        # Load the CSV
        df = pd.read_csv(csv_file)
        
        # Test column detection
        mapping = self.analyzer.detect_column_mapping(df)
        
        # Check that required columns are detected
        self.assertIn('eventTime', mapping)
        self.assertIn('eventSource', mapping)
        self.assertIn('eventName', mapping)
        
        # Check that optional columns are detected
        self.assertIn('userIdentity.type', mapping)
        self.assertIn('userIdentity.arn', mapping)
        self.assertIn('userIdentity.userName', mapping)
        self.assertIn('sourceIPAddress', mapping)
        self.assertIn('awsRegion', mapping)
        
        # Verify no anomalies for missing required columns
        required_anomalies = [a for a in self.analyzer.anomalies if 'Missing required columns' in a]
        self.assertEqual(len(required_anomalies), 0, f"Unexpected required column anomalies: {required_anomalies}")
    
    def test_column_detection_alternate_format(self):
        """Test column detection with alternate format."""
        csv_file = os.path.join(self.test_data_dir, 'alternate_format.csv')
        
        # Load the CSV
        df = pd.read_csv(csv_file)
        
        # Test column detection
        mapping = self.analyzer.detect_column_mapping(df)
        
        # Check that required columns are detected with alternate names
        self.assertIn('eventTime', mapping)
        self.assertEqual(mapping['eventTime'], 'timestamp')
        
        self.assertIn('eventSource', mapping)
        self.assertEqual(mapping['eventSource'], 'service')
        
        self.assertIn('eventName', mapping)
        self.assertEqual(mapping['eventName'], 'operation')
        
        # Check that optional columns are detected
        self.assertIn('userIdentity.type', mapping)
        self.assertEqual(mapping['userIdentity.type'], 'user_type')
        
        self.assertIn('userIdentity.arn', mapping)
        self.assertEqual(mapping['userIdentity.arn'], 'user_arn')
        
        self.assertIn('userIdentity.userName', mapping)
        self.assertEqual(mapping['userIdentity.userName'], 'user_name')
        
        self.assertIn('sourceIPAddress', mapping)
        self.assertEqual(mapping['sourceIPAddress'], 'ip')
        
        self.assertIn('awsRegion', mapping)
        self.assertEqual(mapping['awsRegion'], 'region')
        
        # Verify no anomalies for missing required columns
        required_anomalies = [a for a in self.analyzer.anomalies if 'Missing required columns' in a]
        self.assertEqual(len(required_anomalies), 0, f"Unexpected required column anomalies: {required_anomalies}")
    
    def test_column_detection_minimal_format(self):
        """Test column detection with minimal format (only required columns)."""
        csv_file = os.path.join(self.test_data_dir, 'minimal_format.csv')
        
        # Load the CSV
        df = pd.read_csv(csv_file)
        
        # Test column detection
        mapping = self.analyzer.detect_column_mapping(df)
        
        # Check that required columns are detected
        self.assertIn('eventTime', mapping)
        self.assertEqual(mapping['eventTime'], 'time')
        
        self.assertIn('eventSource', mapping)
        self.assertEqual(mapping['eventSource'], 'source')
        
        self.assertIn('eventName', mapping)
        self.assertEqual(mapping['eventName'], 'action')
        
        # Check that optional columns are NOT detected (which is fine)
        optional_columns = ['userIdentity.type', 'userIdentity.arn', 'userIdentity.userName', 
                           'sourceIPAddress', 'awsRegion']
        for col in optional_columns:
            self.assertNotIn(col, mapping, f"Optional column {col} should not be detected")
        
        # Verify no anomalies for missing required columns
        required_anomalies = [a for a in self.analyzer.anomalies if 'Missing required columns' in a]
        self.assertEqual(len(required_anomalies), 0, f"Unexpected required column anomalies: {required_anomalies}")
    
    def test_session_clustering_standard_format(self):
        """Test session clustering with standard format CSV."""
        csv_file = os.path.join(self.test_data_dir, 'standard_format.csv')
        
        # Create temp directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Load and process the data
        df = self.analyzer.load_single_csv_file(csv_file)
        
        # Verify data was loaded correctly
        self.assertGreater(len(df), 0, "No data loaded from CSV")
        self.assertIn('source_file', df.columns, "source_file column not added")
        
        # Test session identification
        sessions = self.analyzer.identify_sessions(df)
        
        # Should have at least one session
        self.assertGreater(len(sessions), 0, "No sessions identified")
        
        # All events should be in sessions
        total_events = sum(len(session) for session in sessions)
        self.assertEqual(total_events, len(df), "Session events don't match total events")
    
    def test_session_clustering_alternate_format(self):
        """Test session clustering with alternate format CSV."""
        csv_file = os.path.join(self.test_data_dir, 'alternate_format.csv')
        
        # Create temp directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Load and process the data
        df = self.analyzer.load_single_csv_file(csv_file)
        
        # Verify data was loaded correctly
        self.assertGreater(len(df), 0, "No data loaded from CSV")
        self.assertIn('source_file', df.columns, "source_file column not added")
        
        # Test session identification
        sessions = self.analyzer.identify_sessions(df)
        
        # Should have at least one session
        self.assertGreater(len(sessions), 0, "No sessions identified")
        
        # All events should be in sessions
        total_events = sum(len(session) for session in sessions)
        self.assertEqual(total_events, len(df), "Session events don't match total events")
    
    def test_session_clustering_minimal_format(self):
        """Test session clustering with minimal format CSV."""
        csv_file = os.path.join(self.test_data_dir, 'minimal_format.csv')
        
        # Create temp directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Load and process the data
        df = self.analyzer.load_single_csv_file(csv_file)
        
        # Verify data was loaded correctly
        self.assertGreater(len(df), 0, "No data loaded from CSV")
        self.assertIn('source_file', df.columns, "source_file column not added")
        
        # Test session identification
        sessions = self.analyzer.identify_sessions(df)
        
        # Should have at least one session
        self.assertGreater(len(sessions), 0, "No sessions identified")
        
        # All events should be in sessions
        total_events = sum(len(session) for session in sessions)
        self.assertEqual(total_events, len(df), "Session events don't match total events")
    
    def test_missing_required_columns(self):
        """Test behavior when required columns are missing."""
        # Create a CSV with missing required columns
        bad_data = {
            'wrong_time': ['2025-05-07T20:38:57Z'],
            'wrong_source': ['ec2.amazonaws.com'],
            'wrong_name': ['DescribeRegions']
        }
        
        # Create temp file
        self.temp_dir = tempfile.mkdtemp()
        bad_csv = os.path.join(self.temp_dir, 'bad_format.csv')
        
        df = pd.DataFrame(bad_data)
        df.to_csv(bad_csv, index=False)
        
        # Load the bad CSV
        df = pd.read_csv(bad_csv)
        
        # Test column detection
        mapping = self.analyzer.detect_column_mapping(df)
        
        # Should have anomalies for missing required columns
        required_anomalies = [a for a in self.analyzer.anomalies if 'Missing required columns' in a]
        self.assertGreater(len(required_anomalies), 0, "Should have anomalies for missing required columns")
        
        # Required columns should not be detected
        required_columns = ['eventTime', 'eventSource', 'eventName']
        for col in required_columns:
            self.assertNotIn(col, mapping, f"Required column {col} should not be detected")
    
    def test_get_column_helper(self):
        """Test the get_column helper method."""
        csv_file = os.path.join(self.test_data_dir, 'standard_format.csv')
        
        # Load the CSV
        df = pd.read_csv(csv_file)
        self.analyzer.detect_column_mapping(df)
        
        # Test getting existing columns
        event_time_col = self.analyzer.get_column(df, 'eventTime')
        self.assertEqual(event_time_col, 'eventTime')
        
        event_source_col = self.analyzer.get_column(df, 'eventSource')
        self.assertEqual(event_source_col, 'eventSource')
        
        # Test getting non-existent columns
        non_existent = self.analyzer.get_column(df, 'NonExistentColumn')
        self.assertIsNone(non_existent)


if __name__ == '__main__':
    unittest.main()
