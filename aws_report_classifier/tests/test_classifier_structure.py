#!/usr/bin/env python3
"""
Unit tests for AWS CloudTrail Event Classifier structure and consistency.

These tests validate the internal structure and consistency of the classifier
without requiring actual data files.

Author: AI Assistant
Date: 2025-01-27
"""

import unittest
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from event_classifier import EventClassifier
from aws_classifiers.base_classifier import BaseEventClassifier


class TestClassifierStructure(unittest.TestCase):
    """Test the basic structure and consistency of the event classifier."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.classifier = EventClassifier()
    
    def test_classifier_initialization(self):
        """Test that the classifier initializes properly."""
        self.assertIsInstance(self.classifier, EventClassifier)
        self.assertIsNotNone(self.classifier.classifiers)
        self.assertIsNotNone(self.classifier.dashboard_reads)
        self.assertGreater(len(self.classifier.classifiers), 0)
        self.assertGreater(len(self.classifier.dashboard_reads), 0)
    
    def test_no_duplicate_handled_sources(self):
        """Test that no service is handled by multiple classifiers."""
        all_sources = {}
        
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            for source in service_classifier.handled_sources:
                if source in all_sources:
                    self.fail(f"Source {source} is handled by both {all_sources[source]} and {classifier_name}")
                all_sources[source] = classifier_name
    
    def test_no_duplicate_events_within_classifiers(self):
        """Test that no events appear multiple times within the same classifier."""
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            
            # Collect all events from all categories
            all_events = set()
            all_events.update(service_classifier.safe_read_only)
            all_events.update(service_classifier.sensitive_read_only)
            all_events.update(service_classifier.sensitive_write)
            all_events.update(service_classifier.hacking_reads)
            all_events.update(service_classifier.strange_reads)
            all_events.update(service_classifier.infra_reads)
            
            # Check for duplicates
            event_counts = {}
            for event in all_events:
                if event in event_counts:
                    event_counts[event] += 1
                else:
                    event_counts[event] = 1
            
            duplicates = {event: count for event, count in event_counts.items() if count > 1}
            if duplicates:
                for event, count in duplicates.items():
                    source, name = event
                    service = source.replace('.amazonaws.com', '')
                    self.fail(f"Event {service}:{name} appears {count} times in {classifier_name}")
    
    def test_events_match_handled_sources(self):
        """Test that all events belong to sources listed in handled_sources."""
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            
            # Collect all events from all categories
            all_events = set()
            all_events.update(service_classifier.safe_read_only)
            all_events.update(service_classifier.sensitive_read_only)
            all_events.update(service_classifier.sensitive_write)
            all_events.update(service_classifier.hacking_reads)
            all_events.update(service_classifier.strange_reads)
            all_events.update(service_classifier.infra_reads)
            
            # Check each event's source against handled_sources
            for event_source, event_name in all_events:
                if event_source not in service_classifier.handled_sources:
                    service = event_source.replace('.amazonaws.com', '')
                    self.fail(f"Event {service}:{event_name} in {classifier_name} has source not in handled_sources")
    
    def test_dashboard_reads_not_in_service_classifiers(self):
        """Test that dashboard reads events are not also classified in service classifiers."""
        for dashboard_event in self.classifier.dashboard_reads:
            dashboard_source, dashboard_name = dashboard_event
            
            for service_classifier in self.classifier.classifiers:
                classifier_name = service_classifier.__class__.__name__
                service_classification = service_classifier.classify_event(dashboard_source, dashboard_name)
                
                if service_classification and service_classification != 'UNCLASSIFIED':
                    service = dashboard_source.replace('.amazonaws.com', '')
                    self.fail(f"Dashboard event {service}:{dashboard_name} is also classified as {service_classification} in {classifier_name}")
    
    def test_all_classifiers_inherit_base(self):
        """Test that all service classifiers inherit from BaseEventClassifier."""
        for service_classifier in self.classifier.classifiers:
            self.assertIsInstance(service_classifier, BaseEventClassifier)
    
    def test_classifier_has_required_methods(self):
        """Test that all classifiers have required methods."""
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            
            # Check for required attributes
            required_attrs = ['safe_read_only', 'sensitive_read_only', 'sensitive_write', 
                            'hacking_reads', 'strange_reads', 'infra_reads', 'handled_sources']
            for attr in required_attrs:
                self.assertTrue(hasattr(service_classifier, attr), 
                              f"{classifier_name} missing attribute: {attr}")
            
            # Check for required methods
            self.assertTrue(hasattr(service_classifier, 'classify_event'), 
                          f"{classifier_name} missing method: classify_event")
    
    def test_classification_categories_are_sets(self):
        """Test that all classification categories are sets."""
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            
            categories = ['safe_read_only', 'sensitive_read_only', 'sensitive_write', 
                         'hacking_reads', 'strange_reads', 'infra_reads', 'handled_sources']
            
            for category in categories:
                category_value = getattr(service_classifier, category)
                self.assertIsInstance(category_value, set, 
                                    f"{classifier_name}.{category} is not a set")
    
    def test_handled_sources_format(self):
        """Test that handled_sources have the correct format."""
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            
            for source in service_classifier.handled_sources:
                self.assertTrue(source.endswith('.amazonaws.com'), 
                              f"{classifier_name} has invalid source format: {source}")
    
    def test_event_tuples_format(self):
        """Test that events are properly formatted as tuples."""
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            
            categories = ['safe_read_only', 'sensitive_read_only', 'sensitive_write', 
                         'hacking_reads', 'strange_reads', 'infra_reads']
            
            for category in categories:
                category_value = getattr(service_classifier, category)
                for event in category_value:
                    self.assertIsInstance(event, tuple, 
                                        f"{classifier_name}.{category} contains non-tuple: {event}")
                    self.assertEqual(len(event), 2, 
                                   f"{classifier_name}.{category} has invalid tuple length: {event}")
                    
                    event_source, event_name = event
                    self.assertIsInstance(event_source, str, 
                                        f"{classifier_name}.{category} has non-string source: {event_source}")
                    self.assertIsInstance(event_name, str, 
                                        f"{classifier_name}.{category} has non-string name: {event_name}")
                    
                    self.assertTrue(event_source.endswith('.amazonaws.com'), 
                                  f"{classifier_name}.{category} has invalid source format: {event_source}")


if __name__ == '__main__':
    unittest.main()
