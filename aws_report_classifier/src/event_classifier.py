"""
Main Event Classifier

This is the main entry point for AWS CloudTrail event classification.
It uses modular service-specific classifiers and maintains the DASHBOARD_READS category.
"""

from typing import List, Tuple, Set, Dict
from aws_classifiers.base_classifier import BaseEventClassifier
from aws_classifiers.monitoring_classifier import MonitoringEventClassifier
from aws_classifiers.compute_classifier import ComputeEventClassifier
from aws_classifiers.billing_classifier import BillingEventClassifier
from aws_classifiers.identity_classifier import IdentityEventClassifier
from aws_classifiers.iac_classifier import IACEventClassifier
from aws_classifiers.networking_classifier import NetworkingEventClassifier
from aws_classifiers.simple_storage_classifier import SimpleStorageEventClassifier
from aws_classifiers.structured_storage_classifier import StructuredStorageEventClassifier
from aws_classifiers.notifications_classifier import NotificationsEventClassifier
from aws_classifiers.security_classifier import SecurityEventClassifier


class EventClassifier:
    """
    Main AWS CloudTrail event classifier.
    
    This class coordinates multiple service-specific classifiers and maintains
    the DASHBOARD_READS category for high-frequency dashboard components.
    """
    
    def __init__(self):
        """Initialize the main classifier with all service-specific classifiers."""
        # Initialize all service-specific classifiers
        self.classifiers = [
            MonitoringEventClassifier(),
            ComputeEventClassifier(),
            BillingEventClassifier(),
            IdentityEventClassifier(),
            IACEventClassifier(),
            NetworkingEventClassifier(),
            SimpleStorageEventClassifier(),
            StructuredStorageEventClassifier(),
            NotificationsEventClassifier(),
            SecurityEventClassifier()
        ]
        
        # DASHBOARD_READS: High-frequency dashboard components (maintained centrally)
        self.dashboard_reads = {
            # High-frequency events that appear on dashboard loads
            ("notifications.amazonaws.com", "ListNotificationEvents"),
            ("notifications.amazonaws.com", "GetFeatureOptInStatus"),
            ("notifications.amazonaws.com", "ListNotificationHubs"),
            ("ec2.amazonaws.com", "DescribeRegions"),
            ("ce.amazonaws.com", "GetCostAndUsage"),
            ("ce.amazonaws.com", "GetCostForecast"),
            ("health.amazonaws.com", "DescribeEventAggregates"),
            ("cost-optimization-hub.amazonaws.com", "ListEnrollmentStatuses"),
            ("servicecatalog-appregistry.amazonaws.com", "ListApplications"),
            ("organizations.amazonaws.com", "DescribeOrganization"),
            ("cloudformation.amazonaws.com", "DescribeStacks"),
            ("monitoring.amazonaws.com", "DescribeAlarms"),
            ("freetier.amazonaws.com", "GetAccountPlanState"),
            
            # UX Color - Dashboard UI customization (moved from misc)
            ("uxc.amazonaws.com", "GetAccountColor"),
        }
        
        # Validate all classifiers
        self._validate_classifiers()
    
    def _validate_classifiers(self):
        """Validate that all classifiers are properly configured and don't overlap."""
        # Check for overlapping event sources
        all_sources = set()
        for classifier in self.classifiers:
            for source in classifier.handled_sources:
                if source in all_sources:
                    raise ValueError(f"Event source {source} is handled by multiple classifiers")
                all_sources.add(source)
    
    def classify_event(self, event_source: str, event_name: str) -> str:
        """Classify an AWS CloudTrail event based on its source and name."""
        # Normalize the event source
        normalized_source = event_source.replace('.amazonaws.com', '') + '.amazonaws.com'
        event_key = (normalized_source, event_name)
        
        # Check dashboard reads first (highest priority)
        if event_key in self.dashboard_reads:
            return "DASHBOARD_READS"
        
        # Check each service-specific classifier
        for classifier in self.classifiers:
            if classifier.handles_source(event_source):
                classification = classifier.classify_event(event_source, event_name)
                if classification != "UNCLASSIFIED":
                    return classification
        
        return "UNCLASSIFIED"
    
    def get_unclassified_events(self, events: List[Tuple[str, str]]) -> Set[Tuple[str, str]]:
        """Get events that are not classified by any classifier."""
        unclassified = set()
        for event_source, event_name in events:
            if self.classify_event(event_source, event_name) == "UNCLASSIFIED":
                unclassified.add((event_source, event_name))
        return unclassified
    
    def get_classification_summary(self, events: List[Tuple[str, str]]) -> Dict[str, int]:
        """Get counts of events per classification category."""
        summary = {
            "SAFE_READ_ONLY": 0,
            "SENSITIVE_READ_ONLY": 0,
            "SENSITIVE_WRITE": 0,
            "HACKING_READS": 0,
            "STRANGE_READS": 0,
            "INFRA_READS": 0,
            "DASHBOARD_READS": 0,
            "UNCLASSIFIED": 0
        }
        
        for event_source, event_name in events:
            classification = self.classify_event(event_source, event_name)
            summary[classification] += 1
        
        return summary