"""
Base Event Classifier Class

This is the base class that all service-specific classifiers inherit from.
It defines the standard classification buckets and provides common functionality.
"""

from abc import ABC, abstractmethod
from typing import Set, Tuple, List, Dict


class BaseEventClassifier(ABC):
    """
    Base class for AWS event classification.
    
    Each service-specific classifier should inherit from this class and implement
    the _initialize_rules() method to define events for each classification bucket.
    """
    
    def __init__(self):
        """Initialize all classification buckets as empty sets."""
        # Standard classification buckets
        self.safe_read_only = set()      # Low-risk read operations
        self.sensitive_read_only = set() # Read operations that could expose sensitive data
        self.sensitive_write = set()     # Operations that modify resources
        self.hacking_reads = set()       # Pen testing/discovery activities
        self.strange_reads = set()       # Odd/unusual read operations
        
        # Service-specific event sources this classifier handles
        self.handled_sources = set()
        
        # Initialize the classification rules
        self._initialize_rules()
        
        # Validate the configuration
        self._validate_configuration()
    
    @abstractmethod
    def _initialize_rules(self):
        """
        Initialize classification rules for this service.
        
        This method should:
        1. Define self.handled_sources with the AWS services this classifier handles
        2. Populate the classification sets with (event_source, event_name) tuples
        
        Example:
            self.handled_sources = {"ec2.amazonaws.com", "lambda.amazonaws.com"}
            self.safe_read_only.update({
                ("ec2.amazonaws.com", "DescribeRegions"),
                ("lambda.amazonaws.com", "ListFunctions20150331")
            })
        """
        pass
    
    def _validate_configuration(self):
        """Validate that the configuration is correct."""
        # Check that handled_sources is defined
        if not self.handled_sources:
            raise ValueError(f"{self.__class__.__name__}: handled_sources must be defined")
        
        # Check that event sources match handled_sources
        all_events = (self.safe_read_only | self.sensitive_read_only | 
                     self.sensitive_write | self.hacking_reads | 
                     self.strange_reads)
        
        for event_source, _ in all_events:
            if event_source not in self.handled_sources:
                raise ValueError(f"{self.__class__.__name__}: Event source {event_source} not in handled_sources")
    
    def get_all_events(self) -> Set[Tuple[str, str]]:
        """Get all events defined by this classifier."""
        return (self.safe_read_only | self.sensitive_read_only | 
                self.sensitive_write | self.hacking_reads | 
                self.strange_reads)
    
    def get_classification_summary(self) -> Dict[str, int]:
        """Get a summary of event counts by classification."""
        return {
            "SAFE_READ_ONLY": len(self.safe_read_only),
            "SENSITIVE_READ_ONLY": len(self.sensitive_read_only),
            "SENSITIVE_WRITE": len(self.sensitive_write),
            "HACKING_READS": len(self.hacking_reads),
            "STRANGE_READS": len(self.strange_reads)
        }
    
    def classify_event(self, event_source: str, event_name: str) -> str:
        """
        Classify an event based on the rules defined by this classifier.
        
        Returns the classification or "UNCLASSIFIED" if not found.
        """
        # Normalize the event source
        normalized_source = event_source.replace('.amazonaws.com', '') + '.amazonaws.com'
        event_key = (normalized_source, event_name)
        
        # Check each category in order
        if event_key in self.safe_read_only:
            return "SAFE_READ_ONLY"
        elif event_key in self.sensitive_read_only:
            return "SENSITIVE_READ_ONLY"
        elif event_key in self.sensitive_write:
            return "SENSITIVE_WRITE"
        elif event_key in self.hacking_reads:
            return "HACKING_READS"
        elif event_key in self.strange_reads:
            return "STRANGE_READS"
        else:
            return "UNCLASSIFIED"
    
    def handles_source(self, event_source: str) -> bool:
        """Check if this classifier handles the given event source."""
        normalized_source = event_source.replace('.amazonaws.com', '') + '.amazonaws.com'
        return normalized_source in self.handled_sources
    
    def get_unclassified_events(self, events: List[Tuple[str, str]]) -> Set[Tuple[str, str]]:
        """Get events that are not classified by this classifier."""
        unclassified = set()
        for event_source, event_name in events:
            if self.handles_source(event_source) and self.classify_event(event_source, event_name) == "UNCLASSIFIED":
                unclassified.add((event_source, event_name))
        return unclassified
