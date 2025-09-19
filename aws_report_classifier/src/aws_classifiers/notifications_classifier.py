"""
Notifications and Communication Services Event Classifier

Handles events from notification services.
"""

from .base_classifier import BaseEventClassifier


class NotificationsEventClassifier(BaseEventClassifier):
    """
    Classifier for notification services.
    
    Handles:
    - notifications
    """
    
    def _initialize_rules(self):
        """Initialize classification rules for notification services."""
        self.handled_sources = {
            "notifications.amazonaws.com",   # AWS Notifications for account alerts and communications
            "schemas.amazonaws.com"         # Event schemas for event-driven applications
        }
        
        # SAFE_READ_ONLY: Basic notification information
        self.safe_read_only.update({
            # Notifications - Basic notification operations (dashboard reads removed)
        })
        
        # SENSITIVE_READ_ONLY: Notification operations that could expose sensitive information
        self.sensitive_read_only.update({
            # Notifications - Detailed notification information
            ("notifications.amazonaws.com", "GetNotificationEvent"),
            ("notifications.amazonaws.com", "GetNotificationHub"),
            
            # Schemas - Event schema information (moved from IAC)
            ("schemas.amazonaws.com", "DescribeSchema"),
        })
        
        # SENSITIVE_WRITE: Notification operations that modify configurations
        self.sensitive_write.update({
            # Notifications - Notification configuration changes
            ("notifications.amazonaws.com", "CreateNotificationHub"),
            ("notifications.amazonaws.com", "DeleteNotificationHub"),
            ("notifications.amazonaws.com", "UpdateNotificationHub"),
            ("notifications.amazonaws.com", "OptInFeature"),
            ("notifications.amazonaws.com", "OptOutFeature"),
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance
        self.hacking_reads.update({
            # Notifications - Searching for sensitive notification patterns
            ("notifications.amazonaws.com", "SearchNotificationEvents"),
        })
        
        # STRANGE_READS: Unusual notification operations
        self.strange_reads.update({
            # Notifications - Unusual operations
            ("notifications.amazonaws.com", "GetNotificationPreferences"),
        })
        
        # INFRA_READS: Infrastructure notification management
        self.infra_reads.update({
            # Notifications - Infrastructure notification setup
            ("notifications.amazonaws.com", "ListNotificationChannels"),
            ("notifications.amazonaws.com", "GetNotificationChannel"),
        })
