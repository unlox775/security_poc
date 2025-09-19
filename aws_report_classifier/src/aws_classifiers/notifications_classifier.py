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
        """Initialize classification rules for notification services.
        
        Classification Guidelines:
        
        SAFE_READ_ONLY: Operations that expose fundamentally public or harmless information.
        - No external references that could be exploited
        - Information that would be safe if publicly accessible
        - Examples: availability zones, regions, basic account attributes
        
        SENSITIVE_READ_ONLY: Operations that expose information useful for exploitation.
        - Reading reveals exploitable details (IP addresses, security rules, etc.)
        - Information that enables direct connection or attack vectors
        - Examples: security groups with IP addresses, instance details with public IPs
        
        HACKING_READS: Classic reconnaissance operations for gaining exploitation intel.
        - Standard penetration testing activities
        - Gathering information to enable later exploitation
        - Examples: enumerating security groups, finding public instances, backup configs
        
        SENSITIVE_WRITE: Operations that modify or create resources.
        - Any operation that changes system state
        - Examples: creating instances, modifying configurations
        """
        self.handled_sources = {
            "notifications.amazonaws.com",   # AWS Notifications for account alerts and communications
            "schemas.amazonaws.com",        # Event schemas for event-driven applications
            "sns.amazonaws.com"             # Simple Notification Service for messaging
        }
        
        # SAFE_READ_ONLY: Basic notification information
        self.safe_read_only.update({
            # Notifications - Basic notification operations (dashboard reads removed)
            
            # SNS - Topic and subscription information
            ("sns.amazonaws.com", "ListTopics"),
            ("sns.amazonaws.com", "ListSubscriptions"),
            ("sns.amazonaws.com", "ListSubscriptionsByTopic"),
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
        
