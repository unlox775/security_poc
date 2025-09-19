"""
Billing and Cost Services Event Classifier

Handles events from billing, cost management, and financial services.
"""

from .base_classifier import BaseEventClassifier


class BillingEventClassifier(BaseEventClassifier):
    """
    Classifier for billing and cost services.
    
    Handles:
    - ce (Cost Explorer)
    - billingconsole
    - budgets
    - freetier
    - cost-optimization-hub
    """
    
    def _initialize_rules(self):
        """Initialize classification rules for billing services.
        
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
            "ce.amazonaws.com",               # Cost Explorer for analyzing AWS spending patterns
            "billingconsole.amazonaws.com",   # Billing console for payment methods and invoices
            "budgets.amazonaws.com",          # Budget management for cost alerts and tracking
            "freetier.amazonaws.com",         # Free tier usage monitoring and limits
            "cost-optimization-hub.amazonaws.com", # Cost optimization hub for savings recommendations
            "compute-optimizer.amazonaws.com", # Compute optimizer for right-sizing recommendations
            "billing.amazonaws.com",          # Billing service for account billing information
            "mapcredits.amazonaws.com"        # Map Credits for location service billing
        }
        
        # SAFE_READ_ONLY: Basic cost information that doesn't expose sensitive data
        self.safe_read_only.update({
            # Cost Explorer - Basic cost information (dashboard reads removed)
            ("ce.amazonaws.com", "GetDimensionValues"),
            ("ce.amazonaws.com", "ListReports"),
            
            # Free Tier - Account plan information (dashboard reads removed)
            
            # Cost Optimization Hub - Enrollment status (dashboard reads removed)
            
            # Compute Optimizer - Optimization recommendations (moved from misc)
            ("compute-optimizer.amazonaws.com", "GetEnrollmentStatus"),
            
            # Billing - Account billing information
            ("billing.amazonaws.com", "ListBillingViews"),
            
            # Billing Console - Billing dashboard information
            ("billingconsole.amazonaws.com", "DescribeReportDefinitions"),
            ("billingconsole.amazonaws.com", "GetAccountEDPStatus"),
            ("billingconsole.amazonaws.com", "GetBillsForBillingPeriod"),
            ("billingconsole.amazonaws.com", "GetCommercialInvoicesForBillingPeriod"),
            ("billingconsole.amazonaws.com", "GetCredits"),
            ("billingconsole.amazonaws.com", "GetLegacyReportPreferences"),
            ("billingconsole.amazonaws.com", "GetPaymentPreferences"),
            ("billingconsole.amazonaws.com", "GetTotal"),
            
            # Map Credits - Location service billing
            ("mapcredits.amazonaws.com", "ListAssociatedPrograms"),
        })
        
        # SENSITIVE_READ_ONLY: Cost operations that could expose sensitive financial information
        self.sensitive_read_only.update({
            # Cost Explorer - Detailed cost analysis
            ("ce.amazonaws.com", "GetAnomalies"),
            ("ce.amazonaws.com", "GetAnomalyMonitors"),
            ("ce.amazonaws.com", "GetConsoleActionSetEnforced"),
            ("ce.amazonaws.com", "GetCostCategories"),
            ("ce.amazonaws.com", "GetReservationUtilization"),
            ("ce.amazonaws.com", "GetSavingsPlansUtilizationDetails"),
            ("ce.amazonaws.com", "GetTags"),
            
            # Billing Console - Account billing information
            ("billingconsole.amazonaws.com", "GetAccountInformation"),
            ("billingconsole.amazonaws.com", "GetContactInformation"),
            
            # Budgets - Budget information
            ("budgets.amazonaws.com", "DescribeBudgets"),
            ("budgets.amazonaws.com", "DescribeBudgetNotificationsForAccount"),
            ("budgets.amazonaws.com", "DescribeBudgetPerformanceHistory"),
            ("budgets.amazonaws.com", "DescribeBudgetsForAccount"),
            
            # Free Tier - Usage information
            ("freetier.amazonaws.com", "GetFreeTierUsage"),
            
            # Compute Optimizer - Optimization recommendations (moved from misc)
            ("compute-optimizer.amazonaws.com", "GetLambdaFunctionRecommendations"),
        })
        
        # SENSITIVE_WRITE: Billing operations that modify financial configurations
        self.sensitive_write.update({
            # Budgets - Budget modifications
            ("budgets.amazonaws.com", "CreateBudget"),
            ("budgets.amazonaws.com", "UpdateBudget"),
            ("budgets.amazonaws.com", "DeleteBudget"),
            ("budgets.amazonaws.com", "CreateBudgetAction"),
            ("budgets.amazonaws.com", "UpdateBudgetAction"),
            ("budgets.amazonaws.com", "DeleteBudgetAction"),
            ("budgets.amazonaws.com", "ExecuteBudgetAction"),
            
            # Cost Optimization Hub - Optimization actions
            ("cost-optimization-hub.amazonaws.com", "UpdateEnrollmentStatus"),
            
            # Billing Console - Account modifications
            ("billingconsole.amazonaws.com", "UpdateAccountInformation"),
            ("billingconsole.amazonaws.com", "UpdateContactInformation"),
        })
        
        # HACKING_READS: Operations that could be used for financial reconnaissance
        self.hacking_reads.update({
            # Cost Explorer - Searching for sensitive cost patterns
            ("ce.amazonaws.com", "GetUsageReport"),
            ("ce.amazonaws.com", "GetReservationCoverage"),
            
            # Billing Console - Accessing sensitive billing data
            ("billingconsole.amazonaws.com", "GetBillingData"),
            ("billingconsole.amazonaws.com", "GetPaymentMethods"),
        })
        
        # STRANGE_READS: Unusual billing operations
        self.strange_reads.update({
            # Billing Console - Unusual billing operations
            ("billingconsole.amazonaws.com", "GetIAMAccessPreference"),
            ("billingconsole.amazonaws.com", "ListRegions"),
            ("billingconsole.amazonaws.com", "GetSellerOfRecord"),
            ("billingconsole.amazonaws.com", "GetPublicSectorCustomerContract"),
            ("billingconsole.amazonaws.com", "GetBillingNotifications"),
        })
        
