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
        """Initialize classification rules for billing services."""
        self.handled_sources = {
            "ce.amazonaws.com",               # Cost Explorer for analyzing AWS spending patterns
            "billingconsole.amazonaws.com",   # Billing console for payment methods and invoices
            "budgets.amazonaws.com",          # Budget management for cost alerts and tracking
            "freetier.amazonaws.com",         # Free tier usage monitoring and limits
            "cost-optimization-hub.amazonaws.com", # Cost optimization hub for savings recommendations
            "compute-optimizer.amazonaws.com" # Compute optimizer for right-sizing recommendations
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
            ("billingconsole.amazonaws.com", "GetIAMAccessPreference"),
            ("billingconsole.amazonaws.com", "ListRegions"),
            ("billingconsole.amazonaws.com", "GetSellerOfRecord"),
            ("billingconsole.amazonaws.com", "GetPublicSectorCustomerContract"),
            ("billingconsole.amazonaws.com", "GetBillingNotifications"),
            
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
        
        # INFRA_READS: Infrastructure cost management
        self.infra_reads.update({
            # Cost Explorer - Infrastructure cost analysis
            ("ce.amazonaws.com", "GetDimensionValues"),
            ("ce.amazonaws.com", "ListReports"),
            
            # Cost Optimization Hub - Infrastructure optimization (dashboard reads removed)
            ("cost-optimization-hub.amazonaws.com", "GetPreferences"),
        })
