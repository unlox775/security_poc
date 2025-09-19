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
            ("ce.amazonaws.com", "GetDimensionValues"),                     # ✅ Dimension values for cost analysis - public cost categories
            ("ce.amazonaws.com", "ListReports"),                            # ✅ Available cost reports - public report types
            ("ce.amazonaws.com", "GetCostCategories"),                      # ✅ Cost categorization - spending breakdown details (business info, not exploitable - should be safe read)
            ("ce.amazonaws.com", "GetTags"),                                # ✅ Cost tags - resource tagging for cost allocation (administrative info, not exploitable - should be safe read)
            
            # Free Tier - Usage information
            ("freetier.amazonaws.com", "GetFreeTierUsage"),                 # ✅ Free tier usage - free service consumption (account status info, not exploitable - should be safe read)
            
            # Cost Optimization Hub - Enrollment status (dashboard reads removed)
            
            # Compute Optimizer - Optimization recommendations (moved from misc)
            ("compute-optimizer.amazonaws.com", "GetEnrollmentStatus"),     # ✅ Optimization enrollment status - public service status
            
            # Billing - Account billing information
            ("billing.amazonaws.com", "ListBillingViews"),                  # ✅ Billing view options - public billing categories
            
            # Billing Console - Billing dashboard information
            ("billingconsole.amazonaws.com", "DescribeReportDefinitions"),  # ✅ Report definition details - public report formats
            ("billingconsole.amazonaws.com", "GetAccountEDPStatus"),        # ✅ Enterprise Discount Program status - public program status
            ("billingconsole.amazonaws.com", "GetBillsForBillingPeriod"),   # ✅ Bills for billing period - public billing history
            ("billingconsole.amazonaws.com", "GetCommercialInvoicesForBillingPeriod"), # ✅ Commercial invoices - public invoice data
            ("billingconsole.amazonaws.com", "GetCredits"),                 # ✅ Account credits - public credit balance
            ("billingconsole.amazonaws.com", "GetLegacyReportPreferences"), # ✅ Legacy report preferences - public report settings
            ("billingconsole.amazonaws.com", "GetPaymentPreferences"),      # ✅ Payment preferences - public payment settings
            ("billingconsole.amazonaws.com", "GetTotal"),                   # ✅ Total billing amount - public cost summary
            ("billingconsole.amazonaws.com", "ListRegions"),                # ✅ List regions - public region information
            ("billingconsole.amazonaws.com", "GetSellerOfRecord"),          # ✅ Seller of record - unusual billing entity information (business entity info, not exploitable - should be safe read)
            ("billingconsole.amazonaws.com", "GetBillingNotifications"),    # ✅ Billing notifications - unusual billing alert settings (notification preferences, not exploitable - should be safe read)
            
            # Map Credits - Location service billing
            ("mapcredits.amazonaws.com", "ListAssociatedPrograms"),         # ✅ Associated programs - public program associations

            # Budgets - Budget information
            ("budgets.amazonaws.com", "DescribeBudgets"),                   # ✅ Budget details - spending limits and targets (business planning info, not exploitable - should be safe read)
            ("budgets.amazonaws.com", "DescribeBudgetsForAccount"),         # ✅ Account budgets - budget inventory (business planning info, not exploitable - should be safe read)
        })
        
        # SENSITIVE_READ_ONLY: Cost operations that could expose sensitive financial information
        self.sensitive_read_only.update({
            # Cost Explorer - Detailed cost analysis
            ("ce.amazonaws.com", "GetAnomalies"),                           # ✅ Cost anomalies - unusual spending patterns
            ("ce.amazonaws.com", "GetAnomalyMonitors"),                     # ✅ Anomaly monitoring configs - cost alert settings
            ("ce.amazonaws.com", "GetConsoleActionSetEnforced"),            # ✅ Console action enforcement - cost control settings
            ("ce.amazonaws.com", "GetReservationUtilization"),              # ✅ Reservation usage - resource utilization patterns
            ("ce.amazonaws.com", "GetSavingsPlansUtilizationDetails"),      # ✅ Savings plan usage - cost optimization details
            ("ce.amazonaws.com", "GetUsageReport"),                         # ✅ Usage report data - detailed resource consumption (business intelligence, not classic reconnaissance - should be sensitive read)
            ("ce.amazonaws.com", "GetReservationCoverage"),                 # ✅ Reservation coverage - resource commitment analysis (business intelligence, not classic reconnaissance - should be sensitive read)
            
            # Billing Console - Account billing information
            ("billingconsole.amazonaws.com", "GetAccountInformation"),      # ✅ Account billing info - billing account details
            ("billingconsole.amazonaws.com", "GetContactInformation"),      # ✅ Contact information - billing contact details
            
            # Budgets - Budget information
            ("budgets.amazonaws.com", "DescribeBudgetNotificationsForAccount"), # ✅ Budget notifications - alert configurations
            ("budgets.amazonaws.com", "DescribeBudgetPerformanceHistory"),  # ✅ Budget performance - spending trend analysis
                        
            # Compute Optimizer - Optimization recommendations (moved from misc)
            ("compute-optimizer.amazonaws.com", "GetLambdaFunctionRecommendations"), # ✅ Lambda optimization - cost optimization suggestions
        })
        
        # SENSITIVE_WRITE: Billing operations that modify financial configurations
        self.sensitive_write.update({
            # Budgets - Budget modifications
            ("budgets.amazonaws.com", "CreateBudget"),                      # ✅ Create budget - spending limit creation
            ("budgets.amazonaws.com", "UpdateBudget"),                      # ✅ Update budget - spending limit modification
            ("budgets.amazonaws.com", "DeleteBudget"),                      # ✅ Delete budget - spending limit removal
            ("budgets.amazonaws.com", "CreateBudgetAction"),                # ✅ Create budget action - automated budget response
            ("budgets.amazonaws.com", "UpdateBudgetAction"),                # ✅ Update budget action - budget response modification
            ("budgets.amazonaws.com", "DeleteBudgetAction"),                # ✅ Delete budget action - budget response removal
            ("budgets.amazonaws.com", "ExecuteBudgetAction"),               # ✅ Execute budget action - trigger budget response
            
            # Cost Optimization Hub - Optimization actions
            ("cost-optimization-hub.amazonaws.com", "UpdateEnrollmentStatus"), # ✅ Update enrollment status - optimization participation change
            
            # Billing Console - Account modifications
            ("billingconsole.amazonaws.com", "UpdateAccountInformation"),   # ✅ Update account information - billing account modification
            ("billingconsole.amazonaws.com", "UpdateContactInformation"),   # ✅ Update contact information - billing contact modification
        })
        
        # HACKING_READS: Operations that could be used for financial reconnaissance
        self.hacking_reads.update({
            # Billing Console - Accessing sensitive billing data
            ("billingconsole.amazonaws.com", "GetBillingData"),             # ✅ Billing data - detailed financial information
            ("billingconsole.amazonaws.com", "GetPaymentMethods"),          # ✅ Payment methods - financial payment details
        })
        
        # STRANGE_READS: Unusual billing operations
        self.strange_reads.update({
            # Billing Console - Unusual billing operations
            ("billingconsole.amazonaws.com", "GetIAMAccessPreference"),     # ✅ IAM access preferences - unusual billing access control
            ("billingconsole.amazonaws.com", "GetPublicSectorCustomerContract"), # ✅ Public sector contract - unusual government billing info
        })
        
