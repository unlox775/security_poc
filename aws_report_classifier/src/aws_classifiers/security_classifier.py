"""
Security and Compliance Services Event Classifier

Handles events from security, compliance, and access management services.
"""

from .base_classifier import BaseEventClassifier


class SecurityEventClassifier(BaseEventClassifier):
    """
    Classifier for security and compliance services.
    
    Handles:
    - access-analyzer
    - config
    - guardduty
    - securityhub
    - inspector
    - macie
    - trusted-advisor
    """
    
    def _initialize_rules(self):
        """Initialize classification rules for security services.
        
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
            "access-analyzer.amazonaws.com",   # Access Analyzer for policy analysis and access reviews
            "config.amazonaws.com",           # AWS Config for compliance monitoring and auditing
            "guardduty.amazonaws.com",        # GuardDuty for threat detection and security monitoring
            "securityhub.amazonaws.com",      # Security Hub for centralized security findings
            "inspector.amazonaws.com",        # Inspector for vulnerability assessments and security scanning
            "macie.amazonaws.com",           # Macie for data discovery and protection
            "trusted-advisor.amazonaws.com"  # Trusted Advisor for best practice recommendations
        }
        
        # SAFE_READ_ONLY: Basic security information that doesn't expose sensitive data
        self.safe_read_only.update({
            # Trusted Advisor - Basic advisor information
            ("trusted-advisor.amazonaws.com", "DescribeTrustedAdvisorCheckSummaries"),
            ("trusted-advisor.amazonaws.com", "DescribeTrustedAdvisorChecks"),
        })
        
        # SENSITIVE_READ_ONLY: Security operations that could expose sensitive information
        self.sensitive_read_only.update({
            # Access Analyzer - Access analysis
            ("access-analyzer.amazonaws.com", "ListAnalyzers"),
            ("access-analyzer.amazonaws.com", "GetAnalyzer"),
            ("access-analyzer.amazonaws.com", "GetFinding"),
            
            # Config - Configuration compliance
            ("config.amazonaws.com", "GetComplianceDetailsByConfigRule"),
            ("config.amazonaws.com", "GetComplianceDetailsByResource"),
            ("config.amazonaws.com", "GetComplianceSummaryByConfigRule"),
            ("config.amazonaws.com", "GetComplianceSummaryByResourceType"),
            ("config.amazonaws.com", "GetComplianceSummaryByResourceId"),
            ("config.amazonaws.com", "GetAggregateComplianceDetailsByConfigRule"),
            ("config.amazonaws.com", "GetAggregateComplianceSummaryByConfigRule"),
            ("config.amazonaws.com", "GetAggregateComplianceSummaryByResourceType"),
            ("config.amazonaws.com", "GetAggregateComplianceSummaryByResourceId"),
            ("config.amazonaws.com", "DescribePendingAggregationRequests"),
            
            # GuardDuty - Threat detection
            ("guardduty.amazonaws.com", "ListDetectors"),
            ("guardduty.amazonaws.com", "GetFindingsStatistics"),
            ("guardduty.amazonaws.com", "ListMembers"),
            ("guardduty.amazonaws.com", "GetMembers"),
            
            # Security Hub - Security findings
            ("securityhub.amazonaws.com", "GetInsights"),
            ("securityhub.amazonaws.com", "ListInsights"),
            ("securityhub.amazonaws.com", "GetMembers"),
            ("securityhub.amazonaws.com", "ListMembers"),
            
            # Inspector - Vulnerability assessment
            ("inspector.amazonaws.com", "ListAssessmentTargets"),
            ("inspector.amazonaws.com", "ListAssessmentTemplates"),
            ("inspector.amazonaws.com", "ListAssessmentRuns"),
            ("inspector.amazonaws.com", "DescribeAssessmentTargets"),
            ("inspector.amazonaws.com", "DescribeAssessmentTemplates"),
            ("inspector.amazonaws.com", "DescribeAssessmentRuns"),
            ("inspector.amazonaws.com", "ListFindings"),
            ("inspector.amazonaws.com", "DescribeFindings"),
            
            # Macie - Data discovery and classification
            ("macie.amazonaws.com", "ListS3Resources"),
            ("macie.amazonaws.com", "DescribeS3Resources"),
            ("macie.amazonaws.com", "ListMemberAccounts"),
            ("macie.amazonaws.com", "ListS3Resources"),
            
        })
        
        # SENSITIVE_WRITE: Security operations that modify configurations
        self.sensitive_write.update({
            # Access Analyzer - Access analysis configuration
            ("access-analyzer.amazonaws.com", "CreateAnalyzer"),
            ("access-analyzer.amazonaws.com", "DeleteAnalyzer"),
            ("access-analyzer.amazonaws.com", "StartPolicyGeneration"),
            ("access-analyzer.amazonaws.com", "CancelPolicyGeneration"),
            
            # Config - Configuration management
            ("config.amazonaws.com", "PutConfigurationRecorder"),
            ("config.amazonaws.com", "DeleteConfigurationRecorder"),
            ("config.amazonaws.com", "PutConfigRule"),
            ("config.amazonaws.com", "DeleteConfigRule"),
            ("config.amazonaws.com", "StartConfigRulesEvaluation"),
            ("config.amazonaws.com", "StopConfigRulesEvaluation"),
            
            # GuardDuty - Threat detection configuration
            ("guardduty.amazonaws.com", "CreateDetector"),
            ("guardduty.amazonaws.com", "DeleteDetector"),
            ("guardduty.amazonaws.com", "UpdateDetector"),
            ("guardduty.amazonaws.com", "CreateMembers"),
            ("guardduty.amazonaws.com", "DeleteMembers"),
            ("guardduty.amazonaws.com", "UpdateMembers"),
            
            # Security Hub - Security findings management
            ("securityhub.amazonaws.com", "CreateInsight"),
            ("securityhub.amazonaws.com", "DeleteInsight"),
            ("securityhub.amazonaws.com", "UpdateInsight"),
            ("securityhub.amazonaws.com", "CreateMembers"),
            ("securityhub.amazonaws.com", "DeleteMembers"),
            ("securityhub.amazonaws.com", "InviteMembers"),
            ("securityhub.amazonaws.com", "DisassociateMembers"),
            
            # Inspector - Vulnerability assessment configuration
            ("inspector.amazonaws.com", "CreateAssessmentTarget"),
            ("inspector.amazonaws.com", "DeleteAssessmentTarget"),
            ("inspector.amazonaws.com", "CreateAssessmentTemplate"),
            ("inspector.amazonaws.com", "DeleteAssessmentTemplate"),
            ("inspector.amazonaws.com", "StartAssessmentRun"),
            ("inspector.amazonaws.com", "StopAssessmentRun"),
            
            # Macie - Data discovery configuration
            ("macie.amazonaws.com", "AssociateS3Resources"),
            ("macie.amazonaws.com", "DisassociateS3Resources"),
            ("macie.amazonaws.com", "UpdateS3Resources"),
            
        })
        
        # HACKING_READS: Operations that could be used for security reconnaissance
        self.hacking_reads.update({
            # Access Analyzer - Policy analysis for privilege escalation
            ("access-analyzer.amazonaws.com", "ListPolicyGenerations"),
            ("access-analyzer.amazonaws.com", "GetPolicyGeneration"),
            
            # Config - Configuration reconnaissance
            ("config.amazonaws.com", "DescribeConfigurationRecorders"),
            ("config.amazonaws.com", "DescribeConfigRules"),
            ("config.amazonaws.com", "ListConfigurationRecorders"),
            
            # GuardDuty - Security posture analysis
            ("guardduty.amazonaws.com", "GetDetector"),
            ("guardduty.amazonaws.com", "ListFindings"),
            
            # Security Hub - Security findings analysis
            ("securityhub.amazonaws.com", "GetFindings"),
            ("securityhub.amazonaws.com", "ListFindings"),
        })
        
        # STRANGE_READS: Unusual security operations
        self.strange_reads.update({
            # Trusted Advisor - Unusual advisor checks
            ("trusted-advisor.amazonaws.com", "DescribeTrustedAdvisorCheckResult"),
        })
        
