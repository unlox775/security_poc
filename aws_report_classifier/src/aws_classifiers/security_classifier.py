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
        })
        
        # SENSITIVE_READ_ONLY: Security operations that could expose sensitive information
        self.sensitive_read_only.update({
            # Trusted Advisor - Basic advisor information
            ("trusted-advisor.amazonaws.com", "DescribeTrustedAdvisorCheckSummaries"), # ✅ Trusted Advisor summaries - security best practice summaries
            ("trusted-advisor.amazonaws.com", "DescribeTrustedAdvisorChecks"),         # ✅ Trusted Advisor checks - security best practice checks

            # Config - Configuration compliance
            ("config.amazonaws.com", "GetComplianceDetailsByConfigRule"),     # ✅ Compliance details by rule - configuration compliance analysis
            ("config.amazonaws.com", "GetComplianceDetailsByResource"),       # ✅ Compliance details by resource - resource compliance analysis
            ("config.amazonaws.com", "GetComplianceSummaryByConfigRule"),     # ✅ Compliance summary by rule - rule compliance summary
            ("config.amazonaws.com", "GetComplianceSummaryByResourceType"),   # ✅ Compliance summary by type - resource type compliance summary
            ("config.amazonaws.com", "GetComplianceSummaryByResourceId"),     # ✅ Compliance summary by ID - resource compliance summary
            ("config.amazonaws.com", "GetAggregateComplianceDetailsByConfigRule"), # ✅ Aggregate compliance details - multi-account compliance analysis
            ("config.amazonaws.com", "GetAggregateComplianceSummaryByConfigRule"), # ✅ Aggregate compliance summary - multi-account compliance summary
            ("config.amazonaws.com", "GetAggregateComplianceSummaryByResourceType"), # ✅ Aggregate compliance summary by type - multi-account resource type summary
            ("config.amazonaws.com", "GetAggregateComplianceSummaryByResourceId"), # ✅ Aggregate compliance summary by ID - multi-account resource summary
            ("config.amazonaws.com", "DescribePendingAggregationRequests"),   # ✅ Pending aggregation requests - multi-account aggregation status            
        })
        
        # SENSITIVE_WRITE: Security operations that modify configurations
        self.sensitive_write.update({
            # Access Analyzer - Access analysis configuration
            ("access-analyzer.amazonaws.com", "CreateAnalyzer"),             # ✅ Create analyzer - access analysis setup
            ("access-analyzer.amazonaws.com", "DeleteAnalyzer"),             # ✅ Delete analyzer - access analysis removal
            ("access-analyzer.amazonaws.com", "StartPolicyGeneration"),      # ✅ Start policy generation - access policy analysis initiation
            ("access-analyzer.amazonaws.com", "CancelPolicyGeneration"),     # ✅ Cancel policy generation - access policy analysis termination
            
            # Config - Configuration management
            ("config.amazonaws.com", "PutConfigurationRecorder"),            # ✅ Put configuration recorder - configuration tracking setup
            ("config.amazonaws.com", "DeleteConfigurationRecorder"),         # ✅ Delete configuration recorder - configuration tracking removal
            ("config.amazonaws.com", "PutConfigRule"),                       # ✅ Put config rule - compliance rule creation
            ("config.amazonaws.com", "DeleteConfigRule"),                    # ✅ Delete config rule - compliance rule removal
            ("config.amazonaws.com", "StartConfigRulesEvaluation"),          # ✅ Start config rules evaluation - compliance evaluation initiation
            ("config.amazonaws.com", "StopConfigRulesEvaluation"),           # ✅ Stop config rules evaluation - compliance evaluation termination
            
            # GuardDuty - Threat detection configuration
            ("guardduty.amazonaws.com", "CreateDetector"),                   # ✅ Create detector - threat detection setup
            ("guardduty.amazonaws.com", "DeleteDetector"),                   # ✅ Delete detector - threat detection removal
            ("guardduty.amazonaws.com", "UpdateDetector"),                   # ✅ Update detector - threat detection modification
            ("guardduty.amazonaws.com", "CreateMembers"),                    # ✅ Create members - GuardDuty member setup
            ("guardduty.amazonaws.com", "DeleteMembers"),                    # ✅ Delete members - GuardDuty member removal
            ("guardduty.amazonaws.com", "UpdateMembers"),                    # ✅ Update members - GuardDuty member modification
            
            # Security Hub - Security findings management
            ("securityhub.amazonaws.com", "CreateInsight"),                  # ✅ Create insight - security insight creation
            ("securityhub.amazonaws.com", "DeleteInsight"),                  # ✅ Delete insight - security insight removal
            ("securityhub.amazonaws.com", "UpdateInsight"),                  # ✅ Update insight - security insight modification
            ("securityhub.amazonaws.com", "CreateMembers"),                  # ✅ Create members - Security Hub member setup
            ("securityhub.amazonaws.com", "DeleteMembers"),                  # ✅ Delete members - Security Hub member removal
            ("securityhub.amazonaws.com", "InviteMembers"),                  # ✅ Invite members - Security Hub member invitation
            ("securityhub.amazonaws.com", "DisassociateMembers"),            # ✅ Disassociate members - Security Hub member disassociation
            
            # Inspector - Vulnerability assessment configuration
            ("inspector.amazonaws.com", "CreateAssessmentTarget"),           # ✅ Create assessment target - vulnerability assessment target creation
            ("inspector.amazonaws.com", "DeleteAssessmentTarget"),           # ✅ Delete assessment target - vulnerability assessment target removal
            ("inspector.amazonaws.com", "CreateAssessmentTemplate"),         # ✅ Create assessment template - vulnerability assessment template creation
            ("inspector.amazonaws.com", "DeleteAssessmentTemplate"),         # ✅ Delete assessment template - vulnerability assessment template removal
            ("inspector.amazonaws.com", "StartAssessmentRun"),               # ✅ Start assessment run - vulnerability assessment run initiation
            ("inspector.amazonaws.com", "StopAssessmentRun"),                # ✅ Stop assessment run - vulnerability assessment run termination
            
            # Macie - Data discovery configuration
            ("macie.amazonaws.com", "AssociateS3Resources"),                 # ✅ Associate S3 resources - data discovery S3 resource association
            ("macie.amazonaws.com", "DisassociateS3Resources"),              # ✅ Disassociate S3 resources - data discovery S3 resource disassociation
            ("macie.amazonaws.com", "UpdateS3Resources"),                    # ✅ Update S3 resources - data discovery S3 resource modification
            
        })
        
        # HACKING_READS: Operations that could be used for security reconnaissance
        self.hacking_reads.update({
            # Access Analyzer - Access analysis
            ("access-analyzer.amazonaws.com", "ListAnalyzers"),               # ✅ Analyzers - access analyzer inventory (administrative inventory, not exploitable - should be safe read)
            ("access-analyzer.amazonaws.com", "GetAnalyzer"),                 # ✅ Analyzer details - access analyzer configuration
            ("access-analyzer.amazonaws.com", "GetFinding"),                  # ✅ Finding details - access vulnerability findings (should be hacking reads)
            ("access-analyzer.amazonaws.com", "ListPolicyGenerations"),       # ✅ Policy generations - access policy analysis reconnaissance
            ("access-analyzer.amazonaws.com", "GetPolicyGeneration"),         # ✅ Policy generation details - access policy analysis details
            
            # GuardDuty - Threat detection
            ("guardduty.amazonaws.com", "ListDetectors"),                     # ✅ Detectors - threat detection inventory (administrative inventory, not exploitable - should be safe read)
            ("guardduty.amazonaws.com", "GetFindingsStatistics"),             # ✅ Findings statistics - threat detection statistics
            ("guardduty.amazonaws.com", "ListMembers"),                       # ✅ Members - GuardDuty member inventory (administrative inventory, not exploitable - should be safe read)
            ("guardduty.amazonaws.com", "GetMembers"),                        # ✅ Member details - GuardDuty member configuration
            ("guardduty.amazonaws.com", "GetDetector"),                      # ✅ Detector details - threat detection configuration analysis
            ("guardduty.amazonaws.com", "ListFindings"),                     # ✅ Threat findings - security threat findings (should be hacking reads)
            
            # Security Hub - Security findings
            ("securityhub.amazonaws.com", "GetInsights"),                     # ✅ Security insights - security finding insights
            ("securityhub.amazonaws.com", "ListInsights"),                    # ✅ Security insights - security insight inventory (administrative inventory, not exploitable - should be safe read)
            ("securityhub.amazonaws.com", "GetMembers"),                      # ✅ Security Hub members - security hub member configuration
            ("securityhub.amazonaws.com", "ListMembers"),                     # ✅ Security Hub members - security hub member inventory (administrative inventory, not exploitable - should be safe read)
            ("securityhub.amazonaws.com", "GetFindings"),                    # ✅ Security findings - security finding analysis (should be hacking reads)
            ("securityhub.amazonaws.com", "ListFindings"),                   # ✅ Security findings - security finding reconnaissance (should be hacking reads)

            # Trusted Advisor - Security best practice checks
            ("trusted-advisor.amazonaws.com", "DescribeTrustedAdvisorCheckResult"), # ✅ Trusted Advisor results - security best practice check results

            # Inspector - Vulnerability assessment
            ("inspector.amazonaws.com", "ListAssessmentTargets"),             # ✅ Assessment targets - vulnerability assessment target inventory (administrative inventory, not exploitable - should be safe read)
            ("inspector.amazonaws.com", "ListAssessmentTemplates"),           # ✅ Assessment templates - vulnerability assessment template inventory (administrative inventory, not exploitable - should be safe read)
            ("inspector.amazonaws.com", "ListAssessmentRuns"),                # ✅ Assessment runs - vulnerability assessment run inventory (administrative inventory, not exploitable - should be safe read)
            ("inspector.amazonaws.com", "DescribeAssessmentTargets"),         # ✅ Assessment target details - vulnerability assessment target configuration
            ("inspector.amazonaws.com", "DescribeAssessmentTemplates"),       # ✅ Assessment template details - vulnerability assessment template configuration
            ("inspector.amazonaws.com", "DescribeAssessmentRuns"),            # ✅ Assessment run details - vulnerability assessment run configuration
            ("inspector.amazonaws.com", "ListFindings"),                      # ✅ Vulnerability findings - security vulnerability findings (should be hacking reads)
            ("inspector.amazonaws.com", "DescribeFindings"),                  # ✅ Finding details - security vulnerability analysis (should be hacking reads)
            
            # Macie - Data discovery and classification
            ("macie.amazonaws.com", "ListS3Resources"),                       # ✅ S3 resources - data discovery and classification findings (should be hacking reads)
            ("macie.amazonaws.com", "DescribeS3Resources"),                   # ✅ S3 resource details - data discovery and classification analysis (should be hacking reads)
            ("macie.amazonaws.com", "ListMemberAccounts"),                    # ✅ Member accounts - Macie member inventory (administrative inventory, not exploitable - should be safe read)
            ("macie.amazonaws.com", "ListS3Resources"),                       # ✅ S3 resources - data discovery and classification findings (should be hacking reads)

            # Config - Configuration reconnaissance
            ("config.amazonaws.com", "DescribeConfigurationRecorders"),       # ✅ Configuration recorders - configuration tracking reconnaissance
            ("config.amazonaws.com", "DescribeConfigRules"),                 # ✅ Configuration rules - compliance rule reconnaissance
            ("config.amazonaws.com", "ListConfigurationRecorders"),          # ✅ Configuration recorders - configuration tracking inventory (administrative inventory, not exploitable - should be safe read)
        })
        
        # STRANGE_READS: Unusual security operations
        self.strange_reads.update({
        })
        
