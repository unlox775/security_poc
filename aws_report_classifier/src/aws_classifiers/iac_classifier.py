"""
Infrastructure as Code (IAC) Services Event Classifier

Handles events from CloudFormation, CodeBuild, CodePipeline, and other IAC services.
"""

from .base_classifier import BaseEventClassifier


class IACEventClassifier(BaseEventClassifier):
    """
    Classifier for Infrastructure as Code services.
    
    Handles:
    - cloudformation
    - codebuild
    - codepipeline
    - codeconnections
    - tagging
    - resource-groups
    - servicequotas
    """
    
    def _initialize_rules(self):
        """Initialize classification rules for IAC services."""
        self.handled_sources = {
            "cloudformation.amazonaws.com",   # Infrastructure as code for resource provisioning
            "codebuild.amazonaws.com",        # Build service for compiling and testing code
            "codepipeline.amazonaws.com",     # CI/CD pipelines for deployment automation
            "codeconnections.amazonaws.com",  # Code connections for external repositories
            "tagging.amazonaws.com",          # Resource tagging for organization and billing
            "resource-groups.amazonaws.com",  # Resource groups for organizing AWS resources
            "servicequotas.amazonaws.com",    # Service quotas for managing AWS limits
            "resource-explorer-2.amazonaws.com", # Resource discovery across accounts/regions
            "dlm.amazonaws.com",              # Data lifecycle manager for backup automation
            "cloudcontrolapi.amazonaws.com",  # Cloud Control API for standardized resource management
            "support.amazonaws.com"          # AWS Support for technical assistance and case management
        }
        
        # SAFE_READ_ONLY: Basic IAC information that doesn't expose sensitive data
        self.safe_read_only.update({
            # Service Quotas - Service limits
            ("servicequotas.amazonaws.com", "GetAWSDefaultServiceQuota"),
            ("servicequotas.amazonaws.com", "GetServiceQuota"),
            ("servicequotas.amazonaws.com", "ListAWSDefaultServiceQuotas"),
            ("servicequotas.amazonaws.com", "ListRequestedServiceQuotaChangeHistory"),
            ("servicequotas.amazonaws.com", "ListRequestedServiceQuotaChangeHistoryByQuota"),
            ("servicequotas.amazonaws.com", "ListServiceQuotas"),
            ("servicequotas.amazonaws.com", "ListServices"),
        })
        
        # SENSITIVE_READ_ONLY: IAC operations that could expose sensitive information
        self.sensitive_read_only.update({
            # CloudFormation - Stack and resource information (dashboard reads removed)
            ("cloudformation.amazonaws.com", "ListStacks"),
            ("cloudformation.amazonaws.com", "DescribeStackEvents"),
            ("cloudformation.amazonaws.com", "DescribeStackResources"),
            ("cloudformation.amazonaws.com", "DescribeChangeSet"),
            ("cloudformation.amazonaws.com", "DescribeStackResource"),
            ("cloudformation.amazonaws.com", "GetTemplate"),
            ("cloudformation.amazonaws.com", "ListStackResources"),
            ("cloudformation.amazonaws.com", "ListTypes"),
            
            # CodeBuild - Build information
            ("codebuild.amazonaws.com", "BatchGetBuilds"),
            ("codebuild.amazonaws.com", "BatchGetProjects"),
            ("codebuild.amazonaws.com", "ListBuilds"),
            ("codebuild.amazonaws.com", "ListBuildsForProject"),
            ("codebuild.amazonaws.com", "ListProjects"),
            ("codebuild.amazonaws.com", "ListSandboxesForProject"),
            
            # CodePipeline - Pipeline information
            ("codepipeline.amazonaws.com", "GetPipeline"),
            ("codepipeline.amazonaws.com", "GetPipelineExecution"),
            ("codepipeline.amazonaws.com", "GetPipelineState"),
            ("codepipeline.amazonaws.com", "ListActionExecutions"),
            ("codepipeline.amazonaws.com", "ListPipelineExecutions"),
            ("codepipeline.amazonaws.com", "ListPipelines"),
            ("codepipeline.amazonaws.com", "ListRuleExecutions"),
            
            # CodeConnections - Connection information
            ("codeconnections.amazonaws.com", "UseConnection"),
            
            # DLM - Data lifecycle management (moved from misc)
            ("dlm.amazonaws.com", "GetLifecyclePolicies"),
            
            # Cloud Control API - Resource management (moved from misc)
            ("cloudcontrolapi.amazonaws.com", "GetResource"),
            
            
            # Tagging - Resource tagging information
            ("tagging.amazonaws.com", "GetResources"),
            ("tagging.amazonaws.com", "GetTagKeys"),
            ("tagging.amazonaws.com", "GetTagValues"),
            
            # Resource Groups - Resource organization
            ("resource-groups.amazonaws.com", "ListGroups"),
            
            # Resource Explorer - Resource discovery (moved from misc)
            ("resource-explorer-2.amazonaws.com", "ListIndexes"),
            ("resource-explorer-2.amazonaws.com", "ListViews"),
            
            # Service Catalog - Application registry (moved from misc, dashboard reads removed)
            
            # Support - Case information (moved from security)
            ("support.amazonaws.com", "DescribeServices"),
            ("support.amazonaws.com", "DescribeSeverityLevels"),
            ("support.amazonaws.com", "DescribeCreateCaseOptions"),
            ("support.amazonaws.com", "DescribeTrustedAdvisorCheckSummaries"),
            ("support.amazonaws.com", "DescribeTrustedAdvisorChecks"),
            ("support.amazonaws.com", "DescribeCaseAttributes"),
            ("support.amazonaws.com", "DescribeCases"),
            ("support.amazonaws.com", "DescribeCommunications"),
            ("support.amazonaws.com", "DescribeAttachment"),
            ("support.amazonaws.com", "DescribeTrustedAdvisorCheckResult"),
        })
        
        # SENSITIVE_WRITE: IAC operations that modify infrastructure
        self.sensitive_write.update({
            # CloudFormation - Infrastructure changes
            ("cloudformation.amazonaws.com", "CreateStack"),
            ("cloudformation.amazonaws.com", "DeleteStack"),
            ("cloudformation.amazonaws.com", "UpdateStack"),
            ("cloudformation.amazonaws.com", "CreateChangeSet"),
            ("cloudformation.amazonaws.com", "DeleteChangeSet"),
            ("cloudformation.amazonaws.com", "ExecuteChangeSet"),
            
            # CodeBuild - Build operations
            ("codebuild.amazonaws.com", "StartBuild"),
            ("codebuild.amazonaws.com", "StopBuild"),
            ("codebuild.amazonaws.com", "CreateProject"),
            ("codebuild.amazonaws.com", "DeleteProject"),
            ("codebuild.amazonaws.com", "UpdateProject"),
            
            # CodePipeline - Pipeline operations
            ("codepipeline.amazonaws.com", "CreatePipeline"),
            ("codepipeline.amazonaws.com", "DeletePipeline"),
            ("codepipeline.amazonaws.com", "UpdatePipeline"),
            ("codepipeline.amazonaws.com", "StartPipelineExecution"),
            ("codepipeline.amazonaws.com", "StopPipelineExecution"),
            
            # Service Quotas - Quota modifications
            ("servicequotas.amazonaws.com", "RequestServiceQuotaIncrease"),
            
            # DLM - Data lifecycle policy changes (moved from misc)
            ("dlm.amazonaws.com", "CreateLifecyclePolicy"),
            ("dlm.amazonaws.com", "DeleteLifecyclePolicy"),
            ("dlm.amazonaws.com", "UpdateLifecyclePolicy"),
            
            # Cloud Control API - Resource modifications (moved from misc)
            ("cloudcontrolapi.amazonaws.com", "CreateResource"),
            ("cloudcontrolapi.amazonaws.com", "UpdateResource"),
            ("cloudcontrolapi.amazonaws.com", "DeleteResource"),
            
            # Support - Case management (moved from security)
            ("support.amazonaws.com", "CreateCase"),
            ("support.amazonaws.com", "AddCommunicationToCase"),
            ("support.amazonaws.com", "ResolveCase"),
            ("support.amazonaws.com", "AddAttachmentsToSet"),
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance
        self.hacking_reads.update({
            # CloudFormation - Template analysis for vulnerabilities
            ("cloudformation.amazonaws.com", "GetTemplate"),
            ("cloudformation.amazonaws.com", "ListTypes"),
            
            # CodeBuild - Build log analysis
            ("codebuild.amazonaws.com", "GetBuildLogs"),
        })
        
        # STRANGE_READS: Unusual IAC operations
        self.strange_reads.update({
            # Service Quotas - Unusual quota operations
            ("servicequotas.amazonaws.com", "RequestServiceQuotaIncrease"),
        })
        
        # INFRA_READS: Infrastructure management operations (keeping this category for IAC-specific management)
        self.infra_reads.update({
            # CloudFormation - Infrastructure as code management (dashboard reads removed)
            ("cloudformation.amazonaws.com", "ListStacks"),
            ("cloudformation.amazonaws.com", "DescribeStackResources"),
            ("cloudformation.amazonaws.com", "ListStackResources"),
            
            # CodeBuild - Development pipeline management
            ("codebuild.amazonaws.com", "ListBuilds"),
            ("codebuild.amazonaws.com", "ListBuildsForProject"),
            ("codebuild.amazonaws.com", "ListProjects"),
            
            # CodePipeline - CI/CD pipeline management
            ("codepipeline.amazonaws.com", "GetPipeline"),
            ("codepipeline.amazonaws.com", "GetPipelineState"),
            ("codepipeline.amazonaws.com", "ListPipelines"),
            
            # CodeConnections - Development connections
            ("codeconnections.amazonaws.com", "UseConnection"),
        })
