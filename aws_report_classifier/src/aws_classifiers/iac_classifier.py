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
        """Initialize classification rules for IAC services.
        
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
            "support.amazonaws.com",          # AWS Support for technical assistance and case management
            "ssm.amazonaws.com",              # Systems Manager for configuration management
            "ssm-quicksetup.amazonaws.com"    # SSM Quick Setup for configuration automation
        }
        
        # SAFE_READ_ONLY: Basic IAC information that doesn't expose sensitive data
        self.safe_read_only.update({
            # Service Quotas - Service limits
            ("servicequotas.amazonaws.com", "GetAWSDefaultServiceQuota"),   # Default service quotas - public AWS limits
            ("servicequotas.amazonaws.com", "GetServiceQuota"),             # Current service quotas - account limits
            ("servicequotas.amazonaws.com", "ListAWSDefaultServiceQuotas"), # All default quotas - public AWS limits
            ("servicequotas.amazonaws.com", "ListRequestedServiceQuotaChangeHistory"), # Quota change history - request tracking
            ("servicequotas.amazonaws.com", "ListRequestedServiceQuotaChangeHistoryByQuota"), # Quota-specific history - request details
            ("servicequotas.amazonaws.com", "ListServiceQuotas"),           # All service quotas - account limit overview
            ("servicequotas.amazonaws.com", "ListServices"),                # Available services - public service catalog
        })
        
        # SENSITIVE_READ_ONLY: IAC operations that could expose sensitive information
        self.sensitive_read_only.update({
            # CloudFormation - Stack and resource information (dashboard reads removed)
            ("cloudformation.amazonaws.com", "ListStacks"),                 # Stack inventory - infrastructure overview
            ("cloudformation.amazonaws.com", "DescribeStackEvents"),        # Stack event history - deployment tracking
            ("cloudformation.amazonaws.com", "DescribeStackResources"),     # Stack resource details - infrastructure components
            ("cloudformation.amazonaws.com", "DescribeChangeSet"),          # Change set details - planned modifications
            ("cloudformation.amazonaws.com", "DescribeStackResource"),      # Individual resource details - component analysis
            ("cloudformation.amazonaws.com", "ListStackResources"),         # Stack resource inventory - component listing
            
            # CodeBuild - Build information
            ("codebuild.amazonaws.com", "BatchGetBuilds"),                  # Build details - compilation and test results
            ("codebuild.amazonaws.com", "BatchGetProjects"),                # Project configurations - build environment details
            ("codebuild.amazonaws.com", "ListBuilds"),                      # Build history - compilation timeline
            ("codebuild.amazonaws.com", "ListBuildsForProject"),            # Project-specific builds - build history
            ("codebuild.amazonaws.com", "ListProjects"),                    # Project inventory - available build projects
            ("codebuild.amazonaws.com", "ListSandboxesForProject"),         # Project sandboxes - isolated build environments
            
            # CodePipeline - Pipeline information
            ("codepipeline.amazonaws.com", "GetPipeline"),                   # Pipeline configuration - deployment workflow details
            ("codepipeline.amazonaws.com", "GetPipelineExecution"),          # Pipeline execution details - deployment status
            ("codepipeline.amazonaws.com", "GetPipelineState"),              # Pipeline state - current execution status
            ("codepipeline.amazonaws.com", "ListActionExecutions"),          # Action execution history - step-by-step tracking
            ("codepipeline.amazonaws.com", "ListPipelineExecutions"),        # Pipeline execution history - deployment timeline
            ("codepipeline.amazonaws.com", "ListPipelines"),                 # Pipeline inventory - available workflows
            ("codepipeline.amazonaws.com", "ListRuleExecutions"),            # Rule execution history - automation triggers
            
            # CodeConnections - Connection information
            ("codeconnections.amazonaws.com", "UseConnection"),              # External repository connection - source code access
            
            # DLM - Data lifecycle management (moved from misc)
            ("dlm.amazonaws.com", "GetLifecyclePolicies"),                   # Data lifecycle policies - backup and retention rules
            
            # Cloud Control API - Resource management (moved from misc)
            ("cloudcontrolapi.amazonaws.com", "GetResource"),                # Standardized resource access - unified resource management
            
            
            # Tagging - Resource tagging information
            ("tagging.amazonaws.com", "GetResources"),                      # Tagged resources - resource inventory with metadata
            ("tagging.amazonaws.com", "GetTagKeys"),                        # Available tag keys - tagging schema
            ("tagging.amazonaws.com", "GetTagValues"),                      # Tag values for specific keys - tagging data
            
            # Resource Groups - Resource organization
            ("resource-groups.amazonaws.com", "ListGroups"),                # Resource group inventory - organizational structure
            
            # Resource Explorer - Resource discovery (moved from misc)
            ("resource-explorer-2.amazonaws.com", "ListIndexes"),           # Resource indexes - cross-account resource discovery
            ("resource-explorer-2.amazonaws.com", "ListViews"),             # Resource views - filtered resource access
            
            # SSM - Systems Manager information
            ("ssm.amazonaws.com", "DescribeInstanceInformation"),           # Managed instance details - server inventory and status
            ("ssm.amazonaws.com", "DescribeSessions"),                      # Active session details - remote access sessions
            ("ssm.amazonaws.com", "GetConnectionStatus"),                   # Connection status - instance connectivity
            ("ssm.amazonaws.com", "GetParametersByPath"),                   # Parameter store values - configuration data
            ("ssm.amazonaws.com", "ResumeSession"),                         # Resume session - remote access control
            ("ssm.amazonaws.com", "StartSession"),                          # Start session - remote access initiation
            ("ssm.amazonaws.com", "TerminateSession"),                      # Terminate session - remote access termination
            
            # SSM Quick Setup - Configuration management
            ("ssm-quicksetup.amazonaws.com", "ListConfigurationManagers"), # Configuration managers - automation setup
            ("ssm-quicksetup.amazonaws.com", "ListConfigurations"),        # Quick setup configurations - automated deployments
            
            # Service Catalog - Application registry (moved from misc, dashboard reads removed)
            
            # Support - Case information (moved from security)
            ("support.amazonaws.com", "DescribeServices"),                 # Support services - available support categories
            ("support.amazonaws.com", "DescribeSeverityLevels"),           # Support severity levels - case priority options
            ("support.amazonaws.com", "DescribeCreateCaseOptions"),        # Case creation options - support request setup
            ("support.amazonaws.com", "DescribeTrustedAdvisorCheckSummaries"), # Trusted Advisor summaries - infrastructure recommendations
            ("support.amazonaws.com", "DescribeTrustedAdvisorChecks"),       # Trusted Advisor checks - security and cost analysis
            ("support.amazonaws.com", "DescribeCaseAttributes"),             # Support case attributes - case metadata
            ("support.amazonaws.com", "DescribeCases"),                      # Support cases - issue tracking
            ("support.amazonaws.com", "DescribeCommunications"),             # Case communications - support conversation history
            ("support.amazonaws.com", "DescribeAttachment"),                 # Case attachments - support file access
            ("support.amazonaws.com", "DescribeTrustedAdvisorCheckResult"),  # Trusted Advisor results - specific recommendation details
        })
        
        # SENSITIVE_WRITE: IAC operations that modify infrastructure
        self.sensitive_write.update({
            # CloudFormation - Infrastructure changes
            ("cloudformation.amazonaws.com", "CreateStack"),                 # Create infrastructure stack - resource provisioning
            ("cloudformation.amazonaws.com", "DeleteStack"),                 # Delete infrastructure stack - resource destruction
            ("cloudformation.amazonaws.com", "UpdateStack"),                 # Update infrastructure stack - resource modification
            ("cloudformation.amazonaws.com", "CreateChangeSet"),             # Create change set - planned infrastructure changes
            ("cloudformation.amazonaws.com", "DeleteChangeSet"),             # Delete change set - cancel planned changes
            ("cloudformation.amazonaws.com", "ExecuteChangeSet"),            # Execute change set - apply planned changes
            
            # CodeBuild - Build operations
            ("codebuild.amazonaws.com", "StartBuild"),                      # Start build process - initiate compilation
            ("codebuild.amazonaws.com", "StopBuild"),                       # Stop build process - cancel compilation
            ("codebuild.amazonaws.com", "CreateProject"),                   # Create build project - setup build environment
            ("codebuild.amazonaws.com", "DeleteProject"),                   # Delete build project - remove build environment
            ("codebuild.amazonaws.com", "UpdateProject"),                   # Update build project - modify build configuration
            
            # CodePipeline - Pipeline operations
            ("codepipeline.amazonaws.com", "CreatePipeline"),               # Create deployment pipeline - setup CI/CD workflow
            ("codepipeline.amazonaws.com", "DeletePipeline"),               # Delete deployment pipeline - remove CI/CD workflow
            ("codepipeline.amazonaws.com", "UpdatePipeline"),               # Update deployment pipeline - modify CI/CD workflow
            ("codepipeline.amazonaws.com", "StartPipelineExecution"),       # Start pipeline execution - trigger deployment
            ("codepipeline.amazonaws.com", "StopPipelineExecution"),        # Stop pipeline execution - cancel deployment
            
            # Service Quotas - Quota modifications
            ("servicequotas.amazonaws.com", "RequestServiceQuotaIncrease"), # Request quota increase - resource limit modification
            
            # DLM - Data lifecycle policy changes (moved from misc)
            ("dlm.amazonaws.com", "CreateLifecyclePolicy"),                # Create backup policy - automated backup setup
            ("dlm.amazonaws.com", "DeleteLifecyclePolicy"),                # Delete backup policy - remove automated backups
            ("dlm.amazonaws.com", "UpdateLifecyclePolicy"),                # Update backup policy - modify backup configuration
            
            # Cloud Control API - Resource modifications (moved from misc)
            ("cloudcontrolapi.amazonaws.com", "CreateResource"),            # Create resource via Cloud Control - standardized resource creation
            ("cloudcontrolapi.amazonaws.com", "UpdateResource"),            # Update resource via Cloud Control - standardized resource modification
            ("cloudcontrolapi.amazonaws.com", "DeleteResource"),            # Delete resource via Cloud Control - standardized resource deletion
            
            # Support - Case management (moved from security)
            ("support.amazonaws.com", "CreateCase"),                       # Create support case - initiate support request
            ("support.amazonaws.com", "AddCommunicationToCase"),           # Add case communication - update support conversation
            ("support.amazonaws.com", "ResolveCase"),                      # Resolve support case - close support request
            ("support.amazonaws.com", "AddAttachmentsToSet"),               # Add case attachments - attach files to support case
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance
        self.hacking_reads.update({
            # CloudFormation - Template analysis for vulnerabilities
            ("cloudformation.amazonaws.com", "GetTemplate"),                # Stack template content - infrastructure blueprint analysis
            ("cloudformation.amazonaws.com", "ListTypes"),                  # Resource type registry - available resource types for exploitation
            
            # CodeBuild - Build log analysis
            ("codebuild.amazonaws.com", "GetBuildLogs"),                    # Build execution logs - compilation output and secrets
        })
        
        # STRANGE_READS: Unusual IAC operations
        self.strange_reads.update({
            # No unusual IAC operations currently identified
        })
        
