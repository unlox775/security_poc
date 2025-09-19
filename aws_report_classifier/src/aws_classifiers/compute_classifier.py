"""
Compute Services Event Classifier

Handles events from EC2, Lambda, and other compute services.
"""

from .base_classifier import BaseEventClassifier


class ComputeEventClassifier(BaseEventClassifier):
    """
    Classifier for compute services.
    
    Handles:
    - ec2 (Elastic Compute Cloud)
    - lambda (AWS Lambda)
    - ec2-instance-connect
    - autoscaling
    """
    
    def _initialize_rules(self):
        """Initialize classification rules for compute services."""
        self.handled_sources = {
            "ec2.amazonaws.com",                # Elastic Compute Cloud for virtual machines
            "lambda.amazonaws.com",             # AWS Lambda for serverless function execution
            "ec2-instance-connect.amazonaws.com", # EC2 Instance Connect for SSH key management
            "autoscaling.amazonaws.com"         # Auto Scaling for dynamic capacity management
        }
        
        # SAFE_READ_ONLY: Basic compute information that doesn't expose sensitive data
        self.safe_read_only.update({
            # EC2 - Basic region and availability zone information (dashboard reads removed)
            ("ec2.amazonaws.com", "DescribeAvailabilityZones"),
            ("ec2.amazonaws.com", "DescribeAccountAttributes"),
        })
        
        # SENSITIVE_READ_ONLY: Compute operations that could expose sensitive information
        self.sensitive_read_only.update({
            # EC2 - Instance and network information
            ("ec2.amazonaws.com", "DescribeInstances"),
            ("ec2.amazonaws.com", "DescribeInstanceStatus"),
            ("ec2.amazonaws.com", "DescribeInstanceTypes"),
            ("ec2.amazonaws.com", "DescribeImages"),
            ("ec2.amazonaws.com", "DescribeVolumes"),
            ("ec2.amazonaws.com", "DescribeVolumeStatus"),
            ("ec2.amazonaws.com", "DescribeSnapshots"),
            ("ec2.amazonaws.com", "DescribeAddresses"),
            ("ec2.amazonaws.com", "DescribeSecurityGroups"),
            ("ec2.amazonaws.com", "DescribeSecurityGroupRules"),
            ("ec2.amazonaws.com", "DescribeVpcs"),
            ("ec2.amazonaws.com", "DescribeSubnets"),
            ("ec2.amazonaws.com", "DescribeNetworkInterfaces"),
            ("ec2.amazonaws.com", "DescribeKeyPairs"),
            ("ec2.amazonaws.com", "DescribeTags"),
            ("ec2.amazonaws.com", "DescribeCapacityReservations"),
            ("ec2.amazonaws.com", "DescribePlacementGroups"),
            ("ec2.amazonaws.com", "DescribeManagedPrefixLists"),
            ("ec2.amazonaws.com", "DescribeLaunchTemplates"),
            ("ec2.amazonaws.com", "DescribeHosts"),
            
            # Lambda - Function information
            ("lambda.amazonaws.com", "GetFunction20150331v2"),
            ("lambda.amazonaws.com", "GetFunctionConfiguration20150331v2"),
            ("lambda.amazonaws.com", "GetFunctionCodeSigningConfig"),
            ("lambda.amazonaws.com", "GetFunctionEventInvokeConfig"),
            ("lambda.amazonaws.com", "GetFunctionRecursionConfig"),
            ("lambda.amazonaws.com", "GetPolicy20150331"),
            ("lambda.amazonaws.com", "GetPolicy20150331v2"),
            ("lambda.amazonaws.com", "GetRuntimeManagementConfig"),
            ("lambda.amazonaws.com", "ListAliases20150331"),
            ("lambda.amazonaws.com", "ListEventSourceMappings20150331"),
            ("lambda.amazonaws.com", "ListFunctionUrlConfigs"),
            ("lambda.amazonaws.com", "ListFunctions20150331"),
            ("lambda.amazonaws.com", "ListLayers20181031"),
            ("lambda.amazonaws.com", "ListProvisionedConcurrencyConfigs"),
            ("lambda.amazonaws.com", "ListTags20170331"),
            ("lambda.amazonaws.com", "ListVersionsByFunction20150331"),
            ("lambda.amazonaws.com", "GetLayerVersionByArn20181031"),
            ("lambda.amazonaws.com", "GetAccountSettings20160819"),
            
            # Auto Scaling - Scaling configuration information
            ("autoscaling.amazonaws.com", "DescribeAutoScalingGroups"),
            ("autoscaling.amazonaws.com", "DescribePolicies"),
            ("autoscaling.amazonaws.com", "DescribeScalingPolicies"),
            ("autoscaling.amazonaws.com", "DescribeLaunchConfigurations"),
            ("autoscaling.amazonaws.com", "DescribeScheduledActions"),
            
        })
        
        # SENSITIVE_WRITE: Compute operations that modify resources
        self.sensitive_write.update({
            # EC2 - Instance and infrastructure changes
            ("ec2.amazonaws.com", "RunInstances"),
            ("ec2.amazonaws.com", "TerminateInstances"),
            ("ec2.amazonaws.com", "StartInstances"),
            ("ec2.amazonaws.com", "StopInstances"),
            ("ec2.amazonaws.com", "RebootInstances"),
            ("ec2.amazonaws.com", "CreateImage"),
            ("ec2.amazonaws.com", "CreateSnapshot"),
            ("ec2.amazonaws.com", "CreateVolume"),
            ("ec2.amazonaws.com", "AttachVolume"),
            ("ec2.amazonaws.com", "DetachVolume"),
            ("ec2.amazonaws.com", "CreateSecurityGroup"),
            ("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress"),
            ("ec2.amazonaws.com", "RevokeSecurityGroupIngress"),
            
            # Lambda - Function modifications
            ("lambda.amazonaws.com", "CreateFunction20150331"),
            ("lambda.amazonaws.com", "DeleteFunction"),
            ("lambda.amazonaws.com", "UpdateFunctionCode20150331"),
            ("lambda.amazonaws.com", "UpdateFunctionConfiguration20150331"),
            ("lambda.amazonaws.com", "PublishVersion20150331"),
            ("lambda.amazonaws.com", "CreateAlias20150331"),
            ("lambda.amazonaws.com", "UpdateAlias20150331"),
            ("lambda.amazonaws.com", "DeleteAlias20150331"),
            
            # Auto Scaling - Scaling operations
            ("autoscaling.amazonaws.com", "CreateAutoScalingGroup"),
            ("autoscaling.amazonaws.com", "DeleteAutoScalingGroup"),
            ("autoscaling.amazonaws.com", "UpdateAutoScalingGroup"),
            ("autoscaling.amazonaws.com", "SetDesiredCapacity"),
            ("autoscaling.amazonaws.com", "TerminateInstanceInAutoScalingGroup"),
            
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance or exploitation
        self.hacking_reads.update({
            # EC2 Instance Connect - SSH key operations (potential backdoor)
            ("ec2-instance-connect.amazonaws.com", "SendSSHPublicKey"),
            
            # EC2 - Network reconnaissance
            ("ec2.amazonaws.com", "DescribeAddressTransfers"),
            ("ec2.amazonaws.com", "DescribeAddressesAttribute"),
            ("ec2.amazonaws.com", "DescribeCapacityBlockExtensionHistory"),
            ("ec2.amazonaws.com", "DescribeEgressOnlyInternetGateways"),
            ("ec2.amazonaws.com", "DescribeReservedInstances"),
            ("ec2.amazonaws.com", "DescribeReservedInstancesModifications"),
            ("ec2.amazonaws.com", "DescribeSpotFleetRequests"),
            ("ec2.amazonaws.com", "DescribeTransitGatewayAttachments"),
            ("ec2.amazonaws.com", "DescribeTransitGatewayMulticastDomains"),
            ("ec2.amazonaws.com", "DescribeTransitGatewayPolicyTables"),
            ("ec2.amazonaws.com", "DescribeTransitGatewayRouteTables"),
            ("ec2.amazonaws.com", "DescribeVerifiedAccessEndpoints"),
            ("ec2.amazonaws.com", "DescribeVerifiedAccessGroups"),
            ("ec2.amazonaws.com", "DescribeVerifiedAccessInstances"),
            ("ec2.amazonaws.com", "DescribeVerifiedAccessTrustProviders"),
            ("ec2.amazonaws.com", "DescribeVolumesModifications"),
            ("ec2.amazonaws.com", "DescribeVpcBlockPublicAccessOptions"),
        })
        
        # STRANGE_READS: Unusual compute operations
        self.strange_reads.update({
            # EC2 - Unusual or rarely used operations
            ("ec2.amazonaws.com", "DescribeInstanceImageMetadata"),
            ("ec2.amazonaws.com", "DescribeSpotPriceHistory"),
            ("ec2.amazonaws.com", "DescribeReservedInstancesOfferings"),
        })
        
        # INFRA_READS: Infrastructure management operations
        self.infra_reads.update({
            # EC2 - Infrastructure management
            ("ec2.amazonaws.com", "DescribeLaunchTemplates"),
            ("ec2.amazonaws.com", "DescribeVolumeStatus"),
            ("ec2.amazonaws.com", "DescribeHosts"),
            
            # Auto Scaling - Infrastructure scaling management
            ("autoscaling.amazonaws.com", "DescribeAutoScalingGroups"),
            
        })
