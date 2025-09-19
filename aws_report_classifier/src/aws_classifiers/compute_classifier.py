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
        """Initialize classification rules for compute services.
        
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
            "ec2.amazonaws.com",                # Elastic Compute Cloud for virtual machines
            "lambda.amazonaws.com",             # AWS Lambda for serverless function execution
            "ec2-instance-connect.amazonaws.com", # EC2 Instance Connect for SSH key management
            "autoscaling.amazonaws.com",        # Auto Scaling for dynamic capacity management
            "ecs.amazonaws.com"                 # Elastic Container Service for containerized applications
        }
        
        # SAFE_READ_ONLY: Basic compute information that doesn't expose sensitive data
        self.safe_read_only.update({
            # EC2 - Basic region and availability zone information (dashboard reads removed)
            ("ec2.amazonaws.com", "DescribeAvailabilityZones"),             # ✅ Availability zones in region - public infrastructure info
            ("ec2.amazonaws.com", "DescribeAccountAttributes"),             # ✅ Account-level attributes - quota and limit info
            ("ec2.amazonaws.com", "DescribeInstanceStatus"),               # ✅ Instance health and state - operational visibility (could be safe read)
            ("ec2.amazonaws.com", "DescribeInstanceTypes"),                # ✅ Instance specs and capabilities - sizing info (could be safe read)
            ("ec2.amazonaws.com", "DescribeVolumeStatus"),                 # ✅ Volume health and state - operational visibility (could be safe read)
            ("ec2.amazonaws.com", "DescribeTags"),                         # ✅ Resource tags and metadata - asset inventory (could be safe read)
            ("ec2.amazonaws.com", "DescribeCapacityReservations"),         # ✅ Reserved capacity details - cost planning (could be safe read)
            ("ec2.amazonaws.com", "DescribePlacementGroups"),              # ✅ Placement group configuration - performance tuning (could be safe read)
            ("ec2.amazonaws.com", "DescribeInstanceCreditSpecifications"), # ✅ Instance credit specs - cost optimization (could be safe read)
            ("ec2.amazonaws.com", "DescribeReplaceRootVolumeTasks"),       # ✅ Root volume replacement tasks - system recovery (could be safe read)
            ("ec2.amazonaws.com", "DescribeCapacityReservationBillingRequests"), # ✅ Billing requests - cost management (could be safe read)
            ("ec2.amazonaws.com", "DescribeSpotInstanceRequests"),         # ✅ Spot instance requests - cost optimization (could be safe read)
            ("ec2.amazonaws.com", "GetCapacityReservationAccountAttribute"), # ✅ Account-level capacity attributes - quota info (could be safe read)
            ("ec2.amazonaws.com", "DescribeSpotPriceHistory"),              # ✅ Spot price history - cost analysis over time (could be safe read)
            ("ec2.amazonaws.com", "DescribeReservedInstancesOfferings"),    # ✅ Reserved instance offerings - marketplace analysis (could be safe read)

            # Lambda - Function information
            ("lambda.amazonaws.com", "GetFunctionRecursionConfig"),         # ✅ Recursion configuration - call limits (could be safe read)
            ("lambda.amazonaws.com", "GetRuntimeManagementConfig"),         # ✅ Runtime management config - version control (could be safe read)
            ("lambda.amazonaws.com", "ListProvisionedConcurrencyConfigs"),  # ✅ Provisioned concurrency - performance settings (could be safe read)
            ("lambda.amazonaws.com", "ListTags20170331"),                   # ✅ Function tags - metadata and categorization (could be safe read)
            ("lambda.amazonaws.com", "GetAccountSettings20160819"),         # ✅ Account-level Lambda settings - quotas (could be safe read)

            # ECS - Container service information
            ("ecs.amazonaws.com", "ListAccountSettings"),                   # ✅ ECS account settings - service quotas (could be safe read)
        })
        
        # SENSITIVE_READ_ONLY: Compute operations that could expose sensitive information
        self.sensitive_read_only.update({
            # EC2 - Instance and network information
            ("ec2.amazonaws.com", "DescribeInstances"),                    # ✅ Instance details with IPs - useful for targeting
            ("ec2.amazonaws.com", "DescribeImages"),                       # ✅ AMI details and metadata - deployment info
            ("ec2.amazonaws.com", "DescribeVolumes"),                      # ✅ Storage volumes and attachments - data exposure
            ("ec2.amazonaws.com", "DescribeSnapshots"),                    # ✅ Backup snapshots and metadata - data exposure
            ("ec2.amazonaws.com", "DescribeVpcs"),                         # ✅ VPC configuration and CIDR blocks - network topology
            ("ec2.amazonaws.com", "DescribeSubnets"),                      # ✅ Subnet details and CIDR blocks - network segmentation
            ("ec2.amazonaws.com", "DescribeNetworkInterfaces"),            # ✅ Network interface details - connectivity info
            ("ec2.amazonaws.com", "DescribeKeyPairs"),                     # ✅ SSH key pairs - access credentials
            ("ec2.amazonaws.com", "DescribeManagedPrefixLists"),           # ✅ Prefix list details - network filtering rules
            ("ec2.amazonaws.com", "DescribeLaunchTemplates"),              # ✅ Launch template configuration - deployment patterns
            ("ec2.amazonaws.com", "DescribeHosts"),                        # ✅ Dedicated host details - hardware allocation
            ("ec2.amazonaws.com", "DescribeInstanceAttribute"),            # ✅ Instance-specific attributes - configuration details
            ("ec2.amazonaws.com", "DescribeInstanceConnectEndpoints"),     # ✅ Instance Connect endpoints - SSH access points
            ("ec2.amazonaws.com", "DescribeTransitGateways"),              # ✅ Transit gateway details - network architecture
            ("ec2.amazonaws.com", "DescribeCustomerGateways"),             # ✅ Customer gateway details - VPN endpoints
            ("ec2.amazonaws.com", "DescribeDhcpOptions"),                  # ✅ DHCP options sets - network configuration
            ("ec2.amazonaws.com", "DescribeInternetGateways"),             # ✅ Internet gateway details - external connectivity
            ("ec2.amazonaws.com", "DescribeNatGateways"),                  # ✅ NAT gateway details - outbound connectivity
            ("ec2.amazonaws.com", "DescribeNetworkAcls"),                  # ✅ Network ACL details - subnet-level security
            ("ec2.amazonaws.com", "DescribeRouteServers"),                 # ✅ Route server details - BGP routing
            ("ec2.amazonaws.com", "DescribeRouteTables"),                  # ✅ Route table details - network routing rules
            ("ec2.amazonaws.com", "DescribeVpcEndpointServiceConfigurations"), # ✅ VPC endpoint services - internal connectivity
            ("ec2.amazonaws.com", "DescribeVpcEndpoints"),                 # ✅ VPC endpoint details - private connectivity
            ("ec2.amazonaws.com", "DescribeVpcPeeringConnections"),        # ✅ VPC peering details - cross-VPC connectivity
            ("ec2.amazonaws.com", "DescribeVpnConnections"),               # ✅ VPN connection details - site-to-site VPN
            ("ec2.amazonaws.com", "DescribeVpnGateways"),                  # ✅ VPN gateway details - VPN infrastructure
            ("ec2.amazonaws.com", "DescribeAddressTransfers"),              # ✅ Elastic IP transfer history - ownership tracking (could be sensitive read)
            ("ec2.amazonaws.com", "DescribeAddressesAttribute"),            # ✅ Elastic IP attributes - metadata analysis (could be sensitive read)
            ("ec2.amazonaws.com", "DescribeCapacityBlockExtensionHistory"), # ✅ Capacity block extensions - resource planning (could be sensitive read)
            ("ec2.amazonaws.com", "DescribeReservedInstances"),             # ✅ Reserved instance details - cost optimization analysis (could be sensitive read)
            ("ec2.amazonaws.com", "DescribeReservedInstancesModifications"), # ✅ Reserved instance modifications - cost changes (could be sensitive read)
            ("ec2.amazonaws.com", "DescribeSpotFleetRequests"),             # ✅ Spot fleet requests - cost optimization patterns (could be sensitive read)
            ("ec2.amazonaws.com", "DescribeVolumesModifications"),          # ✅ Volume modification history - storage changes (could be sensitive read)
            
            # Lambda - Function information
            ("lambda.amazonaws.com", "GetFunction20150331v2"),              # ✅ Function code and configuration - execution details
            ("lambda.amazonaws.com", "GetFunctionConfiguration20150331v2"), # ✅ Function runtime config - environment variables
            ("lambda.amazonaws.com", "GetFunctionCodeSigningConfig"),       # ✅ Code signing configuration - security validation
            ("lambda.amazonaws.com", "GetFunctionEventInvokeConfig"),       # ✅ Event invoke configuration - trigger settings
            ("lambda.amazonaws.com", "GetPolicy20150331"),                  # ✅ Function resource policies - access permissions
            ("lambda.amazonaws.com", "GetPolicy20150331v2"),                # ✅ Function resource policies v2 - access permissions
            ("lambda.amazonaws.com", "ListAliases20150331"),                # ✅ Function aliases - version routing
            ("lambda.amazonaws.com", "ListEventSourceMappings20150331"),    # ✅ Event source mappings - trigger configurations
            ("lambda.amazonaws.com", "ListFunctionUrlConfigs"),             # ✅ Function URL configurations - HTTP endpoints
            ("lambda.amazonaws.com", "ListFunctions20150331"),              # ✅ Function inventory - available functions
            ("lambda.amazonaws.com", "ListLayers20181031"),                 # ✅ Function layers - shared code libraries
            ("lambda.amazonaws.com", "ListVersionsByFunction20150331"),     # ✅ Function versions - deployment history
            ("lambda.amazonaws.com", "GetLayerVersionByArn20181031"),       # ✅ Layer version details - shared dependencies
            
            # Auto Scaling - Scaling configuration information
            ("autoscaling.amazonaws.com", "DescribePolicies"),              # ✅ Scaling policies - automated scaling rules
            ("autoscaling.amazonaws.com", "DescribeScalingPolicies"),       # ✅ Scaling policy details - trigger conditions
            ("autoscaling.amazonaws.com", "DescribeLaunchConfigurations"),  # ✅ Launch configurations - instance templates
            ("autoscaling.amazonaws.com", "DescribeScheduledActions"),      # ✅ Scheduled scaling actions - time-based scaling
            ("autoscaling.amazonaws.com", "DescribeAutoScalingGroups"),     # ✅ Auto scaling groups - scaling targets
            
            # ECS - Container service information
            ("ecs.amazonaws.com", "DescribeClusters"),                      # ✅ ECS cluster details - container orchestration
            ("ecs.amazonaws.com", "ListClusters"),                          # ✅ ECS cluster inventory - available clusters
            ("ecs.amazonaws.com", "ListTaskDefinitionFamilies"),            # ✅ Task definition families - container templates
            
            
        })
        
        # SENSITIVE_WRITE: Compute operations that modify resources
        self.sensitive_write.update({
            # EC2 - Instance and infrastructure changes
            ("ec2.amazonaws.com", "RunInstances"),                          # ✅ Create new EC2 instances - resource creation
            ("ec2.amazonaws.com", "TerminateInstances"),                    # ✅ Delete EC2 instances - resource destruction
            ("ec2.amazonaws.com", "StartInstances"),                        # ✅ Start stopped instances - state change
            ("ec2.amazonaws.com", "StopInstances"),                         # ✅ Stop running instances - state change
            ("ec2.amazonaws.com", "RebootInstances"),                       # ✅ Reboot instances - system restart
            ("ec2.amazonaws.com", "CreateImage"),                           # ✅ Create AMI from instance - image creation
            ("ec2.amazonaws.com", "CreateSnapshot"),                        # ✅ Create volume snapshot - backup creation
            ("ec2.amazonaws.com", "CreateVolume"),                          # ✅ Create new EBS volume - storage creation
            ("ec2.amazonaws.com", "AttachVolume"),                          # ✅ Attach volume to instance - storage connection
            ("ec2.amazonaws.com", "DetachVolume"),                          # ✅ Detach volume from instance - storage disconnection
            ("ec2.amazonaws.com", "CreateSecurityGroup"),                   # ✅ Create security group - network security creation
            ("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress"),         # ✅ Add inbound rules to security group - access grant
            ("ec2.amazonaws.com", "RevokeSecurityGroupIngress"),            # ✅ Remove inbound rules from security group - access revoke
            
            # Lambda - Function modifications
            ("lambda.amazonaws.com", "CreateFunction20150331"),            # ✅ Create new Lambda function - function creation
            ("lambda.amazonaws.com", "DeleteFunction"),                     # ✅ Delete Lambda function - function destruction
            ("lambda.amazonaws.com", "UpdateFunctionCode20150331"),         # ✅ Update function code - code deployment
            ("lambda.amazonaws.com", "UpdateFunctionConfiguration20150331"), # ✅ Update function config - runtime settings change
            ("lambda.amazonaws.com", "PublishVersion20150331"),             # ✅ Publish function version - version management
            ("lambda.amazonaws.com", "CreateAlias20150331"),               # ✅ Create function alias - version routing
            ("lambda.amazonaws.com", "UpdateAlias20150331"),               # ✅ Update function alias - routing change
            ("lambda.amazonaws.com", "DeleteAlias20150331"),               # ✅ Delete function alias - routing removal
            
            # Auto Scaling - Scaling operations
            ("autoscaling.amazonaws.com", "CreateAutoScalingGroup"),        # ✅ Create auto scaling group - scaling setup
            ("autoscaling.amazonaws.com", "DeleteAutoScalingGroup"),        # ✅ Delete auto scaling group - scaling removal
            ("autoscaling.amazonaws.com", "UpdateAutoScalingGroup"),        # ✅ Update auto scaling group - scaling config change
            ("autoscaling.amazonaws.com", "SetDesiredCapacity"),            # ✅ Set desired capacity - manual scaling
            ("autoscaling.amazonaws.com", "TerminateInstanceInAutoScalingGroup"), # ✅ Terminate instance in ASG - instance removal
            
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance or exploitation
        self.hacking_reads.update({
            # EC2 - Security and network reconnaissance
            ("ec2.amazonaws.com", "DescribeSecurityGroups"),               # ✅ Security group rules with IP addresses - attack surface mapping
            ("ec2.amazonaws.com", "DescribeSecurityGroupRules"),           # ✅ Detailed security group rules - firewall bypass analysis
            ("ec2.amazonaws.com", "DescribeAddresses"),                    # ✅ Elastic IP addresses - external access point discovery
            
            # EC2 Instance Connect - SSH key operations (potential backdoor)
            ("ec2-instance-connect.amazonaws.com", "SendSSHPublicKey"),    # ✅ Send SSH public key to instance - potential backdoor
            
            # EC2 - Network reconnaissance
            ("ec2.amazonaws.com", "DescribeEgressOnlyInternetGateways"),    # ✅ IPv6 egress-only gateways - network topology
            ("ec2.amazonaws.com", "DescribeTransitGatewayAttachments"),     # ✅ Transit gateway attachments - network connectivity
            ("ec2.amazonaws.com", "DescribeTransitGatewayMulticastDomains"), # ✅ Transit gateway multicast - network protocols
            ("ec2.amazonaws.com", "DescribeTransitGatewayPolicyTables"),    # ✅ Transit gateway policies - network access rules
            ("ec2.amazonaws.com", "DescribeTransitGatewayRouteTables"),     # ✅ Transit gateway routes - network routing analysis
            ("ec2.amazonaws.com", "DescribeVerifiedAccessEndpoints"),       # ✅ Verified access endpoints - secure access points
            ("ec2.amazonaws.com", "DescribeVerifiedAccessGroups"),          # ✅ Verified access groups - security group analysis
            ("ec2.amazonaws.com", "DescribeVerifiedAccessInstances"),       # ✅ Verified access instances - secure instances
            ("ec2.amazonaws.com", "DescribeVerifiedAccessTrustProviders"),  # ✅ Verified access trust providers - identity sources
            ("ec2.amazonaws.com", "DescribeVpcBlockPublicAccessOptions"),   # ✅ VPC public access blocking - security configuration
        })
        
        # STRANGE_READS: Unusual compute operations
        self.strange_reads.update({
            # EC2 - Unusual or rarely used operations
            ("ec2.amazonaws.com", "DescribeInstanceImageMetadata"),         # ✅ Instance image metadata - unusual image details
        })
        
