"""
Networking Services Event Classifier

Handles events from Route53, VPC Lattice, Network Firewall, API Gateway, and other networking services.
"""

from .base_classifier import BaseEventClassifier


class NetworkingEventClassifier(BaseEventClassifier):
    """
    Classifier for networking services.
    
    Handles:
    - route53
    - route53domains
    - route53resolver
    - vpc-lattice
    - network-firewall
    - apigateway
    - elasticloadbalancing
    - servicediscovery
    """
    
    def _initialize_rules(self):
        """Initialize classification rules for networking services.
        
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
            "route53.amazonaws.com",            # Route 53 for DNS hosting and domain management
            "route53domains.amazonaws.com",     # Route 53 Domains for domain registration
            "route53resolver.amazonaws.com",    # Route 53 Resolver for DNS queries and firewall
            "vpc-lattice.amazonaws.com",        # VPC Lattice for service-to-service networking
            "network-firewall.amazonaws.com",   # Network Firewall for VPC traffic filtering
            "apigateway.amazonaws.com",         # API Gateway for REST/HTTP API management
            "elasticloadbalancing.amazonaws.com", # Load balancers for traffic distribution
            "servicediscovery.amazonaws.com"    # Service Discovery for service registration
        }
        
        # SAFE_READ_ONLY: Basic networking information that doesn't expose sensitive data
        self.safe_read_only.update({
            # Route53 - Basic DNS information
            ("route53.amazonaws.com", "GetChange"),                          # DNS change status - public change tracking
            ("route53.amazonaws.com", "GetHealthCheckCount"),               # Health check count - public monitoring stats
            ("route53.amazonaws.com", "GetHostedZoneCount"),                # Hosted zone count - public zone statistics
            ("route53.amazonaws.com", "GetTrafficPolicyInstanceCount"),     # Traffic policy count - public policy stats
            ("route53domains.amazonaws.com", "ListDomains"),                # Domain inventory - public domain list
            ("route53domains.amazonaws.com", "ListOperations"),             # Domain operations - public operation history
            
            # Service Discovery - Basic service registry
        })
        
        # SENSITIVE_READ_ONLY: Networking operations that could expose sensitive information
        self.sensitive_read_only.update({
            # Route53 - DNS configuration details
            ("route53.amazonaws.com", "ListHostedZones"),                    # Hosted zone inventory - DNS zone listing
            ("route53.amazonaws.com", "ListHostedZonesByName"),              # Hosted zones by name - DNS zone lookup
            ("route53.amazonaws.com", "ListQueryLoggingConfigs"),            # DNS query logging - DNS monitoring configuration
            ("route53.amazonaws.com", "ListResourceRecordSets"),             # DNS records - zone file contents
            ("route53.amazonaws.com", "ListTagsForResource"),               # DNS resource tags - zone metadata
            ("route53.amazonaws.com", "ListTrafficPolicies"),               # Traffic policies - DNS routing rules
            
            # Route53 Resolver - DNS security configuration
            ("route53resolver.amazonaws.com", "ListFirewallDomainLists"),    # DNS firewall domains - DNS security rules
            ("route53resolver.amazonaws.com", "ListFirewallRuleGroupAssociations"), # DNS firewall associations - security rule mapping
            ("route53resolver.amazonaws.com", "ListFirewallRuleGroups"),     # DNS firewall rule groups - security rule collections
            
            # Network Firewall - Security configuration
            ("network-firewall.amazonaws.com", "DescribeRuleGroupMetadata"), # Firewall rule metadata - network security rules
            ("network-firewall.amazonaws.com", "ListFirewallPolicies"),      # Firewall policies - network security policies
            ("network-firewall.amazonaws.com", "ListFirewalls"),             # Firewall inventory - network security devices
            ("network-firewall.amazonaws.com", "ListRuleGroups"),            # Firewall rule groups - security rule collections
            ("network-firewall.amazonaws.com", "ListTLSInspectionConfigurations"), # TLS inspection configs - SSL/TLS security settings
            
            # VPC Lattice - Network service discovery
            ("vpc-lattice.amazonaws.com", "ListServices"),                   # Lattice services - service-to-service networking
            ("vpc-lattice.amazonaws.com", "ListTargetGroups"),               # Lattice target groups - service routing targets
            
            # API Gateway - API configuration
            ("apigateway.amazonaws.com", "GetRestApi"),                     # REST API details - API configuration and endpoints
            ("apigateway.amazonaws.com", "GetResource"),                    # API resource details - endpoint configuration
            ("apigateway.amazonaws.com", "GetMethod"),                      # API method details - HTTP method configuration
            ("apigateway.amazonaws.com", "GetIntegration"),                 # API integration details - backend service connections
            ("apigateway.amazonaws.com", "GetApiKey"),                      # API key details - authentication credentials
            ("apigateway.amazonaws.com", "GetApiKeys"),                     # API key inventory - authentication credential listing
            ("apigateway.amazonaws.com", "GetUsagePlan"),                   # Usage plan details - API rate limiting and quotas
            ("apigateway.amazonaws.com", "GetUsagePlans"),                  # Usage plan inventory - API rate limiting policies
            ("apigateway.amazonaws.com", "GetVpcLink"),
            ("apigateway.amazonaws.com", "GetVpcLinks"),
            ("apigateway.amazonaws.com", "GetDomainName"),
            ("apigateway.amazonaws.com", "GetDomainNames"),
            ("apigateway.amazonaws.com", "GetClientCertificate"),
            ("apigateway.amazonaws.com", "GetClientCertificates"),
            ("apigateway.amazonaws.com", "GetAuthorizer"),
            ("apigateway.amazonaws.com", "GetAuthorizers"),
            ("apigateway.amazonaws.com", "GetGatewayResponse"),
            ("apigateway.amazonaws.com", "GetGatewayResponses"),
            ("apigateway.amazonaws.com", "GetModel"),
            ("apigateway.amazonaws.com", "GetModels"),
            ("apigateway.amazonaws.com", "GetRequestValidator"),
            ("apigateway.amazonaws.com", "GetRequestValidators"),
            ("apigateway.amazonaws.com", "GetStage"),
            ("apigateway.amazonaws.com", "GetAccount"),
            ("apigateway.amazonaws.com", "GetApi"),
            ("apigateway.amazonaws.com", "GetApis"),
            ("apigateway.amazonaws.com", "GetIntegrations"),
            ("apigateway.amazonaws.com", "GetRoutes"),
            
            # Load Balancer - Load balancer configuration
            ("elasticloadbalancing.amazonaws.com", "DescribeTargetGroups"),
            ("elasticloadbalancing.amazonaws.com", "DescribeTargetHealth"),
            ("elasticloadbalancing.amazonaws.com", "DescribeListeners"),
            ("elasticloadbalancing.amazonaws.com", "DescribeRules"),
            
            # Service Discovery - Service registry details
            ("servicediscovery.amazonaws.com", "GetNamespace"),
            ("servicediscovery.amazonaws.com", "GetService"),
            ("servicediscovery.amazonaws.com", "ListServices"),
            ("servicediscovery.amazonaws.com", "ListInstances"),
        })
        
        # SENSITIVE_WRITE: Networking operations that modify configurations
        self.sensitive_write.update({
            # Route53 - DNS modifications
            ("route53.amazonaws.com", "ChangeResourceRecordSets"),
            ("route53.amazonaws.com", "CreateHostedZone"),
            ("route53.amazonaws.com", "DeleteHostedZone"),
            ("route53.amazonaws.com", "CreateHealthCheck"),
            ("route53.amazonaws.com", "DeleteHealthCheck"),
            ("route53.amazonaws.com", "CreateTrafficPolicy"),
            ("route53.amazonaws.com", "DeleteTrafficPolicy"),
            
            # API Gateway - API modifications
            ("apigateway.amazonaws.com", "CreateRestApi"),
            ("apigateway.amazonaws.com", "DeleteRestApi"),
            ("apigateway.amazonaws.com", "UpdateRestApi"),
            ("apigateway.amazonaws.com", "CreateResource"),
            ("apigateway.amazonaws.com", "DeleteResource"),
            ("apigateway.amazonaws.com", "PutMethod"),
            ("apigateway.amazonaws.com", "DeleteMethod"),
            ("apigateway.amazonaws.com", "PutIntegration"),
            ("apigateway.amazonaws.com", "DeleteIntegration"),
            ("apigateway.amazonaws.com", "CreateApiKey"),
            ("apigateway.amazonaws.com", "DeleteApiKey"),
            ("apigateway.amazonaws.com", "UpdateApiKey"),
            ("apigateway.amazonaws.com", "CreateUsagePlan"),
            ("apigateway.amazonaws.com", "DeleteUsagePlan"),
            ("apigateway.amazonaws.com", "UpdateUsagePlan"),
            ("apigateway.amazonaws.com", "CreateVpcLink"),
            ("apigateway.amazonaws.com", "DeleteVpcLink"),
            ("apigateway.amazonaws.com", "UpdateVpcLink"),
            ("apigateway.amazonaws.com", "CreateDomainName"),
            ("apigateway.amazonaws.com", "DeleteDomainName"),
            ("apigateway.amazonaws.com", "UpdateDomainName"),
            ("apigateway.amazonaws.com", "CreateAuthorizer"),
            ("apigateway.amazonaws.com", "DeleteAuthorizer"),
            ("apigateway.amazonaws.com", "UpdateAuthorizer"),
            ("apigateway.amazonaws.com", "CreateDeployment"),
            ("apigateway.amazonaws.com", "DeleteDeployment"),
            ("apigateway.amazonaws.com", "UpdateDeployment"),
            ("apigateway.amazonaws.com", "PutGatewayResponse"),
            ("apigateway.amazonaws.com", "DeleteGatewayResponse"),
            ("apigateway.amazonaws.com", "UpdateGatewayResponse"),
            ("apigateway.amazonaws.com", "CreateModel"),
            ("apigateway.amazonaws.com", "DeleteModel"),
            ("apigateway.amazonaws.com", "UpdateModel"),
            ("apigateway.amazonaws.com", "CreateRequestValidator"),
            ("apigateway.amazonaws.com", "DeleteRequestValidator"),
            ("apigateway.amazonaws.com", "UpdateRequestValidator"),
            ("apigateway.amazonaws.com", "CreateStage"),
            ("apigateway.amazonaws.com", "DeleteStage"),
            ("apigateway.amazonaws.com", "UpdateStage"),
            
            # Load Balancer - Load balancer modifications
            ("elasticloadbalancing.amazonaws.com", "CreateLoadBalancer"),
            ("elasticloadbalancing.amazonaws.com", "DeleteLoadBalancer"),
            ("elasticloadbalancing.amazonaws.com", "CreateTargetGroup"),
            ("elasticloadbalancing.amazonaws.com", "DeleteTargetGroup"),
            
            # Service Discovery - Service registry modifications
            ("servicediscovery.amazonaws.com", "CreateNamespace"),
            ("servicediscovery.amazonaws.com", "DeleteNamespace"),
            ("servicediscovery.amazonaws.com", "CreateService"),
            ("servicediscovery.amazonaws.com", "DeleteService"),
            ("servicediscovery.amazonaws.com", "RegisterInstance"),
            ("servicediscovery.amazonaws.com", "DeregisterInstance"),
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance
        self.hacking_reads.update({
            # Route53 - DNS reconnaissance
            ("route53.amazonaws.com", "GetHealthCheck"),
            ("route53.amazonaws.com", "ListHealthChecks"),
            ("route53.amazonaws.com", "GetHostedZone"),
            
            # API Gateway - API endpoint discovery
            ("apigateway.amazonaws.com", "GetRestApis"),
            ("apigateway.amazonaws.com", "GetResources"),
            ("apigateway.amazonaws.com", "GetStages"),
        })
        
        # STRANGE_READS: Unusual networking operations
        self.strange_reads.update({
            # Route53 - Unusual DNS operations
            ("route53.amazonaws.com", "GetTrafficPolicy"),
            ("route53.amazonaws.com", "ListTrafficPolicyVersions"),
            
            # API Gateway - Unusual API operations
            ("apigateway.amazonaws.com", "GetUsage"),
            ("apigateway.amazonaws.com", "GetUsagePlanKey"),
            
            # Load Balancer - Infrastructure load balancing (moved back from infra_reads)
            ("elasticloadbalancing.amazonaws.com", "DescribeLoadBalancers"),
            
            # Service Discovery - Infrastructure service discovery (moved back from infra_reads)
            ("servicediscovery.amazonaws.com", "ListNamespaces"),
        })
        
