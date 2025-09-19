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
            ("route53.amazonaws.com", "GetChange"),                          # ✅ DNS change status - public change tracking
            ("route53.amazonaws.com", "GetHealthCheckCount"),               # ✅ Health check count - public monitoring stats
            ("route53.amazonaws.com", "GetHostedZoneCount"),                # ✅ Hosted zone count - public zone statistics
            ("route53.amazonaws.com", "GetTrafficPolicyInstanceCount"),     # ✅ Traffic policy count - public policy stats
            ("route53domains.amazonaws.com", "ListDomains"),                # ✅ Domain inventory - public domain list
            ("route53domains.amazonaws.com", "ListOperations"),             # ✅ Domain operations - public operation history
            ("route53.amazonaws.com", "ListHostedZones"),                    # ✅ Hosted zone inventory - DNS zone listing (administrative inventory, not exploitable - should be safe read)
            ("route53.amazonaws.com", "ListHostedZonesByName"),              # ✅ Hosted zones by name - DNS zone lookup (administrative inventory, not exploitable - should be safe read)
            ("route53.amazonaws.com", "ListTagsForResource"),               # ✅ DNS resource tags - zone metadata (administrative metadata, not exploitable - should be safe read)
            ("route53resolver.amazonaws.com", "ListFirewallRuleGroups"),     # ✅ DNS firewall rule groups - security rule collections (administrative inventory, not exploitable - should be safe read)
        })
        
        # SENSITIVE_READ_ONLY: Networking operations that could expose sensitive information
        self.sensitive_read_only.update({
            # Route53 - DNS configuration details
            ("route53.amazonaws.com", "ListQueryLoggingConfigs"),            # ✅ DNS query logging - DNS monitoring configuration
            ("route53.amazonaws.com", "ListTrafficPolicies"),               # ✅ Traffic policies - DNS routing rules
            ("route53.amazonaws.com", "GetTrafficPolicy"),                    # ✅ Traffic policy details - DNS routing policy analysis
            ("route53.amazonaws.com", "ListTrafficPolicyVersions"),          # ✅ Traffic policy versions - DNS routing policy version history
            
            # Route53 Resolver - DNS security configuration
            ("route53resolver.amazonaws.com", "ListFirewallDomainLists"),    # ✅ DNS firewall domains - DNS security rules
            ("route53resolver.amazonaws.com", "ListFirewallRuleGroupAssociations"), # ✅ DNS firewall associations - security rule mapping
            
            # API Gateway - API configuration
            ("apigateway.amazonaws.com", "GetUsagePlan"),                   # ✅ Usage plan details - API rate limiting and quotas
            ("apigateway.amazonaws.com", "GetDomainName"),                  # ✅ Domain name details - custom domain configuration
            ("apigateway.amazonaws.com", "GetStage"),                       # ✅ Stage details - API deployment stage configuration
            ("apigateway.amazonaws.com", "GetAccount"),                     # ✅ Account details - API Gateway account configuration
            ("apigateway.amazonaws.com", "GetUsage"),                        # ✅ API usage - API consumption analysis
            ("apigateway.amazonaws.com", "GetUsagePlanKey"),                 # ✅ Usage plan key - API rate limiting key analysis
            
            # Load Balancer - Load balancer configuration
            ("elasticloadbalancing.amazonaws.com", "DescribeTargetGroups"),   # ✅ Target groups - load balancer target configuration
            ("elasticloadbalancing.amazonaws.com", "DescribeTargetHealth"),   # ✅ Target health - load balancer health status
            
            # Service Discovery - Service registry details
            ("servicediscovery.amazonaws.com", "GetNamespace"),              # ✅ Namespace details - service discovery namespace configuration
            ("servicediscovery.amazonaws.com", "GetService"),                # ✅ Service details - service discovery service configuration
            ("servicediscovery.amazonaws.com", "ListNamespaces"),             # ✅ Namespaces - service discovery namespace inventory (administrative inventory, not exploitable - should be safe read)            
        })
        
        # SENSITIVE_WRITE: Networking operations that modify configurations
        self.sensitive_write.update({
            # Route53 - DNS modifications
            ("route53.amazonaws.com", "ChangeResourceRecordSets"),            # ✅ Change DNS records - DNS zone record modifications
            ("route53.amazonaws.com", "CreateHostedZone"),                   # ✅ Create hosted zone - DNS zone creation
            ("route53.amazonaws.com", "DeleteHostedZone"),                   # ✅ Delete hosted zone - DNS zone removal
            ("route53.amazonaws.com", "CreateHealthCheck"),                  # ✅ Create health check - DNS health monitoring setup
            ("route53.amazonaws.com", "DeleteHealthCheck"),                  # ✅ Delete health check - DNS health monitoring removal
            ("route53.amazonaws.com", "CreateTrafficPolicy"),                # ✅ Create traffic policy - DNS routing policy creation
            ("route53.amazonaws.com", "DeleteTrafficPolicy"),                # ✅ Delete traffic policy - DNS routing policy removal
            
            # API Gateway - API modifications
            ("apigateway.amazonaws.com", "CreateRestApi"),                   # ✅ Create REST API - API gateway creation
            ("apigateway.amazonaws.com", "DeleteRestApi"),                   # ✅ Delete REST API - API gateway removal
            ("apigateway.amazonaws.com", "UpdateRestApi"),                   # ✅ Update REST API - API gateway modification
            ("apigateway.amazonaws.com", "CreateResource"),                  # ✅ Create resource - API endpoint creation
            ("apigateway.amazonaws.com", "DeleteResource"),                  # ✅ Delete resource - API endpoint removal
            ("apigateway.amazonaws.com", "PutMethod"),                       # ✅ Put method - API HTTP method configuration
            ("apigateway.amazonaws.com", "DeleteMethod"),                    # ✅ Delete method - API HTTP method removal
            ("apigateway.amazonaws.com", "PutIntegration"),                  # ✅ Put integration - API backend integration setup
            ("apigateway.amazonaws.com", "DeleteIntegration"),               # ✅ Delete integration - API backend integration removal
            ("apigateway.amazonaws.com", "CreateApiKey"),                    # ✅ Create API key - API authentication credential creation
            ("apigateway.amazonaws.com", "DeleteApiKey"),                    # ✅ Delete API key - API authentication credential removal
            ("apigateway.amazonaws.com", "UpdateApiKey"),                    # ✅ Update API key - API authentication credential modification
            ("apigateway.amazonaws.com", "CreateUsagePlan"),                 # ✅ Create usage plan - API rate limiting policy creation
            ("apigateway.amazonaws.com", "DeleteUsagePlan"),                 # ✅ Delete usage plan - API rate limiting policy removal
            ("apigateway.amazonaws.com", "UpdateUsagePlan"),                 # ✅ Update usage plan - API rate limiting policy modification
            ("apigateway.amazonaws.com", "CreateVpcLink"),                   # ✅ Create VPC link - private API backend connection setup
            ("apigateway.amazonaws.com", "DeleteVpcLink"),                   # ✅ Delete VPC link - private API backend connection removal
            ("apigateway.amazonaws.com", "UpdateVpcLink"),                   # ✅ Update VPC link - private API backend connection modification
            ("apigateway.amazonaws.com", "CreateDomainName"),               # ✅ Create domain name - custom domain setup
            ("apigateway.amazonaws.com", "DeleteDomainName"),               # ✅ Delete domain name - custom domain removal
            ("apigateway.amazonaws.com", "UpdateDomainName"),               # ✅ Update domain name - custom domain modification
            ("apigateway.amazonaws.com", "CreateAuthorizer"),               # ✅ Create authorizer - API authentication setup
            ("apigateway.amazonaws.com", "DeleteAuthorizer"),               # ✅ Delete authorizer - API authentication removal
            ("apigateway.amazonaws.com", "UpdateAuthorizer"),               # ✅ Update authorizer - API authentication modification
            ("apigateway.amazonaws.com", "CreateDeployment"),               # ✅ Create deployment - API deployment creation
            ("apigateway.amazonaws.com", "DeleteDeployment"),               # ✅ Delete deployment - API deployment removal
            ("apigateway.amazonaws.com", "UpdateDeployment"),               # ✅ Update deployment - API deployment modification
            ("apigateway.amazonaws.com", "PutGatewayResponse"),             # ✅ Put gateway response - API error response configuration
            ("apigateway.amazonaws.com", "DeleteGatewayResponse"),          # ✅ Delete gateway response - API error response removal
            ("apigateway.amazonaws.com", "UpdateGatewayResponse"),          # ✅ Update gateway response - API error response modification
            ("apigateway.amazonaws.com", "CreateModel"),                    # ✅ Create model - API data model creation
            ("apigateway.amazonaws.com", "DeleteModel"),                    # ✅ Delete model - API data model removal
            ("apigateway.amazonaws.com", "UpdateModel"),                    # ✅ Update model - API data model modification
            ("apigateway.amazonaws.com", "CreateRequestValidator"),         # ✅ Create request validator - API validation setup
            ("apigateway.amazonaws.com", "DeleteRequestValidator"),         # ✅ Delete request validator - API validation removal
            ("apigateway.amazonaws.com", "UpdateRequestValidator"),         # ✅ Update request validator - API validation modification
            ("apigateway.amazonaws.com", "CreateStage"),                    # ✅ Create stage - API deployment stage creation
            ("apigateway.amazonaws.com", "DeleteStage"),                    # ✅ Delete stage - API deployment stage removal
            ("apigateway.amazonaws.com", "UpdateStage"),                    # ✅ Update stage - API deployment stage modification
            
            # Load Balancer - Load balancer modifications
            ("elasticloadbalancing.amazonaws.com", "CreateLoadBalancer"),   # ✅ Create load balancer - load balancing setup
            ("elasticloadbalancing.amazonaws.com", "DeleteLoadBalancer"),   # ✅ Delete load balancer - load balancing removal
            ("elasticloadbalancing.amazonaws.com", "CreateTargetGroup"),    # ✅ Create target group - load balancer target setup
            ("elasticloadbalancing.amazonaws.com", "DeleteTargetGroup"),    # ✅ Delete target group - load balancer target removal
            
            # Service Discovery - Service registry modifications
            ("servicediscovery.amazonaws.com", "CreateNamespace"),           # ✅ Create namespace - service discovery namespace creation
            ("servicediscovery.amazonaws.com", "DeleteNamespace"),           # ✅ Delete namespace - service discovery namespace removal
            ("servicediscovery.amazonaws.com", "CreateService"),             # ✅ Create service - service discovery service creation
            ("servicediscovery.amazonaws.com", "DeleteService"),             # ✅ Delete service - service discovery service removal
            ("servicediscovery.amazonaws.com", "RegisterInstance"),          # ✅ Register instance - service instance registration
            ("servicediscovery.amazonaws.com", "DeregisterInstance"),        # ✅ Deregister instance - service instance deregistration
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance
        self.hacking_reads.update({
            # Route53 - DNS reconnaissance
            ("route53.amazonaws.com", "GetHealthCheck"),                     # ✅ Health check details - DNS health monitoring analysis
            ("route53.amazonaws.com", "ListHealthChecks"),                   # ✅ Health check inventory - DNS health monitoring reconnaissance
            ("route53.amazonaws.com", "GetHostedZone"),                      # ✅ Hosted zone details - DNS zone configuration analysis
            ("route53.amazonaws.com", "ListResourceRecordSets"),             # ✅ DNS records - zone file contents (DNS reconnaissance for domain mapping - should be hacking reads)
            
            # API Gateway - API endpoint discovery
            ("apigateway.amazonaws.com", "GetRestApis"),                     # ✅ REST API inventory - API endpoint reconnaissance
            ("apigateway.amazonaws.com", "GetResources"),                    # ✅ API resources - API endpoint mapping
            ("apigateway.amazonaws.com", "GetStages"),                       # ✅ API stages - API deployment reconnaissance

            # Network Firewall - Security configuration
            ("network-firewall.amazonaws.com", "ListFirewallPolicies"),      # ✅ Firewall policies - network security policies (administrative inventory, not exploitable - should be safe read)
            ("network-firewall.amazonaws.com", "ListFirewalls"),             # ✅ Firewall inventory - network security devices (administrative inventory, not exploitable - should be safe read)
            ("network-firewall.amazonaws.com", "ListRuleGroups"),            # ✅ Firewall rule groups - security rule collections (administrative inventory, not exploitable - should be safe read)
            ("network-firewall.amazonaws.com", "ListTLSInspectionConfigurations"), # ✅ TLS inspection configs - SSL/TLS security settings (administrative inventory, not exploitable - should be safe read)
            ("network-firewall.amazonaws.com", "DescribeRuleGroupMetadata"), # ✅ Firewall rule metadata - network security rules

            # Load Balancer - Load balancer configuration
            ("elasticloadbalancing.amazonaws.com", "DescribeLoadBalancers"), # ✅ Load balancers - load balancer inventory (administrative inventory, not exploitable - should be safe read)
            ("elasticloadbalancing.amazonaws.com", "DescribeListeners"),      # ✅ Listeners - load balancer listener configuration
            ("elasticloadbalancing.amazonaws.com", "DescribeRules"),         # ✅ Rules - load balancer routing rules

            # VPC Lattice - Network service discovery
            ("vpc-lattice.amazonaws.com", "ListServices"),                   # ✅ Lattice services - service-to-service networking (administrative inventory, not exploitable - should be safe read)
            ("vpc-lattice.amazonaws.com", "ListTargetGroups"),               # ✅ Lattice target groups - service routing targets (administrative inventory, not exploitable - should be safe read)

            # API Gateway - API configuration
            ("apigateway.amazonaws.com", "GetVpcLinks"),                    # ✅ VPC links - VPC link inventory (administrative inventory, not exploitable - should be safe read)
            ("apigateway.amazonaws.com", "GetDomainNames"),                 # ✅ Domain names - domain name inventory (administrative inventory, not exploitable - should be safe read)
            ("apigateway.amazonaws.com", "GetClientCertificates"),          # ✅ Client certificates - certificate inventory (administrative inventory, not exploitable - should be safe read)
            ("apigateway.amazonaws.com", "GetAuthorizers"),                 # ✅ Authorizers - authorizer inventory (administrative inventory, not exploitable - should be safe read)
            ("apigateway.amazonaws.com", "GetAuthorizer"),                  # ✅ Authorizer details - API authentication configuration
            ("apigateway.amazonaws.com", "GetGatewayResponse"),             # ✅ Gateway response details - API error response configuration
            ("apigateway.amazonaws.com", "GetGatewayResponses"),            # ✅ Gateway responses - response configuration inventory (administrative inventory, not exploitable - should be safe read)
            ("apigateway.amazonaws.com", "GetApiKey"),                      # ✅ API key details - authentication credentials (credential access - should be hacking reads)
            ("apigateway.amazonaws.com", "GetApiKeys"),                     # ✅ API key inventory - authentication credential listing (credential enumeration - should be hacking reads)
            ("apigateway.amazonaws.com", "GetIntegrations"),                # ✅ Integrations - integration inventory (administrative inventory, not exploitable - should be safe read)
            ("apigateway.amazonaws.com", "GetModel"),                       # ✅ Model details - API data model configuration
            ("apigateway.amazonaws.com", "GetModels"),                      # ✅ Models - data model inventory (administrative inventory, not exploitable - should be safe read)
            ("apigateway.amazonaws.com", "GetApi"),                         # ✅ API details - HTTP API configuration
            ("apigateway.amazonaws.com", "GetApis"),                        # ✅ APIs - HTTP API inventory (administrative inventory, not exploitable - should be safe read)
            ("apigateway.amazonaws.com", "GetRoutes"),                      # ✅ Routes - API route inventory (administrative inventory, not exploitable - should be safe read)
            ("apigateway.amazonaws.com", "GetRestApi"),                     # ✅ REST API details - API configuration and endpoints
            ("apigateway.amazonaws.com", "GetResource"),                    # ✅ API resource details - endpoint configuration
            ("apigateway.amazonaws.com", "GetMethod"),                      # ✅ API method details - HTTP method configuration
            ("apigateway.amazonaws.com", "GetIntegration"),                 # ✅ API integration details - backend service connections
            ("apigateway.amazonaws.com", "GetVpcLink"),                     # ✅ VPC link details - private API backend connections
            ("apigateway.amazonaws.com", "GetClientCertificate"),           # ✅ Client certificate details - SSL/TLS certificate configuration
            ("apigateway.amazonaws.com", "GetRequestValidator"),            # ✅ Request validator details - API request validation configuration
            ("apigateway.amazonaws.com", "GetRequestValidators"),           # ✅ Request validators - validator inventory (administrative inventory, not exploitable - should be safe read)

            # Service Discovery - Service discovery configuration
            ("servicediscovery.amazonaws.com", "ListServices"),              # ✅ Services - service discovery service inventory (administrative inventory, not exploitable - should be safe read)
            ("servicediscovery.amazonaws.com", "ListInstances"),             # ✅ Instances - service instance inventory (administrative inventory, not exploitable - should be safe read)
        })
        
        # STRANGE_READS: Unusual networking operations
        self.strange_reads.update({
        })
        
