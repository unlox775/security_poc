"""
Identity and Security Services Event Classifier

Handles events from IAM, STS, KMS, and other security services.
"""

from .base_classifier import BaseEventClassifier


class IdentityEventClassifier(BaseEventClassifier):
    """
    Classifier for identity and security services.
    
    Handles:
    - iam (Identity and Access Management)
    - sts (Security Token Service)
    - kms (Key Management Service)
    - secretsmanager
    - sso
    - organizations
    """
    
    def _initialize_rules(self):
        """Initialize classification rules for identity services.
        
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
            "iam.amazonaws.com",              # Identity and access management for users/roles/policies
            "sts.amazonaws.com",              # Security token service for temporary credentials
            "kms.amazonaws.com",              # Key management service for encryption keys
            "secretsmanager.amazonaws.com",   # Secrets management for passwords/API keys
            "sso.amazonaws.com",              # Single sign-on for centralized authentication
            "organizations.amazonaws.com",    # Organization management across multiple accounts
            "cognito-identity.amazonaws.com", # Cognito identity pools for unauthenticated users
            "cognito-idp.amazonaws.com",      # Cognito user pools for user directories
            "controltower.amazonaws.com",     # Control Tower for governance and compliance
            "account.amazonaws.com",          # Account management for billing/contact info
            "signin.amazonaws.com",           # Sign-in events and authentication logging
            "acm.amazonaws.com"              # Certificate Manager for SSL/TLS certificates
        }
        
        # SAFE_READ_ONLY: Basic identity information that doesn't expose sensitive data
        self.safe_read_only.update({
            # Organizations - Basic organization information (dashboard reads removed)
            ("organizations.amazonaws.com", "ListRoots"),                     # ✅ Organization root structure - public organizational hierarchy
            ("organizations.amazonaws.com", "ListOrganizationalUnitsForParent"), # ✅ Organizational units - public organizational structure
            ("organizations.amazonaws.com", "ListAccountsForParent"),         # ✅ Account hierarchy - public account organization
            ("organizations.amazonaws.com", "ListCreateAccountStatus"),       # ✅ Account creation status - public account provisioning status

            # IAM - User, role, and policy information
            ("iam.amazonaws.com", "ListUsers"),                             # ✅ User inventory - user account list (administrative inventory, not exploitable - should be safe read)
            ("iam.amazonaws.com", "ListRoles"),                             # ✅ Role inventory - role account list (administrative inventory, not exploitable - should be safe read)
            ("iam.amazonaws.com", "ListPolicies"),                         # ✅ Policy inventory - policy account list (administrative inventory, not exploitable - should be safe read)
            ("iam.amazonaws.com", "ListGroups"),                           # ✅ Group inventory - group account list (administrative inventory, not exploitable - should be safe read)
            ("iam.amazonaws.com", "GetAccountEmailAddress"),               # ✅ Account email - basic account contact info (administrative info, not exploitable - should be safe read)
            ("iam.amazonaws.com", "GetAccountName"),                       # ✅ Account name - basic account identification (administrative info, not exploitable - should be safe read)
            ("iam.amazonaws.com", "ListUserTags"),                           # ✅ User tags - user metadata and categorization (administrative metadata, not exploitable - should be safe read)
            ("iam.amazonaws.com", "GetAccountSummary"),                      # ✅ Account summary - basic account statistics (administrative info, not exploitable - should be safe read)
            ("iam.amazonaws.com", "ListAccountAliases"),                     # ✅ Account aliases - account alias list (administrative inventory, not exploitable - should be safe read)

            # SSO - Single sign-on information
            ("sso.amazonaws.com", "DescribeRegisteredRegions"),              # ✅ SSO regions - public SSO region configuration (administrative config, not exploitable - should be safe read)
            ("sso.amazonaws.com", "GetSSOStatus"),                          # ✅ SSO status - public SSO service status (administrative status, not exploitable - should be safe read)
            ("sso.amazonaws.com", "ListInstances"),                         # ✅ SSO instances - SSO service inventory (administrative inventory, not exploitable - should be safe read)

            # Organizations - Organization information
            ("organizations.amazonaws.com", "ListTagsForResource"),         # ✅ Resource tags - organizational metadata (administrative metadata, not exploitable - should be safe read)
            ("organizations.amazonaws.com", "ListAccounts"),                # ✅ Account inventory - organization account list (administrative inventory, not exploitable - should be safe read)

            # Control Tower - Landing zone information
            ("controltower.amazonaws.com", "ListLandingZones"),             # ✅ Landing zones - governance zone inventory (administrative inventory, not exploitable - should be safe read)

            # Account - Account information
            ("account.amazonaws.com", "ListRegions"),                       # ✅ Available regions - public region list (administrative info, not exploitable - should be safe read)
        })
        
        # SENSITIVE_READ_ONLY: Identity operations that could expose sensitive information
        self.sensitive_read_only.update({
            # IAM - User and role information
            ("iam.amazonaws.com", "GetUser"),                               # ✅ User details - user account information
            ("iam.amazonaws.com", "GetRole"),                               # ✅ Role details - role configuration and permissions
            ("iam.amazonaws.com", "ListAttachedRolePolicies"),             # ✅ Role policy attachments - role permission assignments
            ("iam.amazonaws.com", "ListRolePolicies"),                     # ✅ Role inline policies - role permission definitions
            ("iam.amazonaws.com", "GetRolePolicy"),                        # ✅ Role policy content - role permission details
            ("iam.amazonaws.com", "GetPolicy"),                            # ✅ Policy details - policy configuration and permissions
            ("iam.amazonaws.com", "GetPolicyVersion"),                     # ✅ Policy version details - policy version content
            ("iam.amazonaws.com", "ListPolicyVersions"),                   # ✅ Policy version history - policy version inventory
            ("iam.amazonaws.com", "GetGroup"),                             # ✅ Group details - group configuration and membership
            ("iam.amazonaws.com", "ListAttachedGroupPolicies"),            # ✅ Group policy attachments - group permission assignments
            ("iam.amazonaws.com", "ListGroupPolicies"),                    # ✅ Group inline policies - group permission definitions
            ("iam.amazonaws.com", "GetGroupPolicy"),                       # ✅ Group policy content - group permission details
            ("iam.amazonaws.com", "ListMFADevices"),                       # ✅ MFA device inventory - multi-factor authentication devices
            ("iam.amazonaws.com", "GetMFADevice"),                         # ✅ MFA device details - multi-factor authentication configuration
            ("iam.amazonaws.com", "GetInstanceProfile"),                   # ✅ Instance profile details - EC2 role assignment configuration
            ("iam.amazonaws.com", "ListAttachedUserPolicies"),             # ✅ User policy attachments - user permission assignments
            ("iam.amazonaws.com", "ListCloudFrontPublicKeys"),             # ✅ CloudFront public keys - content delivery network keys
            ("iam.amazonaws.com", "ListGroupsForUser"),                    # ✅ User group memberships - user group associations
            ("iam.amazonaws.com", "ListServerCertificates"),               # ✅ Server certificate inventory - SSL/TLS certificate list
            ("iam.amazonaws.com", "ListSigningCertificates"),                # ✅ Signing certificate inventory - code signing certificates
            ("iam.amazonaws.com", "ListUserPolicies"),                       # ✅ User inline policies - user permission definitions
            
            # SSO - Single sign-on information
            ("sso.amazonaws.com", "ListDirectoryAssociations"),             # ✅ Directory associations - identity provider connections
            
            # Organizations - Account and policy information
            ("organizations.amazonaws.com", "AcceptHandshake"),             # ✅ Accept handshake - organization invitation acceptance
            ("organizations.amazonaws.com", "DescribeAccount"),             # ✅ Account details - account configuration and settings
            ("organizations.amazonaws.com", "DescribeResourcePolicy"),      # ✅ Resource policy - organization resource access policies
            ("organizations.amazonaws.com", "ListAWSServiceAccessForOrganization"), # ✅ Service access - organization service permissions
            ("organizations.amazonaws.com", "ListDelegatedAdministrators"), # ✅ Delegated administrators - cross-account admin assignments
            ("organizations.amazonaws.com", "ListHandshakesForAccount"),    # ✅ Account handshakes - organization invitation status
            ("organizations.amazonaws.com", "ListHandshakesForOrganization"), # ✅ Organization handshakes - organization invitation management
            ("organizations.amazonaws.com", "ListParents"),                 # ✅ Parent accounts - account hierarchy relationships
            
            # STS - Token and identity information
            ("sts.amazonaws.com", "GetCallerIdentity"),                      # ✅ Caller identity - current identity context
            ("sts.amazonaws.com", "AssumeRoleWithSAML"),                     # ✅ SAML role assumption - federated identity role access
            ("sts.amazonaws.com", "AssumeRole"),                             # ✅ Role assumption - cross-account role access
            ("sts.amazonaws.com", "AssumeRoleWithWebIdentity"),              # ✅ Web identity role assumption - OIDC federated access
            ("sts.amazonaws.com", "GetSessionToken"),                        # ✅ Session token - temporary credential generation
            ("sts.amazonaws.com", "GetFederationToken"),                     # ✅ Federation token - cross-service access delegation
            
            # KMS - Key information and decryption
            ("kms.amazonaws.com", "Decrypt"),                                # ✅ Data decryption - encrypted data access (should be hacking reads)
            ("kms.amazonaws.com", "DescribeKey"),                            # ✅ Key details - encryption key configuration
            ("kms.amazonaws.com", "ListKeys"),                               # ✅ Key inventory - encryption key list
            ("kms.amazonaws.com", "ListAliases"),                            # ✅ Key aliases - encryption key alias list
            ("kms.amazonaws.com", "GetKeyPolicy"),                           # ✅ Key policy - encryption key access policies
            ("kms.amazonaws.com", "ListKeyPolicies"),                        # ✅ Key policy inventory - encryption key policy list
            ("kms.amazonaws.com", "ListGrants"),                             # ✅ Key grants - encryption key access permissions
            ("kms.amazonaws.com", "GetKeyRotationStatus"),                   # ✅ Key rotation status - encryption key rotation configuration
            
            # Secrets Manager - Secret information
            ("secretsmanager.amazonaws.com", "DescribeSecret"),              # ✅ Secret metadata - secret configuration details
            ("secretsmanager.amazonaws.com", "ListSecrets"),                # ✅ Secret inventory - secret service list
            ("secretsmanager.amazonaws.com", "GetResourcePolicy"),           # ✅ Secret resource policy - secret access policies
            
            # SSO - Single sign-on information
            ("sso.amazonaws.com", "ListAccounts"),                          # ✅ SSO accounts - SSO account list
            ("sso.amazonaws.com", "ListAccountRoles"),                      # ✅ SSO account roles - cross-account role assignments
            
            # Cognito - Identity service details (moved from misc)
            ("cognito-identity.amazonaws.com", "ListIdentityPools"),         # ✅ Identity pools - Cognito identity pool inventory
            ("cognito-idp.amazonaws.com", "ListUserPools"),                  # ✅ User pools - Cognito user pool inventory
            
            # Control Tower - Landing zone information (moved from misc)
            ("controltower.amazonaws.com", "GetLandingZoneStatus"),         # ✅ Landing zone status - governance configuration status
            ("controltower.amazonaws.com", "ListEnabledControls"),          # ✅ Enabled controls - governance policy enforcement
            
            # Account - Account information (moved from misc)
            ("account.amazonaws.com", "GetAccountInformation"),             # ✅ Account information - account configuration details
            
            # Sign-in - Authentication events (moved from misc)
            ("signin.amazonaws.com", "ConsoleLogin"),                       # ✅ Console login - authentication event tracking
            
            # ACM - Certificate information (moved from simple storage)
            ("acm.amazonaws.com", "DescribeCertificate"),                    # ✅ Certificate details - SSL/TLS certificate configuration
            ("acm.amazonaws.com", "ListCertificates"),                      # ✅ Certificate inventory - SSL/TLS certificate list
        })
        
        # SENSITIVE_WRITE: Identity operations that modify permissions or credentials
        self.sensitive_write.update({
            # IAM - User and role modifications
            ("iam.amazonaws.com", "CreateUser"),                             # ✅ Create user - user account creation
            ("iam.amazonaws.com", "DeleteUser"),                             # ✅ Delete user - user account removal
            ("iam.amazonaws.com", "CreateRole"),                             # ✅ Create role - role account creation
            ("iam.amazonaws.com", "DeleteRole"),                             # ✅ Delete role - role account removal
            ("iam.amazonaws.com", "AttachRolePolicy"),                       # ✅ Attach role policy - role permission assignment
            ("iam.amazonaws.com", "DetachRolePolicy"),                       # ✅ Detach role policy - role permission removal
            ("iam.amazonaws.com", "PutRolePolicy"),                          # ✅ Put role policy - role inline policy creation
            ("iam.amazonaws.com", "DeleteRolePolicy"),                       # ✅ Delete role policy - role inline policy removal
            ("iam.amazonaws.com", "CreatePolicy"),                           # ✅ Create policy - permission policy creation
            ("iam.amazonaws.com", "DeletePolicy"),                           # ✅ Delete policy - permission policy removal
            ("iam.amazonaws.com", "CreatePolicyVersion"),                    # ✅ Create policy version - policy version creation
            ("iam.amazonaws.com", "DeletePolicyVersion"),                    # ✅ Delete policy version - policy version removal
            ("iam.amazonaws.com", "CreateGroup"),                            # ✅ Create group - group account creation
            ("iam.amazonaws.com", "DeleteGroup"),                            # ✅ Delete group - group account removal
            ("iam.amazonaws.com", "AddUserToGroup"),                         # ✅ Add user to group - group membership assignment
            ("iam.amazonaws.com", "RemoveUserFromGroup"),                    # ✅ Remove user from group - group membership removal
            ("iam.amazonaws.com", "CreateAccessKey"),                        # ✅ Create access key - credential generation
            ("iam.amazonaws.com", "DeleteAccessKey"),                        # ✅ Delete access key - credential removal
            ("iam.amazonaws.com", "UpdateAccessKey"),                        # ✅ Update access key - credential modification
            ("iam.amazonaws.com", "CreateVirtualMFADevice"),                 # ✅ Create virtual MFA device - multi-factor authentication setup
            ("iam.amazonaws.com", "DeleteVirtualMFADevice"),                 # ✅ Delete virtual MFA device - multi-factor authentication removal
            ("iam.amazonaws.com", "EnableMFADevice"),                        # ✅ Enable MFA device - multi-factor authentication activation
            ("iam.amazonaws.com", "DeactivateMFADevice"),                    # ✅ Deactivate MFA device - multi-factor authentication deactivation
            ("iam.amazonaws.com", "ChangePassword"),                         # ✅ Change password - user password modification
            ("iam.amazonaws.com", "CreateServiceLinkedRole"),                # ✅ Create service linked role - service-specific role creation
            
            # KMS - Key operations
            ("kms.amazonaws.com", "GenerateDataKey"),                        # ✅ Generate data key - encryption key generation
            ("kms.amazonaws.com", "GenerateDataKeyWithoutPlaintext"),        # ✅ Generate data key without plaintext - secure key generation
            ("kms.amazonaws.com", "GenerateRandom"),                         # ✅ Generate random - cryptographic random number generation
            ("kms.amazonaws.com", "Encrypt"),                                # ✅ Encrypt data - data encryption operation
            ("kms.amazonaws.com", "CreateKey"),                              # ✅ Create key - encryption key creation
            ("kms.amazonaws.com", "DeleteKey"),                              # ✅ Delete key - encryption key removal
            ("kms.amazonaws.com", "PutKeyPolicy"),                           # ✅ Put key policy - encryption key access policy
            ("kms.amazonaws.com", "CreateAlias"),                            # ✅ Create alias - encryption key alias creation
            ("kms.amazonaws.com", "DeleteAlias"),                            # ✅ Delete alias - encryption key alias removal
            ("kms.amazonaws.com", "UpdateAlias"),                            # ✅ Update alias - encryption key alias modification
            ("kms.amazonaws.com", "CreateGrant"),                            # ✅ Create grant - encryption key access grant
            ("kms.amazonaws.com", "RevokeGrant"),                            # ✅ Revoke grant - encryption key access revocation
            ("kms.amazonaws.com", "EnableKeyRotation"),                      # ✅ Enable key rotation - encryption key rotation activation
            ("kms.amazonaws.com", "DisableKeyRotation"),                     # ✅ Disable key rotation - encryption key rotation deactivation
            
            # Secrets Manager - Secret modifications
            ("secretsmanager.amazonaws.com", "CreateSecret"),                # ✅ Create secret - secret credential creation
            ("secretsmanager.amazonaws.com", "DeleteSecret"),                # ✅ Delete secret - secret credential removal
            ("secretsmanager.amazonaws.com", "UpdateSecret"),                # ✅ Update secret - secret credential modification
            ("secretsmanager.amazonaws.com", "PutSecretValue"),              # ✅ Put secret value - secret credential value update
            ("secretsmanager.amazonaws.com", "PutResourcePolicy"),           # ✅ Put resource policy - secret access policy
            ("secretsmanager.amazonaws.com", "DeleteResourcePolicy"),        # ✅ Delete resource policy - secret access policy removal
            ("secretsmanager.amazonaws.com", "TagResource"),                 # ✅ Tag resource - secret metadata tagging
            ("secretsmanager.amazonaws.com", "UntagResource"),               # ✅ Untag resource - secret metadata tag removal
            
            # Organizations - Organization modifications
            ("organizations.amazonaws.com", "CreateOrganization"),           # ✅ Create organization - multi-account organization creation
            ("organizations.amazonaws.com", "DeleteOrganization"),           # ✅ Delete organization - multi-account organization removal
            ("organizations.amazonaws.com", "CreateOrganizationalUnit"),     # ✅ Create organizational unit - organizational structure creation
            ("organizations.amazonaws.com", "DeleteOrganizationalUnit"),     # ✅ Delete organizational unit - organizational structure removal
            ("organizations.amazonaws.com", "CreateAccount"),                # ✅ Create account - new account creation
            ("organizations.amazonaws.com", "CloseAccount"),                 # ✅ Close account - account closure
            
            # Cognito - Identity modifications (moved from misc)
            ("cognito-identity.amazonaws.com", "CreateIdentityPool"),        # ✅ Create identity pool - unauthenticated user pool creation
            ("cognito-identity.amazonaws.com", "DeleteIdentityPool"),        # ✅ Delete identity pool - unauthenticated user pool removal
            ("cognito-idp.amazonaws.com", "CreateUserPool"),                 # ✅ Create user pool - user directory creation
            ("cognito-idp.amazonaws.com", "DeleteUserPool"),                 # ✅ Delete user pool - user directory removal
            
            # Account - Account modifications (moved from misc)
            ("account.amazonaws.com", "UpdateAccountInformation"),           # ✅ Update account information - account configuration modification
            ("account.amazonaws.com", "UpdateAlternateContact"),             # ✅ Update alternate contact - account contact modification
            ("account.amazonaws.com", "UpdateContactInformation"),           # ✅ Update contact information - account contact modification
            
            # Control Tower - Landing zone operations (moved from misc)
            ("controltower.amazonaws.com", "CreateLandingZone"),             # ✅ Create landing zone - governance zone creation
            ("controltower.amazonaws.com", "DeleteLandingZone"),             # ✅ Delete landing zone - governance zone removal
            ("controltower.amazonaws.com", "UpdateLandingZone"),             # ✅ Update landing zone - governance zone modification
            
            # Sign-in - Authentication changes (moved from misc)
            ("signin.amazonaws.com", "PasswordUpdated"),                     # ✅ Password updated - authentication credential change
        })
        
        # HACKING_READS: Operations that could be used for privilege escalation or reconnaissance
        self.hacking_reads.update({
            # IAM - Policy analysis for privilege escalation
            ("iam.amazonaws.com", "SimulatePrincipalPolicy"),                # ✅ Principal policy simulation - privilege escalation testing
            ("iam.amazonaws.com", "SimulateCustomPolicy"),                   # ✅ Custom policy simulation - privilege escalation testing
            ("iam.amazonaws.com", "GenerateServiceLastAccessedDetails"),     # ✅ Service access details generation - access pattern analysis
            ("iam.amazonaws.com", "GetServiceLastAccessedDetails"),          # ✅ Service access details retrieval - access pattern analysis
            ("iam.amazonaws.com", "ListAccessKeys"),                       # ✅ Access key inventory - credential enumeration (should be hacking reads)
            ("iam.amazonaws.com", "GetAccessKeyLastUsed"),                 # ✅ Access key usage - credential activity tracking (should be hacking reads)
            ("iam.amazonaws.com", "GetLoginProfile"),                      # ✅ Login profile details - user login configuration (should be hacking reads)
            ("iam.amazonaws.com", "ListSSHPublicKeys"),                    # ✅ SSH public keys - server access credentials (should be hacking reads)
            ("iam.amazonaws.com", "ListServiceSpecificCredentials"),         # ✅ Service-specific credentials - application-specific access keys (should be hacking reads)
            ("iam.amazonaws.com", "GetCredentialReport"),                    # ✅ Credential report - comprehensive access analysis
            
            # STS - Token manipulation
            ("sts.amazonaws.com", "DecodeAuthorizationMessage"),             # ✅ Authorization message decoding - token analysis

            # Secrets Manager - Secret value retrieval
            ("secretsmanager.amazonaws.com", "GetSecretValue"),              # ✅ Secret value retrieval - sensitive credential access (should be hacking reads)

            # Account - Account information
            ("account.amazonaws.com", "GetContactInformation"),             # ✅ Contact information - account contact details (should be hacking reads)
            ("account.amazonaws.com", "GetAlternateContact"),               # ✅ Alternate contact - account contact information (should be hacking reads)

            # SSO - SSO role credentials
            ("sso.amazonaws.com", "GetRoleCredentials"),                    # ✅ SSO role credentials - temporary access credential retrieval (should be hacking reads)

            # KMS - Unusual key operations
            ("kms.amazonaws.com", "GetParametersForImport"),                 # ✅ Import parameters - key material import preparation
            ("kms.amazonaws.com", "ImportKeyMaterial"),                      # ✅ Import key material - external key material import
        })
        
        # STRANGE_READS: Unusual identity operations
        self.strange_reads.update({
        })
        
