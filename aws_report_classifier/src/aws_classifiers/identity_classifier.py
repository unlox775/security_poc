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
        """Initialize classification rules for identity services."""
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
            ("organizations.amazonaws.com", "ListRoots"),
            ("organizations.amazonaws.com", "ListOrganizationalUnitsForParent"),
            ("organizations.amazonaws.com", "ListAccountsForParent"),
            ("organizations.amazonaws.com", "ListCreateAccountStatus"),
        })
        
        # SENSITIVE_READ_ONLY: Identity operations that could expose sensitive information
        self.sensitive_read_only.update({
            # IAM - User and role information
            ("iam.amazonaws.com", "GetUser"),
            ("iam.amazonaws.com", "ListUsers"),
            ("iam.amazonaws.com", "GetRole"),
            ("iam.amazonaws.com", "ListRoles"),
            ("iam.amazonaws.com", "ListAttachedRolePolicies"),
            ("iam.amazonaws.com", "ListRolePolicies"),
            ("iam.amazonaws.com", "GetRolePolicy"),
            ("iam.amazonaws.com", "ListPolicies"),
            ("iam.amazonaws.com", "GetPolicy"),
            ("iam.amazonaws.com", "GetPolicyVersion"),
            ("iam.amazonaws.com", "ListPolicyVersions"),
            ("iam.amazonaws.com", "ListGroups"),
            ("iam.amazonaws.com", "GetGroup"),
            ("iam.amazonaws.com", "ListAttachedGroupPolicies"),
            ("iam.amazonaws.com", "ListGroupPolicies"),
            ("iam.amazonaws.com", "GetGroupPolicy"),
            ("iam.amazonaws.com", "ListAccessKeys"),
            ("iam.amazonaws.com", "GetAccessKeyLastUsed"),
            ("iam.amazonaws.com", "ListMFADevices"),
            ("iam.amazonaws.com", "GetMFADevice"),
            
            # STS - Token and identity information
            ("sts.amazonaws.com", "GetCallerIdentity"),
            ("sts.amazonaws.com", "AssumeRoleWithSAML"),
            ("sts.amazonaws.com", "AssumeRole"),
            ("sts.amazonaws.com", "AssumeRoleWithWebIdentity"),
            ("sts.amazonaws.com", "GetSessionToken"),
            ("sts.amazonaws.com", "GetFederationToken"),
            
            # KMS - Key information and decryption
            ("kms.amazonaws.com", "Decrypt"),
            ("kms.amazonaws.com", "DescribeKey"),
            ("kms.amazonaws.com", "ListKeys"),
            ("kms.amazonaws.com", "ListAliases"),
            ("kms.amazonaws.com", "GetKeyPolicy"),
            ("kms.amazonaws.com", "ListKeyPolicies"),
            ("kms.amazonaws.com", "ListGrants"),
            ("kms.amazonaws.com", "GetKeyRotationStatus"),
            
            # Secrets Manager - Secret information
            ("secretsmanager.amazonaws.com", "GetSecretValue"),
            ("secretsmanager.amazonaws.com", "DescribeSecret"),
            ("secretsmanager.amazonaws.com", "ListSecrets"),
            ("secretsmanager.amazonaws.com", "GetResourcePolicy"),
            
            # SSO - Single sign-on information
            ("sso.amazonaws.com", "ListAccounts"),
            ("sso.amazonaws.com", "ListAccountRoles"),
            ("sso.amazonaws.com", "GetRoleCredentials"),
            
            # Cognito - Identity service details (moved from misc)
            ("cognito-identity.amazonaws.com", "ListIdentityPools"),
            ("cognito-idp.amazonaws.com", "ListUserPools"),
            
            # Control Tower - Landing zone information (moved from misc)
            ("controltower.amazonaws.com", "GetLandingZoneStatus"),
            ("controltower.amazonaws.com", "ListLandingZones"),
            ("controltower.amazonaws.com", "ListEnabledControls"),
            
            # Account - Account information (moved from misc)
            ("account.amazonaws.com", "GetAccountInformation"),
            ("account.amazonaws.com", "GetAlternateContact"),
            ("account.amazonaws.com", "GetContactInformation"),
            ("account.amazonaws.com", "ListRegions"),
            
            # Sign-in - Authentication events (moved from misc)
            ("signin.amazonaws.com", "ConsoleLogin"),
            
            # ACM - Certificate information (moved from simple storage)
            ("acm.amazonaws.com", "DescribeCertificate"),
            ("acm.amazonaws.com", "ListCertificates"),
        })
        
        # SENSITIVE_WRITE: Identity operations that modify permissions or credentials
        self.sensitive_write.update({
            # IAM - User and role modifications
            ("iam.amazonaws.com", "CreateUser"),
            ("iam.amazonaws.com", "DeleteUser"),
            ("iam.amazonaws.com", "CreateRole"),
            ("iam.amazonaws.com", "DeleteRole"),
            ("iam.amazonaws.com", "AttachRolePolicy"),
            ("iam.amazonaws.com", "DetachRolePolicy"),
            ("iam.amazonaws.com", "PutRolePolicy"),
            ("iam.amazonaws.com", "DeleteRolePolicy"),
            ("iam.amazonaws.com", "CreatePolicy"),
            ("iam.amazonaws.com", "DeletePolicy"),
            ("iam.amazonaws.com", "CreatePolicyVersion"),
            ("iam.amazonaws.com", "DeletePolicyVersion"),
            ("iam.amazonaws.com", "CreateGroup"),
            ("iam.amazonaws.com", "DeleteGroup"),
            ("iam.amazonaws.com", "AddUserToGroup"),
            ("iam.amazonaws.com", "RemoveUserFromGroup"),
            ("iam.amazonaws.com", "CreateAccessKey"),
            ("iam.amazonaws.com", "DeleteAccessKey"),
            ("iam.amazonaws.com", "UpdateAccessKey"),
            ("iam.amazonaws.com", "CreateVirtualMFADevice"),
            ("iam.amazonaws.com", "DeleteVirtualMFADevice"),
            ("iam.amazonaws.com", "EnableMFADevice"),
            ("iam.amazonaws.com", "DeactivateMFADevice"),
            ("iam.amazonaws.com", "ChangePassword"),
            ("iam.amazonaws.com", "CreateServiceLinkedRole"),
            
            # KMS - Key operations
            ("kms.amazonaws.com", "GenerateDataKey"),
            ("kms.amazonaws.com", "GenerateDataKeyWithoutPlaintext"),
            ("kms.amazonaws.com", "GenerateRandom"),
            ("kms.amazonaws.com", "Encrypt"),
            ("kms.amazonaws.com", "CreateKey"),
            ("kms.amazonaws.com", "DeleteKey"),
            ("kms.amazonaws.com", "PutKeyPolicy"),
            ("kms.amazonaws.com", "CreateAlias"),
            ("kms.amazonaws.com", "DeleteAlias"),
            ("kms.amazonaws.com", "UpdateAlias"),
            ("kms.amazonaws.com", "CreateGrant"),
            ("kms.amazonaws.com", "RevokeGrant"),
            ("kms.amazonaws.com", "EnableKeyRotation"),
            ("kms.amazonaws.com", "DisableKeyRotation"),
            
            # Secrets Manager - Secret modifications
            ("secretsmanager.amazonaws.com", "CreateSecret"),
            ("secretsmanager.amazonaws.com", "DeleteSecret"),
            ("secretsmanager.amazonaws.com", "UpdateSecret"),
            ("secretsmanager.amazonaws.com", "PutSecretValue"),
            ("secretsmanager.amazonaws.com", "PutResourcePolicy"),
            ("secretsmanager.amazonaws.com", "DeleteResourcePolicy"),
            ("secretsmanager.amazonaws.com", "TagResource"),
            ("secretsmanager.amazonaws.com", "UntagResource"),
            
            # Organizations - Organization modifications
            ("organizations.amazonaws.com", "CreateOrganization"),
            ("organizations.amazonaws.com", "DeleteOrganization"),
            ("organizations.amazonaws.com", "CreateOrganizationalUnit"),
            ("organizations.amazonaws.com", "DeleteOrganizationalUnit"),
            ("organizations.amazonaws.com", "CreateAccount"),
            ("organizations.amazonaws.com", "CloseAccount"),
            
            # Cognito - Identity modifications (moved from misc)
            ("cognito-identity.amazonaws.com", "CreateIdentityPool"),
            ("cognito-identity.amazonaws.com", "DeleteIdentityPool"),
            ("cognito-idp.amazonaws.com", "CreateUserPool"),
            ("cognito-idp.amazonaws.com", "DeleteUserPool"),
            
            # Account - Account modifications (moved from misc)
            ("account.amazonaws.com", "UpdateAccountInformation"),
            ("account.amazonaws.com", "UpdateAlternateContact"),
            ("account.amazonaws.com", "UpdateContactInformation"),
            
            # Control Tower - Landing zone operations (moved from misc)
            ("controltower.amazonaws.com", "CreateLandingZone"),
            ("controltower.amazonaws.com", "DeleteLandingZone"),
            ("controltower.amazonaws.com", "UpdateLandingZone"),
            
            # Sign-in - Authentication changes (moved from misc)
            ("signin.amazonaws.com", "PasswordUpdated"),
        })
        
        # HACKING_READS: Operations that could be used for privilege escalation or reconnaissance
        self.hacking_reads.update({
            # IAM - Policy analysis for privilege escalation
            ("iam.amazonaws.com", "SimulatePrincipalPolicy"),
            ("iam.amazonaws.com", "SimulateCustomPolicy"),
            ("iam.amazonaws.com", "GenerateServiceLastAccessedDetails"),
            ("iam.amazonaws.com", "GetServiceLastAccessedDetails"),
            
            # STS - Token manipulation
            ("sts.amazonaws.com", "DecodeAuthorizationMessage"),
        })
        
        # STRANGE_READS: Unusual identity operations
        self.strange_reads.update({
            # IAM - Unusual operations
            ("iam.amazonaws.com", "GetCredentialReport"),
            ("iam.amazonaws.com", "GetAccountSummary"),
            ("iam.amazonaws.com", "ListAccountAliases"),
            
            # KMS - Unusual key operations
            ("kms.amazonaws.com", "GetParametersForImport"),
            ("kms.amazonaws.com", "ImportKeyMaterial"),
        })
        
        # INFRA_READS: Infrastructure identity management
        self.infra_reads.update({
            # Organizations - Infrastructure organization management (dashboard reads removed)
            ("organizations.amazonaws.com", "ListRoots"),
            
            # IAM - Infrastructure role management
            ("iam.amazonaws.com", "ListRoles"),
            ("iam.amazonaws.com", "ListAttachedRolePolicies"),
            ("iam.amazonaws.com", "ListRolePolicies"),
        })
