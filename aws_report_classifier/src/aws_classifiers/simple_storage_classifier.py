"""
Simple Storage Services Event Classifier

Handles events from S3, ElastiCache, and other simple storage services.
"""

from .base_classifier import BaseEventClassifier


class SimpleStorageEventClassifier(BaseEventClassifier):
    """
    Classifier for simple storage services.
    
    Handles:
    - s3 (Simple Storage Service)
    - elasticache (in-memory caching)
    - acm (certificates stored in ACM)
    """
    
    def _initialize_rules(self):
        """Initialize classification rules for simple storage services.
        
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
            "s3.amazonaws.com",              # Simple Storage Service for object storage
            "elasticache.amazonaws.com"      # ElastiCache for in-memory data caching
        }
        
        # SAFE_READ_ONLY: Basic storage information that doesn't expose sensitive data
        self.safe_read_only.update({
            # S3 - Basic bucket information
            ("s3.amazonaws.com", "ListBuckets"),
            ("s3.amazonaws.com", "GetBucketTagging"),
            ("s3.amazonaws.com", "GetBucketVersioning"),
            
        })
        
        # SENSITIVE_READ_ONLY: Storage operations that could expose sensitive information
        self.sensitive_read_only.update({
            # S3 - Bucket and object configuration details
            ("s3.amazonaws.com", "GetBucketEncryption"),
            ("s3.amazonaws.com", "GetBucketPolicy"),
            ("s3.amazonaws.com", "GetBucketPublicAccessBlock"),
            ("s3.amazonaws.com", "GetBucketAcl"),
            ("s3.amazonaws.com", "GetBucketCors"),
            ("s3.amazonaws.com", "GetBucketLocation"),
            ("s3.amazonaws.com", "GetBucketLogging"),
            ("s3.amazonaws.com", "GetBucketNotification"),
            ("s3.amazonaws.com", "GetBucketWebsite"),
            ("s3.amazonaws.com", "GetObject"),
            ("s3.amazonaws.com", "GetObjectAcl"),
            ("s3.amazonaws.com", "GetObjectTagging"),
            ("s3.amazonaws.com", "ListObjects"),
            ("s3.amazonaws.com", "ListObjectsV2"),
            ("s3.amazonaws.com", "GetAccountPublicAccessBlock"),
            ("s3.amazonaws.com", "GetBucketObjectLockConfiguration"),
            ("s3.amazonaws.com", "GetBucketOwnershipControls"),
            
            # ElastiCache - Cache information
            ("elasticache.amazonaws.com", "DescribeCacheClusters"),
            ("elasticache.amazonaws.com", "DescribeReplicationGroups"),
            ("elasticache.amazonaws.com", "DescribeCacheParameterGroups"),
            ("elasticache.amazonaws.com", "DescribeCacheSubnetGroups"),
            ("elasticache.amazonaws.com", "DescribeCacheSecurityGroups"),
            ("elasticache.amazonaws.com", "DescribeSnapshots"),
            ("elasticache.amazonaws.com", "DescribeEvents"),
            ("elasticache.amazonaws.com", "DescribeEngineDefaultParameters"),
            ("elasticache.amazonaws.com", "DescribeReservedCacheNodes"),
            ("elasticache.amazonaws.com", "DescribeReservedCacheNodesOfferings"),
            ("elasticache.amazonaws.com", "DescribeCacheEngineVersions"),
            ("elasticache.amazonaws.com", "ListAllowedNodeTypeModifications"),
            ("elasticache.amazonaws.com", "DescribeGlobalReplicationGroups"),
        })
        
        # SENSITIVE_WRITE: Storage operations that modify data or configurations
        self.sensitive_write.update({
            # S3 - Bucket and object modifications
            ("s3.amazonaws.com", "CreateBucket"),
            ("s3.amazonaws.com", "DeleteBucket"),
            ("s3.amazonaws.com", "PutObject"),
            ("s3.amazonaws.com", "DeleteObject"),
            ("s3.amazonaws.com", "PutBucketEncryption"),
            ("s3.amazonaws.com", "PutBucketPolicy"),
            ("s3.amazonaws.com", "PutBucketPublicAccessBlock"),
            ("s3.amazonaws.com", "PutBucketAcl"),
            ("s3.amazonaws.com", "PutBucketCors"),
            ("s3.amazonaws.com", "PutBucketLogging"),
            ("s3.amazonaws.com", "PutBucketNotification"),
            ("s3.amazonaws.com", "PutBucketWebsite"),
            ("s3.amazonaws.com", "PutObjectAcl"),
            ("s3.amazonaws.com", "PutObjectTagging"),
            ("s3.amazonaws.com", "DeleteObjectTagging"),
            
            # ElastiCache - Cache modifications
            ("elasticache.amazonaws.com", "CreateCacheCluster"),
            ("elasticache.amazonaws.com", "DeleteCacheCluster"),
            ("elasticache.amazonaws.com", "ModifyCacheCluster"),
            ("elasticache.amazonaws.com", "CreateReplicationGroup"),
            ("elasticache.amazonaws.com", "DeleteReplicationGroup"),
            ("elasticache.amazonaws.com", "ModifyReplicationGroup"),
            ("elasticache.amazonaws.com", "CreateCacheParameterGroup"),
            ("elasticache.amazonaws.com", "DeleteCacheParameterGroup"),
            ("elasticache.amazonaws.com", "ModifyCacheParameterGroup"),
            ("elasticache.amazonaws.com", "CreateCacheSubnetGroup"),
            ("elasticache.amazonaws.com", "DeleteCacheSubnetGroup"),
            ("elasticache.amazonaws.com", "ModifyCacheSubnetGroup"),
            ("elasticache.amazonaws.com", "CreateCacheSecurityGroup"),
            ("elasticache.amazonaws.com", "DeleteCacheSecurityGroup"),
            ("elasticache.amazonaws.com", "AuthorizeCacheSecurityGroupIngress"),
            ("elasticache.amazonaws.com", "RevokeCacheSecurityGroupIngress"),
            ("elasticache.amazonaws.com", "CreateSnapshot"),
            ("elasticache.amazonaws.com", "DeleteSnapshot"),
            ("elasticache.amazonaws.com", "CopySnapshot"),
            ("elasticache.amazonaws.com", "PurchaseReservedCacheNodesOffering"),
            ("elasticache.amazonaws.com", "RebootCacheCluster"),
        })
        
        # HACKING_READS: Operations that could be used for data exfiltration
        self.hacking_reads.update({
            # S3 - Bucket enumeration and access
            ("s3.amazonaws.com", "ListAllMyBuckets"),
            ("s3.amazonaws.com", "GetBucketPolicyStatus"),
        })
        
        # STRANGE_READS: Unusual storage operations
        self.strange_reads.update({
            # S3 - Unusual bucket operations
            ("s3.amazonaws.com", "GetBucketAnalyticsConfiguration"),
            ("s3.amazonaws.com", "ListBucketAnalyticsConfigurations"),
        })
        
