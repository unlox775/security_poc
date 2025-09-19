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
            ("s3.amazonaws.com", "ListBuckets"),                            # ✅ Buckets - S3 bucket inventory (administrative inventory, not exploitable - should be safe read)
            ("s3.amazonaws.com", "GetBucketTagging"),                       # ✅ Bucket tagging - S3 bucket tagging configuration
        })
        
        # SENSITIVE_READ_ONLY: Storage operations that could expose sensitive information
        self.sensitive_read_only.update({
            # S3 - Bucket and object configuration details
            ("s3.amazonaws.com", "GetBucketEncryption"),                      # ✅ Bucket encryption - S3 bucket encryption configuration
            ("s3.amazonaws.com", "GetBucketPolicy"),                         # ✅ Bucket policy - S3 bucket access policies
            ("s3.amazonaws.com", "GetBucketPublicAccessBlock"),              # ✅ Public access block - S3 bucket public access configuration
            ("s3.amazonaws.com", "GetBucketAcl"),                            # ✅ Bucket ACL - S3 bucket access control list
            ("s3.amazonaws.com", "GetBucketCors"),                           # ✅ Bucket CORS - S3 bucket cross-origin resource sharing
            ("s3.amazonaws.com", "GetBucketLocation"),                       # ✅ Bucket location - S3 bucket region information (administrative info, not exploitable - should be safe read)
            ("s3.amazonaws.com", "GetBucketLogging"),                        # ✅ Bucket logging - S3 bucket access logging configuration
            ("s3.amazonaws.com", "GetBucketNotification"),                   # ✅ Bucket notifications - S3 bucket event notification configuration
            ("s3.amazonaws.com", "GetBucketWebsite"),                        # ✅ Bucket website - S3 bucket static website configuration
            ("s3.amazonaws.com", "GetObjectAcl"),                            # ✅ Object ACL - S3 object access control list
            ("s3.amazonaws.com", "GetObjectTagging"),                        # ✅ Object tags - S3 object metadata tags (administrative metadata, not exploitable - should be safe read)
            ("s3.amazonaws.com", "GetAccountPublicAccessBlock"),             # ✅ Account public access block - S3 account public access configuration
            ("s3.amazonaws.com", "GetBucketObjectLockConfiguration"),        # ✅ Object lock configuration - S3 bucket object lock configuration
            ("s3.amazonaws.com", "GetBucketOwnershipControls"),              # ✅ Bucket ownership controls - S3 bucket ownership configuration
            
            # ElastiCache - Cache information
            ("elasticache.amazonaws.com", "DescribeCacheClusters"),           # ✅ Cache clusters - ElastiCache cluster inventory (administrative inventory, not exploitable - should be safe read)
            ("elasticache.amazonaws.com", "DescribeReplicationGroups"),       # ✅ Replication groups - ElastiCache replication group inventory (administrative inventory, not exploitable - should be safe read)
            ("elasticache.amazonaws.com", "DescribeCacheParameterGroups"),    # ✅ Parameter groups - ElastiCache parameter group inventory (administrative inventory, not exploitable - should be safe read)
            ("elasticache.amazonaws.com", "DescribeCacheSubnetGroups"),       # ✅ Cache subnet groups - ElastiCache subnet group configuration
            ("elasticache.amazonaws.com", "DescribeCacheSecurityGroups"),     # ✅ Cache security groups - ElastiCache security group configuration
            ("elasticache.amazonaws.com", "DescribeSnapshots"),               # ✅ Cache snapshots - ElastiCache backup snapshot details
            ("elasticache.amazonaws.com", "DescribeEvents"),                  # ✅ Cache events - ElastiCache event history
            ("elasticache.amazonaws.com", "DescribeEngineDefaultParameters"), # ✅ Engine parameters - ElastiCache engine parameter inventory (administrative inventory, not exploitable - should be safe read)
            ("elasticache.amazonaws.com", "DescribeReservedCacheNodes"),      # ✅ Reserved nodes - ElastiCache reserved node inventory (administrative inventory, not exploitable - should be safe read)
            ("elasticache.amazonaws.com", "DescribeReservedCacheNodesOfferings"), # ✅ Reserved node offerings - ElastiCache reserved node offering inventory (administrative inventory, not exploitable - should be safe read)
            ("elasticache.amazonaws.com", "DescribeCacheEngineVersions"),     # ✅ Engine versions - ElastiCache engine version inventory (administrative inventory, not exploitable - should be safe read)
            ("elasticache.amazonaws.com", "ListAllowedNodeTypeModifications"), # ✅ Node type modifications - ElastiCache node type modification options
            ("elasticache.amazonaws.com", "DescribeGlobalReplicationGroups"), # ✅ Global replication groups - ElastiCache global replication group configuration
        })
        
        # SENSITIVE_WRITE: Storage operations that modify data or configurations
        self.sensitive_write.update({
            # S3 - Bucket and object modifications
            ("s3.amazonaws.com", "CreateBucket"),                             # ✅ Create bucket - S3 bucket creation
            ("s3.amazonaws.com", "DeleteBucket"),                             # ✅ Delete bucket - S3 bucket removal
            ("s3.amazonaws.com", "PutObject"),                                # ✅ Put object - S3 object creation
            ("s3.amazonaws.com", "DeleteObject"),                             # ✅ Delete object - S3 object removal
            ("s3.amazonaws.com", "PutBucketEncryption"),                      # ✅ Put bucket encryption - S3 bucket encryption configuration
            ("s3.amazonaws.com", "PutBucketPolicy"),                         # ✅ Put bucket policy - S3 bucket access policy configuration
            ("s3.amazonaws.com", "PutBucketPublicAccessBlock"),              # ✅ Put public access block - S3 bucket public access configuration
            ("s3.amazonaws.com", "PutBucketAcl"),                            # ✅ Put bucket ACL - S3 bucket access control list configuration
            ("s3.amazonaws.com", "PutBucketCors"),                           # ✅ Put bucket CORS - S3 bucket cross-origin resource sharing configuration
            ("s3.amazonaws.com", "PutBucketLogging"),                        # ✅ Put bucket logging - S3 bucket access logging configuration
            ("s3.amazonaws.com", "PutBucketNotification"),                   # ✅ Put bucket notification - S3 bucket event notification configuration
            ("s3.amazonaws.com", "PutBucketWebsite"),                        # ✅ Put bucket website - S3 bucket static website configuration
            ("s3.amazonaws.com", "PutObjectAcl"),                            # ✅ Put object ACL - S3 object access control list configuration
            ("s3.amazonaws.com", "PutObjectTagging"),                        # ✅ Put object tagging - S3 object metadata tagging
            ("s3.amazonaws.com", "DeleteObjectTagging"),                     # ✅ Delete object tagging - S3 object metadata tag removal
            
            # ElastiCache - Cache modifications
            ("elasticache.amazonaws.com", "CreateCacheCluster"),             # ✅ Create cache cluster - ElastiCache cluster creation
            ("elasticache.amazonaws.com", "DeleteCacheCluster"),             # ✅ Delete cache cluster - ElastiCache cluster removal
            ("elasticache.amazonaws.com", "ModifyCacheCluster"),             # ✅ Modify cache cluster - ElastiCache cluster modification
            ("elasticache.amazonaws.com", "CreateReplicationGroup"),         # ✅ Create replication group - ElastiCache replication group creation
            ("elasticache.amazonaws.com", "DeleteReplicationGroup"),         # ✅ Delete replication group - ElastiCache replication group removal
            ("elasticache.amazonaws.com", "ModifyReplicationGroup"),         # ✅ Modify replication group - ElastiCache replication group modification
            ("elasticache.amazonaws.com", "CreateCacheParameterGroup"),      # ✅ Create parameter group - ElastiCache parameter group creation
            ("elasticache.amazonaws.com", "DeleteCacheParameterGroup"),      # ✅ Delete parameter group - ElastiCache parameter group removal
            ("elasticache.amazonaws.com", "ModifyCacheParameterGroup"),      # ✅ Modify parameter group - ElastiCache parameter group modification
            ("elasticache.amazonaws.com", "CreateCacheSubnetGroup"),         # ✅ Create subnet group - ElastiCache subnet group creation
            ("elasticache.amazonaws.com", "DeleteCacheSubnetGroup"),         # ✅ Delete subnet group - ElastiCache subnet group removal
            ("elasticache.amazonaws.com", "ModifyCacheSubnetGroup"),         # ✅ Modify subnet group - ElastiCache subnet group modification
            ("elasticache.amazonaws.com", "CreateCacheSecurityGroup"),       # ✅ Create security group - ElastiCache security group creation
            ("elasticache.amazonaws.com", "DeleteCacheSecurityGroup"),       # ✅ Delete security group - ElastiCache security group removal
            ("elasticache.amazonaws.com", "AuthorizeCacheSecurityGroupIngress"), # ✅ Authorize security group ingress - ElastiCache security group access authorization
            ("elasticache.amazonaws.com", "RevokeCacheSecurityGroupIngress"), # ✅ Revoke security group ingress - ElastiCache security group access revocation
            ("elasticache.amazonaws.com", "CreateSnapshot"),                 # ✅ Create snapshot - ElastiCache backup snapshot creation
            ("elasticache.amazonaws.com", "DeleteSnapshot"),                 # ✅ Delete snapshot - ElastiCache backup snapshot removal
            ("elasticache.amazonaws.com", "CopySnapshot"),                   # ✅ Copy snapshot - ElastiCache backup snapshot copying
            ("elasticache.amazonaws.com", "PurchaseReservedCacheNodesOffering"), # ✅ Purchase reserved nodes - ElastiCache reserved node purchase
            ("elasticache.amazonaws.com", "RebootCacheCluster"),               # ✅ Reboot cache cluster - ElastiCache cluster reboot
        })
        
        # HACKING_READS: Operations that could be used for data exfiltration
        self.hacking_reads.update({
            # S3 - Bucket enumeration and access
            ("s3.amazonaws.com", "ListAllMyBuckets"),                        # ✅ All buckets - S3 bucket enumeration (should be hacking reads)
            ("s3.amazonaws.com", "GetBucketPolicyStatus"),                   # ✅ Bucket policy status - S3 bucket policy enforcement status
            ("s3.amazonaws.com", "GetBucketVersioning"),                     # ✅ Bucket versioning - S3 bucket versioning configuration
            ("s3.amazonaws.com", "GetObject"),                               # ✅ Object content - S3 object data access (should be hacking reads)
            ("s3.amazonaws.com", "ListObjects"),                             # ✅ Object inventory - S3 object listing (should be hacking reads)
            ("s3.amazonaws.com", "ListObjectsV2"),                           # ✅ Object inventory V2 - S3 object listing (should be hacking reads)
        })
        
        # STRANGE_READS: Unusual storage operations
        self.strange_reads.update({
            # S3 - Unusual bucket operations
            ("s3.amazonaws.com", "GetBucketAnalyticsConfiguration"),         # ✅ Bucket analytics - S3 bucket analytics configuration
            ("s3.amazonaws.com", "ListBucketAnalyticsConfigurations"),       # ✅ Bucket analytics configurations - S3 bucket analytics inventory (administrative inventory, not exploitable - should be safe read)
        })
        
