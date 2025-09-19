"""
Structured Storage Services Event Classifier

Handles events from RDS, DynamoDB, and other structured database services.
"""

from .base_classifier import BaseEventClassifier


class StructuredStorageEventClassifier(BaseEventClassifier):
    """
    Classifier for structured storage services.
    
    Handles:
    - rds (Relational Database Service)
    - dynamodb (NoSQL database)
    """
    
    def _initialize_rules(self):
        """Initialize classification rules for structured storage services.
        
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
            "rds.amazonaws.com",             # Relational Database Service for managed databases
            "dynamodb.amazonaws.com"         # DynamoDB for NoSQL document and key-value storage
        }
        
        # SAFE_READ_ONLY: Basic database information that doesn't expose sensitive data
        self.safe_read_only.update({
            # RDS - Basic database engine information
            ("rds.amazonaws.com", "DescribeDBEngineVersions"),
            ("rds.amazonaws.com", "DescribeOrderableDBInstanceOptions"),
            ("rds.amazonaws.com", "DescribeSourceRegions"),
        })
        
        # SENSITIVE_READ_ONLY: Database operations that could expose sensitive information
        self.sensitive_read_only.update({
            # RDS - Database information
            ("rds.amazonaws.com", "DescribeDBSnapshots"),                     # ✅ DB snapshots - RDS database backup snapshot details
            ("rds.amazonaws.com", "DescribeOptionGroups"),                    # ✅ Option groups - RDS option group inventory (administrative inventory, not exploitable - should be safe read)
            ("rds.amazonaws.com", "DescribeReservedDBInstances"),             # ✅ Reserved DB instances - RDS reserved instance inventory (administrative inventory, not exploitable - should be safe read)
            ("rds.amazonaws.com", "DescribeReservedDBInstancesOfferings"),    # ✅ Reserved DB instance offerings - RDS reserved instance offering inventory (administrative inventory, not exploitable - should be safe read)
            ("rds.amazonaws.com", "DescribeEventCategories"),                 # ✅ Event categories - RDS event category inventory (administrative inventory, not exploitable - should be safe read)
            
            # DynamoDB - NoSQL database information
            ("dynamodb.amazonaws.com", "DescribeTimeToLive"),                 # ✅ Time to live - DynamoDB TTL configuration
            ("dynamodb.amazonaws.com", "ListTagsOfResource"),                 # ✅ Resource tags - DynamoDB resource metadata tags (administrative metadata, not exploitable - should be safe read)
            ("dynamodb.amazonaws.com", "DescribeGlobalTable"),                # ✅ Global table - DynamoDB global table configuration
            ("dynamodb.amazonaws.com", "DescribeGlobalTableSettings"),        # ✅ Global table settings - DynamoDB global table settings
            ("dynamodb.amazonaws.com", "DescribeLimits"),                     # ✅ Service limits - DynamoDB service limit information (administrative info, not exploitable - should be safe read)
        })
        
        # SENSITIVE_WRITE: Database operations that modify data or configurations
        self.sensitive_write.update({
            # RDS - Database modifications
            ("rds.amazonaws.com", "CreateDBInstance"),                        # ✅ Create DB instance - RDS database instance creation
            ("rds.amazonaws.com", "DeleteDBInstance"),                        # ✅ Delete DB instance - RDS database instance removal
            ("rds.amazonaws.com", "ModifyDBInstance"),                        # ✅ Modify DB instance - RDS database instance modification
            ("rds.amazonaws.com", "CreateDBCluster"),                         # ✅ Create DB cluster - RDS database cluster creation
            ("rds.amazonaws.com", "DeleteDBCluster"),                         # ✅ Delete DB cluster - RDS database cluster removal
            ("rds.amazonaws.com", "ModifyDBCluster"),                         # ✅ Modify DB cluster - RDS database cluster modification
            ("rds.amazonaws.com", "CreateDBSnapshot"),                        # ✅ Create DB snapshot - RDS database backup snapshot creation
            ("rds.amazonaws.com", "DeleteDBSnapshot"),                        # ✅ Delete DB snapshot - RDS database backup snapshot removal
            ("rds.amazonaws.com", "CreateDBClusterSnapshot"),                 # ✅ Create DB cluster snapshot - RDS cluster backup snapshot creation
            ("rds.amazonaws.com", "DeleteDBClusterSnapshot"),                 # ✅ Delete DB cluster snapshot - RDS cluster backup snapshot removal
            ("rds.amazonaws.com", "RestoreDBInstanceFromDBSnapshot"),         # ✅ Restore DB instance - RDS database instance restoration
            ("rds.amazonaws.com", "RestoreDBClusterFromSnapshot"),            # ✅ Restore DB cluster - RDS database cluster restoration
            ("rds.amazonaws.com", "CreateDBParameterGroup"),                  # ✅ Create DB parameter group - RDS parameter group creation
            ("rds.amazonaws.com", "DeleteDBParameterGroup"),                  # ✅ Delete DB parameter group - RDS parameter group removal
            ("rds.amazonaws.com", "ModifyDBParameterGroup"),                  # ✅ Modify DB parameter group - RDS parameter group modification
            ("rds.amazonaws.com", "CreateDBSubnetGroup"),                     # ✅ Create DB subnet group - RDS subnet group creation
            ("rds.amazonaws.com", "DeleteDBSubnetGroup"),                     # ✅ Delete DB subnet group - RDS subnet group removal
            ("rds.amazonaws.com", "ModifyDBSubnetGroup"),                     # ✅ Modify DB subnet group - RDS subnet group modification
            ("rds.amazonaws.com", "CreateDBSecurityGroup"),                   # ✅ Create DB security group - RDS security group creation
            ("rds.amazonaws.com", "DeleteDBSecurityGroup"),                   # ✅ Delete DB security group - RDS security group removal
            ("rds.amazonaws.com", "AuthorizeDBSecurityGroupIngress"),          # ✅ Authorize DB security group ingress - RDS security group access authorization
            ("rds.amazonaws.com", "RevokeDBSecurityGroupIngress"),            # ✅ Revoke DB security group ingress - RDS security group access revocation
            ("rds.amazonaws.com", "CreateOptionGroup"),                       # ✅ Create option group - RDS option group creation
            ("rds.amazonaws.com", "DeleteOptionGroup"),                       # ✅ Delete option group - RDS option group removal
            ("rds.amazonaws.com", "ModifyOptionGroup"),                       # ✅ Modify option group - RDS option group modification
            ("rds.amazonaws.com", "PurchaseReservedDBInstancesOffering"),      # ✅ Purchase reserved DB instances - RDS reserved instance purchase
            ("rds.amazonaws.com", "StartDBInstance"),                         # ✅ Start DB instance - RDS database instance startup
            ("rds.amazonaws.com", "StopDBInstance"),                          # ✅ Stop DB instance - RDS database instance shutdown
            ("rds.amazonaws.com", "RebootDBInstance"),                        # ✅ Reboot DB instance - RDS database instance reboot
            
            # DynamoDB - NoSQL database modifications
            ("dynamodb.amazonaws.com", "CreateTable"),                        # ✅ Create table - DynamoDB table creation
            ("dynamodb.amazonaws.com", "DeleteTable"),                        # ✅ Delete table - DynamoDB table removal
            ("dynamodb.amazonaws.com", "UpdateTable"),                        # ✅ Update table - DynamoDB table modification
            ("dynamodb.amazonaws.com", "PutItem"),                            # ✅ Put item - DynamoDB item creation
            ("dynamodb.amazonaws.com", "UpdateItem"),                         # ✅ Update item - DynamoDB item modification
            ("dynamodb.amazonaws.com", "DeleteItem"),                         # ✅ Delete item - DynamoDB item removal
            ("dynamodb.amazonaws.com", "BatchWriteItem"),                     # ✅ Batch write item - DynamoDB batch item operations
            ("dynamodb.amazonaws.com", "UpdateTimeToLive"),                   # ✅ Update time to live - DynamoDB TTL configuration
            ("dynamodb.amazonaws.com", "TagResource"),                        # ✅ Tag resource - DynamoDB resource tagging
            ("dynamodb.amazonaws.com", "UntagResource"),                      # ✅ Untag resource - DynamoDB resource tag removal
            ("dynamodb.amazonaws.com", "UpdateContinuousBackups"),            # ✅ Update continuous backups - DynamoDB backup configuration
            ("dynamodb.amazonaws.com", "CreateGlobalTable"),                  # ✅ Create global table - DynamoDB global table creation
            ("dynamodb.amazonaws.com", "UpdateGlobalTable"),                  # ✅ Update global table - DynamoDB global table modification
            ("dynamodb.amazonaws.com", "DeleteGlobalTable"),                  # ✅ Delete global table - DynamoDB global table removal
            ("dynamodb.amazonaws.com", "UpdateGlobalTableSettings"),          # ✅ Update global table settings - DynamoDB global table settings
            ("dynamodb.amazonaws.com", "ExportTableToPointInTime"),           # ✅ Export table - DynamoDB table export
            ("dynamodb.amazonaws.com", "CancelExportTask"),                   # ✅ Cancel export task - DynamoDB export task cancellation
            ("dynamodb.amazonaws.com", "EnableKinesisStreamingDestination"),  # ✅ Enable Kinesis streaming destination - DynamoDB streaming activation
            ("dynamodb.amazonaws.com", "DisableKinesisStreamingDestination"), # ✅ Disable Kinesis streaming destination - DynamoDB streaming deactivation
            ("dynamodb.amazonaws.com", "UpdateTableReplicaAutoScaling"),       # ✅ Update table replica auto scaling - DynamoDB auto scaling configuration
            ("dynamodb.amazonaws.com", "UpdateGlobalTableReplicaAutoScaling"), # ✅ Update global table replica auto scaling - DynamoDB global auto scaling configuration
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance
        self.hacking_reads.update({
            # RDS - Database reconnaissance
            ("rds.amazonaws.com", "DescribeDBInstances"),                     # ✅ DB instances - RDS instance inventory (administrative inventory, not exploitable - should be safe read)
            ("rds.amazonaws.com", "DescribeDBClusters"),                      # ✅ DB clusters - RDS cluster inventory (administrative inventory, not exploitable - should be safe read)
            ("rds.amazonaws.com", "DescribeDBParameterGroups"),               # ✅ DB parameter groups - RDS parameter group inventory (administrative inventory, not exploitable - should be safe read)
            ("rds.amazonaws.com", "DescribeDBClusterParameterGroups"),        # ✅ DB cluster parameter groups - RDS cluster parameter group inventory (administrative inventory, not exploitable - should be safe read)
            ("rds.amazonaws.com", "DescribeDBClusterSnapshots"),              # ✅ DB cluster snapshots - RDS cluster backup snapshot details
            ("rds.amazonaws.com", "DescribeDBSubnetGroups"),                  # ✅ DB subnet groups - RDS subnet group configuration
            ("rds.amazonaws.com", "DescribeDBClusterSubnetGroups"),           # ✅ DB cluster subnet groups - RDS cluster subnet group configuration
            ("rds.amazonaws.com", "DescribeDBSecurityGroups"),                # ✅ DB security groups - RDS security group configuration
            ("rds.amazonaws.com", "DescribeDBClusterSecurityGroups"),         # ✅ DB cluster security groups - RDS cluster security group configuration
            ("rds.amazonaws.com", "DescribeEvents"),                          # ✅ DB events - RDS database event history
            ("rds.amazonaws.com", "DescribeDBProxyTargets"),                  # ✅ DB proxy targets - RDS proxy target configuration
            ("rds.amazonaws.com", "DescribeDBProxies"),                       # ✅ DB proxies - RDS proxy inventory (administrative inventory, not exploitable - should be safe read)
            ("rds.amazonaws.com", "DescribeGlobalClusters"),                  # ✅ Global clusters - RDS global cluster configuration
            ("rds.amazonaws.com", "DescribeDBLogFiles"),                      # ✅ DB log files - RDS database log file inventory
            ("rds.amazonaws.com", "DownloadDBLogFilePortion"),                # ✅ DB log download - RDS database log data access (should be hacking reads)
            
            # DynamoDB - Table reconnaissance
            ("dynamodb.amazonaws.com", "ListTables"),                         # ✅ Tables - DynamoDB table inventory (administrative inventory, not exploitable - should be safe read)
            ("dynamodb.amazonaws.com", "DescribeTable"),                      # ✅ Table details - DynamoDB table configuration
            ("dynamodb.amazonaws.com", "DescribeContinuousBackups"),          # ✅ Continuous backups - DynamoDB backup configuration
            ("dynamodb.amazonaws.com", "DescribeEndpoints"),                  # ✅ Endpoints - DynamoDB endpoint configuration
            ("dynamodb.amazonaws.com", "DescribeExport"),                     # ✅ Export details - DynamoDB export configuration
            ("dynamodb.amazonaws.com", "ListExports"),                        # ✅ Exports - DynamoDB export inventory (administrative inventory, not exploitable - should be safe read)
            ("dynamodb.amazonaws.com", "DescribeKinesisStreamingDestination"), # ✅ Kinesis streaming destination - DynamoDB streaming configuration
            ("dynamodb.amazonaws.com", "ListKinesisStreamingDestinations"),   # ✅ Kinesis streaming destinations - DynamoDB streaming inventory (administrative inventory, not exploitable - should be safe read)
            ("dynamodb.amazonaws.com", "DescribeTableReplicaAutoScaling"),    # ✅ Table replica auto scaling - DynamoDB auto scaling configuration
            ("dynamodb.amazonaws.com", "DescribeGlobalTableReplicaAutoScaling"), # ✅ Global table replica auto scaling - DynamoDB global auto scaling configuration
        })
        
        # STRANGE_READS: Unusual database operations
        self.strange_reads.update({
        })
        
