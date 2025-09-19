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
        """Initialize classification rules for structured storage services."""
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
            ("rds.amazonaws.com", "DescribeDBInstances"),
            ("rds.amazonaws.com", "DescribeDBClusters"),
            ("rds.amazonaws.com", "DescribeDBSnapshots"),
            ("rds.amazonaws.com", "DescribeDBClusterSnapshots"),
            ("rds.amazonaws.com", "DescribeDBParameterGroups"),
            ("rds.amazonaws.com", "DescribeDBClusterParameterGroups"),
            ("rds.amazonaws.com", "DescribeDBSubnetGroups"),
            ("rds.amazonaws.com", "DescribeDBClusterSubnetGroups"),
            ("rds.amazonaws.com", "DescribeDBSecurityGroups"),
            ("rds.amazonaws.com", "DescribeDBClusterSecurityGroups"),
            ("rds.amazonaws.com", "DescribeOptionGroups"),
            ("rds.amazonaws.com", "DescribeReservedDBInstances"),
            ("rds.amazonaws.com", "DescribeReservedDBInstancesOfferings"),
            ("rds.amazonaws.com", "DescribeEventCategories"),
            ("rds.amazonaws.com", "DescribeEvents"),
            ("rds.amazonaws.com", "DescribeDBLogFiles"),
            ("rds.amazonaws.com", "DownloadDBLogFilePortion"),
            ("rds.amazonaws.com", "DescribeDBProxyTargets"),
            ("rds.amazonaws.com", "DescribeDBProxies"),
            ("rds.amazonaws.com", "DescribeGlobalClusters"),
            
            # DynamoDB - NoSQL database information
            ("dynamodb.amazonaws.com", "DescribeTable"),
            ("dynamodb.amazonaws.com", "ListTables"),
            ("dynamodb.amazonaws.com", "DescribeTimeToLive"),
            ("dynamodb.amazonaws.com", "ListTagsOfResource"),
            ("dynamodb.amazonaws.com", "DescribeContinuousBackups"),
            ("dynamodb.amazonaws.com", "DescribeGlobalTable"),
            ("dynamodb.amazonaws.com", "DescribeGlobalTableSettings"),
            ("dynamodb.amazonaws.com", "DescribeLimits"),
            ("dynamodb.amazonaws.com", "DescribeEndpoints"),
            ("dynamodb.amazonaws.com", "DescribeExport"),
            ("dynamodb.amazonaws.com", "ListExports"),
            ("dynamodb.amazonaws.com", "DescribeKinesisStreamingDestination"),
            ("dynamodb.amazonaws.com", "ListKinesisStreamingDestinations"),
            ("dynamodb.amazonaws.com", "DescribeTableReplicaAutoScaling"),
            ("dynamodb.amazonaws.com", "DescribeGlobalTableReplicaAutoScaling"),
        })
        
        # SENSITIVE_WRITE: Database operations that modify data or configurations
        self.sensitive_write.update({
            # RDS - Database modifications
            ("rds.amazonaws.com", "CreateDBInstance"),
            ("rds.amazonaws.com", "DeleteDBInstance"),
            ("rds.amazonaws.com", "ModifyDBInstance"),
            ("rds.amazonaws.com", "CreateDBCluster"),
            ("rds.amazonaws.com", "DeleteDBCluster"),
            ("rds.amazonaws.com", "ModifyDBCluster"),
            ("rds.amazonaws.com", "CreateDBSnapshot"),
            ("rds.amazonaws.com", "DeleteDBSnapshot"),
            ("rds.amazonaws.com", "CreateDBClusterSnapshot"),
            ("rds.amazonaws.com", "DeleteDBClusterSnapshot"),
            ("rds.amazonaws.com", "RestoreDBInstanceFromDBSnapshot"),
            ("rds.amazonaws.com", "RestoreDBClusterFromSnapshot"),
            ("rds.amazonaws.com", "CreateDBParameterGroup"),
            ("rds.amazonaws.com", "DeleteDBParameterGroup"),
            ("rds.amazonaws.com", "ModifyDBParameterGroup"),
            ("rds.amazonaws.com", "CreateDBSubnetGroup"),
            ("rds.amazonaws.com", "DeleteDBSubnetGroup"),
            ("rds.amazonaws.com", "ModifyDBSubnetGroup"),
            ("rds.amazonaws.com", "CreateDBSecurityGroup"),
            ("rds.amazonaws.com", "DeleteDBSecurityGroup"),
            ("rds.amazonaws.com", "AuthorizeDBSecurityGroupIngress"),
            ("rds.amazonaws.com", "RevokeDBSecurityGroupIngress"),
            ("rds.amazonaws.com", "CreateOptionGroup"),
            ("rds.amazonaws.com", "DeleteOptionGroup"),
            ("rds.amazonaws.com", "ModifyOptionGroup"),
            ("rds.amazonaws.com", "PurchaseReservedDBInstancesOffering"),
            ("rds.amazonaws.com", "StartDBInstance"),
            ("rds.amazonaws.com", "StopDBInstance"),
            ("rds.amazonaws.com", "RebootDBInstance"),
            
            # DynamoDB - NoSQL database modifications
            ("dynamodb.amazonaws.com", "CreateTable"),
            ("dynamodb.amazonaws.com", "DeleteTable"),
            ("dynamodb.amazonaws.com", "UpdateTable"),
            ("dynamodb.amazonaws.com", "PutItem"),
            ("dynamodb.amazonaws.com", "UpdateItem"),
            ("dynamodb.amazonaws.com", "DeleteItem"),
            ("dynamodb.amazonaws.com", "BatchWriteItem"),
            ("dynamodb.amazonaws.com", "UpdateTimeToLive"),
            ("dynamodb.amazonaws.com", "TagResource"),
            ("dynamodb.amazonaws.com", "UntagResource"),
            ("dynamodb.amazonaws.com", "UpdateContinuousBackups"),
            ("dynamodb.amazonaws.com", "CreateGlobalTable"),
            ("dynamodb.amazonaws.com", "UpdateGlobalTable"),
            ("dynamodb.amazonaws.com", "DeleteGlobalTable"),
            ("dynamodb.amazonaws.com", "UpdateGlobalTableSettings"),
            ("dynamodb.amazonaws.com", "ExportTableToPointInTime"),
            ("dynamodb.amazonaws.com", "CancelExportTask"),
            ("dynamodb.amazonaws.com", "EnableKinesisStreamingDestination"),
            ("dynamodb.amazonaws.com", "DisableKinesisStreamingDestination"),
            ("dynamodb.amazonaws.com", "UpdateTableReplicaAutoScaling"),
            ("dynamodb.amazonaws.com", "UpdateGlobalTableReplicaAutoScaling"),
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance
        self.hacking_reads.update({
            # RDS - Database reconnaissance
            ("rds.amazonaws.com", "DescribeDBInstances"),
            ("rds.amazonaws.com", "DescribeDBClusters"),
            
            # DynamoDB - Table reconnaissance
            ("dynamodb.amazonaws.com", "ListTables"),
            ("dynamodb.amazonaws.com", "DescribeTable"),
        })
        
        # STRANGE_READS: Unusual database operations
        self.strange_reads.update({
            # RDS - Unusual database operations
            ("rds.amazonaws.com", "DescribeDBLogFiles"),
            ("rds.amazonaws.com", "DownloadDBLogFilePortion"),
        })
        
        # INFRA_READS: Infrastructure database management
        self.infra_reads.update({
            # RDS - Infrastructure database management
            ("rds.amazonaws.com", "DescribeDBInstances"),
            ("rds.amazonaws.com", "DescribeDBClusters"),
        })
