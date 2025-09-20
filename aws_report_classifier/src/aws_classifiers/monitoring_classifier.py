"""
Monitoring and Health Services Event Classifier

Handles events from monitoring, health, logs, and related services.
"""

from .base_classifier import BaseEventClassifier


class MonitoringEventClassifier(BaseEventClassifier):
    """
    Classifier for monitoring, health, logs, and related services.
    
    Handles:
    - monitoring (CloudWatch)
    - health (AWS Health)
    - logs (CloudWatch Logs)
    - application-insights
    - application-signals
    - oam (Observability Access Manager)
    """
    
    def _initialize_rules(self):
        """Initialize classification rules for monitoring services.
        
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
            "monitoring.amazonaws.com",        # CloudWatch monitoring for metrics and alarms
            "health.amazonaws.com",            # AWS Health for service status and events
            "logs.amazonaws.com",              # CloudWatch Logs for log collection and analysis
            "application-insights.amazonaws.com", # Application Insights for app performance monitoring
            "application-signals.amazonaws.com", # Application Signals for observability data
            "oam.amazonaws.com",               # Observability Access Manager for cross-account monitoring
            "trustedadvisor.amazonaws.com",    # Trusted Advisor for AWS best practices recommendations
            "aiops.amazonaws.com"              # AIOps for AI-powered operations insights
        }
        
        # SAFE_READ_ONLY: Basic monitoring operations that don't expose sensitive data
        self.safe_read_only.update({
            # Health - Basic health status
            ("health.amazonaws.com", "DescribeEvents"),                       # ✅ Health events - AWS service health status
            ("health.amazonaws.com", "DescribeAffectedEntities"),            # ✅ Affected entities - service health impact details

            # Logs - Log group and stream information
            ("logs.amazonaws.com", "DescribeLogGroups"),                     #  ✅ Log groups - log group inventory (administrative inventory, not exploitable - should be safe read)
            ("logs.amazonaws.com", "DescribeLogStreams"),                    # ✅ Log streams - log stream inventory (administrative inventory, not exploitable - should be safe read)
            ("logs.amazonaws.com", "ListLogGroupsForEntity"),                # ✅ Entity log groups - entity log group inventory (administrative inventory, not exploitable - should be safe read)

            # Monitoring - Dashboard and metric information
            ("monitoring.amazonaws.com", "ListDashboards"),                  # ✅ Dashboard inventory - monitoring dashboard list (administrative inventory, not exploitable - should be safe read)
            ("monitoring.amazonaws.com", "ListMetrics"),                     # ✅ Metric inventory - available metrics list (administrative inventory, not exploitable - should be safe read)

            # Application Insights - Application and component information
            ("application-insights.amazonaws.com", "ListApplications"),      # ✅ Application inventory - monitored application list (administrative inventory, not exploitable - should be safe read)
            ("application-insights.amazonaws.com", "ListComponents"),        # ✅ Component inventory - application component list (administrative inventory, not exploitable - should be safe read)

            # Application Signals - Performance monitoring entity information
            ("application-signals.amazonaws.com", "ListObservedEntities"),   # ✅ Observed entities - performance monitoring entity list (administrative inventory, not exploitable - should be safe read)
            
            # AIOps - AI operations insights
            ("aiops.amazonaws.com", "ListInvestigationGroups"),             # ✅ Investigation groups - AIOps investigation inventory (administrative inventory, not exploitable - should be safe read)
        })
        
        # SENSITIVE_READ_ONLY: Monitoring operations that could expose sensitive information
        self.sensitive_read_only.update({
            # Logs - Log analysis and filtering
            ("logs.amazonaws.com", "DescribeQueries"),                       # ✅ Log queries - log query configuration
            ("logs.amazonaws.com", "GetLogGroupFields"),                     # ✅ Log group fields - log structure information
            ("logs.amazonaws.com", "DescribeAccountPolicies"),               # ✅ Account policies - log account access policies
            ("logs.amazonaws.com", "DescribeIndexPolicies"),                 # ✅ Index policies - log indexing configuration
            ("logs.amazonaws.com", "GetTransformer"),                        # ✅ Log transformer - log data transformation configuration
            ("logs.amazonaws.com", "ListLogAnomalyDetectors"),               # ✅ Anomaly detectors - log anomaly detection configuration
            
            # Monitoring - CloudWatch metrics and alarms
            ("monitoring.amazonaws.com", "DescribeAnomalyDetectors"),         # ✅ Anomaly detectors - metric anomaly detection configuration
            ("monitoring.amazonaws.com", "DescribeInsightRules"),            # ✅ Insight rules - metric insight configuration
            ("monitoring.amazonaws.com", "GetDashboard"),                    # ✅ Dashboard details - monitoring dashboard configuration
            ("monitoring.amazonaws.com", "GetMetricWidgetImage"),            # ✅ Metric widget image - dashboard visualization generation
            ("monitoring.amazonaws.com", "DescribeAlarmHistory"),            # ✅ Alarm history - alert notification history
            
            # Application Insights - Application monitoring
            ("application-insights.amazonaws.com", "ListProblems"),          # ✅ Application problems - application issue inventory
            ("application-insights.amazonaws.com", "DescribeProblem"),       # ✅ Problem details - application issue analysis
            ("application-insights.amazonaws.com", "DescribeComponent"),     # ✅ Component details - application component analysis
            ("application-insights.amazonaws.com", "DescribeObservation"),   # ✅ Observation details - application performance observation
            ("application-insights.amazonaws.com", "ListObservations"),      # ✅ Observation inventory - application performance observations
            
            # Application Signals - Performance monitoring
            ("application-signals.amazonaws.com", "GetEntity"),              # ✅ Entity details - performance monitoring entity analysis
            
            # OAM - Observability Access Manager
            ("oam.amazonaws.com", "ListSinks"),                             # ✅ Observability sinks - monitoring sink inventory
            ("oam.amazonaws.com", "GetSink"),                               # ✅ Sink details - observability sink configuration
            ("oam.amazonaws.com", "ListAttachedLinks"),                     # ✅ Attached links - observability link inventory
            ("oam.amazonaws.com", "GetLink"),                               # ✅ Link details - observability link configuration
            
            # Trusted Advisor - Recommendations and checks
            ("trustedadvisor.amazonaws.com", "DescribeAccount"),            # ✅ Account details - Trusted Advisor account configuration
            ("trustedadvisor.amazonaws.com", "DescribeCheckSummaries"),     # ✅ Check summaries - Trusted Advisor recommendation summaries
            ("trustedadvisor.amazonaws.com", "DescribeChecks"),             # ✅ Check details - Trusted Advisor recommendation details
        })
        
        # SENSITIVE_WRITE: Monitoring operations that modify configurations
        self.sensitive_write.update({
            # Monitoring - CloudWatch configuration changes
            ("monitoring.amazonaws.com", "PutMetricAlarm"),                   # ✅ Put metric alarm - alert configuration creation
            ("monitoring.amazonaws.com", "DeleteAlarms"),                     # ✅ Delete alarms - alert configuration removal
            ("monitoring.amazonaws.com", "SetAlarmState"),                    # ✅ Set alarm state - alert state modification
            ("monitoring.amazonaws.com", "PutDashboard"),                     # ✅ Put dashboard - monitoring dashboard creation
            ("monitoring.amazonaws.com", "DeleteDashboards"),                 # ✅ Delete dashboards - monitoring dashboard removal
            
            # Logs - Log group configuration changes
            ("logs.amazonaws.com", "CreateLogGroup"),                         # ✅ Create log group - log collection setup
            ("logs.amazonaws.com", "DeleteLogGroup"),                         # ✅ Delete log group - log collection removal
            ("logs.amazonaws.com", "PutRetentionPolicy"),                     # ✅ Put retention policy - log retention configuration
            ("logs.amazonaws.com", "PutMetricFilter"),                        # ✅ Put metric filter - log filtering configuration
            ("logs.amazonaws.com", "DeleteMetricFilter"),                     # ✅ Delete metric filter - log filtering configuration removal
            
            # Application Insights - Configuration changes
            ("application-insights.amazonaws.com", "CreateApplication"),      # ✅ Create application - application monitoring setup
            ("application-insights.amazonaws.com", "DeleteApplication"),      # ✅ Delete application - application monitoring removal
            ("application-insights.amazonaws.com", "UpdateApplication"),      # ✅ Update application - application monitoring modification
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance
        self.hacking_reads.update({
            # Logs - Searching for sensitive information
            ("logs.amazonaws.com", "StartQuery"),                             # ✅ Start log query - log data search initiation
            ("logs.amazonaws.com", "StopQuery"),                              # ✅ Stop log query - log data search termination
            ("logs.amazonaws.com", "GetLogEvents"),                          # ✅ Log events - application and system log data (should be hacking reads)
            ("logs.amazonaws.com", "FilterLogEvents"),                       # ✅ Filter log events - targeted log data extraction (should be hacking reads)
            ("logs.amazonaws.com", "GetQueryResults"),                       # ✅ Query results - log query data extraction (should be hacking reads)
            ("logs.amazonaws.com", "GetLogRecord"),                          # ✅ Log record - individual log entry access (should be hacking reads)
            
            # Monitoring - Looking for system vulnerabilities
            ("monitoring.amazonaws.com", "GetInsightRuleReport"),             # ✅ Insight rule report - metric insight analysis
            ("monitoring.amazonaws.com", "ListAnomalyDetectors"),             # ✅ Anomaly detector list - metric anomaly detection inventory
            ("monitoring.amazonaws.com", "GetMetricData"),                   # ✅ Metric data - performance and operational metrics (should be hacking reads)
            ("monitoring.amazonaws.com", "GetMetricStatistics"),             # ✅ Metric statistics - performance data analysis (should be hacking reads)

            # Application Signals - Performance monitoring
            ("application-signals.amazonaws.com", "GetServiceGraph"),        # ✅ Service graph - application architecture mapping (should be hacking reads)
            ("application-signals.amazonaws.com", "GetTraceSummaries"),      # ✅ Trace summaries - application execution tracing (should be hacking reads)
        })
        
        # STRANGE_READS: Unusual monitoring operations
        self.strange_reads.update({
            # Health - Detailed health information that might be unusual
        })
        
