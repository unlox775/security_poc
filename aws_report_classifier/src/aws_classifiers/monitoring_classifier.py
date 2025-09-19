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
        """Initialize classification rules for monitoring services."""
        self.handled_sources = {
            "monitoring.amazonaws.com",        # CloudWatch monitoring for metrics and alarms
            "health.amazonaws.com",            # AWS Health for service status and events
            "logs.amazonaws.com",              # CloudWatch Logs for log collection and analysis
            "application-insights.amazonaws.com", # Application Insights for app performance monitoring
            "application-signals.amazonaws.com", # Application Signals for observability data
            "oam.amazonaws.com"               # Observability Access Manager for cross-account monitoring
        }
        
        # SAFE_READ_ONLY: Basic monitoring operations that don't expose sensitive data
        self.safe_read_only.update({
            # Health - Basic health status
            ("health.amazonaws.com", "DescribeEvents"),
            ("health.amazonaws.com", "DescribeAffectedEntities"),
        })
        
        # SENSITIVE_READ_ONLY: Monitoring operations that could expose sensitive information
        self.sensitive_read_only.update({
            # Logs - Log analysis and filtering
            ("logs.amazonaws.com", "DescribeMetricFilters"),
            ("logs.amazonaws.com", "DescribeLogGroups"),
            ("logs.amazonaws.com", "DescribeLogStreams"),
            ("logs.amazonaws.com", "GetLogEvents"),
            ("logs.amazonaws.com", "FilterLogEvents"),
            ("logs.amazonaws.com", "DescribeQueries"),
            ("logs.amazonaws.com", "GetQueryResults"),
            ("logs.amazonaws.com", "GetLogGroupFields"),
            ("logs.amazonaws.com", "GetLogRecord"),
            
            # Monitoring - CloudWatch metrics and alarms
            ("monitoring.amazonaws.com", "DescribeAnomalyDetectors"),
            ("monitoring.amazonaws.com", "DescribeInsightRules"),
            ("monitoring.amazonaws.com", "GetDashboard"),
            ("monitoring.amazonaws.com", "ListDashboards"),
            ("monitoring.amazonaws.com", "GetMetricData"),
            ("monitoring.amazonaws.com", "GetMetricStatistics"),
            ("monitoring.amazonaws.com", "ListMetrics"),
            ("monitoring.amazonaws.com", "GetMetricWidgetImage"),
            ("monitoring.amazonaws.com", "DescribeAlarmHistory"),
            
            # Application Insights - Application monitoring
            ("application-insights.amazonaws.com", "ListApplications"),
            ("application-insights.amazonaws.com", "ListProblems"),
            ("application-insights.amazonaws.com", "DescribeProblem"),
            ("application-insights.amazonaws.com", "ListComponents"),
            ("application-insights.amazonaws.com", "DescribeComponent"),
            ("application-insights.amazonaws.com", "DescribeObservation"),
            ("application-insights.amazonaws.com", "ListObservations"),
            
            # Application Signals - Performance monitoring
            ("application-signals.amazonaws.com", "ListObservedEntities"),
            ("application-signals.amazonaws.com", "GetEntity"),
            ("application-signals.amazonaws.com", "GetServiceGraph"),
            ("application-signals.amazonaws.com", "GetTraceSummaries"),
            
            # OAM - Observability Access Manager
            ("oam.amazonaws.com", "ListSinks"),
            ("oam.amazonaws.com", "GetSink"),
            ("oam.amazonaws.com", "ListAttachedLinks"),
            ("oam.amazonaws.com", "GetLink"),
        })
        
        # SENSITIVE_WRITE: Monitoring operations that modify configurations
        self.sensitive_write.update({
            # Monitoring - CloudWatch configuration changes
            ("monitoring.amazonaws.com", "PutMetricAlarm"),
            ("monitoring.amazonaws.com", "DeleteAlarms"),
            ("monitoring.amazonaws.com", "SetAlarmState"),
            ("monitoring.amazonaws.com", "PutDashboard"),
            ("monitoring.amazonaws.com", "DeleteDashboards"),
            
            # Logs - Log group configuration changes
            ("logs.amazonaws.com", "CreateLogGroup"),
            ("logs.amazonaws.com", "DeleteLogGroup"),
            ("logs.amazonaws.com", "PutRetentionPolicy"),
            ("logs.amazonaws.com", "PutMetricFilter"),
            ("logs.amazonaws.com", "DeleteMetricFilter"),
            
            # Application Insights - Configuration changes
            ("application-insights.amazonaws.com", "CreateApplication"),
            ("application-insights.amazonaws.com", "DeleteApplication"),
            ("application-insights.amazonaws.com", "UpdateApplication"),
        })
        
        # HACKING_READS: Operations that could be used for reconnaissance
        self.hacking_reads.update({
            # Logs - Searching for sensitive information
            ("logs.amazonaws.com", "StartQuery"),
            ("logs.amazonaws.com", "StopQuery"),
            
            # Monitoring - Looking for system vulnerabilities
            ("monitoring.amazonaws.com", "GetInsightRuleReport"),
            ("monitoring.amazonaws.com", "ListAnomalyDetectors"),
        })
        
        # STRANGE_READS: Unusual monitoring operations
        self.strange_reads.update({
            # Health - Detailed health information that might be unusual
        })
        
        # INFRA_READS: Infrastructure monitoring management
        self.infra_reads.update({
            # Monitoring - Infrastructure monitoring setup
            ("monitoring.amazonaws.com", "DescribeAlarmHistory"),
            ("monitoring.amazonaws.com", "ListMetricStreams"),
            ("monitoring.amazonaws.com", "DescribeMetricStreams"),
            
            # OAM - Infrastructure observability management
            ("oam.amazonaws.com", "ListLinks"),
        })
