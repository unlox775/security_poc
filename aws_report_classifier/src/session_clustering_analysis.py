#!/usr/bin/env python3
"""
Session Clustering Analysis Script for AWS CloudTrail Logs

This script analyzes AWS CloudTrail logs to identify activity sessions based on 
3-hour gaps between events. It categorizes actions as read-only or other actions,
and generates detailed session reports.

Author: AI Assistant
Date: 2025-01-27
"""

import pandas as pd
import numpy as np
import re
import os
from datetime import datetime, timedelta
import pytz
from collections import defaultdict, Counter
import glob
from event_classifier import EventClassifier

class SessionClusteringAnalyzer:
    def __init__(self, gap_hours=3):
        """
        Initialize the analyzer with session gap threshold
        
        Args:
            gap_hours (int): Hours between events to consider as separate sessions
        """
        self.gap_hours = gap_hours
        self.gap_seconds = gap_hours * 3600
        self.read_action_pattern = re.compile(r'^(List|Describe|Get|Decrypt)', re.IGNORECASE)
        self.event_classifier = EventClassifier()
        self.anomalies = []
        self.column_mapping = {}
    
    def detect_column_mapping(self, df):
        """
        Detect and map CSV columns to expected field names.
        This makes the tool flexible to handle different CSV formats.
        
        Args:
            df (pd.DataFrame): The CSV data
            
        Returns:
            dict: Mapping of expected fields to actual column names
        """
        mapping = {}
        columns = df.columns.tolist()
        
        # Common column name variations and their expected mappings
        column_variations = {
            'eventTime': ['eventTime', 'eventtime', 'event_time', 'timestamp', 'time'],
            'eventSource': ['eventSource', 'eventsource', 'event_source', 'service', 'source'],
            'eventName': ['eventName', 'eventname', 'event_name', 'action', 'operation'],
            'userIdentity.type': ['userIdentity.type', 'useridentity.type', 'user_type', 'userType', 'identityType'],
            'userIdentity.arn': ['userIdentity.arn', 'useridentity.arn', 'user_arn', 'userArn', 'identityArn'],
            'userIdentity.userName': ['userIdentity.userName', 'useridentity.username', 'user_name', 'userName', 'identityUserName'],
            'sourceIPAddress': ['sourceIPAddress', 'sourceipaddress', 'source_ip', 'ip', 'clientIp'],
            'awsRegion': ['awsRegion', 'awsregion', 'region', 'aws_region']
        }
        
        # Find matching columns
        for expected_field, variations in column_variations.items():
            for col in columns:
                if col in variations:
                    mapping[expected_field] = col
                    break
        
        # Store the mapping for later use
        self.column_mapping = mapping
        
        # Report any missing required columns
        required_fields = ['eventTime', 'eventSource', 'eventName']
        missing_fields = [field for field in required_fields if field not in mapping]
        
        if missing_fields:
            self.anomalies.append(f"Missing required columns: {missing_fields}")
            print(f"⚠️  Warning: Missing required columns: {missing_fields}")
            print(f"Available columns: {columns}")
        
        return mapping
    
    def get_column(self, df, expected_field):
        """
        Get the actual column name for an expected field using the mapping
        
        Args:
            df (pd.DataFrame): The dataframe
            expected_field (str): Expected field name
            
        Returns:
            str: Actual column name or None if not found
        """
        if expected_field in self.column_mapping:
            actual_col = self.column_mapping[expected_field]
            if actual_col in df.columns:
                return actual_col
        return None
        
    def load_and_combine_data(self, dev_file, prod_file):
        """
        Load and combine data from dev and prod CSV files
        
        Args:
            dev_file (str): Path to dev CSV file
            prod_file (str): Path to prod CSV file
            
        Returns:
            pd.DataFrame: Combined and sorted dataframe
        """
        print(f"Loading data from {dev_file} and {prod_file}...")
        
        # Load dev data
        dev_df = pd.read_csv(dev_file)
        dev_df['source_file'] = 'dev'
        
        # Load prod data  
        prod_df = pd.read_csv(prod_file)
        prod_df['source_file'] = 'prod'
        
        # Combine dataframes
        combined_df = pd.concat([dev_df, prod_df], ignore_index=True)
        
        # Detect column mapping for flexible CSV handling
        self.detect_column_mapping(combined_df)
        
        # Get the actual column names for required fields
        event_time_col = self.get_column(combined_df, 'eventTime')
        
        if event_time_col:
            # Convert eventTime to datetime
            combined_df[event_time_col] = pd.to_datetime(combined_df[event_time_col])
            # Sort by eventTime
            combined_df = combined_df.sort_values(event_time_col).reset_index(drop=True)
        else:
            self.anomalies.append("Cannot find eventTime column for sorting")
            print("⚠️  Warning: Cannot find eventTime column for sorting")
        
        # Check for data quality issues
        self._check_data_quality(combined_df)
        
        print(f"Loaded {len(dev_df)} dev events and {len(prod_df)} prod events")
        print(f"Total events: {len(combined_df)}")
        
        return combined_df
    
    def load_data_from_env_vars(self, env_names):
        """
        Load and combine data from environment variables ENV_{NAME}_CSV
        
        Args:
            env_names (list): List of environment names (e.g., ['dev', 'prod', 'staging'])
            
        Returns:
            pd.DataFrame: Combined and sorted dataframe
        """
        import os
        
        dataframes = []
        total_events = 0
        
        print(f"Loading data from {len(env_names)} environments: {', '.join(env_names)}")
        
        for env_name in env_names:
            env_var_name = f"ENV_{env_name.upper()}_CSV"
            csv_file = os.getenv(env_var_name)
            
            if not csv_file:
                raise ValueError(f"Environment variable {env_var_name} not set")
            
            if not os.path.exists(csv_file):
                raise FileNotFoundError(f"CSV file not found for {env_name}: {csv_file}")
            
            # Load data
            df = pd.read_csv(csv_file)
            df['source_file'] = env_name
            dataframes.append(df)
            
            print(f"Loaded {len(df)} events from {env_name} ({csv_file})")
            total_events += len(df)
        
        # Combine all dataframes
        combined_df = pd.concat(dataframes, ignore_index=True)
        print(f"Total events loaded: {total_events}")
        
        # Detect column mapping for flexible CSV handling
        self.detect_column_mapping(combined_df)
        
        # Get the actual column names for required fields
        event_time_col = self.get_column(combined_df, 'eventTime')
        
        if event_time_col:
            # Convert eventTime to datetime and sort
            combined_df[event_time_col] = pd.to_datetime(combined_df[event_time_col])
            combined_df = combined_df.sort_values(event_time_col).reset_index(drop=True)
        else:
            self.anomalies.append("Cannot find eventTime column for sorting")
            print("⚠️  Warning: Cannot find eventTime column for sorting")
        
        # Check for data quality issues
        self._check_data_quality(combined_df)
        
        return combined_df
    
    def load_single_csv_file(self, csv_file):
        """
        Load data from a single CSV file
        
        Args:
            csv_file (str): Path to CSV file
            
        Returns:
            pd.DataFrame: Combined and sorted dataframe
        """
        print(f"Loading data from single file: {csv_file}")
        
        if not os.path.exists(csv_file):
            raise FileNotFoundError(f"CSV file not found: {csv_file}")
        
        df = pd.read_csv(csv_file)
        df['source_file'] = 'data'  # Generic name for single file
        
        print(f"Loaded {len(df)} events")
        
        # Detect column mapping for flexible CSV handling
        self.detect_column_mapping(df)
        
        # Get the actual column names for required fields
        event_time_col = self.get_column(df, 'eventTime')
        
        if event_time_col:
            # Convert eventTime to datetime and sort
            df[event_time_col] = pd.to_datetime(df[event_time_col])
            df = df.sort_values(event_time_col).reset_index(drop=True)
        else:
            self.anomalies.append("Cannot find eventTime column for sorting")
            print("⚠️  Warning: Cannot find eventTime column for sorting")
        
        # Check for data quality issues
        self._check_data_quality(df)
        
        return df
    
    def _check_data_quality(self, df):
        """
        Check for data quality issues and add to anomalies list
        
        Args:
            df (pd.DataFrame): Combined dataframe
        """
        # Get actual column names
        event_time_col = self.get_column(df, 'eventTime')
        event_source_col = self.get_column(df, 'eventSource')
        event_name_col = self.get_column(df, 'eventName')
        
        # Check for missing eventTime
        if event_time_col:
            missing_times = df[event_time_col].isna().sum()
            if missing_times > 0:
                self.anomalies.append(f"Missing eventTime values: {missing_times} events")
        
        # Check for missing eventSource
        if event_source_col:
            missing_sources = df[event_source_col].isna().sum()
            if missing_sources > 0:
                self.anomalies.append(f"Missing eventSource values: {missing_sources} events")
        
        # Check for missing eventName
        if event_name_col:
            missing_names = df[event_name_col].isna().sum()
            if missing_names > 0:
                self.anomalies.append(f"Missing eventName values: {missing_names} events")
        
        # Check for unusual eventSources (not AWS)
        if event_source_col:
            non_aws_sources = df[~df[event_source_col].str.contains('amazonaws.com', na=False)][event_source_col].unique()
            if len(non_aws_sources) > 0:
                self.anomalies.append(f"Non-AWS event sources detected: {list(non_aws_sources)}")
        
        # Check for unusual date ranges
        if event_time_col:
            date_range = df[event_time_col].max() - df[event_time_col].min()
            if date_range.days > 365:
                self.anomalies.append(f"Unusual date range: {date_range.days} days span")
        
    
    def identify_sessions(self, df):
        """
        Identify activity sessions based on time gaps
        
        Args:
            df (pd.DataFrame): Combined dataframe sorted by eventTime
            
        Returns:
            list: List of session dataframes
        """
        print("Identifying activity sessions...")
        
        sessions = []
        current_session = []
        
        # Get the actual column name for eventTime
        event_time_col = self.get_column(df, 'eventTime')
        if not event_time_col:
            raise ValueError("Cannot find eventTime column for session identification")
        
        for i, row in df.iterrows():
            if i == 0:
                # First event starts first session
                current_session.append(row)
            else:
                # Calculate time difference from previous event
                time_diff = (row[event_time_col] - df.iloc[i-1][event_time_col]).total_seconds()
                
                if time_diff <= self.gap_seconds:
                    # Within session gap, add to current session
                    current_session.append(row)
                else:
                    # Gap too large, start new session
                    if current_session:
                        sessions.append(pd.DataFrame(current_session))
                    current_session = [row]
        
        # Add final session
        if current_session:
            sessions.append(pd.DataFrame(current_session))
            
        print(f"Identified {len(sessions)} activity sessions")
        return sessions
    
    def categorize_action(self, event_source, event_name):
        """
        Categorize action using the event classifier
        
        Args:
            event_source (str): AWS event source
            event_name (str): AWS event name
            
        Returns:
            str: Classification from event classifier
        """
        if pd.isna(event_source) or pd.isna(event_name):
            return 'UNCLASSIFIED'
            
        return self.event_classifier.classify_event(event_source, event_name)
    
    def clean_service_name(self, service_name):
        """
        Clean AWS service name by removing 'amazonaws.com' suffix
        
        Args:
            service_name (str): Full AWS service name
            
        Returns:
            str: Cleaned service name
        """
        if pd.isna(service_name):
            return 'Unknown'
            
        # Remove .amazonaws.com suffix
        cleaned = service_name.replace('.amazonaws.com', '')
        return cleaned
    
    def extract_user_info(self, user_type, user_arn, user_name):
        """
        Extract user type from userIdentity.type, ARN or username
        
        Args:
            user_type (str): userIdentity.type field
            user_arn (str): User ARN
            user_name (str): Username
            
        Returns:
            str: Detected user identifier (e.g., 'root', 'user.name', 'john.doe', etc.)
        """
        # Check userIdentity.type first - this is the most reliable indicator
        if not pd.isna(user_type):
            if user_type == 'Root':
                return 'root'
            elif user_type == 'IAMUser':
                # For IAMUser, use the username directly
                if not pd.isna(user_name):
                    return user_name
                else:
                    return 'unknown_iam_user'
            elif user_type == 'AssumedRole':
                # For AssumedRole, extract username from ARN
                if not pd.isna(user_arn):
                    # Extract username from ARN (e.g., assumed-role/RoleName/username)
                    arn_parts = user_arn.split('/')
                    if len(arn_parts) >= 3:
                        username = arn_parts[-1]  # Last part is usually the username
                        if '@' in username:
                            # Extract name part before @ for email addresses
                            username = username.split('@')[0]
                        return username
                    else:
                        # Fallback to using the full ARN
                        return user_arn.split(':')[-1] if ':' in user_arn else user_arn
                elif not pd.isna(user_name):
                    return user_name
                else:
                    return 'unknown_assumed_role'
            elif user_type == 'SAMLUser':
                # For SAMLUser, use the username
                if not pd.isna(user_name):
                    if '@' in user_name:
                        # Extract name part before @ for email addresses
                        return user_name.split('@')[0]
                    else:
                        return user_name
                elif not pd.isna(user_arn):
                    # Try to extract from ARN
                    arn_parts = user_arn.split('/')
                    if len(arn_parts) >= 2:
                        return arn_parts[-1]
                    else:
                        return 'unknown_saml_user'
                else:
                    return 'unknown_saml_user'
            elif user_type == 'FederatedUser':
                # For FederatedUser, try to extract username from ARN or userName
                if not pd.isna(user_arn):
                    arn_parts = user_arn.split('/')
                    if len(arn_parts) >= 2:
                        username = arn_parts[-1]
                        if '@' in username:
                            username = username.split('@')[0]
                        return username
                    else:
                        return user_arn.split(':')[-1] if ':' in user_arn else user_arn
                elif not pd.isna(user_name):
                    if '@' in user_name:
                        return user_name.split('@')[0]
                    else:
                        return user_name
                else:
                    return 'unknown_federated_user'
            else:
                # Unknown userIdentity.type - log it but don't treat as anomalous
                return f'unknown_type_{user_type}'
        
        # Fallback logic for missing userIdentity.type
        if not pd.isna(user_arn) and '/root' in user_arn:
            return 'root'
        elif not pd.isna(user_arn):
            # Try to extract username from ARN
            arn_parts = user_arn.split('/')
            if len(arn_parts) >= 2:
                username = arn_parts[-1]
                if '@' in username:
                    username = username.split('@')[0]
                return username
            else:
                return user_arn.split(':')[-1] if ':' in user_arn else user_arn
        elif not pd.isna(user_name):
            if '@' in user_name:
                return user_name.split('@')[0]
            else:
                return user_name
        else:
            return 'unknown_user'
    
    def analyze_session(self, session_df):
        """
        Analyze a single session and return summary statistics
        
        Args:
            session_df (pd.DataFrame): Session dataframe
            
        Returns:
            dict: Session analysis results
        """
        # Get actual column names
        event_time_col = self.get_column(session_df, 'eventTime')
        event_source_col = self.get_column(session_df, 'eventSource')
        event_name_col = self.get_column(session_df, 'eventName')
        user_type_col = self.get_column(session_df, 'userIdentity.type')
        user_arn_col = self.get_column(session_df, 'userIdentity.arn')
        user_name_col = self.get_column(session_df, 'userIdentity.userName')
        
        if not all([event_time_col, event_source_col, event_name_col]):
            raise ValueError("Missing required columns for session analysis")
        
        # Basic session info
        start_time = session_df[event_time_col].min()
        end_time = session_df[event_time_col].max()
        duration_hours = (end_time - start_time).total_seconds() / 3600
        
        # Convert to PST for display
        pst = pytz.timezone('US/Pacific')
        start_time_pst = start_time.astimezone(pst)
        
        # Categorize actions using event classifier
        session_df['action_category'] = session_df.apply(lambda row: self.categorize_action(row[event_source_col], row[event_name_col]), axis=1)
        
        # Count events by classification category
        classification_counts = session_df['action_category'].value_counts().to_dict()
        
        # Get unique services
        services = session_df[event_source_col].apply(self.clean_service_name).unique()
        services_list = ', '.join(sorted(services))
        
        # Get unique users
        session_df['user_type'] = session_df.apply(
            lambda row: self.extract_user_info(
                row.get(user_type_col) if user_type_col else None,
                row.get(user_arn_col) if user_arn_col else None,
                row.get(user_name_col) if user_name_col else None
            ), 
            axis=1
        )
        users = session_df['user_type'].unique()
        
        # Create user list for filename - use 'multiple' if more than 2 users
        if len(users) > 2:
            users_list = 'multiple'
        else:
            users_list = ', '.join(sorted(users))
        
        # Determine source files involved
        source_files = session_df['source_file'].unique()
        if len(source_files) == 2:
            source_indicator = 'both'
        elif 'dev' in source_files:
            source_indicator = 'dev'
        else:
            source_indicator = 'prod'
        
        # Generate filename components
        date_str = start_time_pst.strftime('%Y-%m-%d')
        time_str = start_time_pst.strftime('%H-%M')
        duration_str = f"{duration_hours:.1f}"
        
        filename = f"{date_str}_{time_str}_duration_{duration_str}hr-{source_indicator}-{users_list}"
        
        # Create session summary
        summary = {
            'filename': filename,
            'start_time': start_time,
            'start_time_pst': start_time_pst,
            'end_time': end_time,
            'duration_hours': duration_hours,
            'total_events': len(session_df),
            'classification_counts': classification_counts,
            'services': services_list,
            'users': users_list,
            'source_files': source_indicator,
            'session_data': session_df
        }
        
        return summary
    
    def generate_session_report(self, session_summary):
        """
        Generate human-readable session report header
        
        Args:
            session_summary (dict): Session analysis results
            
        Returns:
            str: Formatted report header
        """
        report_lines = [
            "=" * 80,
            "ACTIVITY SESSION ANALYSIS REPORT",
            "=" * 80,
            "",
            f"Session Start Time (PST): {session_summary['start_time_pst'].strftime('%Y-%m-%d %I:%M:%S %p')}",
            f"Session End Time (PST):   {session_summary['end_time'].astimezone(pytz.timezone('US/Pacific')).strftime('%Y-%m-%d %I:%M:%S %p')}",
            f"Session Duration:         {session_summary['duration_hours']:.1f} hours",
            "",
            f"Total Events:             {session_summary['total_events']}",
            "",
            "Event Classifications:",
        ]
        
        # Add classification breakdown
        for classification, count in sorted(session_summary['classification_counts'].items()):
            report_lines.append(f"  {classification:<20}: {count:>4} events")
        
        report_lines.extend([
            "",
            f"Services Accessed:        {session_summary['services']}",
            f"Users:                    {session_summary['users']}",
            f"Source Files:             {session_summary['source_files']}",
            "",
            "=" * 80,
            "DETAILED EVENT DATA",
            "=" * 80,
            ""
        ])
        
        return '\n'.join(report_lines)
    
    def create_output_directory(self, base_dir):
        """
        Create activity_sessions output directory and clear any existing files
        
        Args:
            base_dir (str): Base directory path
            
        Returns:
            str: Path to created directory
        """
        output_dir = os.path.join(base_dir, 'activity_sessions')
        
        # Remove existing directory if it exists
        if os.path.exists(output_dir):
            import shutil
            shutil.rmtree(output_dir)
            print(f"Cleared existing output directory: {output_dir}")
        
        # Create fresh directory
        os.makedirs(output_dir, exist_ok=True)
        print(f"Created output directory: {output_dir}")
        return output_dir
    
    def save_session_file(self, session_summary, output_dir):
        """
        Save session data to CSV file with report header
        
        Args:
            session_summary (dict): Session analysis results
            output_dir (str): Output directory path
        """
        filename = session_summary['filename'] + '.csv'
        filepath = os.path.join(output_dir, filename)
        
        # Generate report header
        report_header = self.generate_session_report(session_summary)
        
        # Prepare session data for CSV (move source_file to beginning)
        session_data = session_summary['session_data'].copy()
        cols = list(session_data.columns)
        cols.remove('source_file')
        cols.insert(0, 'source_file')
        session_data = session_data[cols]
        
        # Write file with header
        with open(filepath, 'w') as f:
            f.write(report_header)
            session_data.to_csv(f, index=False)
        
        print(f"Saved session file: {filename}")
    
    def run_analysis(self, dev_file, prod_file, output_base_dir):
        """
        Run complete session clustering analysis
        
        Args:
            dev_file (str): Path to dev CSV file
            prod_file (str): Path to prod CSV file  
            output_base_dir (str): Base directory for output
        """
        print("Starting Session Clustering Analysis")
        print("=" * 50)
        
        # Load and combine data
        combined_df = self.load_and_combine_data(dev_file, prod_file)
        
        # Identify sessions
        sessions = self.identify_sessions(combined_df)
        
        # Create output directory
        output_dir = self.create_output_directory(output_base_dir)
        
        # Analyze and save each session
        print(f"\nProcessing {len(sessions)} sessions...")
        for i, session_df in enumerate(sessions, 1):
            print(f"Processing session {i}/{len(sessions)}...")
            session_summary = self.analyze_session(session_df)
            self.save_session_file(session_summary, output_dir)
        
        print(f"\nAnalysis complete! Generated {len(sessions)} session files in {output_dir}")
        
        # Print summary statistics
        print("\nSummary Statistics:")
        print("-" * 30)
        print(f"Total events processed: {len(combined_df)}")
        print(f"Sessions identified: {len(sessions)}")
        print(f"Average events per session: {len(combined_df) / len(sessions):.1f}")
        
        # Report anomalies
        if self.anomalies:
            print(f"\n⚠️  ANOMALIES DETECTED ({len(self.anomalies)} total):")
            print("-" * 50)
            for i, anomaly in enumerate(self.anomalies, 1):
                print(f"{i}. {anomaly}")
        else:
            print("\n✅ No anomalies detected - all users properly identified")
        
        return sessions
    
    def run_analysis_with_env_vars(self, env_names, output_base_dir):
        """
        Run complete session clustering analysis using environment variables
        
        Args:
            env_names (list): List of environment names (e.g., ['dev', 'prod', 'staging'])
            output_base_dir (str): Base directory for output
        """
        print("Starting Session Clustering Analysis (Multi-Environment)")
        print("=" * 50)
        
        # Load and combine data from environment variables
        combined_df = self.load_data_from_env_vars(env_names)
        
        # Identify sessions
        sessions = self.identify_sessions(combined_df)
        
        # Create output directory
        output_dir = self.create_output_directory(output_base_dir)
        
        # Process and save sessions
        print(f"\nProcessing {len(sessions)} sessions...")
        for i, session_df in enumerate(sessions, 1):
            print(f"Processing session {i}/{len(sessions)}...")
            
            # Analyze session
            session_summary = self.analyze_session(session_df)
            
            # Save session to file
            self.save_session_file(session_summary, output_dir)
            print(f"Saved session file: {session_summary['filename']}.csv")
        
        # Print summary
        print(f"\nAnalysis complete! Generated {len(sessions)} session files in {output_dir}")
        print(f"\nSummary Statistics:")
        print("-" * 30)
        print(f"Total events processed: {len(combined_df)}")
        print(f"Sessions identified: {len(sessions)}")
        print(f"Average events per session: {len(combined_df)/len(sessions):.1f}")
        
        # Report anomalies
        if self.anomalies:
            print(f"\n⚠️  Anomalies detected:")
            for i, anomaly in enumerate(self.anomalies, 1):
                print(f"{i}. {anomaly}")
        else:
            print("\n✅ No anomalies detected - all users properly identified")
        
        return sessions
    
    def run_analysis_with_single_file(self, csv_file, output_base_dir):
        """
        Run complete session clustering analysis using a single CSV file
        
        Args:
            csv_file (str): Path to CSV file
            output_base_dir (str): Base directory for output
        """
        print("Starting Session Clustering Analysis (Single File)")
        print("=" * 50)
        
        # Load data from single file
        combined_df = self.load_single_csv_file(csv_file)
        
        # Identify sessions
        sessions = self.identify_sessions(combined_df)
        
        # Create output directory
        output_dir = self.create_output_directory(output_base_dir)
        
        # Process and save sessions
        print(f"\nProcessing {len(sessions)} sessions...")
        for i, session_df in enumerate(sessions, 1):
            print(f"Processing session {i}/{len(sessions)}...")
            
            # Analyze session
            session_summary = self.analyze_session(session_df)
            
            # Save session to file
            self.save_session_file(session_summary, output_dir)
            print(f"Saved session file: {session_summary['filename']}.csv")
        
        # Print summary
        print(f"\nAnalysis complete! Generated {len(sessions)} session files in {output_dir}")
        print(f"\nSummary Statistics:")
        print("-" * 30)
        print(f"Total events processed: {len(combined_df)}")
        print(f"Sessions identified: {len(sessions)}")
        print(f"Average events per session: {len(combined_df)/len(sessions):.1f}")
        
        # Report anomalies
        if self.anomalies:
            print(f"\n⚠️  Anomalies detected:")
            for i, anomaly in enumerate(self.anomalies, 1):
                print(f"{i}. {anomaly}")
        else:
            print("\n✅ No anomalies detected - all users properly identified")
        
        return sessions

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze AWS CloudTrail events for session clustering')
    parser.add_argument('--csv', help='Path to single CSV file for analysis')
    parser.add_argument('--env-csvs', help='Comma-separated list of environment names (e.g., dev,prod,staging)')
    parser.add_argument('--output-dir', default='.', help='Output directory for session files (default: current directory)')
    parser.add_argument('--gap-hours', type=int, default=3, help='Hours between events to consider separate sessions (default: 3)')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = SessionClusteringAnalyzer(gap_hours=args.gap_hours)
    
    # Determine data loading method and run analysis
    if args.csv:
        # Single CSV file mode
        sessions = analyzer.run_analysis_with_single_file(args.csv, args.output_dir)
    elif args.env_csvs:
        # Multi-environment mode
        env_names = [name.strip() for name in args.env_csvs.split(',')]
        sessions = analyzer.run_analysis_with_env_vars(env_names, args.output_dir)
    else:
        parser.error("Must specify either --csv or --env-csvs")
    
    return sessions

if __name__ == "__main__":
    sessions = main()
