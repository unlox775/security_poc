#!/usr/bin/env python3
"""
AWS CloudTrail Event Classifier Audit Script

This script performs comprehensive audits on the event classifier structure
to ensure it's internally consistent and properly organized.

Audits performed:
1. Dashboard reads overlap check
2. Service source conflict check  
3. Duplicate events within classifiers
4. Empty classifiers check
5. Source consistency validation
6. Classification summary statistics

Author: AI Assistant
Date: 2025-01-27
"""

import sys
import os
from event_classifier import EventClassifier


class ClassifierAuditor:
    """Auditor for AWS CloudTrail event classifier structure and consistency."""
    
    def __init__(self):
        """Initialize the auditor with the event classifier."""
        self.classifier = EventClassifier()
        self.issues_found = []
        self.warnings_found = []
    
    def audit_dashboard_overlaps(self):
        """
        Audit 1: Check for dashboard reads that are also in service-specific classifiers.
        
        Returns:
            dict: Results of the audit
        """
        print("🔍 AUDIT 1: Dashboard Reads Overlap Check")
        print("-" * 50)
        
        dashboard_overlaps = []
        
        for dashboard_event in self.classifier.dashboard_reads:
            dashboard_source, dashboard_name = dashboard_event
            
            for service_classifier in self.classifier.classifiers:
                classifier_name = service_classifier.__class__.__name__
                service_classification = service_classifier.classify_event(dashboard_source, dashboard_name)
                
                if service_classification and service_classification != 'UNCLASSIFIED':
                    dashboard_overlaps.append({
                        'event': dashboard_event,
                        'dashboard_classification': 'DASHBOARD_READS',
                        'service_classification': service_classification,
                        'service_classifier': classifier_name
                    })
        
        if dashboard_overlaps:
            print(f"❌ FOUND {len(dashboard_overlaps)} DASHBOARD READS OVERLAPS:")
            for overlap in dashboard_overlaps:
                source, name = overlap['event']
                service = source.replace('.amazonaws.com', '')
                print(f"  - {service}: {name}")
                print(f"    Dashboard: {overlap['dashboard_classification']}")
                print(f"    Service: {overlap['service_classification']} in {overlap['service_classifier']}")
                print(f"    ⚠️  Remove from service classifier!")
            
            self.issues_found.append(f"{len(dashboard_overlaps)} dashboard overlaps")
        else:
            print("✅ No dashboard reads overlaps found!")
        
        return {
            'passed': len(dashboard_overlaps) == 0,
            'overlaps': dashboard_overlaps,
            'count': len(dashboard_overlaps)
        }
    
    def audit_source_conflicts(self):
        """
        Audit 2: Check for source conflicts between service classifiers.
        
        Returns:
            dict: Results of the audit
        """
        print("\n🔍 AUDIT 2: Service Source Conflict Check")
        print("-" * 50)
        
        source_conflicts = {}
        all_sources_by_classifier = {}
        
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            all_sources_by_classifier[classifier_name] = service_classifier.handled_sources
            
            for source in service_classifier.handled_sources:
                if source not in source_conflicts:
                    source_conflicts[source] = []
                source_conflicts[source].append(classifier_name)
        
        # Find sources handled by multiple classifiers
        multi_handled_sources = {source: classifiers for source, classifiers in source_conflicts.items() 
                               if len(classifiers) > 1}
        
        if multi_handled_sources:
            print(f"❌ FOUND {len(multi_handled_sources)} SOURCE CONFLICTS:")
            for source, classifiers in multi_handled_sources.items():
                service = source.replace('.amazonaws.com', '')
                print(f"  - {service} handled by: {', '.join(classifiers)}")
                print(f"    ⚠️  Remove from all but one classifier!")
            
            self.issues_found.append(f"{len(multi_handled_sources)} source conflicts")
        else:
            print("✅ No source conflicts found!")
        
        return {
            'passed': len(multi_handled_sources) == 0,
            'conflicts': multi_handled_sources,
            'count': len(multi_handled_sources)
        }
    
    def audit_duplicate_events(self):
        """
        Audit 3: Check for duplicate events within service classifiers.
        
        Returns:
            dict: Results of the audit
        """
        print("\n🔍 AUDIT 3: Duplicate Events Within Service Classifiers")
        print("-" * 50)
        
        duplicate_events = []
        
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            
            # Collect all events from all categories
            all_events = set()
            all_events.update(service_classifier.safe_read_only)
            all_events.update(service_classifier.sensitive_read_only)
            all_events.update(service_classifier.sensitive_write)
            all_events.update(service_classifier.hacking_reads)
            all_events.update(service_classifier.strange_reads)
            all_events.update(service_classifier.infra_reads)
            
            # Check for duplicates
            event_counts = {}
            for event in all_events:
                if event in event_counts:
                    event_counts[event] += 1
                else:
                    event_counts[event] = 1
            
            duplicates = {event: count for event, count in event_counts.items() if count > 1}
            
            if duplicates:
                duplicate_events.append({
                    'classifier': classifier_name,
                    'duplicates': duplicates
                })
        
        if duplicate_events:
            print(f"❌ FOUND DUPLICATE EVENTS WITHIN SERVICE CLASSIFIERS:")
            for dup_info in duplicate_events:
                print(f"  - {dup_info['classifier']}:")
                for event, count in dup_info['duplicates'].items():
                    source, name = event
                    service = source.replace('.amazonaws.com', '')
                    print(f"    {service}: {name} (appears {count} times)")
            
            self.issues_found.append(f"Duplicate events in {len(duplicate_events)} classifiers")
        else:
            print("✅ No duplicate events within service classifiers!")
        
        return {
            'passed': len(duplicate_events) == 0,
            'duplicates': duplicate_events,
            'count': len(duplicate_events)
        }
    
    def audit_empty_classifiers(self):
        """
        Audit 4: Check for empty service classifiers.
        
        Returns:
            dict: Results of the audit
        """
        print("\n🔍 AUDIT 4: Empty Service Classifiers Check")
        print("-" * 50)
        
        empty_classifiers = []
        
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            
            total_events = (len(service_classifier.safe_read_only) + 
                           len(service_classifier.sensitive_read_only) + 
                           len(service_classifier.sensitive_write) + 
                           len(service_classifier.hacking_reads) + 
                           len(service_classifier.strange_reads) + 
                           len(service_classifier.infra_reads))
            
            if total_events == 0:
                empty_classifiers.append(classifier_name)
        
        if empty_classifiers:
            print(f"⚠️  FOUND {len(empty_classifiers)} EMPTY SERVICE CLASSIFIERS:")
            for classifier_name in empty_classifiers:
                print(f"  - {classifier_name}")
            print("    Consider removing these classifiers or adding events to them.")
            
            self.warnings_found.append(f"{len(empty_classifiers)} empty classifiers")
        else:
            print("✅ No empty service classifiers found!")
        
        return {
            'passed': len(empty_classifiers) == 0,
            'empty_classifiers': empty_classifiers,
            'count': len(empty_classifiers)
        }
    
    def audit_source_consistency(self):
        """
        Audit 5: Check that all events in classifiers match their handled_sources lists.
        
        Returns:
            dict: Results of the audit
        """
        print("\n🔍 AUDIT 5: Source Consistency Check")
        print("-" * 50)
        
        inconsistent_sources = []
        
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            
            # Collect all events from all categories
            all_events = set()
            all_events.update(service_classifier.safe_read_only)
            all_events.update(service_classifier.sensitive_read_only)
            all_events.update(service_classifier.sensitive_write)
            all_events.update(service_classifier.hacking_reads)
            all_events.update(service_classifier.strange_reads)
            all_events.update(service_classifier.infra_reads)
            
            # Check each event's source against handled_sources
            for event_source, event_name in all_events:
                if event_source not in service_classifier.handled_sources:
                    inconsistent_sources.append({
                        'classifier': classifier_name,
                        'event_source': event_source,
                        'event_name': event_name,
                        'issue': 'Event source not in handled_sources'
                    })
            
            # Check for handled_sources with no events
            for handled_source in service_classifier.handled_sources:
                has_events = any(event_source == handled_source for event_source, _ in all_events)
                if not has_events:
                    inconsistent_sources.append({
                        'classifier': classifier_name,
                        'event_source': handled_source,
                        'event_name': None,
                        'issue': 'Handled source has no events'
                    })
        
        if inconsistent_sources:
            print(f"❌ FOUND {len(inconsistent_sources)} SOURCE CONSISTENCY ISSUES:")
            for issue in inconsistent_sources:
                if issue['event_name']:
                    service = issue['event_source'].replace('.amazonaws.com', '')
                    print(f"  - {issue['classifier']}: {service}:{issue['event_name']}")
                    print(f"    Issue: {issue['issue']}")
                else:
                    service = issue['event_source'].replace('.amazonaws.com', '')
                    print(f"  - {issue['classifier']}: {service}")
                    print(f"    Issue: {issue['issue']}")
            
            self.issues_found.append(f"{len(inconsistent_sources)} source consistency issues")
        else:
            print("✅ All events match their handled_sources lists!")
        
        return {
            'passed': len(inconsistent_sources) == 0,
            'inconsistencies': inconsistent_sources,
            'count': len(inconsistent_sources)
        }
    
    def audit_summary_statistics(self):
        """
        Audit 6: Classification summary statistics.
        
        Returns:
            dict: Results of the audit
        """
        print("\n🔍 AUDIT 6: Classification Summary Statistics")
        print("-" * 50)
        
        total_dashboard_events = len(self.classifier.dashboard_reads)
        total_service_events = 0
        all_service_sources = set()
        
        for service_classifier in self.classifier.classifiers:
            classifier_name = service_classifier.__class__.__name__
            classifier_events = (len(service_classifier.safe_read_only) + 
                               len(service_classifier.sensitive_read_only) + 
                               len(service_classifier.sensitive_write) + 
                               len(service_classifier.hacking_reads) + 
                               len(service_classifier.strange_reads) + 
                               len(service_classifier.infra_reads))
            total_service_events += classifier_events
            all_service_sources.update(service_classifier.handled_sources)
            
            print(f"  {classifier_name:<30}: {classifier_events:>3} events, {len(service_classifier.handled_sources):>2} sources")
        
        print(f"\n  {'DASHBOARD_READS':<30}: {total_dashboard_events:>3} events")
        print(f"  {'TOTAL SERVICE EVENTS':<30}: {total_service_events:>3} events")
        print(f"  {'TOTAL SERVICE SOURCES':<30}: {len(all_service_sources):>3} sources")
        
        return {
            'dashboard_events': total_dashboard_events,
            'service_events': total_service_events,
            'service_sources': len(all_service_sources),
            'total_classifiers': len(self.classifier.classifiers)
        }
    
    def run_all_audits(self):
        """
        Run all audits and return comprehensive results.
        
        Returns:
            dict: Results of all audits
        """
        print("=" * 80)
        print("CLASSIFIER AUDIT - CHECKING FOR INTERNAL CONSISTENCY")
        print("=" * 80)
        
        results = {}
        
        # Run all audits
        results['dashboard_overlaps'] = self.audit_dashboard_overlaps()
        results['source_conflicts'] = self.audit_source_conflicts()
        results['duplicate_events'] = self.audit_duplicate_events()
        results['empty_classifiers'] = self.audit_empty_classifiers()
        results['source_consistency'] = self.audit_source_consistency()
        results['summary'] = self.audit_summary_statistics()
        
        # Summary
        print(f"\n📋 AUDIT SUMMARY:")
        print("-" * 50)
        print(f"  Dashboard Overlaps:     {'❌ FOUND' if not results['dashboard_overlaps']['passed'] else '✅ NONE'}")
        print(f"  Source Conflicts:       {'❌ FOUND' if not results['source_conflicts']['passed'] else '✅ NONE'}")
        print(f"  Duplicate Events:       {'❌ FOUND' if not results['duplicate_events']['passed'] else '✅ NONE'}")
        print(f"  Empty Classifiers:      {'⚠️  FOUND' if not results['empty_classifiers']['passed'] else '✅ NONE'}")
        print(f"  Source Consistency:     {'❌ FOUND' if not results['source_consistency']['passed'] else '✅ NONE'}")
        
        all_passed = all([
            results['dashboard_overlaps']['passed'],
            results['source_conflicts']['passed'],
            results['duplicate_events']['passed'],
            results['source_consistency']['passed']
        ])
        
        if all_passed and len(self.warnings_found) == 0:
            print(f"\n✅ ALL AUDITS PASSED - Classifier is internally consistent!")
        elif all_passed:
            print(f"\n✅ ALL CRITICAL AUDITS PASSED - {len(self.warnings_found)} warnings found")
        else:
            print(f"\n⚠️  ISSUES FOUND - Please fix the above problems before proceeding!")
        
        results['overall_passed'] = all_passed
        results['issues'] = self.issues_found
        results['warnings'] = self.warnings_found
        
        return results


def main():
    """Main execution function."""
    auditor = ClassifierAuditor()
    results = auditor.run_all_audits()
    
    if not results['overall_passed']:
        print(f"\n🔧 RECOMMENDED ACTIONS:")
        print("-" * 50)
        for issue in results['issues']:
            print(f"  • Fix: {issue}")
        
        return False
    else:
        print(f"\n🎉 Classifier is ready for use!")
        return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
