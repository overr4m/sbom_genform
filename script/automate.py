import argparse
import logging
from pathlib import Path
from dependency import Dependency
from exporter import Exporter

class SBOMAutomation:
    def __init__(self, sbom_dir: str, report_dir: str):
        self.sbom_dir = Path(sbom_dir)
        self.report_dir = Path(report_dir)
        self.exporter = Exporter()
        
    def process_all_sboms(self) -> None:
        """Process all SBOM files and generate reports."""
        try:
            dependencies = Dependency.process_sboms(str(self.sbom_dir), str(self.report_dir))
            
            # Process each dependency
            for dep in dependencies:
                try:
                    dep.process_purl(dep.purl)
                    logging.info(f"Processed dependency: {dep.name}@{dep.version}")
                except Exception as e:
                    logging.error(f"Failed to process {dep.name}: {str(e)}")
            
            # Export results
            self.exporter.export_dependencies(dependencies, str(self.report_dir))
            
        except Exception as e:
            logging.error(f"Automation failed: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description='SBOM Processing Automation')
    parser.add_argument('--sbom-dir', required=True, help='Directory containing SBOM files')
    parser.add_argument('--report-dir', required=True, help='Directory for output reports')
    parser.add_argument('--log-level', default='INFO', help='Logging level')
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Run automation
    automation = SBOMAutomation(args.sbom_dir, args.report_dir)
    automation.process_all_sboms()

if __name__ == '__main__':
    main()