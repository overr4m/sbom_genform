import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List
from dependency import Dependency

class SBOMPipeline:
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
    
    async def process_dependencies_parallel(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Process dependencies in parallel."""
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            loop = asyncio.get_event_loop()
            tasks = [
                loop.run_in_executor(
                    executor, 
                    self._process_single_dependency, 
                    dep
                )
                for dep in dependencies
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out failed dependencies
            processed_deps = []
            for result in results:
                if isinstance(result, Exception):
                    logging.error(f"Dependency processing failed: {str(result)}")
                else:
                    processed_deps.append(result)
            
            return processed_deps
    
    def _process_single_dependency(self, dep: Dependency) -> Dependency:
        """Process a single dependency."""
        try:
            dep.process_purl(dep.purl)
            return dep
        except Exception as e:
            logging.error(f"Failed to process {dep.name}: {str(e)}")
            raise

# Usage example
async def run_pipeline():
    pipeline = SBOMPipeline()
    # Get dependencies from SBOM processing
    dependencies = Dependency.process_sboms('sbom_dir', 'report_dir')
    
    # Process in parallel
    processed_deps = await pipeline.process_dependencies_parallel(dependencies)
    
    # Export results
    exporter = Exporter()
    exporter.export_dependencies(processed_deps, 'report_dir')

if __name__ == '__main__':
    asyncio.run(run_pipeline())