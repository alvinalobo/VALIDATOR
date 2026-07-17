from pathlib import Path
import logging
from git_clone import GitRepositoryCloner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


class RuleDiscoveryService:

    SUPPORTED_EXTENSIONS = {".yml", ".yaml", ".kql"}

    def __init__(self, repository_path: Path):
        self.repository_path = repository_path

    def discover_rules(self) -> list[Path]:

        if not self.repository_path.exists():
            raise FileNotFoundError(f"Repository not found: {self.repository_path}")

        rule_files = []

        logger.info("Searching for rule files inside %s", self.repository_path)

        for file in self.repository_path.rglob("*"):
            if file.is_file() and file.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                rule_files.append(file)

        logger.info("Discovery completed.")
        logger.info("Total rule files found: %d", len(rule_files))

        return rule_files


if __name__ == "__main__":

    repository = GitRepositoryCloner(
        repo_url="https://github.com/SigmaHQ/sigma.git",
        branch="master"
    )

    repository_path = repository.clone()

    discovery = RuleDiscoveryService(repository_path)

    rules = discovery.discover_rules()

    logger.info("Showing first 10 rule files")

    for rule in rules[:10]:
        logger.info(rule)

    logger.info("Total Rules Found : %d", len(rules))