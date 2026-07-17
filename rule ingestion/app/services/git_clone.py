from pathlib import Path
import shutil
import logging
from git import Repo, GitCommandError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


class GitRepositoryCloner:

    def __init__(
        self,
        repo_url: str,
        branch: str = "main",
        clone_directory: str = "repositories"
    ):
        self.repo_url = repo_url
        self.branch = branch
        self.clone_directory = Path(clone_directory)

    def clone(self) -> Path:

        self.clone_directory.mkdir(parents=True, exist_ok=True)

        repository_name = self.repo_url.split("/")[-1].replace(".git", "")
        destination = self.clone_directory / repository_name

        if destination.exists():
            shutil.rmtree(destination)
            logger.info("Existing repository removed: %s", destination)

        try:
            logger.info("Cloning repository from %s", self.repo_url)

            Repo.clone_from(
                self.repo_url,
                destination,
                branch=self.branch
            )

            logger.info("Repository cloned successfully.")
            logger.info("Repository location: %s", destination)

            return destination

        except GitCommandError as error:
            logger.error("Failed to clone repository: %s", error)
            raise RuntimeError(
                f"Failed to clone repository: {error}"
            )


if __name__ == "__main__":

    repository = GitRepositoryCloner(
        repo_url="https://github.com/SigmaHQ/sigma.git",
        branch="master"
    )

    local_repository = repository.clone()

    logger.info("Repository available at: %s", local_repository)