import os
import sys
import pytest
from unittest.mock import MagicMock, patch
# Configure python path to root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
from app.api.rules import clone_repo, discover_rule_files
def test_clone_repo_local_directory(tmp_path):
    """Test that clone_repo returns local directory path directly without network calls."""
    local_dir = str(tmp_path)
    result = clone_repo(local_dir)
    assert result == os.path.abspath(local_dir)
@patch("git.Repo")
def test_clone_repo_shallow_new_clone(mock_git_repo, tmp_path):
    """Test that clone_from is invoked with depth=1 and single_branch=True."""
    mock_git_repo.clone_from = MagicMock()
    with path("os.path.exists", side_effect=lambda p: False):
        res = clone_repo("https://github.com/example/rules.git", branch="main", depth=1)
    mock_git_repo.clone_from.assert_called_once()
    kwargs = mock_git_repo.clone_from.call_args[1]
    assert kwargs.get("depth") == 1
    assert kwargs.get("single_branch") is True
    assert kwargs.get("branch") == "main"
@patch("git.Repo")
def test_clone_repo_shallow_existing_fetch(mock_git_repo, tmp_path):
    """Test that existing local clone fetches with depth=1."""
    mock_repo_obj = MagicMock()
    mock_git_repo.return_value = mock_repo_obj
    # Simulate existing path
    fake_path = str(tmp_path / "cloned_repo")
    os.makedirs(fake_path, exist_ok=True)
    with patch("os.path.exists", return_value=True):
        res = clone_repo("https://github.com/example/rules.git", branch="main", depth=1)
    mock_repo_obj.remotes.origin.fetch.assert_called_once_with(depth=1)
    mock_repo_obj.git.checkout.assert_called_once_with("main")
    mock_repo_obj.git.reset.assert_called_once_with("--hard", "origin/main")
