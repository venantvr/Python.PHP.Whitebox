# tests/unit/test_filewalker.py - Unit tests for the PHP file discovery utility

import os
import pytest

from utils.filewalker import find_php_files


class TestFindPhpFiles:
    """Tests for the find_php_files utility."""

    def test_find_php_files(self, samples_dir):
        """find_php_files should discover all .php files in the samples directory."""
        files = find_php_files(samples_dir)
        assert isinstance(files, list)
        # Every returned path should end with .php
        for fpath in files:
            assert fpath.endswith(".php"), (
                f"Expected .php file, got {fpath!r}"
            )

    def test_find_php_files_returns_absolute_paths(self, samples_dir):
        """All returned paths should be absolute."""
        files = find_php_files(samples_dir)
        for fpath in files:
            assert os.path.isabs(fpath), (
                f"Expected absolute path, got {fpath!r}"
            )

    def test_exclude_patterns(self, tmp_path):
        """Exclude patterns should prevent matching files from being returned."""
        # Create a directory structure with PHP files
        (tmp_path / "app").mkdir()
        (tmp_path / "vendor").mkdir()
        (tmp_path / "tests").mkdir()

        (tmp_path / "app" / "index.php").write_text("<?php echo 'hello';")
        (tmp_path / "app" / "util.php").write_text("<?php function x(){}")
        (tmp_path / "vendor" / "lib.php").write_text("<?php // vendor lib")
        (tmp_path / "tests" / "test.php").write_text("<?php // test file")

        # Without extra excludes, vendor is already excluded by default
        files = find_php_files(tmp_path)
        file_names = [os.path.basename(f) for f in files]
        assert "index.php" in file_names
        assert "util.php" in file_names
        assert "lib.php" not in file_names, "vendor/ should be excluded by default"

        # With additional exclude pattern for tests/
        files_ex = find_php_files(tmp_path, exclude_patterns=["tests/*"])
        file_names_ex = [os.path.basename(f) for f in files_ex]
        assert "test.php" not in file_names_ex, "tests/* pattern should exclude test.php"
        assert "index.php" in file_names_ex

    def test_empty_directory(self, tmp_path):
        """An empty directory should return an empty list."""
        files = find_php_files(tmp_path)
        assert files == []

    def test_no_php_files(self, tmp_path):
        """A directory with non-PHP files should return an empty list."""
        (tmp_path / "readme.txt").write_text("Not PHP")
        (tmp_path / "script.py").write_text("print('hello')")
        files = find_php_files(tmp_path)
        assert files == []

    def test_nested_discovery(self, tmp_path):
        """PHP files in nested subdirectories should be found."""
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "deep.php").write_text("<?php echo 'deep';")
        (tmp_path / "top.php").write_text("<?php echo 'top';")

        files = find_php_files(tmp_path)
        basenames = [os.path.basename(f) for f in files]
        assert "deep.php" in basenames
        assert "top.php" in basenames
