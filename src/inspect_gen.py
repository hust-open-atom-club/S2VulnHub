import subprocess


def list_all_tags_for_remote_git_repo(url):
    """
    Given a repository URL, list all tags for that repository without cloning it.
    This function use "git ls-remote", so the "git" command line program must be available.
    """
    # Run the 'git' command to fetch and list remote tags
    result = subprocess.run(
        ["git", "ls-remote", "--tags", url], stdout=subprocess.PIPE, text=True
    )
    # Process the output to extract tag names
    output_lines = result.stdout.splitlines()
    tags = [
        line.split("\trefs/tags/")
        for line in output_lines
        if "refs/tags/" in line and "^{}" not in line
    ]
    return tags
