#!/usr/bin/env python3

# BSD-3-Clause
# Copyright (c) Facebook, Inc. and its affiliates.
# Copyright (c) tig <https://6fx.eu/>.
# Copyright (c) Gusto, Inc.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import json
import logging
import os
import plistlib
import shutil
import subprocess
import sys
import threading
from datetime import datetime
from optparse import OptionParser
from pathlib import Path

import git

SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_TOKEN", None)
AUTOPKG_REPO_DIR = os.getenv("GITHUB_WORKSPACE", "./")
MUNKI_REPO_DIR = os.path.join(AUTOPKG_REPO_DIR, "munki_repo")
RECIPE_TO_RUN = os.environ.get("RECIPE", None)
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY", "None")
MUNKI_REPOSITORY = os.getenv("MUNKI_REPOSITORY", "None")
# setup gitpython repos
MUNKI_REPO = git.Repo(MUNKI_REPO_DIR)
AUTOPKG_REPO = git.Repo(AUTOPKG_REPO_DIR)

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)


class Recipe(object):
    def __init__(self, path):
        self.path = os.path.join(AUTOPKG_REPO_DIR, "overrides", path)
        self.error = False
        self.results = {}
        self.updated = False
        self.verified = None

        self._keys = None
        self._has_run = False

    @property
    def plist(self):
        if self._keys is None:
            with open(self.path, "rb") as f:
                self._keys = plistlib.load(f)

        return self._keys

    @property
    def branch(self):
        return (
            "{}_{}".format(self.name, self.updated_version)
            .strip()
            .replace(" ", "")
            .replace(")", "-")
            .replace("(", "-")
        )

    @property
    def updated_version(self):
        if not self.results or not self.results["imported"]:
            return None

        return self.results["imported"][0]["version"].strip().replace(" ", "")

    @property
    def name(self):
        return self.plist["Input"]["NAME"]

    def verify_trust_info(self):
        cmd = ["/usr/local/bin/autopkg", "verify-trust-info", self.path, "-vvv"]
        output, err, exit_code = run_cmd(cmd)
        if exit_code == 0:
            self.verified = True
        else:
            err = err.decode()
            self.results["message"] = err
            self.verified = False
        return self.verified

    def update_trust_info(self):
        cmd = ["/usr/local/bin/autopkg", "update-trust-info", self.path]
        output, err, exit_code = run_cmd(cmd)
        return output

    def _parse_report(self, report):
        with open(report, "rb") as f:
            report_data = plistlib.load(f)

        failed_items = report_data.get("failures", [])
        imported_items = []
        if report_data["summary_results"]:
            # This means something happened
            munki_results = report_data["summary_results"].get(
                "munki_importer_summary_result", {}
            )
            imported_items.extend(munki_results.get("data_rows", []))

        return {"imported": imported_items, "failed": failed_items}

    def run(self):
        if self.verified == False:
            self.error = True
            self.results["failed"] = True
            self.results["imported"] = ""
        else:
            report = "/tmp/autopkg.plist"
            if not os.path.isfile(report):
                # Letting autopkg create them has led to errors on github runners
                Path(report).touch()
            cmd = [
                "/usr/local/bin/autopkg",
                "run",
                self.path,
                "-v",
                "--post",
                "io.github.hjuutilainen.VirusTotalAnalyzer/VirusTotalAnalyzer",
                "--report-plist",
                report,
            ]
            output, err, exit_code = run_cmd(cmd)
            if err:
                self.error = True
                self.results["failed"] = True
                self.results["imported"] = ""
            self._has_run = True
            self.results = self._parse_report(report)
            if not self.results["failed"] and not self.error and self.updated_version:
                self.updated = True
        return self.results


def run_cmd(cmd):
    logging.debug(f"Running {str(cmd)}")
    run = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = run.communicate()
    exit_code = run.wait()
    return output, err, exit_code


def worktree_commit(recipe):
    MUNKI_REPO.git.worktree("add", recipe.branch, "-b", recipe.branch)
    worktree_repo_path = os.path.join(MUNKI_REPO_DIR, recipe.branch)
    worktree_repo = git.Repo(worktree_repo_path)
    worktree_repo.git.fetch()
    if recipe.branch in MUNKI_REPO.git.branch("--list", "-r"):
        worktree_repo.git.pull("origin", recipe.branch)
    for imported in recipe.results["imported"]:
        shutil.move(
            f"{MUNKI_REPO_DIR}/pkgsinfo/{ imported['pkginfo_path'] }",
            f"{worktree_repo_path}/pkgsinfo/{ imported['pkginfo_path'] }",
        )
        recipe_path = f"{worktree_repo_path}/pkgsinfo/{ imported['pkginfo_path'] }"
        worktree_repo.index.add([recipe_path])
    worktree_repo.index.commit(
        f"'Updated { recipe.name } to { recipe.updated_version }'"
    )
    worktree_repo.git.push("--set-upstream", "origin", recipe.branch)
    MUNKI_REPO.git.worktree("remove", recipe.branch, "-f")
    cmd = [
        "gh",
        "api",
        "--method",
        "POST",
        "-H",
        "'Accept: application/vnd.github+json'",
        "-H",
        "'X-GitHub-Api-Version: 2022-11-28'",
        "/repos/{MUNKI_REPOSITORY}/pulls",
        "-f",
        f"title='feat: { recipe.name } update'",
        "-f",
        f"body='Updated { recipe.name } to { recipe.updated_version }'",
        "-f",
        f"head='{ recipe.branch }'",
        "-f",
        "base='main'",
    ]
    print(str(cmd))
    output, err, exit_code = run_cmd(cmd)
    if exit_code != 0:
        print(err)


def handle_recipe(recipe, opts):
    logging.debug(f"Handling {recipe.name}")
    recipe.verify_trust_info()
    if recipe.verified is False:
        recipe.update_trust_info()
        branch_name = (
            f"update_trust-{recipe.name}-{datetime.now().strftime('%Y-%m-%d')}"
        )
        AUTOPKG_REPO.get.worktree("add", branch_name, "-b", branch_name)
        autopkg_worktree_path = os.path.join(AUTOPKG_REPO_DIR, branch_name)
        autopkg_worktree_repo = git.Repo(autopkg_worktree_path)
        autopkg_worktree_repo.git.add(os.join("overrides", recipe.path))
        autopkg_worktree_repo.git.commit(m=f"Update trust for {recipe.name}")
        autopkg_worktree_repo.git.push("--set-upstream", "origin", branch_name)
        cmd = [
            "gh",
            "api",
            "--method",
            "POST",
            "-H",
            "'Accept: application/vnd.github+json'",
            "-H",
            "'X-GitHub-Api-Version: 2022-11-28'",
            "/repos/{GITHUB_REPOSITORY}/pulls",
            "-f",
            f"title='feat: Update trust for { recipe.name }'",
            "-f",
            f"body='{ recipe.results['message'] }'",
            "-f",
            f"head='{ branch_name }'",
            "-f",
            "base='main'",
        ]
        output, err, exit_code = run_cmd(cmd)
        if exit_code != 0:
            print(err)
        AUTOPKG_REPO.git.worktree("remove", branch_name, "-f")
    if recipe.verified in (True, None):
        recipe.run()
        if recipe.results["imported"]:
            print("Imported")
            worktree_commit(recipe)
    # slack_alert(recipe, opts)
    return


def parse_recipes(recipes, opts):
    recipe_list = []
    if RECIPE_TO_RUN:
        for recipe in recipes:
            ext = os.path.splitext(recipe)[1]
            if ext != ".recipe":
                recipe_list.append(recipe + ".recipe")
            else:
                recipe_list.append(recipe)
    else:
        ext = os.path.splitext(recipes)[1]
        if ext == ".json":
            parser = json.load
        elif ext == ".plist":
            parser = plistlib.load
        else:
            print(f'Invalid run list extension "{ ext }" (expected plist or json)')
            sys.exit(1)
        with open(recipes, "rb") as f:
            recipe_list = parser(f)
    return map(Recipe, recipe_list)


## Icon handling
def import_icons():
    branch_name = "icon_import_{}".format(datetime.now().strftime("%Y-%m-%d"))
    MUNKI_REPO.git.worktree("add", branch_name, "-b", branch_name)
    result = subprocess.check_call(
        "/usr/local/munki/iconimporter munki_repo", shell=True
    )
    MUNKI_REPO.index.add(["icons/"])
    MUNKI_REPO.index.commit("Added new icons")
    MUNKI_REPO.git.push("--set-upstream", "origin", branch_name)
    MUNKI_REPO.git.worktree("remove", branch_name)
    return result


def main():
    parser = OptionParser(description="Wrap AutoPkg with git support.")
    parser.add_option(
        "-l", "--list", help="Path to a plist or JSON list of recipe names."
    )
    parser.add_option(
        "-i",
        "--icons",
        action="store_true",
        help="Run iconimporter against git munki repo.",
    )

    (opts, _) = parser.parse_args()

    recipes = (
        RECIPE_TO_RUN.split(", ") if RECIPE_TO_RUN else opts.list if opts.list else None
    )

    if recipes is None:
        print("Recipe --list or RECIPE_TO_RUN not provided!")
        sys.exit(1)
    recipes = parse_recipes(recipes, opts)
    threads = []

    for recipe in recipes:
        # handle_recipe(recipe, opts)
        thread = threading.Thread(target=handle_recipe(recipe, opts))
        threads.append(thread)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    if opts.icons:
        import_icons()


if __name__ == "__main__":
    main()
