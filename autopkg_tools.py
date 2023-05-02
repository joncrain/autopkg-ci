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

import git
import os
import sys
import json
import plistlib
import shutil
import subprocess
import threading
from pathlib import Path
from optparse import OptionParser
from datetime import datetime


DATE = datetime.now().strftime("%Y-%m-%d")
DEBUG = True
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_TOKEN", None)
MUNKI_DIR = os.path.join(os.getenv("GITHUB_WORKSPACE", "/tmp/"), "munki_repo")
OVERRIDES_DIR = os.path.relpath("overrides/")
# MUNKI_GITHUB_TOKEN = os.environ.get("MUNKI_GITHUB_TOKEN", "WHY_IS_THIS_NOT_SET")
# GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", None)
RECIPE_TO_RUN = os.environ.get("RECIPE", None)
WORKING_DIRECTORY = os.getenv("GITHUB_WORKSPACE", "./")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY", "None")
MUNKI_REPOSITORY = os.getenv("MUNKI_REPOSITORY", "None")
MUNKI_REPO = git.Repo(MUNKI_DIR)
AUTOPKG_REPO = git.Repo(WORKING_DIRECTORY)


class Recipe(object):
    def __init__(self, path):
        self.path = os.path.join(OVERRIDES_DIR, path)
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
        cmd = " ".join(cmd)

        if DEBUG:
            print("Running " + str(cmd))

        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        (output, err) = p.communicate()
        p_status = p.wait()
        if p_status == 0:
            self.verified = True
        else:
            err = err.decode()
            self.results["message"] = err
            self.verified = False
        return self.verified

    def update_trust_info(self):
        cmd = ["/usr/local/bin/autopkg", "update-trust-info", self.path]
        cmd = " ".join(cmd)

        if DEBUG:
            print("Running " + str(cmd))

        # Fail loudly if this exits 0
        try:
            subprocess.check_call(cmd, shell=True)
        except subprocess.CalledProcessError as e:
            print(e.stderr)
            raise e

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
            try:
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
                cmd = " ".join(cmd)
                if DEBUG:
                    print("Running " + str(cmd))

                subprocess.check_call(cmd, shell=True)

            except subprocess.CalledProcessError as e:
                self.error = True

            self._has_run = True
            self.results = self._parse_report(report)
            if not self.results["failed"] and not self.error and self.updated_version:
                self.updated = True

        return self.results


def worktree_commit(recipe):
    MUNKI_REPO.git.worktree("add", recipe.branch, "-b", recipe.branch)
    worktree_repo_path = os.path.join(MUNKI_DIR, recipe.branch)
    worktree_repo = git.Repo(worktree_repo_path)
    worktree_repo.git.fetch()
    if recipe.branch in MUNKI_REPO.git.branch("--list", "-r"):
        worktree_repo.git.pull("origin", recipe.branch)
    for imported in recipe.results["imported"]:
        shutil.move(
            f"{MUNKI_DIR}/pkgsinfo/{ imported['pkginfo_path'] }",
            f"{worktree_repo_path}/pkgsinfo/{ imported['pkginfo_path'] }",
        )
        # TODO: Create flag for commiting pkg
        recipe_path = f"{worktree_repo_path}/pkgsinfo/{ imported['pkginfo_path'] }"
        worktree_repo.index.add([recipe_path])
    worktree_repo.index.commit(
        f"'Updated { recipe.name } to { recipe.updated_version }'"
    )
    worktree_repo.git.push("--set-upstream", "origin", recipe.branch)
    MUNKI_REPO.git.worktree("remove", recipe.branch, "-f")
    cmd = f"""gh api --method POST -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" \
    /repos/{MUNKI_REPOSITORY}/pulls \
    -f title='feat: { recipe.name } update' \
    -f body='Updated { recipe.name } to { recipe.updated_version }' \
    -f head='{ recipe.branch }' \
    -f base='main' """
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        print("Failed to create pull request. It may already exist.")

### Recipe handling
def handle_recipe(recipe, opts):
    print("Handling " + recipe.name)
    if not opts.disable_verification:
        recipe.verify_trust_info()
        if recipe.verified is False:
            recipe.update_trust_info()
            branch_name = f"update_trust-{recipe.name}-{DATE}"
            AUTOPKG_REPO.get.worktree("add", branch_name, "-b", branch_name)
            autopkg_worktree_path = os.path.join(WORKING_DIRECTORY, branch_name)
            autopkg_worktree_repo = git.Repo(autopkg_worktree_path)
            autopkg_worktree_repo.git.add(recipe.path)
            autopkg_worktree_repo.git.commit(m=f"Update trust for {recipe.name}")
            autopkg_worktree_repo.git.push("--set-upstream", "origin", branch_name)
            cmd = f"""gh api --method POST -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" \
            /repos/{GITHUB_REPOSITORY}/pulls \
            -f title='feat: Update trust for { recipe.name }' \
            -f body='{ recipe.results['message'] }' \
            -f head='{ branch_name }' \
            -f base='main' """
            try:
                subprocess.check_call(cmd, shell=True)
            except:
                print("Failed to create pull request. It may already exist.")
            subprocess.check_call(cmd, shell=True)
            AUTOPKG_REPO.git.worktree("remove", branch_name, "-f")
    if recipe.verified in (True, None):
        recipe.run()
        if recipe.results["imported"]:
            print("Imported")
            worktree_commit(recipe)
    # slack_alert(recipe, opts)
    # if not opts.disable_verification:
    #     if not recipe.verified:
    #         failures.append(recipe)
    return


def parse_recipes(recipes, opts):
    recipe_list = []
    ## Added this section so that we can run individual recipes
    if RECIPE_TO_RUN or opts.recipe:
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
        "-g",
        "--gitrepo",
        help="Path to git repo. Defaults to MUNKI_DIR from Autopkg preferences.",
        default=MUNKI_DIR,
    )
    parser.add_option(
        "-d",
        "--debug",
        action="store_true",
        help="Disables sending Slack alerts and adds more verbosity to output.",
    )
    parser.add_option(
        "-v",
        "--disable_verification",
        action="store_true",
        help="Disables recipe verification.",
    )
    parser.add_option(
        "-r",
        "--recipe",
        help="Run a single recipe.",
    )
    parser.add_option(
        "-i",
        "--icons",
        action="store_true",
        help="Run iconimporter against git munki repo.",
    )

    (opts, _) = parser.parse_args()

    global DEBUG
    DEBUG = bool(opts.debug)

    recipes = (
        RECIPE_TO_RUN.split(", ")
        if RECIPE_TO_RUN
        else [opts.recipe]
        if opts.recipe
        else opts.list
        if opts.list
        else None
    )

    if recipes is None:
        print("Recipe --list or RECIPE_TO_RUN not provided!")
        sys.exit(1)
    recipes = parse_recipes(recipes, opts)
    threads = []

    for recipe in recipes:
        handle_recipe(recipe, opts)
    #     thread = threading.Thread(target=handle_recipe(recipe, opts))
    #     threads.append(thread)

    # for thread in threads:
    #     thread.start()

    # for thread in threads:
    #     thread.join()

    # if not opts.disable_verification:
    #     if failures:
    #         title = " ".join([f"{recipe.name}" for recipe in failures])
    #         lines = [f"{recipe.results['message']}\n" for recipe in failures]
    #         branch_name = f"update_trust-{DATE}"
    #         AUTOPKG_REPO.git.checkout(branch_name, b=True)
    #         AUTOPKG_REPO.git.add("overrides")
    #         AUTOPKG_REPO.git.commit(m=f"Update trust for {title}")
    #         AUTOPKG_REPO.git.push("--set-upstream", "origin", branch_name)
    #         AUTOPKG_REPO.git.checkout("main")

    if opts.icons:
        import_icons()


if __name__ == "__main__":
    main()
