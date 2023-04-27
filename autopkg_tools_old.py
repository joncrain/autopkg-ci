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

import os
import sys
import json
import plistlib
import requests
import subprocess
from pathlib import Path
from optparse import OptionParser
from datetime import datetime
import boto3
from botocore.exceptions import ClientError
from time import time


AWS_S3_BUCKET = os.environ.get("AWS_S3_BUCKET", None)
DEBUG = os.environ.get("DEBUG", False)
MUNKI_REPO = os.path.join(os.getenv("GITHUB_WORKSPACE", "/tmp/"), "munki_repo")
MUNKI_WEBSITE = "munki-prd.itops.unity3d.com"
OVERRIDES_DIR = os.path.relpath("overrides/")
RECIPE_TO_RUN = os.environ.get("RECIPE", None)
S3_CLIENT = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
)
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_TOKEN", None)
SUMMARY_WEBHOOK = os.environ.get("SUMMARY_WEBHOOK", None)


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
            "autopkg-{}_{}".format(self.name, self.updated_version)
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


### S3 FUNCTIONS
def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    credit: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3-uploading-files.html
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    S3_CLIENT = boto3.client("s3")
    try:
        S3_CLIENT.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        print(e.stderr)
        return False
    return True


### GIT FUNCTIONS
def git_run(cmd):
    cmd = ["git"] + cmd
    hide_cmd_output = True

    if DEBUG:
        print("Running " + " ".join(cmd))
        hide_cmd_output = False

    try:
        result = subprocess.run(
            " ".join(cmd), shell=True, cwd=MUNKI_REPO, capture_output=hide_cmd_output
        )
    except subprocess.CalledProcessError as e:
        print(e.stderr)
        raise e


def current_branch():
    git_run(["rev-parse", "--abbrev-ref", "HEAD"])


def checkout(branch, new=True):
    if current_branch() != "main" and branch != "main":
        checkout("main", new=False)

    gitcmd = ["checkout"]
    if new:
        gitcmd += ["-b"]

    gitcmd.append(branch)
    # Lazy branch exists check
    try:
        git_run(gitcmd)
    except subprocess.CalledProcessError as e:
        if new:
            checkout(branch, new=False)
        else:
            raise e


### Recipe handling
def handle_recipe(recipe, opts):
    if not opts.disable_verification:
        recipe.verify_trust_info()
        if recipe.verified is False:
            recipe.update_trust_info()
    if recipe.verified in (True, None):
        recipe.run()
        if recipe.results["imported"]:
            checkout(recipe.branch)
            for imported in recipe.results["imported"]:
                # git_run(["add", f"'pkgs/{ imported['pkg_repo_path'] }'"])
                git_run(["add", f"'pkgsinfo/{ imported['pkginfo_path'] }'"])
                PKG_PATH = os.path.join(MUNKI_REPO, "pkgs", imported["pkg_repo_path"])
                DEST_PKG_PATH = os.path.join("pkgs", imported["pkg_repo_path"])
                upload_file(PKG_PATH, AWS_S3_BUCKET, DEST_PKG_PATH)
            git_run(
                [
                    "commit",
                    "-m",
                    f"'Updated { recipe.name } to { recipe.updated_version }'",
                ]
            )
            git_run(["push", "--set-upstream", "origin", recipe.branch])
    return recipe


def parse_recipes(recipes):
    recipe_list = []
    ## Added this section so that we can run individual recipes
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
    checkout(branch_name)
    result = subprocess.check_call(
        "/usr/local/munki/iconimporter munki_repo", shell=True
    )
    git_run(["add", "icons/"])
    git_run(["commit", "-m", "Added new icons"])
    git_run(["push", "--set-upstream", "origin", f"{branch_name}"])


def slack_alert(recipe, opts):
    if opts.debug:
        print("Debug: skipping Slack notification - debug is enabled!")
        return

    if not SLACK_WEBHOOK:
        print("Skipping slack notification - webhook is missing!")
        return

    if not recipe.verified:
        task_title = (
            f"*{ recipe.name } failed trust verification* \n"
            + recipe.results["message"]
        )
    elif recipe.error:
        task_title = f"*Failed to import { recipe.name }* \n"
        if not recipe.results["failed"]:
            task_title += "Unknown error"
        else:
            task_title += f'Error: {recipe.results["failed"][0]["message"]} \n'
            if "No releases found for repo" in task_title:
                # Just no updates
                return
    elif recipe.updated:
        task_title = (
            f"*Imported {recipe.name} {str(recipe.updated_version)}* \n"
            + f'*Catalogs:* {recipe.results["imported"][0]["catalogs"]} \n'
            + f'*Package Path:* `{recipe.results["imported"][0]["pkg_repo_path"]}` \n'
            + f'*Pkginfo Path:* `{recipe.results["imported"][0]["pkginfo_path"]}` \n'
        )
    else:
        # Also no updates
        return

    try:
        icon = recipe.plist["Input"]["pkginfo"]["icon_name"]
    except:
        icon = recipe.name + ".png"

    block = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": task_title,
            },
            "accessory": {
                "type": "image",
                "image_url": f"https://{MUNKI_WEBSITE}/icons/{icon}",
                "alt_text": recipe.name,
            },
        }
    ]

    slack_data = {"blocks": block}
    byte_length = str(sys.getsizeof(slack_data))
    headers = {"Content-Type": "application/json", "Content-Length": byte_length}

    response = requests.post(
        SLACK_WEBHOOK, data=json.dumps(slack_data), headers=headers
    )
    if response.status_code != 200:
        print(
            f"WARNING: Request to slack returned an error {response.status_code}, the response is:\n{response.text}"
        )


def slack_summary(applications, opts):
    if opts.debug:
        print("Debug: skipping Slack notification - debug is enabled!")
        return
    if not SUMMARY_WEBHOOK:
        print("Skipping slack notification - webhook is missing!")
        return
    app_string = ""
    app_version = ""
    for app, version in applications.items():
        app_string = f"{app_string}\n{app}"
        app_version = f"{app_version}\n{version}"
    slack_data = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":new: The following items have been updated",
                    "emoji": True,
                },
            },
            {"type": "divider"},
        ],
        "attachments": [
            {
                "mrkdwn_in": ["text"],
                "color": "00FF00",
                "ts": time(),
                "fields": [
                    {
                        "title": "Application",
                        "short": True,
                        "value": app_string,
                    },
                    {
                        "title": "Version",
                        "short": True,
                        "value": app_version,
                    },
                ],
                "footer": "Autopkg Automated Run",
                "footer_icon": "https://avatars.slack-edge.com/2020-10-30/1451262020951_7067702535522f0c569b_48.png",
            }
        ],
    }
    byte_length = str(sys.getsizeof(slack_data))
    headers = {"Content-Type": "application/json", "Content-Length": byte_length}

    response = requests.post(
        SUMMARY_WEBHOOK, data=json.dumps(slack_data), headers=headers
    )
    if response.status_code != 200:
        print(
            f"WARNING: Request to slack returned an error {response.status_code}, the response is:\n{response.text}"
        )


def main():
    parser = OptionParser(description="Wrap AutoPkg with git support.")
    parser.add_option(
        "-l", "--list", help="Path to a plist or JSON list of recipe names."
    )
    parser.add_option(
        "-g",
        "--gitrepo",
        help="Path to git repo. Defaults to MUNKI_REPO from Autopkg preferences.",
        default=MUNKI_REPO,
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
        "-i",
        "--icons",
        action="store_true",
        help="Run iconimporter against git munki repo.",
    )

    (opts, _) = parser.parse_args()

    global DEBUG
    DEBUG = bool(DEBUG or opts.debug)

    failures = []

    recipes = (
        RECIPE_TO_RUN.split(", ") if RECIPE_TO_RUN else opts.list if opts.list else None
    )
    if recipes is None:
        print("Recipe --list or RECIPE_TO_RUN not provided!")
        sys.exit(1)
    recipes = parse_recipes(recipes)
    application_updates = {}
    for recipe in recipes:
        handle_recipe(recipe, opts)
        if recipe.results["imported"]:
            application_updates[recipe.name] = recipe.updated_version
        slack_alert(recipe, opts)
        if not opts.disable_verification:
            if not recipe.verified:
                failures.append(recipe)
    if application_updates:
        slack_summary(application_updates, opts)
    if not opts.disable_verification:
        if failures:
            title = " ".join([f"{recipe.name}" for recipe in failures])
            lines = [f"{recipe.results['message']}\n" for recipe in failures]
            with open("pull_request_title", "a+") as title_file:
                title_file.write(f"fix: Update trust for {title}")
            with open("pull_request_body", "a+") as body_file:
                body_file.writelines(lines)
    if opts.icons:
        import_icons()


if __name__ == "__main__":
    main()
