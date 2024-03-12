import dataclasses
import json
import traceback
from dataclasses import dataclass
from typing import Optional, List, Set

from urllib.parse import urlparse, parse_qs

import requests
from loguru import logger
from tqdm import tqdm

from bintools.general.file_tool import load_from_json_file, save_to_json_file
from main.extractors.src_function_feature_extractor.constants import C_EXTENSION_SET, CPP_EXTENSION_SET
from setting.settings import GITHUB_TOKEN

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}


def fetch_table_column_values_and_headers(url):
    # 发送请求获取HTML内容
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')
    texts = []
    spans = soup.find_all('span', class_="bg-secondary-subtle bg-opacity-25 p-1 rounded")
    for span in spans:
        texts.extend(span.stripped_strings)  # 获取所有文本字段
    return texts


def parse_git_url(url):
    """
    解析git rul
    demo: "https://git.samba.org/?p=samba.git;a=blob;f=source4/dsdb/samdb/ldb_modules/samldb.c;h=df285d91485ba8393d368ddf6328957d26ff57dd;hb=df285d91485ba8393d368ddf6328957d26ff57dd"
    :param url:
    :return: {
        "project_path": "samba.git",
        "action": "blob",
        "file_path": "source4/dsdb/samdb/ldb_modules/samldb.c",
        "hash_value": "df285d91485ba8393d368ddf6328957d26ff57dd",
        "hash_base": "df285d91485ba8393d368ddf6328957d26ff57dd"
    }
    """
    # 解析URL
    url = url.replace(';', '&')
    parsed_url = urlparse(url)
    # 解析查询参数
    query_params = parse_qs(parsed_url.query)

    # 提取信息
    project_path = query_params.get('p', [None])[0]
    action = query_params.get('a', [None])[0]
    file_path = query_params.get('f', [None])[0]
    hash_value = query_params.get('h', [None])[0]
    hash_base = query_params.get('hb', [None])[0]

    # 构造并返回一个包含解析信息的字典
    return {
        'project_path': project_path,
        'action': action,
        'file_path': file_path,
        'hash_value': hash_value,
        'hash_base': hash_base
    }


def parse_patch(patch: str):
    """
    解析patch

    :param patch:
    :return: [{
                "function_name": "xxx",
                "patch_start_line_before_change": 1,
                "patch_size_before_change": 1,
                "patch_before_change": ["- xxx", "+ xxx"],
                "patch_start_line_after_change": 1,
                "patch_size_after_change": 1,
                "patch_after_change": ["- xxx", "+ xxx"]
                },
                ...]
    """
    changes = []
    lines = patch.split("\n")

    # parse patch lines
    change_context = ""
    patch_start_line_before_change = 0
    patch_size_before_change = 0
    patch_start_line_after_change = 0
    patch_size_after_change = 0
    patch_before_change = []
    patch_after_change = []
    for line in lines:
        if line.startswith("@@"):
            if patch_before_change or patch_after_change:
                change_info = {
                    "change_context": change_context,
                    "snippet_start_line_before_change": patch_start_line_before_change,
                    "snippet_size_before_change": patch_size_before_change,
                    "snippet_before_change": patch_before_change,
                    "snippet_start_line_after_change": patch_start_line_after_change,
                    "snippet_size_after_change": patch_size_after_change,
                    "snippet_after_change": patch_after_change
                }
                changes.append(change_info)
                # reset
                patch_before_change = []
                patch_after_change = []
            # TODO 没有函数名的情况，目前会解析错误
            # parse new patch info
            _, line_num, change_context = line.split("@@")
            patch_line_num_before_change, patch_line_num_after_change = line_num.strip().split(" ")
            patch_start_line_before_change, patch_size_before_change = patch_line_num_before_change[1:].split(",")
            patch_start_line_after_change, patch_size_after_change = patch_line_num_after_change[1:].split(",")
        elif line.startswith("-"):
            patch_before_change.append(line)
        elif line.startswith("+"):
            patch_after_change.append(line)
        else:
            patch_before_change.append(line)
            patch_after_change.append(line)

    change_info = {
        "change_context": change_context,
        "snippet_start_line_before_change": int(patch_start_line_before_change),
        "snippet_size_before_change": int(patch_size_before_change),
        "snippet_before_change": patch_before_change,
        "snippet_start_line_after_change": int(patch_start_line_after_change),
        "snippet_size_after_change": int(patch_size_after_change),
        "snippet_after_change": patch_after_change
    }
    changes.append(change_info)
    return changes


def extract_function_name(code: str):
    try:
        code = " ".join(code.split()[:3])
        if "(" in code:
            return code.split("(")[0].split()[-1]
        else:
            return None
    except:
        return code


def get_github_commit_info(commit_link):
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    response = requests.get(commit_link, headers=headers)
    commit_data = response.json()
    return commit_data


@dataclass
class RawVulInfo:
    access_gained: Optional[str] = None
    attack_origin: Optional[str] = None
    authentication_required: Optional[str] = None
    availability: Optional[str] = None
    cve_id: Optional[str] = None
    cve_link: Optional[str] = None
    cwe_id: Optional[str] = None
    complexity: Optional[str] = None
    confidentiality: Optional[str] = None
    integrity: Optional[str] = None
    known_exploits: Optional[str] = None
    publish_date: Optional[str] = None
    score: Optional[float] = None
    summary: Optional[str] = None
    update_date: Optional[str] = None
    vulnerability_classification: Optional[str] = None
    add_lines: Optional[int] = None
    code_link: Optional[str] = None
    commit_id: Optional[str] = None
    commit_message: Optional[str] = None
    del_lines: Optional[int] = None
    file_path: Optional[str] = None
    files_changed: Optional[str] = None
    func_after: Optional[str] = None
    func_before: Optional[str] = None
    lang: Optional[str] = None
    lines_after: Optional[int] = None
    lines_before: Optional[int] = None
    parent_id: Optional[str] = None
    patch: Optional[str] = None
    project: Optional[str] = None
    file_after_commit: Optional[str] = None
    file_before_commit: Optional[str] = None
    vul: Optional[int] = None
    vul_func_with_fix: Optional[str] = None

    # 以下是解析出来的信息
    changes_in_patch: Optional[List[dict]] = None
    vul_function_names: Optional[List[str]] = None
    current_function_name: Optional[str] = None

    def __hash__(self):
        return hash(json.dumps(self.commit_id))

    def __eq__(self, other):
        return self.commit_id == other.commit_id

    @classmethod
    def init_from_original_dict(cls, json_data_item):
        return cls(
            access_gained=json_data_item.get("Access Gained"),
            attack_origin=json_data_item.get("Attack Origin"),
            authentication_required=json_data_item.get("Authentication Required"),
            availability=json_data_item.get("Availability"),
            cve_id=json_data_item.get("CVE ID"),
            cve_link=json_data_item.get("CVE Page"),
            cwe_id=json_data_item.get("CWE ID"),
            complexity=json_data_item.get("Complexity"),
            confidentiality=json_data_item.get("Confidentiality"),
            integrity=json_data_item.get("Integrity"),
            known_exploits=json_data_item.get("Known Exploits"),
            publish_date=json_data_item.get("Publish Date"),
            score=json_data_item.get("Score"),
            summary=json_data_item.get("Summary"),
            update_date=json_data_item.get("Update Date"),
            vulnerability_classification=json_data_item.get("Vulnerability Classification"),
            add_lines=json_data_item.get("add_lines"),
            code_link=json_data_item.get("codeLink"),
            commit_id=json_data_item.get("commit_id"),
            commit_message=json_data_item.get("commit_message"),
            del_lines=json_data_item.get("del_lines"),
            file_path=json_data_item.get("file_name"),
            files_changed=json_data_item.get("files_changed"),
            func_after=json_data_item.get("func_after"),
            func_before=json_data_item.get("func_before"),
            lang=json_data_item.get("lang"),
            lines_after=json_data_item.get("lines_after"),
            lines_before=json_data_item.get("lines_before"),
            parent_id=json_data_item.get("parentID"),
            patch=json_data_item.get("patch"),
            project=json_data_item.get("project"),
            file_after_commit=json_data_item.get("project_after"),
            file_before_commit=json_data_item.get("project_before"),
            vul=json_data_item.get("vul"),
            vul_func_with_fix=json_data_item.get("vul_func_with_fix")
        )

    def customer_serialize(self):
        return {
            "access_gained": self.access_gained,
            "attack_origin": self.attack_origin,
            "authentication_required": self.authentication_required,
            "availability": self.availability,
            "cve_id": self.cve_id,
            "cve_link": self.cve_link,
            "cwe_id": self.cwe_id,
            "complexity": self.complexity,
            "confidentiality": self.confidentiality,
            "integrity": self.integrity,
            "known_exploits": self.known_exploits,
            "publish_date": self.publish_date,
            "score": self.score,
            "summary": self.summary,
            "update_date": self.update_date,
            "vulnerability_classification": self.vulnerability_classification,
            "add_lines": self.add_lines,
            "code_link": self.code_link,
            "commit_id": self.commit_id,
            "commit_message": self.commit_message,
            "del_lines": self.del_lines,
            "file_path": self.file_path,
            "files_changed": self.files_changed,
            "func_after": self.func_after,
            "func_before": self.func_before,
            "lang": self.lang,
            "lines_after": self.lines_after,
            "lines_before": self.lines_before,
            "parent_id": self.parent_id,
            "patch": self.patch,
            "project": self.project,
            "file_after_commit": self.file_after_commit,
            "file_before_commit": self.file_before_commit,
            "vul": self.vul,
            "vul_func_with_fix": self.vul_func_with_fix,
            "changes_in_patch": self.changes_in_patch,
            "vul_function_names": self.vul_function_names,
            "current_function_name": self.current_function_name
        }

    @classmethod
    def init_from_dict(cls, json_data_item):
        return cls(
            access_gained=json_data_item.get("access_gained"),
            attack_origin=json_data_item.get("attack_origin"),
            authentication_required=json_data_item.get("authentication_required"),
            availability=json_data_item.get("availability"),
            cve_id=json_data_item.get("cve_id"),
            cve_link=json_data_item.get("cve_link"),
            cwe_id=json_data_item.get("cwe_id"),
            complexity=json_data_item.get("complexity"),
            confidentiality=json_data_item.get("confidentiality"),
            integrity=json_data_item.get("integrity"),
            known_exploits=json_data_item.get("known_exploits"),
            publish_date=json_data_item.get("publish_date"),
            score=json_data_item.get("score"),
            summary=json_data_item.get("summary"),
            update_date=json_data_item.get("update_date"),
            vulnerability_classification=json_data_item.get("vulnerability_classification"),
            add_lines=json_data_item.get("add_lines"),
            code_link=json_data_item.get("code_link"),
            commit_id=json_data_item.get("commit_id"),
            commit_message=json_data_item.get("commit_message"),
            del_lines=json_data_item.get("del_lines"),
            file_path=json_data_item.get("file_path"),
            files_changed=json_data_item.get("files_changed"),
            func_after=json_data_item.get("func_after"),
            func_before=json_data_item.get("func_before"),
            lang=json_data_item.get("lang"),
            lines_after=json_data_item.get("lines_after"),
            lines_before=json_data_item.get("lines_before"),
            parent_id=json_data_item.get("parent_id"),
            patch=json_data_item.get("patch"),
            project=json_data_item.get("project"),
            file_after_commit=json_data_item.get("file_after_commit"),
            file_before_commit=json_data_item.get("file_before_commit"),
            vul=json_data_item.get("vul"),
            vul_func_with_fix=json_data_item.get("vul_func_with_fix"),
            changes_in_patch=json_data_item.get("changes_in_patch"),
            vul_function_names=json_data_item.get("vul_function_names"),
            current_function_name=json_data_item.get("current_function_name")
        )


@dataclass
class CVEInfo:
    cve_id: str
    cve_link: str

    cwe_id: str
    score: float
    publish_date: str
    update_date: str
    vulnerability_classification: str
    affected_versions: str = None

    def normalize(self):
        self.cve_id = self.cve_id.strip()
        self.cve_link = self.cve_link.strip()
        self.cwe_id = self.cwe_id.strip()
        self.score = float(self.score) if self.score else None
        self.publish_date = self.publish_date.strip()
        self.update_date = self.update_date.strip()
        self.vulnerability_classification = self.vulnerability_classification.strip()

    def custom_serialize(self):
        return {
            "cve_id": self.cve_id,
            "cve_link": self.cve_link,
            "cwe_id": self.cwe_id,
            "affected_versions": self.affected_versions,
            "score": self.score,
            "publish_date": self.publish_date,
            "update_date": self.update_date,
            "vulnerability_classification": self.vulnerability_classification
        }

    @classmethod
    def init_from_dict(cls, data):
        return cls(
            cve_id=data.get("cve_id"),
            cve_link=data.get("cve_link"),
            cwe_id=data.get("cwe_id"),
            affected_versions=data.get("affected_versions"),
            score=data.get("score"),
            publish_date=data.get("publish_date"),
            update_date=data.get("update_date"),
            vulnerability_classification=data.get("vulnerability_classification")
        )


@dataclass
class SnippetChange:
    change_context: str
    snippet_start_line_before_change: int
    snippet_size_before_change: int
    snippet_start_line_after_change: int
    snippet_size_after_change: int
    snippet_before_change: List[str]
    snippet_after_change: List[str]

    @classmethod
    def init_from_dict(cls, data):
        return cls(
            change_context=data.get("change_context"),
            snippet_start_line_before_change=data.get("snippet_start_line_before_change"),
            snippet_size_before_change=data.get("snippet_size_before_change"),
            snippet_start_line_after_change=data.get("snippet_start_line_after_change"),
            snippet_size_after_change=data.get("snippet_size_after_change"),
            snippet_before_change=data.get("snippet_before_change"),
            snippet_after_change=data.get("snippet_after_change")
        )

    def custom_serialize(self):
        return {
            "change_context": self.change_context,
            "snippet_start_line_before_change": self.snippet_start_line_before_change,
            "snippet_size_before_change": self.snippet_size_before_change,
            "snippet_start_line_after_change": self.snippet_start_line_after_change,
            "snippet_size_after_change": self.snippet_size_after_change,
            "snippet_before_change": self.snippet_before_change,
            "snippet_after_change": self.snippet_after_change
        }


@dataclass
class Patch:
    """
            {
            "sha": "356c0f3c01b109a18e5a9000e2d59b414d5e4aae",
            "filename": "yodl/VERSION",
            "status": "modified",
            "additions": 2,
            "deletions": 2,
            "changes": 4,
            "blob_url": "https://github.com/fbb-git/yodl/blob/fd85f8c94182558ff1480d06a236d6fb927979a3/yodl%2FVERSION",
            "raw_url": "https://github.com/fbb-git/yodl/raw/fd85f8c94182558ff1480d06a236d6fb927979a3/yodl%2FVERSION",
            "contents_url": "https://api.github.com/repos/fbb-git/yodl/contents/yodl%2FVERSION?ref=fd85f8c94182558ff1480d06a236d6fb927979a3",
            "patch": "@@ -1,2 +1,2 @@\n-#define VERSION \"3.06.00\"\n-#define YEARS   \"1996-2015\"\n+#define VERSION \"3.07.00\"\n+#define YEARS   \"1996-2016\""
        },
    """
    sha: str
    file_name: str
    status: str
    additions: int
    deletions: int
    changes: int
    blob_url: str
    raw_url: str
    contents_url: str
    raw_patch_content: str
    snippet_changes: List[SnippetChange] = dataclasses.field(default_factory=list)

    @classmethod
    def init_from_github_file_dict(cls, data):
        return cls(
            sha=data.get("sha"),
            file_name=data.get("filename"),
            status=data.get("status"),
            additions=data.get("additions"),
            deletions=data.get("deletions"),
            changes=data.get("changes"),
            blob_url=data.get("blob_url"),
            raw_url=data.get("raw_url"),
            contents_url=data.get("contents_url"),
            raw_patch_content=data.get("patch")
        )

    @classmethod
    def init_patches_from_github(cls, owner, repo, commit_id) -> List["Patch"]:
        commit_api = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_id}"
        commit_info = get_github_commit_info(commit_api)
        files = commit_info.get("files", [])
        patches: List[Patch] = []
        for file in files:
            patch = cls.init_from_github_file_dict(file)
            if patch.raw_patch_content is not None:
                patch.parse_patch_content()
            patches.append(patch)
        return patches

    def parse_patch_content(self):
        try:
            snippet_change_dict_list = parse_patch(self.raw_patch_content)
            self.snippet_changes = [SnippetChange.init_from_dict(sc_dict) for sc_dict in snippet_change_dict_list]
        except Exception as e:
            logger.error(f"parse_patch_content error: {e}, error patch: {self.raw_patch_content}")
            logger.error(f"traceback: {traceback.format_exc()}")
            self.snippet_changes = []

    @classmethod
    def init_from_dict(cls, data):
        return cls(
            sha=data.get("sha"),
            file_name=data.get("file_name"),
            status=data.get("status"),
            additions=data.get("additions"),
            deletions=data.get("deletions"),
            changes=data.get("changes"),
            blob_url=data.get("blob_url"),
            raw_url=data.get("raw_url"),
            contents_url=data.get("contents_url"),
            raw_patch_content=data.get("raw_patch_content"),
            snippet_changes=[SnippetChange.init_from_dict(sc) for sc in data.get("snippet_changes")]
        )

    def custom_serialize(self):
        return {
            "sha": self.sha,
            "file_name": self.file_name,
            "status": self.status,
            "additions": self.additions,
            "deletions": self.deletions,
            "changes": self.changes,
            "blob_url": self.blob_url,
            "raw_url": self.raw_url,
            "contents_url": self.contents_url,
            "raw_patch_content": self.raw_patch_content,
            "snippet_changes": [sc.custom_serialize() for sc in self.snippet_changes]
        }


@dataclass
class RepairInfo:
    platform_github = "github"
    platform_git = "git"

    platform: str
    owner: str
    repo: str

    commit_id: str
    commit_link: str
    patches: List[Patch]
    affected_since: str = None
    fixed_in: str = None

    def normalize(self):
        self.commit_id = self.commit_id.strip()
        self.commit_link = self.commit_link.strip()

    def custom_serialize(self):
        return {
            "platform": self.platform,
            "owner": self.owner,
            "repo": self.repo,
            "affected_since": self.affected_since,
            "fixed_in": self.fixed_in,
            "commit_id": self.commit_id,
            "commit_link": self.commit_link,
            "patches": [p.custom_serialize() for p in self.patches]
        }

    @classmethod
    def init_from_dict(cls, data):
        return cls(
            platform=data.get("platform"),
            owner=data.get("owner"),
            repo=data.get("repo"),
            affected_since=data.get("affected_since"),
            fixed_in=data.get("fixed_in"),
            commit_id=data.get("commit_id"),
            commit_link=data.get("commit_link"),
            patches=[Patch.init_from_dict(p) for p in data.get("patches")]
        )


@dataclass
class VulInfo:
    project_name: str
    cve_info: CVEInfo
    repair_info: RepairInfo

    @classmethod
    def init_from_raw_vul_info(cls, raw_vul_info: RawVulInfo):
        if not raw_vul_info.cve_id or not raw_vul_info.cve_link:
            return None

        cve_info = CVEInfo(
            cve_id=raw_vul_info.cve_id,
            cve_link=raw_vul_info.cve_link,
            cwe_id=raw_vul_info.cwe_id,
            score=raw_vul_info.score,
            publish_date=raw_vul_info.publish_date,
            update_date=raw_vul_info.update_date,
            vulnerability_classification=raw_vul_info.vulnerability_classification
        )
        cve_info.normalize()

        platform = RepairInfo.platform_github if RepairInfo.platform_github in raw_vul_info.code_link else RepairInfo.platform_git
        if platform == RepairInfo.platform_github:
            parts = raw_vul_info.code_link.split("/")
            owner = parts[3]
            repo = parts[4]
            repair_info = RepairInfo(
                platform=platform,
                owner=owner,
                repo=repo,
                commit_id=raw_vul_info.commit_id,
                commit_link=raw_vul_info.code_link,
                patches=Patch.init_patches_from_github(owner, repo, raw_vul_info.commit_id)
            )
            repair_info.normalize()

            return cls(project_name=raw_vul_info.project, cve_info=cve_info, repair_info=repair_info)

        else:
            # TODO 目前只处理github的数据
            return None

    def custom_serialize(self, index: int = None):
        if index:
            return {
                "index": index,
                "project_name": self.project_name,
                "cve_info": self.cve_info.custom_serialize(),
                "repair_info": self.repair_info.custom_serialize()
            }
        else:
            return {
                "project_name": self.project_name,
                "cve_info": self.cve_info.custom_serialize(),
                "repair_info": self.repair_info.custom_serialize()
            }

    @classmethod
    def init_from_dict(cls, data):
        return cls(
            project_name=data.get("project_name"),
            cve_info=CVEInfo.init_from_dict(data.get("cve_info")),
            repair_info=RepairInfo.init_from_dict(data.get("repair_info"))
        )


def filter_raw_vul_info():
    raw_json_path = "Resources/vuls/MSR_data_cleaned.json"
    filtered_json_path = "Resources/vuls/MSR_data_filtered.json"
    # load
    raw_vul_dict = load_from_json_file(raw_json_path)

    # convert
    raw_vul_info_set: Set[RawVulInfo] = set()
    for k, v in tqdm(raw_vul_dict.items(), desc="Converting"):
        vul_info = RawVulInfo.init_from_original_dict(v)
        # TODO 实际上，目前后续步骤中，只处理了github的数据
        if not vul_info.code_link.split("://")[1].startswith(("git.", "github.")):
            continue
        raw_vul_info_set.add(vul_info)
    logger.info(f"len(raw_vul_info_set): {len(raw_vul_info_set)}")

    save_to_json_file([v.customer_serialize() for v in raw_vul_info_set], filtered_json_path)

    git_count = 0
    github_count = 1
    for raw_vul_info in raw_vul_info_set:
        commit_link = raw_vul_info.code_link
        if commit_link.split("://")[1].startswith("git."):
            git_count += 1
        else:
            github_count += 1
    print(f"git_count: {git_count}，github_count: {github_count}")


def convert_raw_vul_info():
    filtered_json_path = "Resources/vuls/MSR_data_filtered.json"
    processed_json_path = "Resources/vuls/MSR_data_processed.json"
    raw_vul_info_list = load_from_json_file(filtered_json_path)
    raw_vul_info_list = [RawVulInfo.init_from_dict(v) for v in raw_vul_info_list]

    vul_info_list = []
    for raw_vul_info in tqdm(raw_vul_info_list, desc="Converting"):
        vul_info = VulInfo.init_from_raw_vul_info(raw_vul_info)
        if vul_info:  # 因为目前只处理了github的数据，不是github的数据会返回None
            vul_info_list.append(vul_info)
    print(f"len(vul_info_list): {len(vul_info_list)}")
    vul_info_list.sort(key=lambda x: x.cve_info.cve_id)
    vul_info_list.sort(key=lambda x: x.project_name)
    save_to_json_file([v.custom_serialize(i) for i, v in enumerate(vul_info_list, start=1)], processed_json_path)


def process_vul_info():
    """
    再次处理vul_info
        1. 过滤，没有成功解析patch的数据
        2. 补充，受影响的版本
        3. 补充，修复的版本
        4. 二进制测试用例[修复前，修复后]
        5. 合并openssl的漏洞信息？

    :return:
    """

    converted_json_path = "Resources/vuls/MSR_data_converted.json"
    processed_json_path = "Resources/vuls/MSR_data_processed.json"
    processed_json_simplified_path = "Resources/vuls/MSR_data_processed_simplified.json"

    # load
    json_vuls = load_from_json_file(converted_json_path)
    vuls = [VulInfo.init_from_dict(v) for v in json_vuls]

    project_set = set()
    for vul in tqdm(vuls):
        # 过滤patch数据
        filtered_patches = []
        for patch in vul.repair_info.patches:
            if not patch.snippet_changes:
                # print(f"no patch.snippet_changes: {patch.file_name}")
                continue
            if not patch.file_name.endswith((*C_EXTENSION_SET, *CPP_EXTENSION_SET)):
                # print(f"not .c file: {patch.file_name}")
                continue
            filtered_patches.append(patch)
        if not filtered_patches:
            print(f"no filtered_patches: {vul.project_name}")
            continue
        vul.repair_info.patches = filtered_patches
        # 删除下面这一行。临时代码，方便查看
        # vul.repair_info.patches = []
        url = f"https://www.cvedetails.com/cve/{vul.cve_info.cve_id}"
        vul.cve_info.affected_versions = " ".join(fetch_table_column_values_and_headers(url))
        project_set.add(vul.project_name)

    print(f"len(project_set): {len(project_set)}, len(vuls): {len(vuls)}")  # 247, 2915
    save_to_json_file([v.custom_serialize(i) for i, v in enumerate(vuls, start=1)], processed_json_path)

    # 简要版本
    vul_dict = {}
    for i, v in enumerate(vuls, start=1):
        project_name = v.project_name
        if project_name not in vul_dict:
            vul_dict[project_name] = {
                "count": 0,
                "CVE_IDs": []
            }
        vul_dict[project_name]["count"] += 1
        vul_dict[project_name]["CVE_IDs"].append(v.cve_info.cve_id)
    save_to_json_file(vul_dict, processed_json_simplified_path)


if __name__ == '__main__':
    # filter_raw_vul_info() # 过滤数据，只保留github的数据
    # convert_raw_vul_info()  # 转换数据, 挑选重要信息，获取github api信息，生成我自己需要的格式
    process_vul_info()  # 再次处理vul_info, 增加版本号信息。