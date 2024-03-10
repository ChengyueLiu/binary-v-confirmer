import json
from dataclasses import dataclass
from typing import Optional, List

from urllib.parse import urlparse, parse_qs

def parse_git_url(url):
    # 解析URL
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

@dataclass
class VulInfo:
    access_gained: Optional[str] = None
    attack_origin: Optional[str] = None
    authentication_required: Optional[str] = None
    availability: Optional[str] = None
    cve_id: Optional[str] = None
    cve_page: Optional[str] = None
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
    project_after: Optional[str] = None
    project_before: Optional[str] = None
    vul: Optional[int] = None
    vul_func_with_fix: Optional[str] = None

    @classmethod
    def init_from_dict(cls, json_data_item):
        return cls(
            access_gained=json_data_item.get("Access Gained"),
            attack_origin=json_data_item.get("Attack Origin"),
            authentication_required=json_data_item.get("Authentication Required"),
            availability=json_data_item.get("Availability"),
            cve_id=json_data_item.get("CVE ID"),
            cve_page=json_data_item.get("CVE Page"),
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
            project_after=json_data_item.get("project_after"),
            project_before=json_data_item.get("project_before"),
            vul=json_data_item.get("vul"),
            vul_func_with_fix=json_data_item.get("vul_func_with_fix")
        )

    def custom_serialize(self):
        return {
            "access_gained": self.access_gained,
            "attack_origin": self.attack_origin,
            "authentication_required": self.authentication_required,
            "availability": self.availability,
            "cve_id": self.cve_id,
            "cve_page": self.cve_page,
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
            "project_after": self.project_after,
            "project_before": self.project_before,
            "vul": self.vul,
            "vul_func_with_fix": self.vul_func_with_fix
        }

    def normalize(self):
        parse_result = parse_git_url(self.project_after)
        file_path = parse_result.get('file_path')
        self.file_path = file_path



def convert_raw_vul_info():
    raw_json_path = "Resources/vuls/raw_vul_demo.json"

    # load
    with open(raw_json_path, 'r') as f:
        raw_vul_dict = json.load(f)

    # convert
    vul_info_list:List[VulInfo] = []
    for k, v in raw_vul_dict.items():
        vul_info = VulInfo.init_from_dict(v)
        vul_info.normalize()
        vul_info_list.append(vul_info)
        break

    # save
    vul_info_json = [vul_info.custom_serialize() for vul_info in vul_info_list]
    with open("Resources/vuls/processed_vuls.json", 'w') as f:
        json.dump(vul_info_json, f, indent=4)

if __name__ == '__main__':
    convert_raw_vul_info()