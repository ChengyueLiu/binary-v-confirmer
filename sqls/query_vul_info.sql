-- 需要的信息
-- 组件信息：library_name, version_number, github_link,
--      漏洞信息：cve_number, cve_link, date, title, description, severity
--              修复信息： affected_since, fixed_in, commit_id, commit_link

WITH wt_cve_tab AS
(
	SELECT ss.id AS sec_id,
	       ss.public_id AS cve_number,
       		 'https://nvd.nist.gov/vuln/detail/' || ss.public_id  AS cve_link,
       		 ss.publish_date , --这个不是实际的publish 时间，是数据的创建时间
       		 --没有 title
       		 ss.description,
       		 --severtity
       		 sv.id AS cve_vul1_id
	FROM scantist_securityissue ss
	JOIN "1_scantist_vulnerability" sv
	  ON ss.public_id  = sv.public_id
	  AND sv.is_valid =  TRUE
	WHERE ss.public_id = 'CVE-2021-3711'
),
 wt_patch_tab AS
(
	SELECT tt.vulnerability_id, string_agg( sp1.url, chr(13) ) AS url --, tt.raw --, sp2.vulnerable_code , sp2.patched_code , sp2.hunk_code
	FROM
	(
	   SELECT DISTINCT sp.patch_hash ,sp.vulnerability_id FROM "1_scantist_patch" sp WHERE sp.is_valid = TRUE
	)tt
	LEFT JOIN ( SELECT *
	  			  FROM (
						SELECT ROW_NUMBER () over(PARTITION BY patch_hash, vulnerability_id ORDER BY url) rn , patch_hash, vulnerability_id, url
					      FROM  "1_scantist_patchsource"
					     WHERE is_patch_extracted  = TRUE
			     ) sp
			     WHERE  sp.rn = 1) sp1
	       ON tt.patch_hash = sp1.patch_hash
		  AND tt.vulnerability_id = sp1.vulnerability_id
    GROUP BY tt.vulnerability_id
)
SELECT sl3."name", sl3.vendor, sl3.platform, slv2.version_number , vrug.repo_url,
      wct.cve_number, wct.cve_link, wct.publish_date, wct.description, --没有 title , severtity 没有直接的值，需要写个判断
      svl.version_ranges, svl.exclude_versions, wpt.url
 FROM wt_cve_tab wct
 JOIN  scantist_libraryversionissue sl2
   ON wct.sec_id = sl2.security_issue_id
 JOIN scantist_library_version slv2
   ON sl2.library_version_id = slv2.id
   AND slv2.is_valid = TRUE
 JOIN scantist_library sl3
   on sl3.id = slv2.library_id
 LEFT JOIN v_repo_url_get vrug
        ON sl3.id = vrug.library_id
 LEFT JOIN "1_scantist_vulnerability_library" svl
        ON svl.vulnerability_id = wct.cve_vul1_id
       AND sl3.id = svl.library_id
       AND svl.is_valid = TRUE
 LEFT JOIN wt_patch_tab wpt
   ON wct.cve_vul1_id = wpt.vulnerability_id
  ;

