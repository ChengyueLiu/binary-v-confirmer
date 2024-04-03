-- 查询漏洞信息
SELECT distinct ss.public_id,
       sl.id              AS library_id,
       sl."name" as library_name,
       sl.vendor,
       sl.platform,
       slv.id as version_id,
       slv.version_number AS version_number

FROM scantist_library sl
         JOIN scantist_library_version slv ON sl.id = slv.library_id AND slv.is_valid = TRUE
         JOIN scantist_libraryversionissue sl2 ON slv.id = sl2.library_version_id
         JOIN scantist_securityissue ss ON ss.id = sl2.security_issue_id AND ss.is_valid = TRUE
WHERE sl.id IN
      (6774594, 8662121, 53385, 6774677, 2, 6775192, 3768312, 6774571, 14711, 1802459, 4456, 15680, 1977, 6776434,
       6775442, 6774629, 6774752, 45663, 12818, 2160);

-- 查询漏洞的补丁信息
SELECT DISTINCT ss.public_id,
                sp.url,
                sp2.raw,
                sp3.hunk_code,
                sp3.affected_file,
                sp3.affected_function,
                sp3.vulnerable_code,
                sp3.patched_code
FROM scantist_securityissue ss
JOIN "1_scantist_vulnerability" sv ON sv.public_id = ss.public_id AND sv.is_valid = TRUE
JOIN "1_scantist_patchsource" sp ON sp.vulnerability_id = sv.id AND sp.url LIKE '%github%'
JOIN "1_scantist_patch" sp2 ON sp2.vulnerability_id = sv.id AND sp2.is_valid = TRUE
JOIN "1_scantist_patchhunk" sp3 ON sp3.patch_id = sp2.id
WHERE ss.public_id IN ('CVE-2015-6838');

-- 两步一起查
SELECT ss.public_id,
                sp.url,
                sp2.raw,
                sp3.hunk_code,
                sp3.affected_file,
                sp3.affected_function
--                 sp3.vulnerable_code,
--                 sp3.patched_code
FROM scantist_securityissue ss
JOIN "1_scantist_vulnerability" sv ON sv.public_id = ss.public_id AND sv.is_valid = TRUE
JOIN "1_scantist_patchsource" sp ON sp.vulnerability_id = sv.id AND sp.url LIKE '%github%'
JOIN "1_scantist_patch" sp2 ON sp2.vulnerability_id = sv.id AND sp2.is_valid = TRUE
JOIN "1_scantist_patchhunk" sp3 ON sp3.patch_id = sp2.id
WHERE ss.public_id IN (
      SELECT DISTINCT ss.public_id
      FROM scantist_library sl
      JOIN scantist_library_version slv ON sl.id = slv.library_id AND slv.is_valid = TRUE
      JOIN scantist_libraryversionissue sl2 ON slv.id = sl2.library_version_id
      JOIN scantist_securityissue ss ON ss.id = sl2.security_issue_id AND ss.is_valid = TRUE
      WHERE sl.id IN
            (6774594, 8662121, 53385, 6774677, 2, 6775192, 3768312, 6774571, 14711, 1802459, 4456, 15680, 1977, 6776434,
             6775442, 6774629, 6774752, 45663, 12818, 2160)
);
