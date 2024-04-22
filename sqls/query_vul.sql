SELECT sl."name",
       sl.vendor,
       sl.platform,
       sl.id              as library_id,
       slv.version_number AS affected_version_number,
       ss.public_id,
       sp.url,
       sp2.raw,
       sp3.hunk_code,
       sp3.affected_file,
       sp3.affected_function,
       sp3.vulnerable_code,
       sp3.patched_code
FROM scantist_library sl
         JOIN scantist_library_version slv
              ON sl.id = slv.library_id
                  AND slv.is_valid = TRUE
         JOIN scantist_libraryversionissue sl2 -- 版本和 scantist_securityissue 的映射
              ON slv.id = sl2.library_version_id
         JOIN scantist_securityissue ss --漏洞表
              ON ss.id = sl2.security_issue_id
                  AND ss.is_valid = TRUE
         JOIN "1_scantist_vulnerability" sv --漏洞表 staging
              ON sv.public_id = ss.public_id
                  AND sv.is_valid = TRUE
         JOIN "1_scantist_patchsource" sp --patch 下载的url
              ON sp.vulnerability_id = sv.id
                  AND sp.url LIKE '%github%'
         JOIN "1_scantist_patch" sp2 --raw
              ON sp2.vulnerability_id = sv.id
                  AND sp2.is_valid = TRUE
         JOIN "1_scantist_patchhunk" sp3 --解析后
              ON sp3.patch_id = sp2.id
        WHERE sl.id = 6775546;


-- cve detail 查询组件名称，github确认vendor名称，然后用上面的sql查询漏洞信息

-- name,vendor,platform,id,vul_count
-- openssl,openssl,github,6774594,246
-- FFmpeg,FFmpeg,github,4,426
-- curl,haxx,NOT_SPECIFIED,14711,57

-- libtiff,libtiff_project,NOT_SPECIFIED,53385,250
-- libav,libav,github,6774677,105
-- libxml2,xmlsoft,NOT_SPECIFIED,2,89
-- libming,libming,github,6775192,83
-- libvirt,"",Debian,3768312,73
-- libarchive,libarchive,github,6774571,59
-- librenms/librenms,"",Packagist,1802459,55
-- libraw,libraw,NOT_SPECIFIED,4456,51
-- libdwarf,libdwarf_project,NOT_SPECIFIED,15680,45
-- libpng,libpng,NOT_SPECIFIED,1977,45
-- libsixel,saitoha,github,6776434,42
-- libexpat,libexpat,github,6775442,35
-- libgd,libgd,github,6774629,34
-- libsass,sass,github,6774752,27
-- libsndfile,libsndfile_project,NOT_SPECIFIED,45663,27
-- libxslt,xmlsoft,NOT_SPECIFIED,12818,22
-- libssh,libssh,NOT_SPECIFIED,2160,21


SELECT *FROM scantist_library sl
WHERE sl."name" = 'openssl'
AND sl.vendor = 'openssl'
AND sl.platform = 'github'


-- SELECT *
-- FROM scantist_library_version slv
-- WHERE slv.library_id = 6774594