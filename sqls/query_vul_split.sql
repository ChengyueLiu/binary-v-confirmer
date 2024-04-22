-- 查询漏洞信息
SELECT distinct ss.public_id,
                sl.id              AS library_id,
                sl."name"          as library_name,
                sl.vendor,
                sl.platform,
                slv.id             as version_id,
                slv.version_number AS version_number

-- select count(distinct public_id)
FROM scantist_library sl
         JOIN scantist_library_version slv ON sl.id = slv.library_id AND slv.is_valid = TRUE
         JOIN scantist_libraryversionissue sl2 ON slv.id = sl2.library_version_id
         JOIN scantist_securityissue ss ON ss.id = sl2.security_issue_id AND ss.is_valid = TRUE
WHERE sl.id IN
      (6774594, 2, 53385, 6774677, 2, 6775192, 3768312, 6774571, 14711, 1802459, 4456, 1977, 6776434,
       6775442, 6774629, 6774752, 45663, 2160,
       -- 下面是补充的
       6513);

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
         JOIN "1_scantist_patchsource" sp ON sp.vulnerability_id = sv.id
         JOIN "1_scantist_patch" sp2 ON sp2.vulnerability_id = sv.id AND sp2.is_valid = TRUE
         JOIN "1_scantist_patchhunk" sp3 ON sp3.patch_id = sp2.id
WHERE ss.public_id IN
      (6774594, 2, 53385, 6774677, 2, 6775192, 3768312, 6774571, 14711, 1802459, 4456, 1977, 6776434,
       6775442, 6774629, 6774752, 45663, 2160);

-- 两步一起查
-- SELECT distinct ss.public_id
SELECT ss.public_id, sp.url
--                 sp2.raw,
--                 sp3.hunk_code,
--                 sp3.affected_file,
--                 sp3.affected_function
FROM scantist_securityissue ss
         JOIN "1_scantist_vulnerability" sv ON sv.public_id = ss.public_id AND sv.is_valid = TRUE
         JOIN "1_scantist_patchsource" sp ON sp.vulnerability_id = sv.id
         JOIN "1_scantist_patch" sp2 ON sp2.vulnerability_id = sv.id AND sp2.is_valid = TRUE
         JOIN "1_scantist_patchhunk" sp3 ON sp3.patch_id = sp2.id
WHERE ss.public_id IN (SELECT DISTINCT ss.public_id
                       FROM scantist_library sl
                                JOIN scantist_library_version slv ON sl.id = slv.library_id AND slv.is_valid = TRUE
                                JOIN scantist_libraryversionissue sl2 ON slv.id = sl2.library_version_id
                                JOIN scantist_securityissue ss ON ss.id = sl2.security_issue_id AND ss.is_valid = TRUE
                       --       WHERE sl.id in (6774594, 2, 53385, 6774677, 6775192,
--       3768312, 6774571, 14711, 1802459, 4456, 1977, 6776434,
--        6775442, 6774629, 6774752, 45663, 2160)
                       where sl.id = 6513);

-- name,vendor,platform,id,vul_count
-- openssl,openssl,github,6774594,246
-- FFmpeg,FFmpeg,github,4,426
-- libtiff,libtiff_project,NOT_SPECIFIED,53385,250
-- libav,libav,github,6774677,105
-- libxml2,xmlsoft,NOT_SPECIFIED,2,89
-- libming,libming,github,6775192,83
-- libvirt,"",Debian,3768312,73
-- libarchive,libarchive,github,6774571,59
-- curl,haxx,NOT_SPECIFIED,14711,57
-- librenms/librenms,"",Packagist,1802459,55
-- libraw,libraw,NOT_SPECIFIED,4456,51
-- libpng,libpng,NOT_SPECIFIED,1977,45
-- libsixel,saitoha,github,6776434,42
-- libexpat,libexpat,github,6775442,35
-- libgd,libgd,github,6774629,34
-- libsass,sass,github,6774752,27
-- libsndfile,libsndfile_project,NOT_SPECIFIED,45663,27
-- libssh,libssh,NOT_SPECIFIED,2160,21
-- libdwarf,libdwarf_project,NOT_SPECIFIED,15680,45
-- libxslt,xmlsoft,NOT_SPECIFIED,12818,22

-- 补充
-- lighttpd,lighttpd,github,6513,