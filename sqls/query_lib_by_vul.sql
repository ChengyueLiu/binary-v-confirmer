SELECT sl2.id AS library_id, sl2."name" , sl2.vendor , sl2.platform , ss.public_id , slv.version_number
FROM scantist_securityissue ss
JOIN scantist_libraryversionissue sl
  ON ss.id = sl.security_issue_id
  AND ss.public_id = 'CVE-2023-45322'
  AND sl.is_valid = TRUE
JOIN scantist_library_version slv
  ON sl.library_version_id = slv.id
  AND slv.is_valid = TRUE
JOIN scantist_library sl2
  ON slv.library_id = sl2.id
  AND sl2.is_valid = TRUE
ORDER BY 1