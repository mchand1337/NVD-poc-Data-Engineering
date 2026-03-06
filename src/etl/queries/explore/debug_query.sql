SELECT CVE_ID, COUNT(*)
from silver_nvd.vulnerability_summary
GROUP BY CVE_ID
HAVING COUNT(*) = 1
ORDER BY COUNT(*) DESC;