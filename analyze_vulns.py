import re
import pandas as pd
def detect_vulerabilities(http_request):
  
    #LFI_TEST
        #Define LFI  patterns to check
        LFI_patterns=[
              #detect code injection 1/3
              r'(?:@[\w-]+\s*\()|(?:]\s*\(\s*["!]\s*\w)|(?:<[?%](?:php)?.*(?:[?%]>)?)|(?:;[\s\w|]*\$\w+\s*=)|(?:\$\w+\s*=(?:(?:\s*\$?\w+\s*[(;])|\s*".*"))|(?:;\s*\{\W*\w+\s*\()',
              #detect code injection 2/3
              r'(?:(?:[;]+|(<[?%](?:php)?)).*(?:define|eval|file_get_contents|include|require|require_once|set|shell_exec|phpinfo|system|passthru|preg_\w+|execute)\s*["(@])',
              #detect cod injection 3/3
              r'(?:(?:[;]+|(<[?%](?:php)?)).*[^\w](?:echo|print|print_r|var_dump|[fp]open))|(?:;\s*rm\s+-\w+\s+)|(?:;.*{.*\$\w+\s*=)|(?:\$\w+\s*\[\]\s*=\s*)',
              #Detects etc/passwd inclusion attempts
              r'(?:etc\/\W*passwd)'
        ]

        for pattern in LFI_patterns:
                if re.search(pattern, http_request, re.IGNORECASE):
                   return "LFI"

    #PATH_TRAVERSAL
        #Define PATH_TRAVERSAL patterns to check
        PATH_TRAVERSAL_patterns=[
              #Detects basic directory traversal
              r'(?:(?:\/|\\)?\.+(\/|\\)(?:\.+)?)|(?:\w+\.exe\??\s)|(?:;\s*\w+\s*\/[\w*-]+\/)|(?:\d\.\dx\|)|(?:%(?:c0\.|af\.|5c\.))|(?:\/(?:%2e){2})',
              #Detects specific directory and path traversal
              r'(?:%c0%ae\/)|(?:(?:\/|\\)(home|conf|usr|etc|proc|opt|s?bin|local|dev|tmp|kern|[br]oot|sys|system|windows|winnt|program|%[a-z_-]{3,}%)(?:\/|\\))|(?:(?:\/|\\)inetpub|localstart\.asp|boot\.ini)'     
        ]
        for pattern in PATH_TRAVERSAL_patterns:
                if re.search(pattern, http_request, re.IGNORECASE):
                   return "PATH TRAVERSAL"
    

    #SQLI_TEST
                 # Define SQL injection patterns to check
        sql_injection_patterns = [
            #BASIC SQLI
            r"\bOR\b|\bAND\b\s*['\"]?1['\"]?\s*=\s*['\"]?1['\"]?",
            r'(?:\d"\s+"\s+\d)|(?:^admin\s*"|(\/\*)+"+\s?(?:--|#|\/\*|{)?)|(?:"\s*or[\w\s-]+\s*[+<>=(),-]\s*[\d"])|(?:"\s*[^\w\s]?=\s*")|(?:"\W*[+=]+\W*")|(?:"\s*[!=|][\d\s!=+-]+.*["(].*$)|(?:"\s*[!=|][\d\s!=]+.*\d+$)|(?:"\s*like\W+[\w"(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:"[<>~]+|OR")',
            #Detects basic SQL authentication bypass attempts 1/3
            r'(?:\d"\s+"\s+\d)|(?:^admin\s*"|(\/\*)+"+\s?(?:--|#|\/\*|{)?)|(?:"\s*or[\w\s-]+\s*[+<>=(),-]\s*[\d"])|(?:"\s*[^\w\s]?=\s*")|(?:"\W*[+=]+\W*")|(?:"\s*[!=|][\d\s!=+-]+.*["(].*$)|(?:"\s*[!=|][\d\s!=]+.*\d+$)|(?:"\s*like\W+[\w"(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:"[<>~]+")]]',
            #Detects basic SQL authentication bypass attempts 2/3
                r'(?:union\s*(?:all|distinct|[(!@]*)\s*[([]*\s*select)|(?:\w+\s+like\s+\")|(?:like\s*"\%)|(?:"\s*like\W*["\d])|(?:"\s*(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:"\s*\*\s*\w+\W+")|(?:"\s*[^?\w\s=.,;)(]+\s*[(@"]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,"-]+from)|(?:find_in_set\s*\()',
            #Detects basic SQL authentication bypass attempts 3/3
                r'(?:in\s*\(+\s*select)|(?:(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*"|[=\d]+x))|("\s*\d\s*(?:--|#))|(?:"[%&<>^=]+\d\s*(=|or))|(?:"\W+[\w+-]+\s*=\s*\d\W+")|(?:"\s*is\s*\d.+"?\w)|(?:"\|?[\w-]{3,}[^\w\s.,]+")|(?:"\s*is\s*[\d.]+\s*\W.*")',
            #Detects concatenated basic SQL injection and SQLLFI attempts
                r'(?:[\d\W]\s+as\s*["\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|("\s+regexp\W)|(?:[\s(]load_file\s*\()',
            #Detects chained SQL injection attempts 1/2 
                r'(?:@.+=\s*\(\s*select)|(?:\d+\s*or\s*\d+\s*[\-+])|(?:\/\w+;?\s+(?:having|and|or|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?or|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*["=()])',
            #Detects chained SQL injection attempts 2/2
                r'(?:"\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w"\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+"\w)|(?:";\s*(?:if|while|begin))|(?:"[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(])',
            #Detects SQL benchmark and sleep injection attempts including conditional queries
                r'(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+)',
            #Detects MySQL UDF injection and other data/structure manipulation attempts
                r'(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,})',
            #Detects MySQL charset switch and MSSQL DoS attempts
                r'(?:alter\s*\w+.*character\s+set\s+\w+)|(";\s*waitfor\s+time\s+")|(?:";.*:\s*goto)',
            #Detects MySQL and PostgreSQL stored procedure/function injections
                r'(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@)',
            #Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts
                r'(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?"+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\/\*|{))',
            #Detects MSSQL code execution and information gathering attempt
                r'(?:\sexec\s+xp_cmdshell)|(?:"\s*!\s*["\w])|(?:from\W+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:";?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*")',
            #Detects MATCH AGAINST, MERGE, EXECUTE IMMEDIATE and HAVING injections
                r'(?:merge.*using\s*\()|(execute\s*immediate\s*")|(?:\W+\d*\s*having\s*[^\s\-])|(?:match\s*[\w(),+-]+\s*against\s*\()',
            #Detects MySQL comment-/space-obfuscated injections and backtick termination
               r'(?:,.*[)\da-f"]"(?:".*"|\Z|[^"]+))|(?:\Wselect.+\W*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\()']
        
        for pattern in sql_injection_patterns:
                if re.search(pattern, http_request, re.IGNORECASE):
                   return "SQLI"
    
    
    
    

    #RFI
       #Define RFI patterns¨
                RFI_patterns=[
                  r'\bfile\s*=\s*(http|https)',
                  r'\b(?:include|require|include_once|require_once)\s*\([\'"]?(https?|ftp):\/\/(?:[^\/\s]+\/)*[^\'"]+\.(php|txt|html)[\'"]?\)'
                  r'\b(file|include|require|require_once|include_once)\b\s*=\s*(http|https)://'
              ]
                for pattern in RFI_patterns:
                   if re.search(pattern, http_request, re.IGNORECASE):
                      return "RFI"

    

        

    #XSS
       #Define XSS patterns 
        XSS_patterns=[
             #Finds html breaking injections including whitespace attacks
              r'(?:"[^"]*[^-]?>)|(?:[^\w\s]\s*\/>)|(?:>")',
              #Detects JavaScript string properties and methods
              r'([^*:\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\/_@\-\|])(\s*return\s*)?(?:set|atob|btoa|charat|charcodeat|charset|concat|crypto|frames|fromcharcode|indexof|lastindexof|match|navigator|toolbar|menubar|replace|regexp|slice|split|substr|substring|escape|\w+codeuri\w*)(?(1)[^\w%"]|(?:\s*[^@\s\w%,.+\-]))',
              #Detects JavaScript language constructs
              r'(?:\)\s*\[)|([^*":\s\w,.\/?+-]\s*)?(?<![a-z]\s)(?<![a-z_@\|])(\s*return\s*)?(?:globalstorage|sessionstorage|postmessage|callee|constructor|content|domain|prototype|try|catch|top|call|apply|url|function|object|array|string|math|if|for\s*(?:each)?|elseif|case|switch|regex|boolean|location|(?:ms)?setimmediate|settimeout|setinterval|void|setexpression|namespace|while)(?(1)[^\w%"]|(?:\s*[^@\s\w%".+\-\/]))',
               #Detects very basic XSS probings
              r'(?:,\s*(?:alert|showmodaldialog|eval)\s*,)|(?::\s*eval\s*[^\s])|([^:\s\w,.\/?+-]\s*)?(?<![a-z\/_@])(\s*return\s*)?(?:(?:document\s*\.)?(?:.+\/)?(?:alert|eval|msgbox|showmod(?:al|eless)dialog|showhelp|prompt|write(?:ln)?|confirm|dialog|open))\s*(?:[^.a-z\s\-]|(?:\s*[^\s\w,.@\/+-]))|(?:java[\s\/]*\.[\s\/]*lang)|(?:\w\s*=\s*new\s+\w+)|(?:&\s*\w+\s*\)[^,])|(?:\+[\W\d]*new\s+\w+[\W\d]*\+)|(?:document\.\w)'
              #Detects advanced XSS probings via Script(), RexExp, constructors and XML namespaces
              r'(?:=\s*(?:top|this|window|content|self|frames|_content))|(?:\/\s*[gimx]*\s*[)}])|(?:[^\s]\s*=\s*script)|(?:\.\s*constructor)|(?:default\s+xml\s+namespace\s*=)|(?:\/\s*\+[^+]+\s*\+\s*\/)',
              #Detects url-, name-, JSON, and referrer-contained payload attacks
              r'(?:[+\/]\s*name[\W\d]*[)+])|(?:;\W*url\s*=)|(?:[^\w\s\/?:>]\s*(?:location|referrer|name)\s*[^\/\w\s-])',
              #Detects JavaScript with(), ternary operators and XML predicate attacks
              r'(?:[=(].+\?.+:)|(?:with\([^)]*\)\))|(?:\.\s*source\W)',
              #Detects self-executing JavaScript functions
              r'(?:\/\w*\s*\)\s*\()|(?:\([\w\s]+\([\w\s]+\)[\w\s]+\))|(?:(?<!(?:mozilla\/\d\.\d\s))\([^)[]+\[[^\]]+\][^)]*\))|(?:[^\s!][{([][^({[]+[{([][^}\])]+[}\])][\s+",\d]*[}\])])|(?:"\)?\]\W*\[)|(?:=\s*[^\s:;]+\s*[{([][^}\])]+[}\])];)'
              ]
        
        
        for pattern in XSS_patterns :
              if re.search(pattern,http_request,re.IGNORECASE):
                    return "XSS"

        
        #BRUTE_FORCE
              


           
        return "NONE"



