# phishhook
Phishing domain finder using python and certstream

Use it to better protect your self and your brand against phishing based on your domain and trigger words.

Phishhook will permutate your domain name or brand and score it against incoming domain names when every they are getting a new certificate.

The score is calculated based on your brand name position in the domain name as well as the occurrences of score words.

Here is a list of possible Apple phishing domains found over a period of just a few hours.
```
Verdict    Brand   Score Has IP  Domain name
--------------------------------------------------------------------------
Suspicious [Apple] [2 ] [active] [apple-supportfind.com]                
Suspicious [Apple] [2 ] [active] [support-appleld.us]                   
Suspicious [Apple] [1 ] [active] [apple-in.us]                          
Suspicious [Apple] [2 ] [active] [apple-lcloud.us]                      
Suspicious [Apple] [2 ] [active] [support-apple.us]                     
Suspicious [Apple] [10] [active] [supportid-apple.com]                  
Suspicious [Apple] [2 ] [active] [applesupports-ec.com]                 
Suspicious [Apple] [9 ] [active] [isupports-apple.com]                  
Suspicious [Apple] [4 ] [active] [lsupport-appleid.com]                 
Suspicious [Apple] [3 ] [active] [soporte-appleid.com]                  
Suspicious [Apple] [3 ] [active] [help-appleaccount.us]                 
Suspicious [Apple] [10] [active] [isupportid-apple.com]                 
Suspicious [Apple] [9 ] [active] [findmyid-apple.com]                   
Suspicious [Apple] [3 ] [active] [soporte-appleid.us]                   
Suspicious [Apple] [4 ] [active] [supports-appleid.com]                 
Suspicious [Apple] [2 ] [active] [support-appleld.com]                  
Suspicious [Apple] [2 ] [active] [apple-flndmyid.com]                   
Suspicious [Apple] [2 ] [active] [www.apple-flndmyid.us]                
Suspicious [Apple] [2 ] [active] [www.apple-lcloud.us]                  
Suspicious [Apple] [1 ] [active] [www.apple-in.us]                      
Suspicious [Apple] [3 ] [active] [www.soporte-appleid.us]               
Suspicious [Apple] [2 ] [active] [www.support-apple.us]                 
Suspicious [Apple] [9 ] [active] [www.findmyid-apple.com]               
Suspicious [Apple] [2 ] [active] [appleld.online-logs.info]             
Suspicious [Apple] [2 ] [active] [www.appleld.online-logs.info]         
Suspicious [Apple] [2 ] [active] [apple-support.com.thesearemybeats.com]
--------------------------------------------------------------------------
```

Please note this is solely based on guessing with no other information than your domain name and trigger words hence
false positive will probably be the rule rather than the exception if you brand contains common words.