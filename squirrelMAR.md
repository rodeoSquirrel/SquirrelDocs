[//]: # (My Malware Analysis Report - case - Threat/Month)
# Organization Malware Analysis Report - case no - Threat Name/MM-YYYY

[//]: # (Based on https://zeltser.com/media/docs/rating-sheet-threat-reports-info.pdf)
### Actionable Information
[//]: # (What are the most important conclusions about the threat?)

### Threat Objectives
[//]: # (What IT ordata components is the threat intendingto harm?)
[//]: # (Is the threat focused on specific geographies, industries, or other demographics?)
[//]: # (What business processes or human targets is the threat pursuing, if any?)
[//]: # (How motivated is the threat actor to achieve the objectives?)

### Threat Capabilities
[//]: # (What are the threat’s propagation methods?)
[//]: # (What are the mechanics of the threat once it reaches the target?)
[//]: # (How capable is the threat at achieving the objectives?)

### Threat Efficacy
[//]: # (How broad is our attack surface?)
[//]: # (How vulnerable are we to the threat’s methods?)
[//]: # (What mitigation measures do we have?)
[//]: # (How effective are our countermeasures?)

### Threat Intelligence
[//]: # (Have we had any incidents related to this or a similar threat?)
[//]: # (How does the threat affect other industry participants?)
[//]: # (Do we have any adversary group, tool name, or other attribution details?)

### Threat Detection, Prevention, and Mitigation
[//]: # (What steps can reduce the attack surface?)
[//]: # (What countermeasures can helpusprevent, detect, and respond to the threat?)
[//]: # (What should we do next, if anything?)

### Analysis
[//]: # (What tools and other resources helped with the analysis?)
[//]: # (What data and observations supported the conclusions?)
[//]: # (How certain are we that the analysis is accurate?)
[//]: # (Who participated in the analysis and its review?)

### Appendix
[//]: # (This is where you can list any tools used, acronyms, external references, etc at length that is useful but doesn't fit into the rest of the sections in full but should be available for quick reference)

#### Relevant IOCs
[//]: # (Create a table and keep them sorted by type)

Observable | Type
:--- | ---:
value | SHA256
value | MD5
value | IP
value | Domain
value | URL+URI

#### YARA Rule(s)
[//]: # (Use inline code blocks)
```
rule MALW_trickbot_bankBot : Trojan
{
meta:
 author = "Marc Salinas @Bondey_m"
 description = "Detects Trickbot Banking Trojan"
 reference = "https://github.com/Yara-Rules/rules/blob/master/malware/MALW_TrickBot.yar"
strings:
$str_trick_01 = "moduleconfig"
$str_trick_02 = "Start"
$str_trick_03 = "Control"
$str_trick_04 = "FreeBuffer"
$str_trick_05 = "Release"
condition:
all of ($str_trick_*)
}
```

#### Suricata Rule(s)
[//]: # (Use inline code blocks)
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"PowerTrick Task Checkin\"; content:\"POST\"; http_method; content:\"p3=\"; offset:0; depth:3; http_client_body; content:\"p=i\"; http_client_body; content:\"p1=\"; http_client_body; content:\"p2=\"; http_client_body; content:\"p9=\"; http_client_body; classtype:trojan-activity; sid:9000020; rev:1; metadata:author Jason Reaves; reference: url, https://github.com/SentineLabs/PowerTrick/blob/master/IOCs/2020-01-08-powetrick-iocs-vk-misp-json.json;
```
