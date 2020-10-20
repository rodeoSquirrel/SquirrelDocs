[//]: # (My Malware Analysis Report - case - Threat/Month)
# <p style="text-align: center;">MyOrg Malware Analysis Report</p>
## <p style="text-align: center;">case no - Threat Name/MM-YYYY</p>
### <p style="text-align: center;">Analysis by rodeoSquirrel</p>


[//]: # (Based on https://zeltser.com/media/docs/rating-sheet-threat-reports-info.pdf)
## **Summary and Actionable Items**
[//]: # (What are the most important conclusions about the threat?)
This is where you should discuss the strategic takeaways from the exercise. Keep it short, sweet, and
bottom-line up front.

This is not the section to discuss the technical details, it should be management/executive friendly. Just be
mindful of the audience for your write-ups.

## **Threat Objectives and Known Targets**
[//]: # (What IT or data components is the threat intending to harm?)
[//]: # (Is the threat focused on specific geographies, industries, or other demographics?)
[//]: # (What business processes or human targets is the threat pursuing, if any?)
[//]: # (How motivated is the threat actor to achieve the objectives?)
Begin discussing details about the goals the threat is attempting to achieve given its capabilities. Details
about the capabilities themselves will be covered in the next section. You are not looking for a comprehensive
overview of the actor/threat, just a synopsis of business verticals, geographic regions, goals historically
observed by activity groups leveraging the observed threat, details about the pace in reaching actions on
objective, and potential motivations that can be derived(i.e. financial/political/etc) from past campaigns.

## **Threat Capabilities**
[//]: # (What are the threat’s propagation methods?)
[//]: # (What are the mechanics of the threat once it reaches the target?)
[//]: # (How capable is the threat at achieving the objectives?)
This is where the technical details can begin, describe details like delivery, lateral movement, persistence,
and notable capabilities in reaching actions on objective. Screenshots from IDA/Ghidra/x64dbg or code snippets
are appropriate for this section.

Based on the identified capabilities, spell out the likelihood of future successful installation and actions on
objective being reached.


## **Threat Surface**
[//]: # (How broad is our attack surface?)
[//]: # (How vulnerable are we to the threat’s methods?)
[//]: # (What mitigation measures do we have?)
[//]: # (How effective are our countermeasures?)
Describe our attack surface for this threat, whether we are vulnerable to exploits that it has leverages,
whether our current controls or settings can be modified to mitigate the capabilities, and the org's success
in disrupting the threat. The last point is important to show what worked so that you are not just beating
your team over the head with missed opportunities.

## **Threat History**
[//]: # (Have we had any incidents related to this or a similar threat?)
[//]: # (How does the threat affect other industry participants?)
[//]: # (Do we have any adversary group, tool name, or other attribution details?)

## **Threat Detection, Prevention, and Mitigation**
[//]: # (What steps can reduce the attack surface?)
[//]: # (What countermeasures can help us prevent, detect, and respond to the threat?)
[//]: # (What should we do next, if anything?)

## **Analysis**
[//]: # (What tools and other resources helped with the analysis?)
[//]: # (What data and observations supported the conclusions?)
[//]: # (How certain are we that the analysis is accurate?)
[//]: # (Who participated in the analysis and its review?)

## **Appendix**
[//]: # (This is where you can list any tools used, acronyms, external references, etc at length that is useful but doesn't fit into the rest of the sections in full but should be available for quick reference)

### Observables(Hash/IP/Domain/URL)
[//]: # (Create a table and keep them sorted by type)

Observable | Type
:--- | ---:
value | SHA256
value | MD5
value | IP
value | Domain
value | URL+URI

### YARA Rule(s)
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

### Suricata Rule(s)
[//]: # (Use inline code blocks)
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"PowerTrick Task Checkin\"; content:\"POST\"; http_method; content:\"p3=\"; offset:0; depth:3; http_client_body; content:\"p=i\"; http_client_body; content:\"p1=\"; http_client_body; content:\"p2=\"; http_client_body; content:\"p9=\"; http_client_body; classtype:trojan-activity; sid:9000020; rev:1; metadata:author Jason Reaves; reference: url, https://github.com/SentineLabs/PowerTrick/blob/master/IOCs/2020-01-08-powetrick-iocs-vk-misp-json.json;
```
