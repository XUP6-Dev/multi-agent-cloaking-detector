PhishDecloaker: Detecting CAPTCHA-cloaked
Phishing Websites via Hybrid Vision-based
Interactive Models
Xiwen Teoh, Shanghai Jiao Tong University; National University of Singapore;
Yun Lin, Shanghai Jiao Tong University; Ruofan Liu, Zhiyong Huang, and
Jin Song Dong, National University of Singapore
https://www.usenix.org/conference/usenixsecurity24/presentation/teoh
This paper is included in the Proceedings of the
33rd USENIX Security Symposium.
August 14–16, 2024 • Philadelphia, PA, USA
978-1-939133-44-1
Open access to the Proceedings of the
33rd USENIX Security Symposium
is sponsored by USENIX.

PhishDecloaker: Detecting CAPTCHA-cloaked Phishing Websites via Hybrid
Vision-based Interactive Models
XiwenTeoh1,2,YunLin1∗,RuofanLiu2,ZhiyongHuang2,JinSongDong2
ShanghaiJiaoTongUniversity1,NationalUniversityofSingapore2
xiwen@nus.edu.sg,lin_yun@sjtu.edu.cn,liu.ruofan16@u.nus.edu,dcshuang@nus.edu.sg,dcsdjs@nus.edu.sg
Abstract 1 Introduction
Phishingattackscauseenormousfinanciallossesandunder-
Phishingisacybersecurityattackbasedonsocialengineering minesocietaltrust.Inrecentyears,thenumberofphishing
thatincurssignificantfinanciallossesanderodessocietaltrust. attacks has grown by over 150% per year [1]. To mitigate
Whilephishingdetectiontechniquesareemerging,attackers theseconsequences,researchershaveproposedvariousphish-
continuallystrivetobypassstate-of-the-arts.Recentphishing ingdetectionsolutions[12,15,34–37,42]toreportandexplain
campaignshaveshownthatemergingphishingattacksadopt diversezero-dayphishingwebsites.Whilethosesolutionscan
CAPTCHA-basedcloakingtechniques,markinganewround beeffectiveagainstthephishingwebsite,theireffectiveness
ofcat-and-mousegame.Ourstudyshowsthatphishingweb- islargelybasedontheassumptionthatasecuritycrawlercan
sites,hardenedbyCAPTCHA-cloaking,cancompromiseall accessthephishingcontentofthewebsites.Unfortunately,in
knownstate-of-the-artindustrialandacademicdetectorswith thenewroundofphishingcampaigns,agrowingbodyofevi-
almostzerocost. dence[46,64]hasshownthattheassumptionislesslikelyto
Inthiswork,wedevelopPhishDecloaker,anAI-powered holdtrueduetotheemergenceofCAPTCHA-basedcloaking
solutiontosoftentheshieldoftheCAPTCHA-cloakingused techniques.
byphishingwebsites.PhishDecloakerisdesignedtomimic Cloakingisanevasiontechniqueincreasinglyadoptedby
human behaviors to solve the CAPTCHAs,allowing mod- phishing attackers to display different content to security
ernsecurity-crawlerstoseetheuncloakedphishingcontent. crawlersandhumanvictims[64].Attackerscandeployeither
Technically,PhishDecloakerorchestratesfivedeepcomputer server-sideorclient-sidecloakingfortheirphishingwebpages.
visionmodelstodetecttheexistenceofCAPTCHAs,analyze Server-sidecloakingcheckshumanvisitsbyanalyzingHTTP
itstype,andsolvethechallengeinaninteractivemanner.We requestsfromtheserverendanddenyvisitsfromcertainIP
conductextensiveexperimentstoevaluatePhishDecloakerin addressesandUser-Agents[32]. On theotherhand,client-
termsofitseffectiveness,efficiency,androbustnessagainst sidecloakingcheckshumanvisitsbyanalyzingtheruntime
potentialadversaries.TheresultsshowthatPhishDecloaker browserbehavior,includingcookies,canvasfingerprints,and
(1)recoversthephishingdetectionrateofmanystate-of-the- WebGLcapabilities[13,64].Inrecentyears,researchersand
artphishingdetectorsfrom0%touptoonaverage74.25%on securityengineershaveproposedremediessuchassimulating
diverseCAPTCHA-cloakedphishingwebsites(2)generalizes ahuman-mimicHTTPheader(toaddressserver-sidecloak-
tounseenCAPTCHA(withprecisionof86%andrecallof ing)[32]andforcingtheexecutionofJavaScriptcodeused
69%),and(3)isrobustagainstvariousadversariessuchas incloaking(toaddressclient-sidecloaking)[64].However,
FGSM,JSMA,PGD,DeepFool,andDPatch,whichallows CAPTCHA-basedcloaking,beinganovelphishing-cloaking
theexistingphishingdetectorstoachievenewstate-of-the-art technique,caneasilynullifythoseanti-cloakingefforts.
performanceonCAPTCHA-cloakedphishingwebpages. Our CAPTCHA(CompletelyAutomatedPublicTuringtestto
fieldstudyover30daysshowsthatPhishDecloakercanhelp tellComputersandHumansApart)wasinitiallydeveloped
usuniquelydiscover7.6%morephishingwebsitescloakedby as challenge-response authentication to limit the abuse of
CAPTCHAs,raisingalarmoftheemergenceofCAPTCHA- webcrawling.CAPTCHAvalidatesahumanvisitwiththe
cloakedfeaturesinthemodernphishingcampaigns. interactionbetweentheclientandtheserver. Ontheclient
side,the website prompts a CAPTCHA challenge,suchas
pictureselectionandtextrecognition,tocollectthechallenge
∗Correspondingauthor response.Ontheserverside,thechallengeresponseisvali-
USENIX Association 33rd USENIX Security Symposium 505

problem[35,36,59]onawebpagescreenshot.Then,PhishDe-
Listing1:EmbededCAPTCHACodeinHTMLFile.
cloakerrecognizesthetypeofCAPTCHA(bytreatingitasa
<html>
metriclearningproblem)sothatitcanscheduleafollow-up
...
|              |          |     |     |     |     |     | solving plan. | This | three-stage | design | allows | us to flexibly |
| ------------ | -------- | --- | --- | --- | --- | --- | ------------- | ---- | ----------- | ------ | ------ | -------------- |
| <!-- CAPTCHA | library> |     |     |     |     |     |               |      |             |        |        |                |
<script src="https://js.hcaptcha.com/1/api.js" extend PhishDecloaker to solve new types of CAPTCHA
| async | defer></script> |     |     |     |     |     |              |     |             |      |                        |     |
| ----- | --------------- | --- | --- | --- | --- | --- | ------------ | --- | ----------- | ---- | ---------------------- | --- |
| ...   |                 |     |     |     |     |     | and maintain | its | performance | even | on out-of-distribution |     |
<!-- embedded CAPTCHA div-tag> CAPTCHAs. Our implementation of PhishDecloaker sup-
<div id="cloaking">
<form id="form" method="post" portsreCAPTCHAv2,hCaptcha,sliderCAPTCHA,andro-
<div class="h-captcha" data-sitekey="..." tationCAPTCHA,covering98.9%oftheCAPTCHAmarket
|     | data-callback="submitForm" |     |     | />  |     |     |     |     |     |     |     |     |
| --- | -------------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
share[2].
| <input | type="hidden" | value="hcaptcha" |     |     | name=" |     |            |           |             |     |     |                   |
| ------ | ------------- | ---------------- | --- | --- | ------ | --- | ---------- | --------- | ----------- | --- | --- | ----------------- |
|        | captchaType"  | />               |     |     |        |     |            |           |             |     |     |                   |
|        |               |                  |     |     |        |     | We conduct | extensive | experiments |     | to  | evaluate PhishDe- |
</form>
cloakerregardingitseffectiveness,efficiency,androbustness
</div>
...
againstpotentialadversaries.TheresultsshowthatPhishDe-
</html>
cloaker(1)recoversthephishingdetectionrateofmanystate-
of-the-artphishingdetectorsfrom0%toanaverageof74.25%
|     |     |     |     |     |     |     | on diverse | CAPTCHA-cloaked |     | phishing |     | websites and (2) |
| --- | --- | --- | --- | --- | --- | --- | ---------- | --------------- | --- | -------- | --- | ---------------- |
datedagainsttheground-truthanswer.Bythismeans,neither generalizes to unseen CAPTCHA (with average precision
theHTTP-requestmodificationnortheJavascriptforceexe-
andrecallof86%and69%),and(3)isrobustagainstadver-
cutiontechniquecanbypassthisvalidation.CAPTCHAcan sarial attacks such as FGSM,JSMA,PGD,DeepFool,and
effectivelyserveasacloakingtechniqueinthreeaspects: DPatch. Furthermore,our field study over 30 days on the
emergingreal-worldwebsiteswithdifferentdecloakingtech-
• FalseSenseofLegitimacy:CAPTCHAsarewidelyused niques show that PhishDecloakerallows us to detect 7.6%
onlegitimatewebsites,allowingaphishingwebsitewitha
morephishingwebsitescloakedbyCAPTCHAs(66outof
promptedCAPTCHAchallengetooftenmaintainitsplau-
869phishingwebsites).
sibilitywithoutarousingsuspicion.
Insummary,thisworkmakesthefollowingcontributions:
• LowDeploymentCost:Anywebsitecanconvenientlyinte-
• WedevelopPhishDecloaker,ahybriddeep-visionsystem
grateaCAPTCHAservicebycallingitsAPI(seeListing1).
todetect,recognize,andsolvediverseCAPTCHAs.This
Therefore,itisnotdifficultforphishingattackerstoauto-
systemsupportsmainstreamCAPTCHAsandisdesigned
maticallygeneratephishingkitsequippedwithCAPTCHA
tobeextensiblefornewtypesofCAPTCHAs.Tothebestof
cloaking.Additionally,therearemanyfreeCAPTCHAser-
ourknowledge,ourworkisthefirsttoaddressCAPTCHA-
vices(e.g.,reCAPTCHAv2)available,resultinginalmost
cloakingforphishingdetection.
zerocosttohardenphishingwebsiteswithaCAPTCHA.
• WedeliverCloaken,aCAPTCHA-basedhardeningframe-
• HardtoBypass:DuetoCAPTCHA’sclient-serverarchi-
work,whichallowsustoautomaticallycloakaphishingkit
| tecture, | it is non-trivial | for | modern | security | crawlers | to  |     |     |     |     |     |     |
| -------- | ----------------- | --- | ------ | -------- | -------- | --- | --- | --- | --- | --- | --- | --- |
automaticallybypassit. withCAPTCHAsanddeployitthroughrandomlygener-
atedURLs.Weimplementthiscloakingtechniqueontop
oftheDynaPDdataset1[37].
| Recent | studies have | shown | that | phishing | attackers | are |     |     |     |     |     |     |
| ------ | ------------ | ----- | ---- | -------- | --------- | --- | --- | --- | --- | --- | --- | --- |
adoptingCAPTCHAasanovelcloakingtechnique[14,37,
• WedeliverPhishDecloakerasatoolintegratedwithexisting
| 41,46,59,64]. | The | number | of CAPTCHA-cloaked |     |     | phish- |     |     |     |     |     |     |
| ------------- | --- | ------ | ------------------ | --- | --- | ------ | --- | --- | --- | --- | --- | --- |
SOTAphishingdetectorsPhishpedia[35]andPhishInten-
| ing websites | has increased |     | almost | tenfold     | from         | 55,447 on |                     |     |       |              |     |                    |
| ------------ | ------------- | --- | ------ | ----------- | ------------ | --------- | ------------------- | --- | ----- | ------------ | --- | ------------------ |
|              |               |     |        |             |              |           | tion [36],enhancing |     | their | capabilities |     | to detect zero-day |
| January2023  | to 524,344    | on  | June   | 2023. [10]. | Furthermore, |           |                     |     |       |              |     |                    |
phishingwebsites.
| ourempiricalstudy(see |                      | Section |          | 2) shows   | thatnone   | ofthe      |              |           |             |     |     |                   |
| --------------------- | -------------------- | ------- | -------- | ---------- | ---------- | ---------- | ------------ | --------- | ----------- | --- | --- | ----------------- |
| publicly              | available industrial |         | phishing | detection  |            | engines or |              |           |             |     |     |                   |
|                       |                      |         |          |            |            |            | • We conduct | extensive | experiments |     | to  | evaluate PhishDe- |
| academic              | state-of-the-art     | models  |          | can detect | a CAPTCHA- |            |              |           |             |     |     |                   |
cloaker.OurresultsshowthatPhishDecloakereffectively
cloakedphishingwebsite.
|     |     |     |     |     |     |     | decloaks | phishing | websites | found | in  | the wild. Further- |
| --- | --- | --- | --- | --- | --- | --- | -------- | -------- | -------- | ----- | --- | ------------------ |
Inthiswork,weproposePhishDecloakerasthefirststep
more,PhishDecloakerisrobustagainstout-of-distribution
toaddresstheCAPTCHA-basedcloakingproblem.PhishDe-
CAPTCHAsandadversarialattacks.
cloakerisdesignedtosimulatehumanbehaviorsinorderto
solvetheCAPTCHAinaninteractivemanner.Technically,
Giventhespacelimit,moredetailsofPhishDecloakerare
PhishDecloakeremploysfivetypesofdeepcomputervision
availableat[9].
modelsacrossthreestages:detection,recognition,andsolv-
ing.Specifically,PhishDecloakerbeginsbydetectingthepres-
1TheDynaPDdatasetprovidesmorethan6,000phishingkitsforsecurity
enceofaCAPTCHA,formulatingitasanobjectdetection
researcherstointeractwith.
| 506    33rd USENIX Security Symposium |     |     |     |     |     |     |     |     |     |     | USENIX Association |     |
| ------------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ------------------ | --- |

| 2 An | Empirical |     | Study | of  | Anti-Phishing |     | Enti- |     |     |     |     |     |     |     |
| ---- | --------- | --- | ----- | --- | ------------- | --- | ----- | --- | --- | --- | --- | --- | --- | --- |
designPhishDecloaker.Wewilldiscusstheethicalconcerns
| tiesagainstCAPTCHA-Cloaking |     |     |     |     |     |     |     | onthisexperimentininSection6. |     |     |     |     |     |     |
| --------------------------- | --- | --- | --- | --- | --- | --- | --- | ----------------------------- | --- | --- | --- | --- | --- | --- |
Inthissection,weconductanempiricalstudytoanswerthe
3 ThreatModel
question:whatistheperformanceofthestate-of-the-artanti-
| phishingsolutionsindetectingCAPTCHA-cloakedphishing?. |     |     |     |     |     |     |     |        |            |      |                 |     |           | D   |
| ----------------------------------------------------- | --- | --- | --- | --- | --- | --- | --- | ------ | ---------- | ---- | --------------- | --- | --------- | --- |
|                                                       |     |     |     |     |     |     |     | Assume | that there | is a | set of phishing |     | detectors | =   |
Toanswerthequestion,wedesignaphishinghardening
|     |     |     |     |     |     |     |     | {d ,d ,...,d | },whereeachdetectord |     |     | (i=1,2,...,n)needs |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------ | -------------------- | --- | --- | ------------------ | --- | --- |
|     |     |     |     |     |     |     |     | 1 2          | n                    |     |     | i                  |     |     |
framework, Cloaken, to automatically cloak phishing kits to access the content of a webpage w ∈ W for phishing
| with CAPTCHAs. |     | Technically, |     | Cloaken |     | functions | as a re- |           |      |            |          |          |     |            |
| -------------- | --- | ------------ | --- | ------- | --- | --------- | -------- | --------- | ---- | ---------- | -------- | -------- | --- | ---------- |
|                |     |              |     |         |     |           |          | analysis. | Each | detector d | i can be | modelled | as  | a function |
verseproxythatblocksvisitorswithaCAPTCHApagefrom d(.):W →{0,1}whereW isthesetofwebpages.Specifi-
i
a selection oftemplates (e.g.,hCaptcha,reCAPTCHA v2). cally,adetectord(.)mapsawebpagew∈W
|     |     |     |     |     |     |     |     |     |     | i   |     |     | toaboolean |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---------- | --- |
OncethevisitorsolvestheCAPTCHA,Cloakenverifiesthe
valuewherew=0or1indicatesthatwisbenignorphishing.
submittedchallengeandrevealsthephishingcontent. An attacker can equip their phishing website w with a
p
PhishingDetectionService.Weselect2popularURLblack- CAPTCHAinstancec∈C whereC
isthesetofCAPTCHA
lists:GoogleSafeBrowsing(GSB)andMicrosoftDefender instances under pre-defined CAPTCHA types (e.g., re-
SmartScreenforevaluation.GSBisusedbyChrome,Firefox, CAPTCHA,hCaptcha,andGeeTest).Equippedwithahuman-
| and Safari | web | browsers, | accounting |     | for | 81.36% | of desk- |     |     |     |     |     |     |     |
| ---------- | --- | --------- | ---------- | --- | --- | ------ | -------- | --- | --- | --- | --- | --- | --- | --- |
authenticationchallengec,theattackercanrenderanewweb-
topand90.17%mobileusersworldwide.Ontheotherhand, pagew′ ←c⊕w sothat∀d ∈D,d(w′)=0,where⊕isan
|     |     |     |     |     |     |     |     | p   |     | p   | i   | i p |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
SmartScreenprotectsEdgeandaccountsfor12.75%ofdesk-
|     |     |     |     |     |     |     |     | operationtorendertheCAPTCHAontopofthewebpagew |     |     |     |     |     | p . |
| --- | --- | --- | --- | --- | --- | --- | --- | --------------------------------------------- | --- | --- | --- | --- | --- | --- |
topusers.WealsoincludeVirusTotal(VT)[52],theworld’s ThepreparedCAPTCHAsetssharethefollowingfeatures:
largestthreatcorpuswith92integratedphishingdetectors.
URLConfiguration.Weprepare5cloakingtypesofphish- • Diverse Types of CAPTCHAs. The attacker can adopt
ingwebsites(t p ): nocloaking(baseline)and4CAPTCHA- diverse types ofCAPTCHAs,including commercialver-
cloakedtypes(i.e.,reCAPTCHAv2,hCAPTCHA,GeeTest sions(e.g.,reCAPTCHAandhCaptcha)andopen-source
|     |     |     |     |     |     |     |     | versions. | Additionally, |     | we assume | that | the attacker | can |
| --- | --- | --- | --- | --- | --- | --- | --- | --------- | ------------- | --- | --------- | ---- | ------------ | --- |
Slide,andRotation).Theyarechoosenbasedontheirmarket
share[54].Wecallapairofdetectionserviceandcloaking customize their own implementation of well-known
type,(d,t ),as a configuration. For each cloaking type t , CAPTCHAchallenges,forexample,withasimilarappear-
|     | p   |     |     |     |     |     | p   |     |     |     |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
we generate k random unique URLs andsubmititto d for ancetoreCAPTCHAandhCaptcha.
analysis.Inthisstudy,weletkbe100.Therefore,thereare
|     |     |     |     |     |     |     |     | • Code | Obfuscation. | The | CAPTCHA | can | have | its partial |
| --- | --- | --- | --- | --- | --- | --- | --- | ------ | ------------ | --- | ------- | --- | ---- | ----------- |
500URLssubmittedto3differentdetectionservice.
executionontheclientside,forexampleimplementedby
URLSubmission.ToreporteachofourphishingURLs,we
JavaScriptcode.Weassumethattheattackercanadoptcode
| submit them | to  | GSB | via its | online | submission |     | portal and |     |     |     |     |     |     |     |
| ----------- | --- | --- | ------- | ------ | ---------- | --- | ---------- | --- | --- | --- | --- | --- | --- | --- |
obfuscationtechniques[11,58]tomodifytheunderlying
| to VirusTotalvia |     | its API. | Since | SmartScreen |     | receives | data |     |     |     |     |     |     |     |
| ---------------- | --- | -------- | ----- | ----------- | --- | -------- | ---- | --- | --- | --- | --- | --- | --- | --- |
codeorstructureofCAPTCHAswhilepreservingthesame
fromotheranti-phishingentities,includingMicrosoft’sown
appearanceandfunctionalityinsideabrowser.
internalcybersecurityecosystem,wemass-submitemailswith
the phishing URLs to an Outlook account with Microsoft • AdversarialImages.Anattackermayintroducenoiseand
DefenderSafeLinkactivated.
|     |     |     |     |     |     |     |     | distortion | into | CAPTCHA | images | [30,50,56]. |     | This can |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------- | ---- | ------- | ------ | ----------- | --- | -------- |
URLMonitoring.WemonitoreverydayifanyoftheURLs make it difficult for deep learning models to extract the
correspondingtoaconfiguration(e.g.,d-t pair)arereported relevant features and classify the CAPTCHA accurately,
p
| asphishing.Ifitis,itmeansthataserviced |     |     |     |     |     | canpenetratea |     |     |     |     |     |     |     |     |
| -------------------------------------- | --- | --- | --- | --- | --- | ------------- | --- | --- | --- | --- | --- | --- | --- | --- |
asthemodifiedCAPTCHAmaynolongerconformtothe
cloakingtypet .WemonitorGSBthroughitsLookupAPI expectedpatternsorfeaturesusedforclassification.
p
| and VT | by requesting |     | a new | URL | scan | and reviewing | the |       |           |        |        |          |                |     |
| ------ | ------------- | --- | ----- | --- | ---- | ------------- | --- | ----- | --------- | ------ | ------ | -------- | -------------- | --- |
|        |               |     |       |     |      |               |     | Given | the above | threat | model, | we adopt | a vision-based |     |
resultinganalysisreport.WemonitorSmartScreenbyloading
theURLsontoanon-headlessEdgebrowserusingPlaywright solutiontodetectandclassifyCAPTCHAs.Inotherwords,
andcheckifSmartScreen’sblockpageshowsup. oursolution(1)doesnotrelyonfrontendcodeanalysisand
Results. Table 1 shows our results. All baseline sites are (2) must be robust against out-of-distribution CAPTCHAs
blacklistedwithin24hours,whereasallCAPTCHA-cloaked andadversarialattackssuchasnoiseanddistortion.
| sites remain                                         | undetected |         | for          | 7 days | and counting,which |           | is  |            |     |     |     |     |     |     |
| ---------------------------------------------------- | ---------- | ------- | ------------ | ------ | ------------------ | --------- | --- | ---------- | --- | --- | --- | --- | --- | --- |
| morethansufficientforasuccessfulphishingcampaign[47, |            |         |              |        |                    |           |     | 4 Approach |     |     |     |     |     |     |
| 49]2. Overall,                                       |            | none of | the selected |        | phishing           | detectors | can |            |     |     |     |     |     |     |
revealCAPTCHA-cloakedphishing,furthermotivatingusto Overview.Figure1providesanoverviewofPhishDecloaker.
|     |     |     |     |     |     |     |     | Givenasuspiciouswebpagew |     |     | p withcloakingpotential,in- |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------------------ | --- | --- | --------------------------- | --- | --- | --- |
2WereportedourfindingstoVT,GSB,andSmartScreen.GSB(Google)
|     |     |     |     |     |     |     |     | steadoffeedingw |     | intoaphishingdetector,PhishDecloaker |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --------------- | --- | ------------------------------------ | --- | --- | --- | --- |
andSmartScreen(Microsoft)haveacknowledgedourreportandareinvesti- p
triestoremoveits“cloak”bylookingatandinteractingwith
gatingthepotentialsolution.
| USENIX Association |     |     |     |     |     |     |     |     |     | 33rd USENIX Security Symposium    507 |     |     |     |     |
| ------------------ | --- | --- | --- | --- | --- | --- | --- | --- | --- | ------------------------------------- | --- | --- | --- | --- |

Table1:EmpiricalresultsonperformanceofSOTAindustrialphishingdetectorsinrevealingCAPTCHA-cloakedphishingsites.
Category PhishingDetectionService URLsBlacklisted/URLsSubmitted
|     |     |     |     | Baseline | reCAPTCHAv2 | hCaptcha GeeTestSlide |     | Rotation |
| --- | --- | --- | --- | -------- | ----------- | --------------------- | --- | -------- |
API-based VirusTotal(incl.92phishingdetectors) 100/100 0/100 0/100 0/100 0/100
Browser-based GoogleSafeBrowsing 100/100 0/100 0/100 0/100 0/100
Browser-based MicrosoftDefenderSmartScreen 100/100 0/100 0/100 0/100 0/100
CAPTCHA
|     |     |     | CAPTCHA   |     |     | CAPTCHA     |           |     |
| --- | --- | --- | --------- | --- | --- | ----------- | --------- | --- |
|     |     |     | Detection |     |     | Recognition | Templates |     |
CAPTCHA
| A Suspicious Webpage |     |     |     |     | CAPTCHA Region | Query |     |     |
| -------------------- | --- | --- | --- | --- | -------------- | ----- | --- | --- |
CAPTCHA
Solver
Repository
CAPTCHA Solver
Phishing Detector
|     |     |     | Phishing Content |     |     | PhishDecloaker |     |     |
| --- | --- | --- | ---------------- | --- | --- | -------------- | --- | --- |
Figure1:SystemDesignofPhishDecloaker.PhishDecloakerisdesignedtoremovethe“cloak”ofaCAPTCHA-cloakedphishing
webpage,bydetecting,recognizing,andsolvingtheCAPTCHAchallenges.
w .Technically,PhishDecloakeroperatesonthescreenshot
p
ofw tobypasspotentialcodeobfuscation,whichinvolves
| p   |     |     |     |     |     |     | Feature Pyramid  |     |
| --- | --- | --- | --- | --- | --- | --- | ---------------- | --- |
threesteps:
|     |     |     |     |     |     | Feature Pyramid  |     | F FPN features P N  f e a t u r es |
| --- | --- | --- | --- | --- | --- | ---------------- | --- | ---------------------------------- |
|     |     |     |     |     |     | Network Backbone |     | F P N  fe a t u r e s              |
Step1.CAPTCHADetection(Section4.1).Weidentifythe
CAPTCHAinstanceonthewebpagebyformulatingitasan
|                                                    |     |     |     |     | Webpage Screenshot |                    |     | Region Proposal  |
| -------------------------------------------------- | --- | --- | --- | --- | ------------------ | ------------------ | --- | ---------------- |
| objectdetectionproblemincomputervision.Wedenotethe |     |     |     |     |                    |                    |     | Network          |
| detectedCAPTCHAasc.                                |     |     |     |     |                    | Region of Interest |     |                  |
Align
| Step 2. CAPTCHA | Recognition | (Section | 4.2). | With our |     |     |     |     |
| --------------- | ----------- | -------- | ----- | -------- | --- | --- | --- | --- |
prepared database of CAPTCHA templates,we determine Region of Interest FFPPNN  ffeeaattuurreess
Head
| thetypeoftheCAPTCHAc,t |     | ,bymatchingtheCAPTCHA |     |     |     |     |     | Region  |
| ---------------------- | --- | --------------------- | --- | --- | --- | --- | --- | ------- |
c
instancecwithitsbestfitinthetemplatedatabasethrougha object localization loss Proposals
learnedOCR-aidedMetricLearningnetwork.Thesolution Detected CAPTCHA
| is designedin | a similarwayas | a facerecognition |     | problem |     |     |     |     |
| ------------- | -------------- | ----------------- | --- | ------- | --- | --- | --- | --- |
incomputervision.Bythismeans,PhishDecloakerprovides Figure2:ModelarchitectureofCAPTCHAdetectionmodel,
anextensibleCAPTCHArecognitionframeworktoflexibly consistingofmulti-stageprocesses
includingnewCAPTCHAtypes.
Step3.CAPTCHASolving(Section4.3).PhishDecloaker 4.1 CAPTCHADetection
| is further | equipped with an | arsenal | of CAPTCHA | solvers. |     |     |     |     |
| ---------- | ---------------- | ------- | ---------- | -------- | --- | --- | --- | --- |
S,
GiventheCAPTCHAtypet ,weformulateitasaqueryto Given a webpage screenshot, denoted as as input, the
c
findthemostappropriateCAPTCHAsolver.Thefoundsolver CAPTCHA detection model generates object proposals
C(S)={t|t=⟨x,y,w,h⟩}.AsshowedinFigure2,thesepro-
| interactswiththewebpagew |     | tosolvethechallenge. |     | This |     |     |     |     |
| ------------------------ | --- | -------------------- | --- | ---- | --- | --- | --- | --- |
p
interactioncanberepeatedmultipletimestoincreasethesuc- posals(inreddashedrectangle)consistofboundingboxes
thatcontainstheCAPTCHAregion.
cessrateofanti-phishingcrawlers.PhishDecloakerprovides
suchanextensibledesigntointegratenewCAPTCHAsolvers Figure 2 illustrates our model design. We employ an
intheCAPTCHAsolverrepository. Object Localization Network (OLN) [33],which is a two-
| 508    33rd USENIX Security Symposium |     |     |     |     |     |     | USENIX Association |     |
| ------------------------------------- | --- | --- | --- | --- | --- | --- | ------------------ | --- |

stagenetworkcomprisingaRegionProposalNetwork(RPN) xxtteexxttuuaall
| stage and        | a Region   |             | of Interest | (RoI)   | stage.            | Given a web-    |     |     |     |     |     |     |     |
| ---------------- | ---------- | ----------- | ----------- | ------- | ----------------- | --------------- | --- | --- | --- | --- | --- | --- | --- |
| page screenshot, |            | the         | backbone    | network | (Feature          | Pyramid         |     |     |     |     |     |     |     |
| Network)         | transforms |             | the webpage |         | into a            | feature pyramid |     |     |     |     |     |     |     |
| F ={f|f          | =k×k,f     | ∈R2}wherek= |             |         | W,W,W....Eachele- |                 |     |     |     |     |     |     |     |
|                  |            |             |             |         | 4 8               | 16              |     |     |     |     |     |     |     |
mentinF
isafeaturemapintheformofak×kmatrix,and
|     |     |     |     |     |     |     |     |     |     | xxvviissuuaall |     | xxccaappttcchhaa |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | -------------- | --- | ---------------- | --- |
W isthemaximumofwebpagewidthandwebpageheight.
|     |     |     |     |     |     |     | Testing CAPTCHA |     |     |     | Feature  |     | cosine_dist(x, x') |
| --- | --- | --- | --- | --- | --- | --- | --------------- | --- | --- | --- | -------- | --- | ------------------ |
Eachfeaturemapcapturesthespatialfeaturesofthewebpage shared weights
Extractor f(.)
screenshotindifferentgranularity.Then,thefeaturepyramid
xx''tteexxttuuaall
isfedintotheRegionProposalNetwork,generatinginitiallo-
cationproposalsfortheforegroundobject(i.e.,CAPTCHA).
TheseproposalsundergofurtherrefinementintheRegionof
Interest(RoI)networktoyieldthefinalboundingboxes.
Differentfromaconventionalobjectdetectionmodel[53]
whereobjectsarebothdetectedandclassified,wecustomize xx''vviissuuaall xx''ccaappttcchhaa
A CAPTCHA Template
| ourCAPTCHA |     | detectorto |     | have only | detection | functional- |     |     |     |     |     |     |     |
| ---------- | --- | ---------- | --- | --------- | --------- | ----------- | --- | --- | --- | --- | --- | --- | --- |
ity.Technically,insteadofatrainingobjectivecovering(1) CAPTCHA Template Repository
objectlocationonx,y,w,andhand(2)objectclassification,
...
| we train      | our CAPTCHA                            |     | detector | with | a sole | focus on ob- |     |     |     |     |     |     |     |
| ------------- | -------------------------------------- | --- | -------- | ---- | ------ | ------------ | --- | --- | --- | --- | --- | --- | --- |
| jectlocation. | Thecustomizationallowsourmodeltraining |     |          |      |        |              |     |     |     |     |     |     |     |
processtofocusonasingleoptimizationobjective.Thisis
usefulconsideringthattheCAPTCHAcontainerscanbevery Figure 3: OCR-aided Metric Learning Model. The
diverse,whichcaninclude(1)taskinstructionsforsolving CAPTCHArecognitionsystemcomprisesafeatureextractor
theCAPTCHA,(2)thechallengebodywithvisualelements, f(.)andarecognitionhead.TheextractormapsaCAPTCHA
and(3)userinteractionbuttonsforcontrollingandengaging imagetoalow-dimensionalembeddingx .Therecog-
captcha
nitionheadmatchesthetestingCAPTCHAwithCAPTCHA
withtheCAPTCHA.Theycantakevariousformsandstyles,
whichmayencompassdistortedtext,images,specificobject templatesusingcosinedistance.
clicks,orevenbehavioralcuessuchassliderdragging.
|     |     |     |     |     |     |     | • Inter-type | generalization: |     | As  | CAPTCHA |     | technology |
| --- | --- | --- | --- | --- | --- | --- | ------------ | --------------- | --- | --- | ------- | --- | ---------- |
4.2 CAPTCHARecognition
evolves,newtypesemerge.Themodelmustbeeasilyadapt-
abletonewtypesofCAPTCHAs.
| The CAPTCHA |     | recognition |     | model | is designed | to map a |     |     |     |     |     |     |     |
| ----------- | --- | ----------- | --- | ----- | ----------- | -------- | --- | --- | --- | --- | --- | --- | --- |
testCAPTCHAinstancectoitsbestfitinasetofprepared
|                   |     |     |                     |     |     |           | To incorporate |     | both textual | and | visual | features | into the |
| ----------------- | --- | --- | ------------------- | --- | --- | --------- | -------------- | --- | ------------ | --- | ------ | -------- | -------- |
| CAPTCHAtemplatesC |     |     | whereeachelementinC |     |     |           |                |     |              |     |        |          |          |
|                   |     |     | t                   |     |     | t isarep- |                |     |              |     |        |          |          |
representation,weintroduceadual-brancharchitecturefor
resentativeCAPTCHAinstanceofaCAPTCHAtype.Our
|     |     |     |     |     |     |     | ourfeatureextractor |     | f θ(.)(SeeFigure3). |     |     | Thearchitecture |     |
| --- | --- | --- | --- | --- | --- | --- | ------------------- | --- | ------------------- | --- | --- | --------------- | --- |
CAPTCHArecognitionmodelconsistsofafeatureextractor
consistsof:(1)atextencoder,pre-trainedonanOpticalChar-
mappinganobjectproposal(i.e.,aCAPTCHAinstance)toa
|                    |     |          |         |                          |      |              | acter Recognition |       | (OCR)                | task, and | (2) an | image | encoder, |
| ------------------ | --- | -------- | ------- | ------------------------ | ---- | ------------ | ----------------- | ----- | -------------------- | --------- | ------ | ----- | -------- |
| featurevector,i.e. |     | f θ(.):C |         | →Rn.Wedenotethetypefunc- |      |              |                   |       |                      |           |        |       |          |
|                    |     |          |         |                          |      |              | pre-trained       | on an | image classification |           | task.  | Both  | encoders |
| tiontype:C         | →T  |          |         |                          |      |              |                   |       |                      |           |        |       |          |
|                    |     | which    | returns | the                      | type | of a CAPTCHA |                   |       |                      |           |        |       |          |
instance,whereT isthesetofCAPTCHAtypesinC.Then, takes the CAPTCHA image as input,and produces the re-
|     |     |     |     |     |     | t   | spectiveembeddingsx |     |     | andx | .Thesetwobranches |     |     |
| --- | --- | --- | --- | --- | --- | --- | ------------------- | --- | --- | ---- | ----------------- | --- | --- |
wecanselectthebestfitc∗ofatestCAPTCHAinstancecby visual textual
capturedistinctyetcomplementaryinformation.TheOCR-
c∗=argmaxcos(f θ(c),f θ(c based encoder focuses on character-indicative features es-
|     |     |     |     |     | t   | ))  |     |     |     |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
ct∈C sential for understanding task instructions. In contrast,the
t
imageencoderidentifiessalientvisualpatterns,capturingthe
Givenathresholdth,wecandecidethetypeofcbytype(c∗)
|                |                   |     |     |     |                       |     | CAPTCHA’s | layout | and design. | A   | fully-connected |     | projec- |
| -------------- | ----------------- | --- | --- | --- | --------------------- | --- | --------- | ------ | ----------- | --- | --------------- | --- | ------- |
| ifcos(f θ(c),f | θ(c∗))>th.Tolearn |     |     | f   | θ,weaddressthefollow- |     |           |        |             |     |                 |     |         |
tionlayerisaddedtofusethetwomodalitieswithadditional
| ingchallenges: |     |     |     |     |     |     |                 |         | =σ(WT[x |        |            |       |     |
| -------------- | --- | --- | --- | --- | --- | --- | --------------- | ------- | ------- | ------ | ---------- | ----- | --- |
|                |     |     |     |     |     |     | non-linearity:x | captcha |         | visual | ⊕x textual | ]+b). |     |
Withthefeatureextractor,wedesigntherecognitionhead.
• Multi-modalrepresentationlearning:ACAPTCHAchal-
AstraightforwardapproachinvolvesaddingaSoftmaxacti-
lengecontainsmulti-modalinformation,includingthechal-
vationandusingconventionalCross-entropyLossformodel
lengedescriptioninbothplaintextandimages.
fitting.However,thisapproachtendstooverfittoobserved
• Intra-type diversity: Challenges within the same samples,especially when the training set is small,leading
CAPTCHAtypecandiffersignificantlyduetovariousser- toinaccuratepredictionsfornewvariantswithinknowncat-
vicevendorsorupdatestotheCAPTCHApool. egories. Additionally,this approach lacks the flexibility to
| USENIX Association |     |     |     |     |     |     |     |     | 33rd USENIX Security Symposium    509 |     |     |     |     |
| ------------------ | --- | --- | --- | --- | --- | --- | --- | --- | ------------------------------------- | --- | --- | --- | --- |

(a)reCAPTCHAv2 (b)hCaptcha(Variant1) (c)hCaptcha(Variant2) (d)GeeTestSlider (e)BaiduRotation
Figure4:ExamplesofCAPTCHAchallengesofdifferenttypes.
accommodatenewCAPTCHAtypesduringruntime,asthe Additionally,toaddressclassimbalance,assomeCAPTCHA
numberofclassesmustbepredefinedbeforeinference. typesaremorecommonthanothers,weassignclassweights
|                                                |     |     |     |     | totheloss,calculatedas |     | 1 ,wheren | iseachclass’sfre- |     |
| ---------------------------------------------- | --- | --- | --- | --- | ---------------------- | --- | --------- | ----------------- | --- |
| Inthiswork,weemployadeepmetriclearningsolution |     |     |     |     |                        |     |           | c                 |     |
log(nc)
toaddressthechallengesoutlinedearlier.Themodelaimsto quencyinthetrainingset.
learnanembeddingspacethataccuratelycapturessemantic
similaritiesbetweenimages.Itistrainedonpairsofsamples,
4.3 CAPTCHASolvers
denotedas“positivepair”iftheybelongtothesameclassand
“negativepairs”iftheycomefromdifferentclasses.Aloss
ThetypesofchallengespresentedbyCAPTCHAsarediverse,
functionensuresthatpositivepairsarecloserintheembed- asshowninFigure4.Eachtypemayrequireauniqueskill
dingspacethannegativepairs.SpecificallyforCAPTCHAs,
|     |     |     |     |     | set, such | as object recognition, | visual | question | answering, |
| --- | --- | --- | --- | --- | --------- | ---------------------- | ------ | -------- | ---------- |
ourgoalistoclusterthoseofthesametypetogether.During patternmatching,ororientationidentification.Toaddressthe
inference,weinputthetestCAPTCHAalongwithasetof
|     |     |     |     |     | problem,we | develop an | arsenal of | CAPTCHA | solvers for |
| --- | --- | --- | --- | --- | ---------- | ---------- | ---------- | ------- | ----------- |
CAPTCHAtemplatesfromdifferentclassesofCAPTCHAs.
eachsupportedCAPTCHAtype.ForsomeCAPTCHAtypes
Wethenrankthedistancestoidentifytheclosestclassasthe (e.g., reCAPTCHA), we adopt the state-of-the-art solvers;
finalprediction.
|     |     |     |     |     | while for | other important | CAPTCHA | types | (e.g.,rotation) |
| --- | --- | --- | --- | --- | --------- | --------------- | ------- | ----- | --------------- |
Inthismanner,weeffectivelytackletheaforementioned wherenosolverisavailable,wedevelopourownAI-powered
| challenges: | For the | intra-type | diversity issue,the | pairwise |     |     |     |     |     |
| ----------- | ------- | ---------- | ------------------- | -------- | --- | --- | --- | --- | --- |
solvingsolutions.Wedonotclaimcontributioninsolvinga
trainingparadigmenablesthemodeltobemoresensitivein
particularCAPTCHAtypeasoursystemisextensibletonew
distinguishing“variationswithintheclass”from“variations CAPTCHA solvers. We support four types of CAPTCHA
| relative | to other classes”. | Given | an unseen | sample from a |     |     |     |     |     |
| -------- | ------------------ | ----- | --------- | ------------- | --- | --- | --- | --- | --- |
solversasfollows.
knownclass,themodelismoreinclinedtotreatitasavariant reCAPTCHAv2Solver.GooglereCAPTCHAv2isthemost
| of a | known class rather | than | a novel class | of CAPTCHA. |     |     |     |     |     |
| ---- | ------------------ | ---- | ------------- | ----------- | --- | --- | --- | --- | --- |
prevalenttypeofCAPTCHAamongtheTop1MillionSites
Fortheinter-typegeneralizationissue,accommodatingnew
[2].WesolvethereCAPTCHAv2challengesbyemploying
CAPTCHAtypesisstraightforward:newCAPTCHAscan anobjectdetectionmodelsimilartothatofHossenetal.[31].
beeasilyaddedtothetemplatedatabase,servingasreference
hCaptchaSolver.hCaptchaisanimage-basedCAPTCHA
pointsforfuturequeries. servicesimilartoreCAPTCHA.However,hCaptchapresents
Technically,duringtraining,wefreezethetextualbranch
userswithmorerealisticandevenAI-generatedimages.We
andfine-tuneallotherremainingmodulesusingSub-center
addresstwocommonvariantsofhCaptcha:
ArcFaceloss[21]:
• Variant1(BinarySelection).Object-IdentifyinghCaptcha
|     | 1 N            |           | es·(cos(θyi +m)−1) |             |                                                 |     |     |     |     |
| --- | -------------- | --------- | ------------------ | ----------- | ----------------------------------------------- | --- | --- | --- | --- |
| L   | ∑              |           |                    |             | issimilartoreCAPTCHAv2(SeeFigure4b).Butitoffers |     |     |     |     |
|     | =− log         |           |                    |             |                                                 |     |     |     |     |
|     | N  es·(cos(θyi | +m)−1)+∑C |                    | es·cos(θ j) |                                                 |     |     |     |     |
i=1 j=1,j̸=yi ! morecomplexchallengedescriptions,enrichedwithextra
|     |     |     |     | (1) | contextonstylesorrelationstootherobjects(e.g.,some- |     |     |     |     |
| --- | --- | --- | --- | --- | --------------------------------------------------- | --- | --- | --- | --- |
oneplayingfootball).Hence,weapproachtheproblemas
InEquation4.2,welearnasetofparametersrepresenting an open-set visual question answering (VQA) model. In
theembeddingcentersforeachclass.Theembeddingfeature a typicalVQA task,a modelis presentedwithan image
i andthe centerforits groundtruthclass y are considered alongside a text-based question about the visual content.
i
a “positive pair”,while i andthe centerforanotherclass j Themodelthengeneratesananswer,whichcanbeasimple
forma“negativepair”.θ istheanglebetweenthepositive “yes”or“no”oramorecomplextextualanswer.Givena
yi
pair,andθ
j istheanglebetweenthenegativepair.Thisloss CAPTCHAchallengespecifyingtheobjectdescriptionas
functionencouragesCAPTCHAembeddingstobecloseto x,wetransformitintoaquestion“Isthisa/anx?”foreach
theirrespectiveclasscentersanddistantfromirrelevantones. candidate grid,then output an answer of either “yes” or
| 510    33rd USENIX Security Symposium |     |     |     |     |     |     |     | USENIX Association |     |
| ------------------------------------- | --- | --- | --- | --- | --- | --- | --- | ------------------ | --- |

“no”.Asaresult,thesolverselectsallthegridswith“yes”. atelyperturbinputs andinduce incorrectpredictions. Both
our CAPTCHA detector and recognition models could be
• Variant2(AreaSelection).Thisisanemergingvariant
susceptibletothistypeofattack.
(See Figure 4c) that asks the user to point out a specific
Tocountertheformer,weuseadversarialtrainingforall
location within an image. To solve these more advanced
our deep-learning models. This approach aims to enhance
challenges,weemploytheoff-the-shelftoolhCaptchaChal-
modelrobustnessbyintroducingadversarialexamplesduring
lenger[6].
training. These examples are created by applying random
augmentationstotheoriginalinputdata,potentiallyleading
ForreCAPTCHAv2andhCaptcha,ifthedeep-learning-
themodeltomakeincorrectpredictions.Inourwork,wecon-
basedsolverfails,wedeferthechallengetoavisuallanguage
siderthefollowingtypesofaugmentationssuchasRandom
model(VLM)agentandaskforacontrolledresponse(e.g.,
Mask,GaussianNoise,andGaussianBlur.Wemixadversar-
clickonsquares1,5,7orcoordinates(x,y)).
ialandcleansamplesataratioof6:4.Tocounterthelatter,we
SliderCAPTCHASolver.Slider-basedCAPTCHAsrequire
implementPhishDecloakerwiththegradientmaskingtech-
users to slide a puzzle piece into an emptyspoton a back-
niqueasproposedin[35].Specifically,wereplacetheReLU
ground image [54,67]. In addition to the accuracy of the
activation function with a step ReLU function defined as
placement,theCAPTCHAsalsoanalyzetheslidingtrajec-
f(x)=max(0,α·⌈x⌉),whereαisthediscretizationparame-
torytodetectautomatedbehavior.Forexample,humanusers α
ter.Thisrenderstheactivationsnon-differentiable,effectively
areunlikelytomaintainaconstantspeedthroughouttheslide.
zeroingoutthegradients.
Wedesignourslidersolverwithtraditionalcomputervision
techniques.First,weidentifythethebackgroundimageand
puzzle piece elements from the webpage source code. We 5 Experiments
thenapplypre-processingtechniqueslikeGaussianblurring
for denoising and grayscale conversion followed by Sobel WeevaluatePhishDecloakerwiththefollowingquestions:
edgedetectionforedgesharpening.Next,weusethepuzzle
pieceasatemplatefortemplatematching,locatingasimilar • RQ1(Effectiveness):WhatistheperformanceofPhishDe-
regionwithinthebackgroundimage.Finally,thesolveruses cloakerinrevealingCAPTCHA-cloakedphishingkits?
easingfunctionstosimulateahuman-likedraggingtrajectory.
• RQ2(CAPTCHADetection&Recognition):Whatare
RotationCAPTCHASolver.RotationCAPTCHAsrequire
theperformancesofPhishDecloaker’sCAPTCHAdetec-
userstoadjustrandomlyrotatedimagestotheiruprightori-
tionandrecognitioncomponents?
entation[29].Thesechallengeimagesusuallyfeaturenatural
andman-madelandscapes.
• RQ3(CAPTCHASolving):Whatistheperformanceof
In this work, we treat the image rotation problem as a
PhishDecloaker’sCAPTCHAsolvers?
regressiontasktopredictthecurrentdegreeofrotationfor
thechallengeimage.Oncetherotationangleisdetermined, • RQ4 (Ablation Study): What are the alternatives for
the solver can interact with the CAPTCHA to correct the PhishDecloaker’sdesign,andhowdotheyperform?
orientation. Toconstructourmodel,weadoptEfficientNet
• RQ5 (Adversarial Attacks): Is PhishDecloaker robust
[60],pretrainedonImageNet.Wefurtherfine-tunethemodel
againstadversarialattacksonitsdeeplearningmodels?
usingrandomlyrotatedsamplesfromtheLandscapeDataset
[7],acommunity-contributedcollectionof7,268imagesthat
• RQ6 (Field Study): Can PhishDecloaker help discover
depictnaturalandman-madelandscapes.Cosinedistanceto
morezero-dayphishingwebsitesinthewild?
theground-truthangleservesasthetrainingloss.
Toaddresseachquestion,wefirstintroducetheexperimen-
4.4 AdversarialCountermeasure talsettings(e.g.,modeltraining),followedbytheobjective
metricsusedtoevaluateeachresearchquestion.Moreexperi-
SincePhishDecloakerorchestratesseveraldeep-learningmod-
mentdetailsareavailableat[9].
els,it may be vulnerable to adversarial attacks at runtime.
Weidentifytwoplausibleattackscenarios,i.e.,system-level
5.1 RQ1:ExperimentalEffectiveness
attackandmodel-dependantattack.Asystem-levelattackin-
troducesblurring,noise,orotherobfuscationstoCAPTCHA
5.1.1 ExperimentSetup
challenges,hinderingthemodels’abilitytoidentifycontent.
ThiscommonlyoccurswhenCAPTCHAsdetectsuspicious PhishingDetectors.WeselectPhishpedia[35]andPhishIn-
activitiesfromanIPaddressandpresentmorechallenging tention[36]fortheirstate-of-the-artperformanceondetecting
images. This attack is model-agnostic and does not target zero-dayphishingwebsites.Followingtheinstructionsofboth
any specific model. A model-dependentattackexploits ex- detectors,weuseareferencelistof277phishingtargets(i.e.,
istinggradient-basedmethods[28,38,40,44,51]todeliber- Facebook,BankofAmerica,etc).
USENIX Association 33rd USENIX Security Symposium 511

Table2:PhishingdetectionrateonDynaPD.Thepercentagesarecalculatedaschangesrelativetothebaseline(NoCloaking).
Theaverageruntimeoverheadiscomputedforeachmodule(CAPTCHAdetection,CAPTCHArecognitionandCAPTCHA
solver)andconcatenatedby“+”.
Group NoCloaking AfterCloaking
reCAPTCHAv2 hCaptcha GeeTestSlide Rotation
Phishpedia 0.73 0.00(↓100%) 0.00(↓100%) 0.00(↓100%) 0.00(↓100%)
PhishIntention 0.53 0.00(↓100%) 0.00(↓100%) 0.00(↓100%) 0.00(↓100%)
Phishpedia+PhishDecloaker 0.73 0.57(↓22.2%) 0.29(↓59.8%) 0.69(↓5.1%) 0.61(↓16.1%)
PhishIntention+PhishDecloaker 0.53 0.41(↓22.3%) 0.21(↓59.8%) 0.50(↓5.1%) 0.45(↓16.0%)
RuntimeOverhead(s) - 0.13+0.05+44.17 0.12+0.05+8.81 0.13+0.06+5.12 0.13+0.08+5.01
Phishing Dataset. We apply our hardening framework, and84%onrotationCAPTCHA.Overall,PhishDecloaker’s
Cloaken,totheDynaPDdataset[37].TheDynaPDdataset contributioncomeswithacceptableruntimecost.Notethat
comprises approximately 6k deployable and interactable themainoverheadliesinCAPTCHAsolving.Specifically,
phishing kits,providing a replicable environment to study solvingareCAPTCHAinstancetakesanaverageof44.17s.
CAPTCHAcloakingonphishingkits.Duetolimitationsin ThisisbecausereCAPTCHAcaniterativelyreplaceselected
thereferencelistsofphishingdetectors[35,36],wefilterout imageswithnewonesandprompttheusertoclick“verify”
phishingkitstargetingsitesnotincludedinthereferencelist. oncetherearenotargetobjects(e.g.,motorcycle)left.This
Thisfilteringresultsinadatasetof2,960phishingkitsforour iterativeinteractionincursasignificantruntimeoverhead.
study.Cloakencloakseachphishingkitwith4CAPTCHAin-
stancesunderthecategoryofreCAPTCHA,hCaptcha,slider,
5.1.3 QualitativeAnalysis
androtation,noneoftheseCAPTCHAinstancesareusedfor
trainingthemodels. Next,wefurtherinvestigateandcategorizetheCAPTCHAs
Measurement.WeevaluatewhetherPhishDecloakercanhelp whichPhishDecloakercannotaddress.Thereasonliesinas
the phishing detectors to recoverits access to the phishing follows.
content.Specifically,weevaluatedetectionrateofaphishing Incapabilityofthe off-the-shelfsolvers.Weobservethat
detector on DynaPD,r ,its detection rate on the different theoff-the-shelfsolvers(e.g.,hCaptchasolver)canhavetheir
1
typesofcloakedphishingwebsitevariants,r ,anditsdetec- limitations. Figure 5a shows an example where PhishDe-
2
tionrateafterequippedwithPhishDecloaker,r .Notethat, cloakersuccessfullydetectandrecognizethehCaptchatype
3
PhishDecloakerisnotdesignedforimprovingtheprecision butthehCaptchasolverfailstosolvethechallengeofclick
ofexistingphishingdetectors,thusweonlyevaluatetherecall each image containing a diamond bracelet. Our investiga-
measurementinthestudy. tionshowsthatthemodelmistakenlyrecognizeearringsas
Environment. We use Chrome version 114 and ensure a bracelet,whichareofsimilarvisualsemantics.Apotential
cleanbrowserstateforeachsession,i.e.,withnocachesor remedyistoretrainthemodeltofurtherdistinguishtheem-
cookiespreservedbetweenconsecutiverequests.Toconceal beddingspaceofthemodel.Wewilldiscussonhowtoim-
any indications of a headless browser and automation,we provethecapabilityinSection6.
modifytherequestsandwebbrowsercharacteristics,suchas HumanverificationbeyondCAPTCHA.Wediscoverthat
customizingUser-AgentheadersandadjustingtotheNaviga- some CAPTCHAs such as reCAPTCHA v2 verifies a hu-
torobjectproperties,aswellasmodifyingtoWebGLvendor. manusingmorethananinteractivechallenge.Itmayinclude
AllsolversoperatefromasingleIPaddressandmachinewith mousebehavioranalysisandbrowserfingerprinting,which
20CPUcores,125Gmemory,andA100GPU. will block our visits despite solving the challenge. We ac-
knowledgethesignificanceofthesemethods.Sincethereare
relevantworks[31,64]onthisdirection(seeAppendixA.3),
5.1.2 Results
welimitourfocusoncounteringCAPTCHAcloaking,which
Table 2 shows the overall experiment results. On the 2.9k complements these works. A hybrid security crawler with
phishingwebsiteswithoutanycloaking,PhishpediaandPhish- variousdecloakingtechniquesisvitalforeffectiveness.
Intentionachievedetectionratesof72.6%and53.0%respec- Therestrictionoftrainingdataset.Finally,wefindthatour
tively. Any CAPTCHA-cloaked variants can compromise customizedsolversmightbelimitedbyourtrainingdataset.In
theireffectiveness,droppingthedetectionrateto0%. Incon- general,ourregressionmodel(seeSection4.3)learnsupright
trast,PhishDecloakercanrecovertheirdetectionratesback orientationfordifferentpictures.Ifapicturetoberotatedis
to a percentage of their original performance: 78% on re- deviated from the training dataset,the model might fail to
CAPTCHA,40%on hCaptcha,95%on sliderCAPTCHA, predictitsrotationdegreeeffectively.Forexample,Figure5b
512 33rd USENIX Security Symposium USENIX Association

Table3:PerformanceforCAPTCHARecognitiononOpen-
setCAPTCHAs.
|     |     |     |     | Class         |     | Precision Recall | F1-Score |
| --- | --- | --- | --- | ------------- | --- | ---------------- | -------- |
|     |     |     |     | arkose_select |     | 0.93 0.91        | 0.92     |
capycaptcha_drag
|     |     |     |     |     |     | 0.88 0.58 | 0.70 |
| --- | --- | --- | --- | --- | --- | --------- | ---- |
(b)asolvedrotation
|     |     |     |     | dicecaptcha_qa |     | 0.97 0.68 | 0.80 |
| --- | --- | --- | --- | -------------- | --- | --------- | ---- |
CAPTCHAinstance.
|     |     |     |     | funcaptcha_select_1 |     | 0.99 0.87 | 0.93 |
| --- | --- | --- | --- | ------------------- | --- | --------- | ---- |
|     |     |     |     | funcaptcha_select_2 |     | 0.98 0.48 | 0.64 |
|     |     |     |     | funcaptcha_select_3 |     | 0.88 0.52 | 0.65 |
funcaptcha_select_4
|                         |     |     |     |                     |     | 0.62 0.91 | 0.74 |
| ----------------------- | --- | --- | --- | ------------------- | --- | --------- | ---- |
| (a)aninstanceofhCaptcha |     |     |     | funcaptcha_select_5 |     | 1.00 0.53 | 0.69 |
| (V1)whichcannotbe       |     |     |     | funcaptcha_select_6 |     | 0.88 0.72 | 0.79 |
|                         |     |     |     | keycaptcha_drag     |     | 0.93 0.75 | 0.83 |
solvedbyPhishDecloaker.
|     |     |     |     | mtcaptcha_text |     | 0.46 0.63 | 0.53 |
| --- | --- | --- | --- | -------------- | --- | --------- | ---- |
(c)anunsolvedrotation
CAPTCHAinstance.
|     |     |     |     | Average |     | 0.86 0.69 | 0.75 |
| --- | --- | --- | --- | ------- | --- | --------- | ---- |
Figure5:ExamplecasesinsolvingCAPTCHAs
of0.02andmomentumof0.9.
|     |     |     |     | Measurement. | We use | the mean average precision | (mAP) |
| --- | --- | --- | --- | ------------ | ------ | -------------------------- | ----- |
and Figure 5c manifest different genres of images, which andmeanaveragerecall(mAR)toevaluatetheperformance,
| leads to performance | disparity. | Although we | do not claim |     |     |     |     |
| -------------------- | ---------- | ----------- | ------------ | --- | --- | --- | --- |
whicharethestandardmetricsforevaluatingthecompleteness
contributiononsolvinganyparticularCAPTCHAinstance,
|     |     |     |     | and redundancy | of the | reported objects in | object detection |
| --- | --- | --- | --- | -------------- | ------ | ------------------- | ---------------- |
wewilldiscusspotentiallybettersolutionsinSection6.
|     |     |     |     | tasks[33,53]. | ThemAPandmARarecomputedoverIoU |     |     |
| --- | --- | --- | --- | ------------- | ------------------------------ | --- | --- |
thresholdsrangingfrom0.5to0.95.
Results.TheOLNdetectorachievesameanaverageprecision
5.2 RQ2:CAPTCHADetection&Recognition
andrecallof0.92and0.97respectively.
5.2.1 CAPTCHADetection
5.2.2 CAPTCHARecognition
DatasetCollection.Tocollectthetrainingdatasetofdetect-
ing CAPTCHA, we adopt XDriver [23] to crawl the web- Dataset Collection. We have collected a total of 6,612
siteslistedintheAlexatop1-millionwebsites. Itautomat- CAPTCHAsamplesspanning38classes,sourcedfromdemo
icallylocatestheformsonthepage,fillsinallforminputs
websites(e.g.,NetEase,Tencent,ArkoseLabs),officialAPI
with simulated data,and submits the form in order to trig- keysprovidedbyvendors(e.g.,Google,hCaptcha,GeeTest),
gerCAPTCHAs.Itthencapturesscreenshotsofthesepages, and open-source community datasets. During training,we
whichwemanuallyannotatetoidentifytheboundingboxes employeda9:1train-testsplit,allocating5,950samplesfor
foranyCAPTCHAspresent.Duetoethicalandsecuritycon- trainingand662samplesfortesting.Thisdatasetservesas
siderations,westrictlylimitourcrawlingtoasingleinstance
thetemplatedatabaseatdeploymenttime.
perwebsite,withamaximumdepthof2.Overtwoweeks,we Training Settings. As for the feature extractor,the visual
collectedandlabeled1,764webpagescreenshotscontaining branchemploysaResNet-50modelpre-trainedonImageNet
CAPTCHAs. We employ data augmentation to enrich our withitsclassificationheadremoved.Thisbranchtakesare-
datasetwithadditionalsyntheticsamples,bringingthetotal sizedCAPTCHAregionofdimensions224×224asinputand
| to 10,680 webpage | screenshots. | Examples ofthe | synthetic |     |     |     |     |
| ----------------- | ------------ | -------------- | --------- | --- | --- | --- | --- |
outputsthevisualembedding.Thetextualbranchisadapted
samplesgeneratedareshowninAppendixA.1.Weperforma from EasyOCR [5]. It utilizes a Character-Region Aware-
9:1train-testsplit,where9,612samplesarefortrainingand nessforText(CRAFT)model[18]pre-trainedonSynthText
1,068samplesfortesting. forboundingboxdetectionandaConvolutionalLongShort
TrainingSettings.Weusethetrainingframeworkprovided Term Memory (CLSTM) [55] model pre-trained with the
by the authors of [33], which is built upon OpenMMLab STRframework[17]fortextualembeddingprojection.Dur-
DetectionToolbox[8].TheOLNobjectdetectionmodeluses ing training,we freeze the textual branch and fine-tune all
Faster-RCNNpre-trainedonImageNetasitsbackbone,with otherbranchesusingSub-centerArcFace[21]asdescribedin
theRPNandRoIheadmodifiedasdescribedinSection4.1. Section4.2.Wetrainthemodelfor100epochs,withabatch
Wetrainthemodelfor8epochs,withabatchsizeof2per sizeof2perGPU,usingStochasticGradientDescentwitha
GPU,usingStochasticGradientDescentwithalearningrate learningrateof0.02andamomentumof0.9.
| USENIX Association |     |     |     |     | 33rd USENIX Security Symposium    513 |     |     |
| ------------------ | --- | --- | --- | --- | ------------------------------------- | --- | --- |

Measurement.Weevaluatethetrainingandtestingaccuracy Table4:CAPTCHAMetricsandDetectionRates
ofourmodelinrecognizingaparticularCAPTCHAtype.In
addition,we evaluate the generalizability of our model by CAPTCHA Category Solvingrate
whetherourmodelcanrecognizethenewCAPTCHAtypes
|                    |     |     |        |          |      |           |      |     |             |     | Easy     | 75.5% |     |     |
| ------------------ | --- | --- | ------ | -------- | ---- | --------- | ---- | --- | ----------- | --- | -------- | ----- | --- | --- |
| without retraining |     | the | model. | We argue | that | utilizing | deep |     |             |     |          |       |     |     |
|                    |     |     |        |          |      |           |      |     | reCAPTCHAv2 |     | Moderate | 74.0% |     |     |
Siamese learning for CAPTCHA recognition can improve Difficult 35.0%
performanceinopen-setscenarios.Tovalidatethis,wefirst
|     |     |     |     |     |     |     |     |     |     |     | Easy | 85.0% |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---- | ----- | --- | --- |
collectanadditional11CAPTCHAtypesnotpresentinthe
|     |     |     |     |     |     |     |     |     | hCaptcha |     | Moderate | 92.0% |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | -------- | --- | -------- | ----- | --- | --- |
trainingdatasetsofourCAPTCHAdetectionandrecognition
|     |     |     |     |     |     |     |     |     |     |     | Difficult | 71.0% |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --------- | ----- | --- | --- |
models.ThesenewlyacquiredCAPTCHAsaresuperimposed
|     |     |     |     |     |     |     |     |     |     |     | GeeTest | 95.0% |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ------- | ----- | --- | --- |
ontorandomwebpagescreenshotstocreateopen-settestsam-
|     |     |     |     |     |     |     |     |     | Slider |     | Tencent | 89.0% |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | ------ | --- | ------- | ----- | --- | --- |
ples.WethenupdatePhishDecloaker’stemplatedatabasewith
|     |     |     |     |     |     |     |     |     |     |     | NetEase | 100.0% |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ------- | ------ | --- | --- |
referencesfromthesenewCAPTCHAclassesandassessthe
system’sabilitytocorrectlyclassifythesenovelCAPTCHAs. Rotation Baidu 74.5%
Results.Table3presentsourresultsontheopen-setdataset.
Oursystemyieldssatisfactoryperformanceincorrectlyiden- 0.20 1.0
| tifyingunseenCAPTCHAtypes,withanaverageprecision |     |     |     |     |     |     |     | 0.18 |     |     |     |     |     | 0.9 |
| ------------------------------------------------ | --- | --- | --- | --- | --- | --- | --- | ---- | --- | --- | --- | --- | --- | --- |
| of86.0%andanaveragerecallof69%.                  |     |     |     |     |     |     |     | 0.16 |     |     |     |     |     | 0.8 |
|                                                  |     |     |     |     |     |     |     | 0.14 |     |     |     |     |     | 0.7 |
noitroporP
|     |     |     |     |     |     |     |     | 0.12 |     |     |     |     |     | 0.6 |
| --- | --- | --- | --- | --- | --- | --- | --- | ---- | --- | --- | --- | --- | --- | --- |
5.3 RQ3:CAPTCHASolving
|         |            |     |     |         |     |              |     | 0.10 |     |     |     |     |     | 0.5 |
| ------- | ---------- | --- | --- | ------- | --- | ------------ | --- | ---- | --- | --- | --- | --- | --- | --- |
|         |            |     |     |         |     |              |     | 0.08 |     |     |     |     |     | 0.4 |
| CAPTCHA | Benchmark. |     | Our | CAPTCHA |     | benchmarking |     |      |     |     |     |     |     |     |
|         |            |     |     |         |     |              |     | 0.06 |     |     |     |     |     | 0.3 |
datasetincludesreCAPTCHAv2,hCaptcha(V1&2),slider
|          |     |          |          |     |     |           |     | 0.04 |     |     |     |     |     | 0.2 |
| -------- | --- | -------- | -------- | --- | --- | --------- | --- | ---- | --- | --- | --- | --- | --- | --- |
| CAPTCHA, | and | rotation | CAPTCHA. |     | For | reCAPTCHA |     | 0.02 |     |     |     |     |     | 0.1 |
v2, hCaptcha (V1&2), we test different difficulty levels: 0.00 0.0
|     |     |     |     |     |     |     |     | 0   | 20 40 | 60  | 80 100 | 120 140 | 160 |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | ----- | --- | ------ | ------- | --- | --- |
easy, moderate, and difficult, which is categorized by the Angle Estimation Error (degress)
CAPTCHA vendor. As for slider CAPTCHA, we include Figure6:Histogramofangularerrorsandtheircumulative
threedifferentversionsfromGeeTest,Tencent,andNetEase.
distribution(redline)fortheregressionmodelonthetestset
Lastly,weselectBaidu’srotationCAPTCHAforevaluation. inLandscapeDataset.
| In general, | we generate |     | 200 CAPTCHA |     | variants |     | for each |     |     |     |     |     |     |     |
| ----------- | ----------- | --- | ----------- | --- | -------- | --- | -------- | --- | --- | --- | --- | --- | --- | --- |
version.Intotal,weevaluated10CAPTCHAversionsinthe
| study. |     |     |     |     |     |     |     | Results. | For reCAPTCHA |     | and | hCaptcha,we | observe | that |
| ------ | --- | --- | --- | --- | --- | --- | --- | -------- | ------------- | --- | --- | ----------- | ------- | ---- |
Measurement. For reCAPTCHA v2, hCaptcha, all slider oursolversperformwelloneasyandmoderatechallenges.
CAPTCHA variations,andBaidu rotation CAPTCHA,we Performance degrades for difficult cases,with reasons dis-
determinetheirsuccessratebycalculatingtheproportionof cussedinSection5.1.Usingthetemplatematchingalgorithm,
successfullyresolvedCAPTCHAsessionscomparedtothe
thesliderCAPTCHAsolverperformsuniformlywellacross
totalnumberofrequestedCAPTCHAsessions.Toelaborate, threedifferentserviceproviders,becausethatthealgorithmis
during eachCAPTCHA session,the solvermay encounter robustagainstnoiseanddistortioninthebackgroundimages.
oneormoreconsecutiveCAPTCHAchallenges.Inorderfor
Therotationsolverachievesameanangularerrorof15.62.
aCAPTCHAsessiontobeconsideredassuccessfullysolved, Figure6displaysahistogramoftheangularerrorsalongwith
thesolvermustsuccessfullycompleteallpresentedchallenges
itscumulativedistribution.Weobservethatmorethan90%
andreceiveaconfirmationofsuccess(e.g.,agreencheckmark ofthe testsamples exhibitan angularerrorofless than 35
inreCAPTCHAv2). degrees,and the histogram follows a long-tail distribution.
| Additionally,to |     | furtheranalyze |     | ourrotation |     | CAPTCHA |     |     |     |     |     |     |     |     |
| --------------- | --- | -------------- | --- | ----------- | --- | ------- | --- | --- | --- | --- | --- | --- | --- | --- |
Thisindicatesthatthesolverwasabletoreorientthemajority
solver,weevaluateitonthetestsetintheLandscapeDataset. ofimages.WethenconductedatestusingBaidu’srotation
| The test | samples | are randomly |     | rotated | between |     | 0 to 360 |     |     |     |     |     |     |     |
| -------- | ------- | ------------ | --- | ------- | ------- | --- | -------- | --- | --- | --- | --- | --- | --- | --- |
CAPTCHAservice,limitingthenumberofattemptsto200.
degrees. We use mean angular error (MAE) as the evalua- Thesolverachievesasolvingrateof74.5%.
| tionmetric.GivenabatchofN |     |     |     | predictedanglesθ |     |     | andtheir |     |     |     |     |     |     |     |
| ------------------------- | --- | --- | --- | ---------------- | --- | --- | -------- | --- | --- | --- | --- | --- | --- | --- |
i
| groundtruth(rotated)anglesθˆ |     |     |     | ,MAEisdefinedasfollows: |     |     |     |     |     |     |     |     |     |     |
| ---------------------------- | --- | --- | --- | ----------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
i
5.4 RQ4:AblationStudy
1 N
MAE= ∑ 180− |θ −θˆ |−180 (2) We explore alternatives for PhishDecloaker’s architecture
|     |     |     |     | i   | i   |     |     |     |     |     |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
N
|     |     | i=1 |          |          |     |                  |     | design | on recognizing |     | a CAPTCHA | type | from a webpage |     |
| --- | --- | --- | -------- | -------- | --- | ---------------- | --- | ------ | -------------- | --- | --------- | ---- | -------------- | --- |
|     |     |     | (cid:16) | (cid:12) |     | (cid:12)(cid:17) |     |        |                |     |           |      |                |     |
Thismetricquantifiestheaver(cid:12)ageangulardis(cid:12)crepancybe- screenshot(i.e.,apipelinedtaskofCAPTCHAdetectionand
tweenthepredictedandactualangles. recognition).Wetestthefollowingalternatives:
| 514    33rd USENIX Security Symposium |     |     |     |     |     |     |     |     |     |     |     | USENIX Association |     |     |
| ------------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ------------------ | --- | --- |

Table5:Resultsofourabalationstudy. AttacksonCAPTCHADetection.WeconductDPatchat-
tack[38]tocompromisetheCAPTCHAdetectioncomponent
ofPhishDecloaker.DPatchgeneratesadversarialpatchesthat
Configuration Result can be applied to a webpage. In our case, the patches are
Detector Recognizer Precision Recall untargeted,Tocreateuntargetedpatches,DPatchfindsapatch
pattern⃗P
F-RCNN ResNet-50 0.89 0.84 u thatmaximizethelossoftheobjectdetectortothe
F-RCNN Single-branchSiamese 0.92 0.84 trueclasslabel⃗yandboundingboxlabel⃗Bwhenthepatch
| F-RCNN | Dual-branchSiamese | 0.91 | 0.82 |     |     |     |     |     |
| ------ | ------------------ | ---- | ---- | --- | --- | --- | --- | --- |
isappliedtoawebpagescreenshotxusing“apply”function
OLN ResNet-50 0.85 0.77 A,asshowninEquation3[38].TheapplyfunctionA(x,P)
OLN Single-branchSiamese 0.92 0.86 meansaddingpatchPontowebpagescreenshotx.Asaresult,
| OLN | Dual-branchSiamese | 0.93 | 0.86 |                    |          |             |               |     |
| --- | ------------------ | ---- | ---- | ------------------ | -------- | ----------- | ------------- | --- |
|     |                    |      |      | an objectdetection | modelcan | potentially | failto locate | the |
correctregioncontainingCAPTCHAs.
• OP1(alternativerecognizer):Howdoesadeepclassifier ⃗P =argmaxE L(A(x,P);⃗y,⃗B)
|                                                  |     |     |     |     | u   | x   |     | (3) |
| ------------------------------------------------ | --- | --- | --- | --- | --- | --- | --- | --- |
| (implementedbyResNet-50)comparewithSiamesemetric |     |     |     |     |     | P   |     |     |
|                                                  |     |     |     |     |     | h   | i   |     |
learningmodelinrecognizingCAPTCHAtypes? AttacksonCAPTCHARecognition.Weconductadversar-
|                    |                   |     |                | ial attacks | on CAPTCHA | images including | Fast Gradient |     |
| ------------------ | ----------------- | --- | -------------- | ----------- | ---------- | ---------------- | ------------- | --- |
| • OP2 (alternative | object detector): | How | does Faster R- |             |            |                  |               |     |
SignMethod(FGSM)[28],JacobianSaliencyMapAttack
CNNcomparewithOLNindetectingCAPTCHAs?
|     |     |     |     | (JSMA) | [51],ProjectedGradientDescent(PGD) |     | [40],and |     |
| --- | --- | --- | --- | ------ | ---------------------------------- | --- | -------- | --- |
• OP3(alternativebranchdesign):Howdoesadual-branch DeepFool [44] to compromise the CAPTCHA recognition
componentofPhishDecloaker.Intheattack,weassumethat
Siamese(i.e.,visual&OCR-aidedtextualbranch)compare
withasingle-branchSiamese(i.e.,visualbranch)? theattackercanaccessthewhite-boxmodelbutcannotpoison
ormodifyPhishDecloakerdeployedonline,
Dataset.ToevaluatetheprecisionandrecallofCAPTCHA AugmentationAttacks.Additionally,weconductgenericim-
recognition,weoverlaythetestsamplesfromourCAPTCHA ageaugmentationattacksonPhishDecloakerbyperforming6
recognitiondataset(Section5.2.2)onto622screenshotsof typesoftransformationsontheCAPTCHAimageandoverlay
|                 |                   |         |         | the transformedCAPTCHA |     | onto random | webpage | screen- |
| --------------- | ----------------- | ------- | ------- | ---------------------- | --- | ----------- | ------- | ------- |
| benign webpages | andsupplementthem | with100 | webpage |                        |     |             |         |         |
screenshotswithoutCAPTCHAs. shots.Specifically,theyareRandomStretch,GaussianNoise,
Results.Table5showsourresults.WeobservethatPhishDe- RandomCrop,RandomMask,Salt&Pepper,andGaussian
cloaker’sdesignisthemostoptimal.ComparedtoSiamese Blur.AppendixA.2visualizestheattacks.Thoseaugmenta-
models,aclassifierachieveslessaccuracy,especiallyinthose tionsarecommonlyfoundinphishingwebpages[16].Dif-
screenshots without CAPTCHAs. Compared to Faster R- ferentfromgeneratingtheadversarialimagesforCAPTCHA
CNN,OLNmanifestsbetterrecall.Finally,thedual-branch detectionandrecognitioncomponent,thoseadversarialsam-
| Siamese design | has a marginal | improvement | over single- | plesarevisible. |     |     |     |     |
| -------------- | -------------- | ----------- | ------------ | --------------- | --- | --- | --- | --- |
branchdesignbyconsideringtextualfeatures(0.93over0.92 Dataset. We apply all the above attacks on the dataset de-
inprecision).Securitypractitionerscanmakeatrade-offbe- scribedinSection5.2.2.
tweenmodelcomplexityandperformance. Measurement. We measure the performance of PhishDe-
cloakerbeforeandafterattacksintermsoftheaccuracyofthe
resultsofapipelinedCAPTCHAdetectionandCAPTCHA
5.5 RQ5:RobustnessAgainstAdversaries
|     |     |     |     | recognition. | We evaluate | the robustness | against the | adver- |
| --- | --- | --- | --- | ------------ | ----------- | -------------- | ----------- | ------ |
Inthissection,weassessPhishDecloaker’srobustnesstoeva- sariesbytheperturbationofoverallCAPTCHArecognition
sion attacks bygenerating custom CAPTCHA images that ratebeforeandaftertheattack.Wedonotevaluatethesolving
targetspecificcomponentsofPhishDecloaker.Wethenevalu- accuracyaswecannotchangetheonlineCAPTCHAs.
atethesystem’soverallresilience.
5.5.2 Results
5.5.1 Adversaries
Table6andTable7showthattheaccuracylossunderattacks.
We model our adversary as a phisher with no constraints Wecanseethatouradoptedgradientmaskingtechniqueis
intimeandcomputingresourcestodeployevasionattacks. effectiveindefendingthestate-of-the-artgradient-basedad-
Theadversary’saimistocreateaCAPTCHA-cloakingpage versarialattackonthedeeplearningmodels,i.e.,CAPTCHA
thatremainsundetectedbyPhishDecloaker.Tothisend,we detectionandrecognitionmodels.
conductadversarialattacksondetection,recognition,andthe Furthermore,Table8showstheperformanceofPhishDe-
solvingcomponents,withtheassumptionthattheadversary cloaker in recognizing augmented CAPTCHAs, including
possessesperfectknowledgeofPhishDecloaker’sdesign. attackssuchasRandomStretchandGaussianNoise,among
| USENIX Association |     |     |     |     | 33rd USENIX Security Symposium    515 |     |     |     |
| ------------------ | --- | --- | --- | --- | ------------------------------------- | --- | --- | --- |

Table 6: The robustness of CAPTCHA recognition model StudyGroups.Weprepare6differentstudygroupstoana-
againstdiverseadversarialattack. lyzecrawledsitesforphishing,eachusingPhishIntentionas
thebasephishingdetectorforitsstate-of-the-artperformance
indetectingzero-dayphishingwebsites.Group1isacontrol
Attack Accuracy(noDef.) Accuracy(withDef.) groupwithnoJavaScript(JS)renderingordecloakingtech-
NoAttack 0.97 1.00 niques.Group2hasonlyJSrendering.Groups3to6have
JSMA 0.50(-48.5%) 1.00(-0.0%) JSrenderingandeachisequippedwithatypeofdecloaking
| PGD      | 0.12(-87.6%) |     | 1.00(-0.0%) |     |     | techniquebelow:             |             |     |              |               |     |           |
| -------- | ------------ | --- | ----------- | --- | --- | --------------------------- | ----------- | --- | ------------ | ------------- | --- | --------- |
| DeepFool | 0.07(-92.8%) |     | 1.00(-0.0%) |     |     |                             |             |     |              |               |     |           |
|          |              |     |             |     |     | • Anti-interaction-cloaking |             |     | (AI):        | Automatically |     | closes    |
| FGSM     | 0.06(-93.8%) |     | 1.00(-0.0%) |     |     |                             |             |     |              |               |     |           |
|          |              |     |             |     |     | alert,                      | permission, | and | notification | windows.      | It  | also ran- |
domlymovesandclicksthemouseafterthepageisloaded.
| Table 7: The | robustness | of CAPTCHA |     | detection | model |                             |     |     |       |            |     |          |
| ------------ | ---------- | ---------- | --- | --------- | ----- | --------------------------- | --- | --- | ----- | ---------- | --- | -------- |
|              |            |            |     |           |       | • Anti-fingerprint-cloaking |     |     | (AF): | Randomizes |     | its user |
againstadversarialattack. agent and cookie storage, spoofs its referrer, and uses a
stealthheadlessbrowser.
• Anti-behavior-cloaking(AB):Automaticallyfollowsall
| Attack | mAP(noDef.) |     | mAP(withDef.) |     |     |     |     |     |     |     |     |     |
| ------ | ----------- | --- | ------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
redirectsandwaitsfor5secondsifthepageisblank(i.e.,
| NoAttack | 97.70 |     | 91.55 |     |     |     |     |     |     |     |     |     |
| -------- | ----- | --- | ----- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
loading).Itretriesupto3timesifthepagefailstoload.
| DPatch | 54.65(-44.1%) |     | 85.71(-6.4%) |     |     |     |     |     |     |     |     |     |
| ------ | ------------- | --- | ------------ | --- | --- | --- | --- | --- | --- | --- | --- | --- |
• Anti-CAPTCHA-cloaking(AC):UsesPhishDecloakerto
automaticallydetectandsolveCAPTCHAs.
others.Weobservethattransformation-basedattackscanbe Validation&Monitoring.Wemanuallyinspectandconfirm
reportedphishingwebsites.Further,wesubmittheconfirmed
effectivelycounteredthroughadversarialtraining.Although
phishingwebsitestoVTandtracktheirlifespan.Weconsider
| the adversarial | training process |     | has only | a subset | of trans- |            |           |     |                  |     |          |          |
| --------------- | ---------------- | --- | -------- | -------- | --------- | ---------- | --------- | --- | ---------------- | --- | -------- | -------- |
|                 |                  |     |          |          |           | a manually | confirmed |     | phishing website | as  | zero-day | if it is |
formations(i.e.,RandomMask,GaussianNoiseandBlur),
|     |     |     |     |     |     | notreportedbyanyofthedetectorsinVT. |     |     |     |     | Inaddition,we |     |
| --- | --- | --- | --- | --- | --- | ----------------------------------- | --- | --- | --- | --- | ------------- | --- |
themodelperformedwellagainstotherattacks,suggesting
thatlearnedtransformationscanbegeneralizedtoeffectively measurethetimetakenforsitestoexpire(time-to-takedown)
andblacklistedbyVT(time-to-blacklist).
handleunseentransformations.
| Table8:TherobustnessofPhishDecloakeragainstaugmenta- |     |     |     |     |     | 5.6.2 Results |     |     |     |     |     |     |
| ---------------------------------------------------- | --- | --- | --- | --- | --- | ------------- | --- | --- | --- | --- | --- | --- |
tionattacks.
|        |                  |     |     |                    |     | In this      | field study, | we    | captured      | totally 869 | unique | phish- |
| ------ | ---------------- | --- | --- | ------------------ | --- | ------------ | ------------ | ----- | ------------- | ----------- | ------ | ------ |
|        |                  |     |     |                    |     | ing websites | by           | all 6 | study groups. | Of these,   | 7.6%   | were   |
| Attack | Accuracy(noDef.) |     |     | Accuracy(withDef.) |     |              |              |       |               |             |        |        |
CAPTCHA-cloakedphishingwebsites,allofwhichweredis-
NoAttack 0.97 1.00 covered solely by PhishDecloaker. Table 9 further details
RandomStretch 0.95(-1.9%) 0.96(-4.0%) howeachdecloakinggroupscontributetophishingdiscovery.
| GaussianNoise | 0.87(-10.2%) |     |     | 0.94(-6.0%) |     |     |     |     |     |     |     |     |
| ------------- | ------------ | --- | --- | ----------- | --- | --- | --- | --- | --- | --- | --- | --- |
Group3(e.g.,randommousemovement),Group5(e.g.,repet-
RandomCrop 0.82(-15.3%) 0.83(-17.0%) itivevisits),andGroup6(withPhishDecloaker)reportunique
| RandomMask | 0.76(-21.5%) |     |     | 0.90(-10.0%) |     |     |     |     |     |     |     |     |
| ---------- | ------------ | --- | --- | ------------ | --- | --- | --- | --- | --- | --- | --- | --- |
phishingwebsites,i.e.,thephishingwebsitesreportedonlyby
| SaltandPepper | 0.33(-66.4%) |     |     | 0.92(-8.0%) |     |     |     |     |     |     |     |     |
| ------------- | ------------ | --- | --- | ----------- | --- | --- | --- | --- | --- | --- | --- | --- |
thespecificgroup.WeconsiderGroup3-5asbasicandtradi-
| GaussianBlur | 0.18(-82.0%) |     |     | 0.93(-7.0%) |     |     |     |     |     |     |     |     |
| ------------ | ------------ | --- | --- | ----------- | --- | --- | --- | --- | --- | --- | --- | --- |
tionaldecloakingfunctions(e.g.,randomlymovingthemouse
andrepetitivevisitstoawebsite),whichstillplayanimportant
roleinreportzero-dayphishingwebsites(i.e.,Group6reports
|     |     |     |     |     |     | 203; Group | 5 reports | 198; | andGroup | 3 reports | 197). | Nev- |
| --- | --- | --- | --- | --- | --- | ---------- | --------- | ---- | -------- | --------- | ----- | ---- |
5.6 RQ6:FieldStudy ertheless,comparedtothosetraditionaldecloakinggroups,
CAPTCHA-basedcloakingisemerging,whichranksthesec-
Wefurtherdesignafieldstudytoevaluatetheemergenceof ondin terms ofunique ratio andranks the firstin terms of
CAPTCHA-cloakedphishingwebsitesintherealworld. thenumberofdiscoveredzero-dayphishingwebsites,which
raisesalarmtothephishingdetectioncommunity.Further,the
resultindicatesapracticalorcommercialphishingdecloaking
5.6.1 ExperimentSetup
shallbehybridtohandledifferentcloakingtechniques.
URLSource.WecrawlfreshURLsfromCertstream[3]in Next,weinvestigatethefeaturesofCAPTCHA-cloaked
real-timefor4weeks,whichprovidesdomainswithnewly phishingwebsitesregardingthesectorsoftheirtargetbrands,
issuedTLS/SSLcertificates. CAPTCHAtypes,lifespan,andtimetobeblacklisted.
| 516    33rd USENIX Security Symposium |     |     |     |     |     |     |     |     |     | USENIX Association |     |     |
| ------------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ------------------ | --- | --- |

Table9:FieldstudyresultsofeachdecloakinggrouponCert-
|                                                            |                     |     |                          |     |     |       |          | reCAPTCHA v2 | hCaptcha | Text | Press & Hold |     | Slider |
| ---------------------------------------------------------- | ------------------- | --- | ------------------------ | --- | --- | ----- | -------- | ------------ | -------- | ---- | ------------ | --- | ------ |
| stream URLs.                                               | PI: PhishIntention. |     | JS: JavaScriptrendering. |     |     |       |          |              |          |      |              |     |        |
| AI:anti-interaction-cloaking.AF:anti-fingerprint-cloaking. |                     |     |                          |     |     | puorG | Benign   |              |          |      |              |     |        |
| AB:anti-behavior-cloaking.AC:anti-CAPTCHA-cloaking.        |                     |     |                          |     |     |       | Phishing |              |          |      |              |     |        |
|                                                            |                     |     |                          |     |     |       | 0%       | 20%          | 40%      | 60%  |              | 80% | 100%   |
Percentage
Group Setup UniqueRatio #0-Days #Phishing Figure 7: Distribution of CAPTCHA types on benign and
| G1 PI                                             |     | 0.0%  | 101(−0.0%)      | 361(−0.0%)  |     | phishingsites. |      |                    |             |                 |                    |          |         |
| ------------------------------------------------- | --- | ----- | --------------- | ----------- | --- | -------------- | ---- | ------------------ | ----------- | --------------- | ------------------ | -------- | ------- |
| G2 PI+JS                                          |     | 0.0%  | 176(↑74.3%)     | 582(↑61.2%) |     |                |      |                    |             |                 |                    |          |         |
| G3 PI+JS+AI                                       |     | 14.1% | 197(↑95.0%)     | 710(↑96.7%) |     |                |      |                    |             |                 |                    |          |         |
| G4 PI+JS+AF                                       |     | 0.0%  | 165(↑63.4%)     | 543(↑50.4%) |     |                |      |                    |             |                 |                    |          |         |
|                                                   |     |       |                 |             |     |                |      | CAPTCHA-cloaked    |             |                 |                    | Ordinary |         |
| G5 PI+JS+AB                                       |     | 7.4%  | 198(↑96.0%)     | 692(↑91.7%) |     | 100            |      |                    |             | 100             |                    |          |         |
| G6 PI+JS+AC                                       |     | 10.2% | 203(↑101.0%)    | 648(↑79.5%) |     | )%( egatnecreP |      |                    |             |                 |                    |          |         |
|                                                   |     |       |                 |             |     |                | 75   |                    |             | 75              |                    |          |         |
|                                                   |     |       |                 |             |     |                | 50   |                    |             | 50              |                    |          |         |
| Table10:Top-5targetedsectorsbyordinaryandCAPTCHA- |     |       |                 |             |     |                | 25   |                    |             | 25              |                    |          |         |
|                                                   |     |       |                 |             |     |                | 0    |                    |             | 0               |                    |          |         |
| cloakedphishingsites.                             |     |       |                 |             |     |                | 0 24 | 48 72              | 96 >120     | 0               | 24                 | 48 72    | 96 >120 |
|                                                   |     |       |                 |             |     |                |      | Time Alive (hours) |             |                 | Time Alive (hours) |          |         |
|                                                   |     |       |                 |             |     |                |      |                    | Blacklisted | Not Blacklisted |                    |          |         |
|                                                   |     |       |                 |             |     |                |      | 25th Percentile    |             | 50th Percentile | 75th Percentile    |          |         |
| Ordinary                                          |     | %     | CAPTCHA-Cloaked |             | %   |                |      |                    |             |                 |                    |          |         |
Figure8:CumulativedistributionoflifespanforCAPTCHA-
| Telecommunications |     | 23.8 | Cryptocurrency |     | 43.9 |     |     |     |     |     |     |     |     |
| ------------------ | --- | ---- | -------------- | --- | ---- | --- | --- | --- | --- | --- | --- | --- | --- |
SocialNetworking 22.8 SocialNetworking 19.3 cloakedandordinaryphishingsites.
| Gambling                |     | 12.5 | Logistics/Courier   |     | 15.8 |          |       |      |          |            |       |       |        |
| ----------------------- | --- | ---- | ------------------- | --- | ---- | -------- | ----- | ---- | -------- | ---------- | ----- | ----- | ------ |
| OnlineServices/Software |     | 12.3 | GovernmentServices  |     | 8.8  |          |       |      |          |            |       |       |        |
|                         |     |      |                     |     |      | phishing | sites | take | a median | time of 16 | hours | to be | black- |
| Financial/Insurance     |     | 10.1 | Financial/Insurance |     | 5.3  |          |       |      |          |            |       |       |        |
listed,whichis45.5%longerthanordinaryphishingsites(11
hours).TheresultindicatesthatCAPTCHA-cloakedphishing
websitesaremoreactiveandevasivefortraditionalphishing
| TargetSectors.Wefurtherinvestigatethesectorsofthetar- |     |     |     |     |     | detectors. |     |     |     |     |     |     |     |
| ----------------------------------------------------- | --- | --- | --- | --- | --- | ---------- | --- | --- | --- | --- | --- | --- | --- |
Overhead.Inthisstudy,themediantimeofPhishDecloaker
getbrandsoftraditionalphishingwebsitesandCAPTCHA-
cloakedphishingwebsitesasshowedinTable10.Weobserve onCAPTCHAdetectionandrecognitionare0.4sand0.3sre-
spectively,makingGroup653.1%(0.68s)slowerthanGroup
thatCAPTCHA-cloakedphishingwebsitesaremorelikelyto
targetvibrantsectorslikecryptocurrency(e.g.,Coinbaseand 2.AlthoughmediantimeforCAPTCHAsolvingis15.3s,it
TrustWallet).Incontrast,traditionalphishingwebsitesstill canbedecoupledandprocessedasynchronously.
targetsectorssuchastelecommunication(e.g.,Orangeand
AT&T).
6 Discussion
CAPTCHATypesandTheirUsage.AsshowedinFigure7,
phishers tend to use free and convenient CAPTCHA ser- Limitations.AlthoughPhishDecloakercanbeextendedto
vices.ThedistributionofCAPTCHAtypesusedbybenign include new CAPTCHA types for CAPTCHA detection
websitesare:reCAPTCHAv2(76.0%),hCaptcha(19.3%), and recognition, it is limited by the number of supported
TextCAPTCHA(4.0%),Press&Hold(0.6%),Slider(0.1%),
CAPTCHAsolvers.WhenPhishDecloakerencountersarare
whereasitismainlyhCaptcha(77.3%)andreCAPTCHAv2 CAPTCHAwithoutacorrespondingsolverinitsrepository,
(22.7%)onphishingsites.Interestingly,wefindthatfewer weoffertwosuggestions.First,PhishDecloakercanintegrate
than20%ofCAPTCHAAPIkeys(i.e.,thekeysusedtoac- with existing CAPTCHA solving services (e.g.,2Captcha)
cesscommercialCAPTCHAservices)accountformorethan thatrelyonpaidlabour.TheseservicesprovideaAPIend-
| 55% of the | discovered | CAPTCHA-cloaked |     | phishing | sites. |     |     |     |     |     |     |     |     |
| ---------- | ---------- | --------------- | --- | -------- | ------ | --- | --- | --- | --- | --- | --- | --- | --- |
pointforeachdifferentCAPTCHAtype.Inthiscase,PhishDe-
One hCaptcha key was even found to be shared across 19 cloakercanidentifytheCAPTCHAtypeandcalltherightAPI
sites.ItpotentiallyindicatesthatCAPTCHA-cloakedphish- forthetask.Second,PhishDecloakercanautomaticallynotify
ingattackersmightalsobesensitivetothe“attackingcost”.
in-househumanoperatorsofunsolvableCAPTCHAs.Nev-
LifeSpanandTimetoBlacklist.Differentfromourexpecta- ertheless,intheeraofArtificialGeneralIntelligence(AGI),
tion,CAPTCHA-cloakedphishingwebsiteshaveshorterlifes- weexpectthatemergingAIsolutionscanfurtherempower
pancomparedtoordinaryphishingsites(9.7vs.13.2hours), PhishDecloakertoachievebetterperformance.
asshowedinFigure8.However,ittakesblacklist-basedde- EthicalConsiderations. OurempiricalstudysubmitsURLs
tectorssuchasGoogleSafeBrowserandSmartScreenmore ofself-hostedphishingkitstoanti-phishingentities,which
timetoputtheURLsofCAPTCHA-cloakedphishingsites mayhaveanegativeimpacttothecommunity.Morespecifi-
intheirblacklist,asshowedinFigure9.CAPTCHA-cloaked cally,securitycrawlersmayspendunnecessaryresourceson
| USENIX Association |     |     |     |     |     |     |     | 33rd USENIX Security Symposium    517 |     |     |     |     |     |
| ------------------ | --- | --- | --- | --- | --- | --- | --- | ------------------------------------- | --- | --- | --- | --- | --- |

100
75
50
25
0
0 24 48 72 96 >120
Time-to-Blacklist (hours)
)%(
egatnecreP
CAPTCHA-cloaked Ordinary typesexist:server-sideandclient-sidecloaking.Server-side
100
cloakingidentifiesusersviaHTTPrequests,oftenusing.htac-
75 cessorPHPscripts[19,41,46,47,49,65].ItemploysIPand
50 keywordblacklists,geolocation,anduser-agentstofiltertraf-
25 fic.CountermeasuresincludemultiplevisitswithspoofedIPs
0 anduser-agents[13,32,35,36,64].
0 24 48 72 96 >120
Time-to-Blacklist (hours) Client-sidecloakingoperateswithinbrowsers.Itemploys
25th Percentile 50th Percentile 75th Percentile
browserfingerprintinganduserinteraction,suchaspop-upsor
Figure9:Cumulativedistributionoftimetakentobeblack- CAPTCHAs[13,41,59,64].Italsomanipulatesbotbehavior
listedbySmartScreenorGSBforCAPTCHA-cloakedand to delay loading times [64]. Despite its rising popularity,
ordinaryphishingsites. client-sidecloakingchallengesanti-phishingengines[41,47].
Thoughlackingasystematicapproach,someadvanceshave
beenmade.Forexample,CrawlphishusesJavaScriptforce
analyzingsimulatedthreatsandinnocentvisitorsmaystumble executiontodetectclient-sidecloakingbutfocusesmoreon
uponthesesites.Tomitigatethis,westrictlyfollowtheestab- post-hocanalysisthanreal-timedetection[64].
lishedguidelinesofpreviousworks[13,46,47]byrandomly
CAPTCHASolving.Deeplearningmodelshavebeenusedto
generatinglongURLs,submittingthemonlytoanti-phishing
solvespecificCAPTCHAtypes[26,31,57,66,67],butnosys-
entitiesthroughproperchannels,restrictingthetotalnumber
temexistsforautomaticallyidentifyingarbitraryCAPTCHAs,
ofsubmissionsto500perentity,andusedefangedphishing
consistentwith[59].Someadhocsolversinclude:Sivakorn
kitsthatdonotstorenorsharecredentials.Besides,PhishDe-
et al. [57] tackled Google reCAPTCHA v2 by exploiting
cloakercanbeexploitedtocompromisebenignwebsites.We
challengeinstructions.Theyusedimageannotationservices
opttokeepitclosed-source,sharingexclusivelywithtrusted
andWord2Vectomatchtagswithchallengetext.Hossenet
researchers,securityfirms,andgovernmentagencies.Wecan
al.[31]employedacustomobjectdetectionmodeltorecog-
alsodeployitasarestrictedcloudservice,whereaccesskey
nizetheobjectspresentinthechallengeimages.Forslider
isrevokedifabused.
CAPTCHAs,Zhaoetal.[67]developedanalgorithmtomatch
FutureWork.Recently,vision-languagefoundationmodels
backgroundandtargetimagestoidentifythepuzzleregion,
havedemonstratedextraordinaryemergentabilitiesonweb
whereasWuetal.[62]usedobjectdetection.
navigationtasks[22,25].Thesemodelsenabletransformative
Unliketheabovesolutions,PhishDecloakerdetects,recog-
generalization and are capable of solving wide ranges of
nizes,andthensolvesvariousCAPTCHAsusinganexpand-
interactivedecisionmakingproblemsinthewild[45].Hence,
ablerepositoryofCAPTCHAsolversforanti-phishing.
itispossibletostudythefeasibilityofthesemodelsaszero-
shotorfew-shotgeneralizedCAPTCHAsolvers.
8 Conclusion
7 RelatedWork
We studied CAPTCHA cloaking, a prevalent technique
among phishing websites. Our empirical study showed
Phishing Detection. Conventional phishing detection sys-
that none of the selected phishing detectors could detect
temssuchasSmartScreen,GoogleSafeBrowsing,andOpen-
CAPTCHA-cloaked phishing. Motivated by this, we de-
Phishrelyonblacklists,whichareupdatedthroughuserre-
velopedPhishDecloakertoautomaticallydetect,recognize,
ports,automaticcrawling,andmanualverification.However,
andsolveCAPTCHAs.OurexperimentconfirmedPhishDe-
thismethodislimitedbydelaysinlistupdatesandfrequently
cloaker’sabilitytorestorephishingdetectionratesofPhish-
missesshort-livedphishingcampaigns[49].
pedia and PhishIntention on CAPTCHA-cloaked phishing
Toautomateverification,feature-engineering-basedsolu-
kits,anditremainedrobustagainstadversarialattacks.We
tions [20,24,27,34,39,61,63] use feature extraction and
furtherconfirmeditspracticalimpactthroughafieldstudy
classificationtechniques,focusingonHTMLcode,URLs,do-
onCertstreamURLs,revealinginterestingbehaviorof0-day
mains,andscreenshots.Despitetheirutility,thesesolutions
CAPTCHA-cloakedphishingsitesinthewild.
areinflexibleandsusceptibletocodeobfuscation,resulting
in rapid data obsolescence. To overcome these limitations,
reference-based solutions [12,15,35–37,42] employ deep- Acknowledgments
visiontechniquestocomparetherepresentationsofaphishing
pageagainstapre-definedreferencelist,determiningitstarget WethankKhurshidJuraevforhisworkontheearlyprototypes
brand.Theseapproachesarebothextensibleandexplainable, ofreCAPTCHAv2andhCaptchasolvers. Thisresearchis
advancingthestate-of-the-artinphishingdetection. supportedinpartbyNationalNaturalScienceFoundationof
Cloaking. Phishing websites use advanced cloaking tech- China(62172099,23Z990203011),theMinisterofEducation,
niquestoevadedetection[14,41,48,59,64,65].Twomain Singapore(MOET32020-0004),theNationalResearchFoun-
518 33rd USENIX Security Symposium USENIX Association

dation,Singapore,andCyberSecurityAgencyofSingapore [13] BhupendraAcharyaandPhaniVadrevu. {PhishPrint}:
underitsNationalCybersecurityResearchandDevelopment evadingphishingdetectioncrawlersbypriorprofiling.
Programme(AwardNo. NRF-NCR_TAU_2021-0002) and In30thUSENIXSecuritySymposium(USENIXSecurity
A*STAR,CISCOSystems(USA)Pte.LtdandNationalUni- 21),pages3775–3792,2021.
versityofSingaporeunderitsCisco-NUSAcceleratedDig-
italEconomyCorporateLaboratory(AwardI21001E0002), [14] BhupendraAcharyaandPhaniVadrevu. Ahumanin
NationalResearchFoundation,Singapore,andtheCyberSe- everyape:Delineatingandevaluatingthehumananal-
|               |                    |               |          | ysissystemsofanti-phishingentities. |     |     | InInternational |     |
| ------------- | ------------------ | ------------- | -------- | ----------------------------------- | --- | --- | --------------- | --- |
| curity Agency | under its National | Cybersecurity | R&D Pro- |                                     |     |     |                 |     |
gramme(NCRP25-P04-TAICeN),DSONationalLaborato- Conference on Detection of Intrusions and Malware,
riesundertheAISingaporeProgramme(AISGAwardNo: andVulnerabilityAssessment,pages156–177.Springer,
| AISG2-GC-2023-008). |     |     |     | 2022.                               |     |     |                  |     |
| ------------------- | --- | --- | --- | ----------------------------------- | --- | --- | ---------------- | --- |
|                     |     |     |     | [15] SadiaAfrozandRachelGreenstadt. |     |     | Phishzoo:Detect- |     |
References
|     |     |     |     | ingphishingwebsitesbylookingatthem. |     |     | In2011IEEE         |     |
| --- | --- | --- | --- | ----------------------------------- | --- | --- | ------------------ | --- |
|     |     |     |     | fifthinternationalconference        |     | on  | semanticcomputing, |     |
[1] AWPG.PhishingActivityTrendsReport,4thQuarter
pages368–375.IEEE,2011.
| 2022. | https://docs.apwg.org/reports/apwg_tre |     |     |     |     |     |     |     |
| ----- | -------------------------------------- | --- | --- | --- | --- | --- | --- | --- |
nds_report_q3_2022.pdf.
|     |     |     |     | [16] Giovanni | Apruzzese, | Hyrum | S Anderson, | Savino |
| --- | --- | --- | --- | ------------- | ---------- | ----- | ----------- | ------ |
[2] BuiltWith®.CAPTCHAUsageDistributionintheTop Dambra, David Freeman, Fabio Pierazzi, and Kevin
1MillionSites. https://trends.builtwith.com/w Roundy. “real attackers don’t compute gradients”:
idgets/captcha. Bridgingthegapbetweenadversarialmlresearchand
|                 |                                 |     |     | practice. | In2023IEEEConferenceonSecureandTrust- |                   |       |          |
| --------------- | ------------------------------- | --- | --- | --------- | ------------------------------------- | ----------------- | ----- | -------- |
| [3] Certstream. | https://certstream.calidog.io/. |     |     |           |                                       |                   |       |          |
|                 |                                 |     |     | worthy    | Machine                               | Learning (SaTML), | pages | 339–364. |
IEEE,2023.
| [4] curl-impersonate. | https://github.com/lwthiker/ |     |     |     |     |     |     |     |
| --------------------- | ---------------------------- | --- | --- | --- | --- | --- | --- | --- |
curl-impersonate.
[17] JeonghunBaek,GeewookKim,JunyeopLee,Sungrae
[5] EasyOCR. https://github.com/JaidedAI/EasyOC Park,DongyoonHan,SangdooYun,SeongJoonOh,and
R/tree/master.
HwalsukLee.Whatiswrongwithscenetextrecognition
|                         |                          |     |     | model | comparisons? | dataset and | model analysis. | In  |
| ----------------------- | ------------------------ | --- | --- | ----- | ------------ | ----------- | --------------- | --- |
| [6] hCaptchaChallenger. | https://github.com/QIN2D |     |     |       |              |             |                 |     |
ProceedingsoftheIEEE/CVFinternationalconference
IM/hcaptcha-challenger.
oncomputervision,pages4715–4723,2019.
| [7] LandscapeDataset. | https://github.com/koishi7 |     |     |     |     |     |     |     |
| --------------------- | -------------------------- | --- | --- | --- | --- | --- | --- | --- |
0/Landscape-Dataset. [18] YoungminBaek,BadoLee,DongyoonHan,Sangdoo
|                                            |     |     |     | Yun,     | and Hwalsuk | Lee. Character | region | awareness |
| ------------------------------------------ | --- | --- | --- | -------- | ----------- | -------------- | ------ | --------- |
| [8] OpenMMLabDetectionToolboxandBenchmark. |     |     | ht  |          |             |                |        |           |
|                                            |     |     |     | for text | detection.  | In Proceedings | of the | IEEE/CVF  |
tps://github.com/open-mmlab/mmdetection.
conferenceoncomputervisionandpatternrecognition,
[9] PhishDecloaker’sWebsite. https://sites.google pages9365–9374,2019.
.com/view/phishdecloaker/home.
[19] HugoBijmans,TimBooij,AnnekeSchwedersky,Aria
[10] TrendMicro.AddressingCAPTCHA-EvadingPhishing
|     |     |     |     | Nedgabat,andRolfvan |     | Wegberg. | Catching | phishers |
| --- | --- | --- | --- | ------------------- | --- | -------- | -------- | -------- |
Threats With Behavior-Based AI Protection. https: bytheirbait:Investigatingthedutchphishinglandscape
//www.trendmicro.com/vinfo/id/security/new
throughphishingkitdetection.In30thUSENIXSecurity
s/internet-of-things/addressing-captcha-e
Symposium(USENIXSecurity21),pages3757–3774,
vading-phishing-threats-with-behavior-bas
2021.
ed-ai-protection.
[20] MarcoCova,ChristopherKruegel,andGiovanniVigna.
| [11] MoatazAbdelKhalekandAhmedShosha. |     |     | Jsdes:Anau- |     |     |     |     |     |
| ------------------------------------- | --- | --- | ----------- | --- | --- | --- | --- | --- |
tomatedde-obfuscationsystemformaliciousjavascript. There is no free phish: An analysis of"free" andlive
|     |     |     |     | phishingkits. | WOOT,8:1–8,2008. |     |     |     |
| --- | --- | --- | --- | ------------- | ---------------- | --- | --- | --- |
Inproceedingsofthe12thInternationalConferenceon
Availability,ReliabilityandSecurity,pages1–13,2017.
|     |     |     |     | [21] Jiankang | Deng, | Jia Guo, Tongliang | Liu, | Mingming |
| --- | --- | --- | --- | ------------- | ----- | ------------------ | ---- | -------- |
[12] SaharAbdelnabi,KatharinaKrombholz,andMarioFritz. Gong, and Stefanos Zafeiriou. Sub-center arcface:
Visualphishnet: Zero-day phishing website detection Boosting face recognition by large-scale noisy web
byvisualsimilarity. InProceedingsofthe2020ACM faces. In Computer Vision–ECCV 2020: 16th Euro-
SIGSACconferenceoncomputerandcommunications pean Conference,Glasgow,UK,August 23–28,2020,
security,pages1681–1698,2020. Proceedings,PartXI16,pages741–757.Springer,2020.
| USENIX Association |     |     |     |     | 33rd USENIX Security Symposium    519 |     |     |     |
| ------------------ | --- | --- | --- | --- | ------------------------------------- | --- | --- | --- |

[22] XiangDeng,YuGu,BoyuanZheng,ShijieChen,Sam [33] Dahun Kim, Tsung-Yi Lin, Anelia Angelova, In So
Stevens,BoshiWang,HuanSun,andYuSu. Mind2web: Kweon,andWeichengKuo.Learningopen-worldobject
Towards a generalist agent for the web. Advances in proposalswithoutlearningtoclassify. IEEERobotics
NeuralInformationProcessingSystems,36,2024. andAutomationLetters,7(2):5453–5460,2022.
[23] KostasDrakonakis,SotirisIoannidis,andJasonPolakis. [34] YukunLi,ZhenguoYang,XuChen,HuapingYuan,and
Thecookiehunter:Automatedblack-boxauditingfor WenyinLiu. Astackingmodelusingurlandhtmlfea-
| webauthenticationandauthorizationflaws. |     |     |     |     |     | InProceed- |                                   |     |     |     |               |     |
| --------------------------------------- | --- | --- | --- | --- | --- | ---------- | --------------------------------- | --- | --- | --- | ------------- | --- |
|                                         |     |     |     |     |     |            | turesforphishingwebpagedetection. |     |     |     | FutureGenera- |     |
ingsofthe2020ACMSIGSACConferenceonComputer tionComputerSystems,94:27–39,2019.
andCommunicationsSecurity,pages1953–1970,2020.
[35] YunLin,RuofanLiu,DinilMonDivakaran,JunYang
[24] Birhanu Eshete, Adolfo Villafiorita, and Komminist Ng,QingZhouChan,YiwenLu,YuxuanSi,FanZhang,
| Weldemariam. |     |     | Binspect: | Holistic | analysis | and detec- |                 |     |                                |     |     |     |
| ------------ | --- | --- | --------- | -------- | -------- | ---------- | --------------- | --- | ------------------------------ | --- | --- | --- |
|              |     |     |           |          |          |            | andJinSongDong. |     | Phishpedia:Ahybriddeeplearning |     |     |     |
tionofmaliciouswebpages. InSecurityandPrivacy basedapproachtovisuallyidentifyphishingwebpages.
in Communication Networks: 8th International ICST In30thUSENIXSecuritySymposium(USENIXSecurity
Conference,SecureComm2012,Padua,Italy,September
21),pages3793–3810,2021.
3-5,2012.RevisedSelectedPapers8,pages149–166.
Springer,2013. [36] RuofanLiu,YunLin,XianglinYang,SiangHweeNg,
|     |     |     |     |     |     |     | Dinil | Mon Divakaran,and |     | Jin Song | Dong. | Inferring |
| --- | --- | --- | --- | --- | --- | --- | ----- | ----------------- | --- | -------- | ----- | --------- |
[25] HirokiFuruta,OfirNachum,Kuang-HueiLee,Yutaka phishingintentionviawebpageappearanceanddynam-
| Matsuo,ShixiangShaneGu,andIzzeddinGur. |     |     |     |     |     | Multi- |        |             |                 |     |         |        |
| -------------------------------------- | --- | --- | --- | --- | --- | ------ | ------ | ----------- | --------------- | --- | ------- | ------ |
|                                        |     |     |     |     |     |        | ics: A | deep vision | based approach. |     | In 31st | USENIX |
modalwebnavigationwithinstruction-finetunedfoun- SecuritySymposium(USENIXSecurity22),pages1633–
| dationmodels. |     | arXivpreprintarXiv:2305.11854,2023. |     |     |     |     |     |     |     |     |     |     |
| ------------- | --- | ----------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
1650,2022.
[26] Yipeng Gao, Haichang Gao, Sainan Luo, Yang Zi, [37] RuofanLiu,YunLin,YifanZhang,PennHanLee,and
ShudongZhang,WenjieMao,PingWang,YulongShen,
|     |     |     |     |     |     |     | JinSongDong. | Knowledgeexpansionandcounterfac- |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | ------------ | -------------------------------- | --- | --- | --- | --- |
andJeffYan. Researchonthesecurityofvisualreason- tualinteractionfor{Reference-Based}phishingdetec-
| ing{CAPTCHA}. |     |     | In30thUSENIXsecuritysymposium |     |     |     |       |                                      |     |     |     |     |
| ------------- | --- | --- | ----------------------------- | --- | --- | --- | ----- | ------------------------------------ | --- | --- | --- | --- |
|               |     |     |                               |     |     |     | tion. | In32ndUSENIXSecuritySymposium(USENIX |     |     |     |     |
(USENIXsecurity21),pages3291–3308,2021.
Security23),pages4139–4156,2023.
[27] SujataGarera,NielsProvos,MonicaChew,andAvielD
[38] XinLiu,HuanruiYang,ZiweiLiu,LinghaoSong,Hai
| Rubin.             | A   | framework | fordetection              |     | and measurement |     |                    |     |                                 |     |     |     |
| ------------------ | --- | --------- | ------------------------- | --- | --------------- | --- | ------------------ | --- | ------------------------------- | --- | --- | --- |
|                    |     |           |                           |     |                 |     | Li,andYiranChen.   |     | Dpatch:Anadversarialpatchattack |     |     |     |
| ofphishingattacks. |     |           | InProceedingsofthe2007ACM |     |                 |     |                    |     |                                 |     |     |     |
|                    |     |           |                           |     |                 |     | onobjectdetectors. |     | arXivpreprintarXiv:1806.02299,  |     |     |     |
workshoponRecurringmalcode,pages1–8,2007.
2018.
| [28] Ian | J Goodfellow, |                                         | Jonathon | Shlens, | and | Christian |                     |            |                                |     |       |            |
| -------- | ------------- | --------------------------------------- | -------- | ------- | --- | --------- | ------------------- | ---------- | ------------------------------ | --- | ----- | ---------- |
|          |               |                                         |          |         |     |           | [39] Christian      | Ludl, Sean | McAllister,                    |     | Engin | Kirda, and |
| Szegedy. |               | Explainingandharnessingadversarialexam- |          |         |     |           |                     |            |                                |     |       |            |
|          |               |                                         |          |         |     |           | ChristopherKruegel. |            | Ontheeffectivenessoftechniques |     |       |            |
ples. arXivpreprintarXiv:1412.6572,2014. InDetectionofIntrusionsand
todetectphishingsites.
[29] R Gossweiler, M Kamvar, and S Baluja. A captcha Malware, and Vulnerability Assessment: 4th Interna-
tionalConference,DIMVA2007Lucerne,Switzerland,
| basedonimageorientation. |     |     |     | Proc.ACM,2009. |     |     |     |     |     |     |     |     |
| ------------------------ | --- | --- | --- | -------------- | --- | --- | --- | --- | --- | --- | --- | --- |
July12-13,2007Proceedings4,pages20–39.Springer,
[30] DorjanHitaj,BrilandHitaj,SushilJajodia,andLuigiV
2007.
| Mancini. |     | Capturethebot:Usingadversarialexamples |     |     |     |     |     |     |     |     |     |     |
| -------- | --- | -------------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
to improve captcha robustness to bot attacks. IEEE [40] Aleksander Madry, Aleksandar Makelov, Ludwig
|     |     |     |     |     |     |     | Schmidt,DimitrisTsipras,andAdrianVladu. |     |     |     |     | Towards |
| --- | --- | --- | --- | --- | --- | --- | --------------------------------------- | --- | --- | --- | --- | ------- |
IntelligentSystems,36(5):104–112,2020.
|         |       |         |        |     |          |        | deep learning | models | resistant | to adversarial |     | attacks. |
| ------- | ----- | ------- | ------ | --- | -------- | ------ | ------------- | ------ | --------- | -------------- | --- | -------- |
| [31] Md | Imran | Hossen, | Yazhou | Tu, | Md Fazle | Rabby, |               |        |           |                |     |          |
arXivpreprintarXiv:1706.06083,2017.
| Md  | Nazmul | Islam, | Hui | Cao, and | Xiali | Hei. An |     |     |     |     |     |     |
| --- | ------ | ------ | --- | -------- | ----- | ------- | --- | --- | --- | --- | --- | --- |
object detection based solver for {Google’s} image [41] SourenaMaroofi,MaciejKorczyn´ski,andAndrzejDuda.
{reCAPTCHA}v2. In23rdinternationalsymposium Areyouhuman?resilienceofphishingdetectiontoeva-
onresearchinattacks,intrusionsanddefenses(RAID sion techniques basedon human verification. In Pro-
2020),pages269–284,2020. ceedingsoftheACMInternetMeasurementConference,
pages78–86,2020.
| [32] Luca | Invernizzi, |     | Kurt Thomas, | Alexandros |     | Kaprave- |     |     |     |     |     |     |
| --------- | ----------- | --- | ------------ | ---------- | --- | -------- | --- | --- | --- | --- | --- | --- |
los, Oxana Comanescu, Jean-Michel Picod, and Elie [42] Eric Medvet, Engin Kirda, and Christopher Kruegel.
Bursztein.Cloakofvisibility:Detectingwhenmachines Visual-similarity-basedphishingdetection. InProceed-
browseadifferentweb. In2016IEEESymposiumon ingsofthe4thinternationalconferenceonSecurityand
SecurityandPrivacy(SP),pages743–758.IEEE,2016. privacyincommunicationnetowrks,pages1–6,2008.
| 520    33rd USENIX Security Symposium |     |     |     |     |     |     |     |     |     | USENIX Association |     |     |
| ------------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ------------------ | --- | --- |

[43] XianghangMi,XuanFeng,XiaojingLiao,BaojunLiu, 2016IEEEEuropeansymposiumonsecurityandpri-
XiaoFengWang,FengQian,ZhouLi,SumayahAlrwais, vacy(EuroS&P),pages372–387.IEEE,2016.
| LiminSun,andYingLiu. |     |     |     | Residentevil:Understanding |     |     |     |     |     |     |     |     |
| -------------------- | --- | --- | --- | -------------------------- | --- | --- | --- | --- | --- | --- | --- | --- |
[52] PengPeng,LiminYang,LinhaiSong,andGangWang.
| residential |     | ip proxy | as a dark | service. | In 2019 | IEEE |     |     |     |     |     |     |
| ----------- | --- | -------- | --------- | -------- | ------- | ---- | --- | --- | --- | --- | --- | --- |
symposiumonsecurityandprivacy(SP),pages1185– Openingtheblackboxofvirustotal:Analyzingonline
|     |     |     |     |     |     |     | phishingscanengines. |     |     | InProceedingsoftheInternet |     |     |
| --- | --- | --- | --- | --- | --- | --- | -------------------- | --- | --- | -------------------------- | --- | --- |
1201.IEEE,2019.
MeasurementConference,pages478–485,2019.
[44] Seyed-MohsenMoosavi-Dezfooli,AlhusseinFawzi,and
|                                 |           |     |           |          |               |          | [53] Shaoqing | Ren,                                        | Kaiming  | He,       | Ross Girshick, | and Jian  |
| ------------------------------- | --------- | --- | --------- | -------- | ------------- | -------- | ------------- | ------------------------------------------- | -------- | --------- | -------------- | --------- |
| Pascal                          | Frossard. |     | Deepfool: | a simple | and           | accurate |               |                                             |          |           |                |           |
|                                 |           |     |           |          |               |          | Sun.          | Fasterr-cnn:Towardsreal-timeobjectdetection |          |           |                |           |
| methodtofooldeepneuralnetworks. |           |     |           |          | InProceedings |          |               |                                             |          |           |                |           |
|                                 |           |     |           |          |               |          | with region   |                                             | proposal | networks. | Advances       | in neural |
oftheIEEEconferenceoncomputervisionandpattern
recognition,pages2574–2582,2016. informationprocessingsystems,28,2015.
[45] ReiichiroNakano,JacobHilton,SuchirBalaji,JeffWu, [54] AndrewSearles,YoshimichiNakatsuka,ErcanOzturk,
|     |     |     |     |     |     |     | AndrewPaverd,GeneTsudik,andAiEnkoji. |     |     |     |     | Anempir- |
| --- | --- | --- | --- | --- | --- | --- | ------------------------------------ | --- | --- | --- | --- | -------- |
LongOuyang,ChristinaKim,ChristopherHesse,Shan-
icalstudy&evaluationofmodern{CAPTCHAs}. In
| tanuJain,VineetKosaraju,WilliamSaunders,etal. |     |     |     |     |     | We- |     |     |     |     |     |     |
| --------------------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
32ndUSENIXSecuritySymposium(USENIXSecurity
bgpt:Browser-assistedquestion-answeringwithhuman
23),pages3081–3097,2023.
| feedback. |     | arXivpreprintarXiv:2112.09332,2021. |     |     |     |     |                                       |     |     |     |     |           |
| --------- | --- | ----------------------------------- | --- | --- | --- | --- | ------------------------------------- | --- | --- | --- | --- | --------- |
|           |     |                                     |     |     |     |     | [55] BaoguangShi,XiangBai,andCongYao. |     |     |     |     | Anend-to- |
[46] AdamOest,YeganehSafaei,AdamDoupé,Gail-Joon
endtrainableneuralnetworkforimage-basedsequence
| Ahn,BradWardman,andKevinTyers. |     |     |     |     | Phishfarm:A |     |     |     |     |     |     |     |
| ------------------------------ | --- | --- | --- | --- | ----------- | --- | --- | --- | --- | --- | --- | --- |
recognitionanditsapplicationtoscenetextrecognition.
scalableframeworkformeasuringtheeffectivenessof
IEEEtransactionsonpatternanalysisandmachinein-
evasiontechniquesagainstbrowserphishingblacklists.
In2019IEEESymposiumonSecurityandPrivacy(SP), telligence,39(11):2298–2304,2016.
pages1344–1361.IEEE,2019.
[56] ChenghuiShi,XiaogangXu,ShoulingJi,KaiBu,Jian-
|           |       |         |         |         |        |      | haiChen,RaheemBeyah,andTingWang. |     |     |     |     | Adversarial |
| --------- | ----- | ------- | ------- | ------- | ------ | ---- | -------------------------------- | --- | --- | --- | --- | ----------- |
| [47] Adam | Oest, | Yeganeh | Safaei, | Penghui | Zhang, | Brad |                                  |     |     |     |     |             |
captchas.IEEEtransactionsoncybernetics,52(7):6095–
Wardman,KevinTyers,YanShoshitaishvili,andAdam
6108,2021.
Doupé.{PhishTime}:Continuouslongitudinalmeasure-
| mentoftheeffectivenessofanti-phishingblacklists. |     |     |     |     |     | In  |                |           |     |       |          |               |
| ------------------------------------------------ | --- | --- | --- | --- | --- | --- | -------------- | --------- | --- | ----- | -------- | ------------- |
|                                                  |     |     |     |     |     |     | [57] Suphannee | Sivakorn, |     | Jason | Polakis, | and Angelos D |
29thUSENIXSecuritySymposium(USENIXSecurity
|     |     |     |     |     |     |     | Keromytis. | I’mnotahuman:Breakingthegooglere- |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | ---------- | --------------------------------- | --- | --- | --- | --- |
20),pages379–396,2020.
|           |       |          |        |              |     |           | captcha.       | BlackHat,14:1–12,2016. |                    |     |                  |             |
| --------- | ----- | -------- | ------ | ------------ | --- | --------- | -------------- | ---------------------- | ------------------ | --- | ---------------- | ----------- |
| [48] Adam | Oest, | Yeganeh  | Safei, | Adam Doupé,  |     | Gail-Joon |                |                        |                    |     |                  |             |
|           |       |          |        |              |     |           | [58] Philippe  | Skolka,                | Cristian-Alexandru |     |                  | Staicu, and |
| Ahn,      | Brad  | Wardman, | and    | Gary Warner. |     | Inside a  |                |                        |                    |     |                  |             |
|           |       |          |        |              |     |           | MichaelPradel. |                        | Anythingtohide?    |     | studyingminified |             |
phisher’smind:Understandingtheanti-phishingecosys- andobfuscatedcodeintheweb. InTheworldwideweb
| temthroughphishingkitanalysis. |     |     |     | In2018APWGSym- |     |     |     |     |     |     |     |     |
| ------------------------------ | --- | --- | --- | -------------- | --- | --- | --- | --- | --- | --- | --- | --- |
conference,pages1735–1746,2019.
posiumonElectronicCrimeResearch(eCrime),pages
1–12.IEEE,2018. [59] KarthikaSubramani,WilliamMelicher,OleksiiStarov,
|     |     |     |     |     |     |     | PhaniVadrevu,andRobertoPerdisci. |     |     |     |     | Phishinpatterns: |
| --- | --- | --- | --- | --- | --- | --- | -------------------------------- | --- | --- | --- | --- | ---------------- |
[49] AdamOest,PenghuiZhang,BradWardman,EricNunes,
measuringeliciteduserinteractionsatscaleonphishing
| Jakub | Burgis,Ali |     | Zand,Kurt | Thomas,Adam |     | Doupé, |           |     |             |     |          |              |
| ----- | ---------- | --- | --------- | ----------- | --- | ------ | --------- | --- | ----------- | --- | -------- | ------------ |
|       |            |     |           |             |     |        | websites. | In  | Proceedings | of  | the 22nd | ACM Internet |
andGail-JoonAhn. Sunrisetosunset:Analyzingthe MeasurementConference,pages589–604,2022.
end-to-endlifecycleandeffectivenessofphishingat-
tacksatscale. In29th{USENIX}SecuritySymposium [60] MingxingTanandQuocLe. Efficientnet:Rethinking
({USENIX}Security20),2020. model scaling for convolutional neural networks. In
|     |     |     |     |     |     |     | International |     | conference | on  | machine | learning,pages |
| --- | --- | --- | --- | --- | --- | --- | ------------- | --- | ---------- | --- | ------- | -------------- |
[50] MargaritaOsadchy,JulioHernandez-Castro,StuartGib-
6105–6114.PMLR,2019.
| son,OrrDunkelman,andDanielPérez-Cabo. |     |     |     |     |     | Nobot |     |     |     |     |     |     |
| ------------------------------------- | --- | --- | --- | --- | --- | ----- | --- | --- | --- | --- | --- | --- |
expectsthedeepcaptcha!introducingimmutableadver- [61] Rakesh Verma and Keith Dyer. On the character of
sarialexamples,withapplicationstocaptchageneration. phishingurls:Accurateandrobuststatisticallearning
IEEETransactionsonInformationForensicsandSecu- classifiers. InProceedingsofthe5thACMConference
rity,12(11):2640–2653,2017. onDataandApplicationSecurityandPrivacy,pages
111–122,2015.
[51] NicolasPapernot,PatrickMcDaniel,SomeshJha,Matt
Fredrikson,ZBerkayCelik,andAnanthramSwami.The [62] DanniWu,JingQiu,HuiwuHuang,LihuaYin,Zhao-
limitationsofdeeplearninginadversarialsettings. In quanGu,andZhihongTian. Resnet-basedslidepuzzle
| USENIX Association |     |     |     |     |     |     |     |     | 33rd USENIX Security Symposium    521 |     |     |     |
| ------------------ | --- | --- | --- | --- | --- | --- | --- | --- | ------------------------------------- | --- | --- | --- |

captchaautomaticresponsesystem. InArtificialIntelli- AblationDataset(Usage:see5.4).Contents:722webpage
genceandSecurity:6thInternationalConference,ICAIS screenshots(1920×1080),622withCAPTCHAsspanning
2020,Hohhot,China,July 17–20,2020,Proceedings, 38classes,100without.
PartIII6,pages140–153.Springer,2020. LandscapeDataset(Usage:see4.3).Contents:7,268natural
andman-madelandscapeimages(320×180).
| [63] Guang | Xiang,Jason      | Hong,Carolyn |                     | P Rose,and | Lor-     |     |     |     |     |     |     |     |
| ---------- | ---------------- | ------------ | ------------------- | ---------- | -------- | --- | --- | --- | --- | --- | --- | --- |
| rie        | Cranor. Cantina+ | a            | feature-richmachine |            | learning |     |     |     |     |     |     |     |
frameworkfordetectingphishingwebsites.ACMTrans-
actionsonInformationandSystemSecurity(TISSEC),
14(2):1–28,2011.
|     |     |     |     |     |     |     | (a) |     | (b) |     | (c) |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
[64] PenghuiZhang,AdamOest,HaehyunCho,ZhiboSun,
RCJohnson,BradWardman,ShaownSarker,Alexan-
Figure10:ExamplesofCAPTCHA(a)detection(b)recognition
drosKapravelos,TiffanyBao,RuoyuWang,etal.Crawl-
(c)open-setdatasets.
phish:Large-scaleanalysisofclient-sidecloakingtech-
| niquesinphishing. |     | In2021IEEESymposiumonSecu- |     |     |     |     |     |     |     |     |     |     |
| ----------------- | --- | -------------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
rityandPrivacy(SP),pages1109–1124.IEEE,2021.
A.2 VisualizationofAugmentationAttacks
[65] PenghuiZhang,ZhiboSun,SukwhaKyung,HansWal-
Figure11visualizestheaugmentationattacksusedinadver-
terBehrens,ZionLeonahenaheBasque,HaehyunCho,
sarialstudy.
| Adam            | Oest, Ruoyu | Wang,                               | Tiffany | Bao, | Yan Shoshi- |     |     |     |     |     |     |     |
| --------------- | ----------- | ----------------------------------- | ------- | ---- | ----------- | --- | --- | --- | --- | --- | --- | --- |
| taishvili,etal. |             | I’mspartacus,no,i’mspartacus:Proac- |         |      |             |     |     |     |     |     |     |     |
tivelyprotectingusersfromphishingbyintentionally
triggeringcloakingbehavior.InProceedingsofthe2022
ACMSIGSACConferenceonComputerandCommuni-
cationsSecurity,pages3165–3179,2022.
[66] YangZhang,HaichangGao,GePei,SainanLuo,Guo- (a)Salt&Pepper (b)GaussianNoise (c)GaussianBlur
| qin | Chang,andNuoCheng. |     | Asurveyofresearchon |     |     |     |     |     |     |     |     |     |
| --- | ------------------ | --- | ------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
Figure11:Examplesofadversarialaugmentations.
| captcha | designing | and | breaking | techniques. | In 2019 |     |     |     |     |     |     |     |
| ------- | --------- | --- | -------- | ----------- | ------- | --- | --- | --- | --- | --- | --- | --- |
18thIEEEInternationalConferenceOnTrust,Security
AndPrivacyInComputingAndCommunications/13th
IEEE International Conference On Big Data Science A.3 OtherHumanVerificationMethods
AndEngineering(TrustCom/BigDataSE),pages75–84.
Thissectionoffersaqualitativeanalysisofhumanverification
IEEE,2019.
|                                                    |     |     |     |     |         | methods        | apartfrom      | CAPTCHA | challenges |               | to rate-limitor |        |
| -------------------------------------------------- | --- | --- | --- | --- | ------- | -------------- | -------------- | ------- | ---------- | ------------- | --------------- | ------ |
| [67] BinbinZhao,HaiqinWeng,ShoulingJi,JianhaiChen, |     |     |     |     |         | blockvisitors. |                |         |            |               |                 |        |
|                                                    |     |     |     |     |         | TLS/SSL        | Fingerprinting |         | Identify   | the visitor’s | web             | client |
| TingWang,QinmingHe,andReheemBeyah.                 |     |     |     |     | Towards |                |                |         |            |               |                 |        |
evaluating the security of real-world deployed image using TLS and HTTP handshakes,and then present differ-
entcontentfordifferentclients.Countermeasure:handshake
| captchas.                                          | InProceedingsofthe11thACMWorkshopon |     |     |     |     |                   |     |     |     |     |     |     |
| -------------------------------------------------- | ----------------------------------- | --- | --- | --- | --- | ----------------- | --- | --- | --- | --- | --- | --- |
| ArtificialIntelligenceandSecurity,pages85–96,2018. |                                     |     |     |     |     | impersonation[4]. |     |     |     |     |     |     |
GeoIPFilteringRestrictaccessbasedonvisitor’sgeograph-
|     |     |     |     |     |     | ical | location and | IP addresse. | Countermeasure: |     |     | residential |
| --- | --- | --- | --- | --- | --- | ---- | ------------ | ------------ | --------------- | --- | --- | ----------- |
A Appendix
proxies[43].
BehaviorAnalysisAnalyzeinteractionsofmousecursorsto
A.1 SummaryofDatasets
distinguishbetweenhumanusersandautomatedbots.Coun-
termeasure:generatehuman-likemousetrajectories.
CAPTCHADetectionDataset(Usage:see5.2.1).Contents:
|     |     |     |     |     |     | BrowserFingerprinting |     |     | ExploitJavaScriptAPI |     |     | to gather |
| --- | --- | --- | --- | --- | --- | --------------------- | --- | --- | -------------------- | --- | --- | --------- |
19,680webpagescreenshots(1920×1080),10,680withan-
data(e.g.,screensize,screenorientation,displayaspectratio,
notatedCAPTCHAboundingboxes,9,000without.
devicehardware,fonts,plugins,extensions,user-agent)and
CAPTCHARecognitionDataset(Usage:see5.2.2).Con-
inferthevisitor’sidentity.Countermeasure:spoofing.
tents:6,612CAPTCHAimagesdistributedacross38classes.
CAPTCHAOpen-setDataset(Usage:see5.2.2).Contents:
1,500webpagescreenshots(1920×1080),allofwhichhave
| annotated | CAPTCHA | classes | spanning | 15 different | cate- |     |     |     |     |     |     |     |
| --------- | ------- | ------- | -------- | ------------ | ----- | --- | --- | --- | --- | --- | --- | --- |
gories.
| 522    33rd USENIX Security Symposium |     |     |     |     |     |     |     |     |     | USENIX Association |     |     |
| ------------------------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ------------------ | --- | --- |