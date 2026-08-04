2021 IEEE Symposium on Security and Privacy (SP)
CrawlPhish: Large-scale Analysis of
Client-side Cloaking Techniques in Phishing
Penghui Zhang∗, Adam Oest∗†, Haehyun Cho∗, Zhibo Sun∗, RC Johnson†, Brad Wardman†, Shaown Sarker‡,
Alexandros Kapravelos‡, Tiffany Bao∗, Ruoyu Wang∗, Yan Shoshitaishvili∗, Adam Doupe´∗ and Gail-Joon Ahn∗§
∗Arizona State University, †PayPal, Inc., ‡North Carolina State University, §Samsung Research
∗{penghui.zhang, aoest, haehyun, zhibo.sun, tbao, fishw, yans, doupe, gahn}@asu.edu
†{raouljohnson, bwardman}@paypal.com, ‡{ssarker, akaprav}@ncsu.edu
Abstract—Phishing is a critical threat to Internet users. Al- to delay or avoid detection by automated anti-phishing sys-
though an extensive ecosystem serves to protect users, phishing tems, which, in turn, maximizes the attackers’ return-on-
websites are growing in sophistication, and they can slip past
investment[43].Suchevasion—knownascloaking—typically
the ecosystem’s detection systems—and subsequently cause real-
seeks to determine if a visitor to the website is a bot, and
world damage—with the help of evasion techniques. Sophisti-
cated client-side evasion techniques, known as cloaking, leverage shows benign content if so. The danger posed by successful
JavaScript to enable complex interactions between potential evasionisexacerbatedbythesewebsites’effortstostealmore
victims and the phishing website, and can thus be particularly than just usernames and passwords: today’s phishing attacks
effectiveinslowingorentirelypreventingautomatedmitigations.
seek to harvest victims’ full identities, which can cause wider
Yet,neithertheprevalencenortheimpactofclient-sidecloaking
damage throughout the ecosystem and is more challenging to
has been studied.
effectively mitigate [54].
In this paper, we present CrawlPhish, a framework for
automaticallydetectingandcategorizingclient-sidecloakingused Thwarting phishers’ evasion efforts is, thus, an important
by known phishing websites. We deploy CrawlPhish over 14 problem within the anti-phishing community, as timely de-
monthsbetween2018and2019tocollectandthoroughlyanalyze tection is the key to successful mitigation. Prior research has
a dataset of 112,005 phishing websites in the wild. By adapting
characterizedserver-sidecloakingtechniquesusedbyphishing
state-of-the-art static and dynamic code analysis, we find that
websites [30,37,44] and showed that they can defeat key
35,067 of these websites have 1,128 distinct implementations of
client-sidecloakingtechniques.Moreover,wefindthatattackers’ ecosystem defenses such as browser-based detection [43].
use of cloaking grew from 23.32% initially to 33.70% by the However, the nature and prevalence of advanced cloaking
end of our data collection period. Detection of cloaking by our techniques,suchasthoseimplementedontheclient-sideusing
frameworkexhibitedlowfalse-positiveandfalse-negativeratesof
JavaScript, is poorly understood. Client-side cloaking can be
1.45% and 1.75%, respectively. We analyze the semantics of the
particularly dangerous because it enables the implementation
techniques we detected and propose a taxonomy of eight types
of evasion across three high-level categories: User Interaction, of complex interactions with potential victims.
Fingerprinting, and Bot Behavior. By analyzing—at scale—the client-side source code of
Using 150 artificial phishing websites, we empirically show known phishing websites in the wild, we can not only gain
that each category of evasion technique is effective in avoiding
an understanding of the evasion techniques used by phish-
browser-based phishing detection (a key ecosystem defense).
ers, but also leverage this understanding to improve existing
Additionally,throughauserstudy,weverifythatthetechniques
generally do not discourage victim visits. Therefore, we propose phishing detection systems and guide the mitigations used
waysinwhichourmethodologycanbeusedtonotonlyimprove by the ecosystem. Unlike server-side code used by phishing
the ecosystem’s ability to mitigate phishing websites with client- websites, client-side code can trivially be obtained through
side cloaking, but also continuously identify emerging cloaking web crawling. However, a key challenge in gaining further
techniques as they are launched by attackers.
insights from this data is the dynamic nature of JavaScript
code, which hampers automated analysis [32]. In this paper,
I. INTRODUCTION
we overcome this challenge and evaluate client-side evasion
Despite extensive research by the security community, by developing CrawlPhish.
phishingattacksremainprofitabletoattackersandcontinueto CrawlPhish is a robust framework that harvests the source
causesubstantialdamagenotonlytothevictimusersthatthey code of live, previously reported phishing websites in the
target, but also the organizations they impersonate [27,55]. In wild and automatically detects and categorizes the client-
recent years, phishing websites have taken the place of mal- side cloaking techniques used by these websites. By effi-
warewebsitesasthemostprevalentweb-basedthreat[22,52]. ciently adapting advanced program analysis techniques in-
Even though technical countermeasures effectively mitigate spiredbypriorresearchofJavaScriptmalware[18,32,34,36],
web-based malware, phishing websites continue to grow in our framework can not only identify the semantics of these
sophisticationandsuccessfullyslippastmoderndefenses[46]. cloaking techniques, but also track the evolution of code
In a cat-and-mouse game with the anti-phishing ecosystem, written by specific phishing kit authors [16].
sophisticated phishing websites implement evasion techniques We use the CrawlPhish framework to perform a large-scale
© 2021, Penghui Zhang. Under license to IEEE. 1109
DOI 10.1109/SP40001.2021.00021
12000.1202.10004PS/9011.01
:IOD
| EEEI
1202©
00.13$/12/5-4398-1827-1-879
|
)PS(
ycavirP
dna
ytiruceS
no
muisopmyS
EEEI
1202
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore. Restrictions apply.

evaluation of the landscape of client-side cloaking used by CloakingType Attributes Examples
phishing websites. In total, over a period of 14 months from RepeatCloaking
IPCloaking
mid-2018 to mid-2019, we collected and thoroughly analyzed Server-side HTTPRequest User-agentCloaking
ReferrerCloaking
112,005 phishing websites. We measured the prevalence of
client-side cloaking techniques within these websites and Client-sideCharacteristics Redirection
Client-side
ExecutionofJavaScript Cloaking
discovered that 35,067 (31.3%) use such cloaking. Thereof,
we identified 1,128 groups of related implementations which
TABLE I: Summary of cloaking types from previous studies.
we believe stem from distinct threat actors. Moreover, we
observed that the percentage of phishing websites with client-
side cloaking grew from 23.32% in 2018 to 33.70% in 2019. evaluation showing that these techniques represent a
To understand why client-side cloaking is used so fre- threat to the current ecosystem.
quently,wecharacterizethewaysinwhichitfunctions,andwe • Methodology for improving the ability of ecosystem
defineeightdifferenttypesofevasiontechniquesinthreehigh- anti-phishing defenses to detect highly evasive phishing
level categories: User Interaction, Fingerprinting, and Bot websites.
Behavior. Respectively, the techniques within these categories
require human visitors to perform a task, profile the visitor
II. BACKGROUND
based on various attributes, or exploit technical differences Over the past years, a myriad of techniques have been
between browsers used by crawlers and real browsers. implemented by the anti-phishing ecosystem to detect and
We evaluated CrawlPhish and found that it could detect the mitigatephishingattacks[44].AnalysisofphishingURLs[11,
presenceofcloakingwithlowfalse-positive(1.45%)andfalse- 12,29,33] and website content [10,13,62,64,67] has given
negative (1.75%) rates, while requiring an average of 29.96 rise to ecosystem-level defenses such as e-mail spam filters,
seconds to analyze each phishing website. Once CrawlPhish malicious infrastructure detection, and URL blacklists.
has detected cloaking, it can then reliably categorize the Specifically, systems such as Google Safe Browsing [61]
semantics of the cloaking technique by using both static and and Microsoft SmartScreen [40] power the anti-phishing
dynamic code features. backends that display prominent warnings across major web
browsers when phishing is detected. These warnings are pri-
Finally,toshowthatclient-sidecloakingposesareal-world
marily blacklist-based: they rely on content-based detection.
threat, we deploy 150 carefully-controlled artificial phishing
Evasion techniques commonly used by phishing websites are
websites to empirically demonstrate that all three categories
capableofbypassingordelayingsuchblacklisting[38,43,45].
of evasion can successfully bypass browser-based detection
by Google Chrome, Microsoft Edge, and other major web
A. Cloaking Techniques in Phishing
browsers. We also demonstrate that these websites remain ac-
Attackers leverage cloaking techniques to evade detection
cessible to potential human victims. As a result, we disclosed
by anti-phishing systems: phishing websites with cloaking
our findings to the aforementioned browser developers, who
display benign-looking content instead of the phishing page
are working to improve the timeliness of the detection of the
whenever they suspect that a visit originates from security
corresponding phishing websites.
infrastructure [44]. Cloaking techniques can be categorized
Our analysis furthers the understanding of the nature of
into two groups: server-side and client-side (Table I shows
sophisticated phishing websites. In addition, the CrawlPhish
examples of each type). Server-side cloaking techniques iden-
framework can be deployed to continuously monitor trends
tify users via information in HTTP requests [59]. Client-side
within complex evasion techniques while identifying new
cloakingisimplementedthroughcodethatrunsinthevisitor’s
types of techniques as they are introduced by attackers. Our
browser (JavaScript) to apply filters using attributes such as
methodology can not only directly help address gaps in the
cookies or mouse movement.
ecosystem’s detection of sophisticated phishing websites, but
Existing anti-cloaking methodologies focus on bypassing
can also aid in the development of attributes to improve exist-
server-side cloaking by comparing the visual and textual
inganti-phishingmitigationssuchasbrowser-baseddetection.
features of different versions of a crawled website retrieved
Our contributions are thus as follows:
bysendingmultiplewebrequestswithdifferentconfigurations
• A scalable, automated framework for evaluating client- (e.g., user agents or IP addresses) [25,30,59]. Client-side
side evasion techniques used by phishing websites in cloaking techniques, however, are still poorly understood due
the wild, supported by a novel adaptation of multiple to challenges in automatically analyzing JavaScript code and
JavaScript code analysis approaches. understanding its semantics. Moreover, neither the prevalence
• The first in-depth study of the nature and prevalence norimpactofclient-sidecloakinghasbeeninvestigatedinthe
of client-side evasion techniques used by sophisticated context of phishing.
phishing websites, and a taxonomy of these techniques Figure1showshowclient-sidecloakingtechniquesareused
based on semantic categorization. in phishing websites. Cloaking code embedded in the HTTP
• Measurements indicating the increasing use of client- response payload shows different web page content based on
side evasion techniques by phishers, and an empirical the identification of visitors (as either potential victims or
1110
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore. Restrictions apply.

|     |     |     |     |     |     |     |     | CloakingCategory |     | Cloakingtype |     |     | Requirement |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------------- | --- | ------------ | --- | --- | ----------- | --- | --- |
Phishing Website
|     |     |     |     |     |              |     |     |                 |     |                | Pop-up   | Clickonalert/notificationwindow |     |     |     |
| --- | --- | --- | --- | --- | ------------ | --- | --- | --------------- | --- | -------------- | -------- | ------------------------------- | --- | --- | --- |
|     |     |     |     |     | Visited      |     |     | UserInteraction |     | MouseDetection |          | Movemouseoverbrowser            |     |     |     |
|     |     |     |     |     |              |     |     |                 |     | ClickThrough   |          | PassClickThroughonbrowser       |     |     |     |
|     |     |     |     |     |              |     |     |                 |     |                | Cookie   | Checkdocument.cookie            |     |     |     |
|     |     |     |     |     | Same Payload |     |     | Fingerprinting  |     |                | Referrer | Checkdocument.referrer          |     |     |     |
|     |     |     |     |     |              |     |     |                 |     | User-Agent     |          | Checknavigator.userAgent        |     |     |     |
Renderwebpageaftercertaintime
Timing
|     |     |     |     |     | Visitor |     |     |     |     |     |     | usingsleep()/Date.getTime() |     |     |     |
| --- | --- | --- | --- | --- | ------- | --- | --- | --- | --- | --- | --- | --------------------------- | --- | --- | --- |
BotBehavior
|     |     |     |     |     | Identification |     |     |     |     | Randomization |     | Showcontentrandomlyusing |     |     |     |
| --- | --- | --- | --- | --- | -------------- | --- | --- | --- | --- | ------------- | --- | ------------------------ | --- | --- | --- |
Math.random()
Phishing or Benign
|     |     |     |     |     |     |     |     | TABLE | II: Summary |     | of the | client-side | cloaking | technique |     |
| --- | --- | --- | --- | --- | --- | --- | --- | ----- | ----------- | --- | ------ | ----------- | -------- | --------- | --- |
Content Shown Based
|     |     |     |     |     |     |     |     | types identified |     | in this | work. |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------------- | --- | ------- | ----- | --- | --- | --- | --- |
on Visitor Identification
| Fig. 1: | Typical | operation | of client-side |     | cloaking | in  | phishing |     |     |     |     |     |     |     |     |
| ------- | ------- | --------- | -------------- | --- | -------- | --- | -------- | --- | --- | --- | --- | --- | --- | --- | --- |
websites.
III. OVERVIEW
|     |     |     |     |     |     |     |     | Client-side |     | cloaking | techniques | can | help | phishing | websites |
| --- | --- | --- | --- | --- | --- | --- | --- | ----------- | --- | -------- | ---------- | --- | ---- | -------- | -------- |
bots). Consequently, cloaked phishing websites may have a evadedetectionbyanti-phishingentities[43],yetpriorstudies
| longer life | span | than ones | without: | by  | delaying | or  | avoiding |          |              |     |      |            |         |          |      |
| ----------- | ---- | --------- | -------- | --- | -------- | --- | -------- | -------- | ------------ | --- | ---- | ---------- | ------- | -------- | ---- |
|             |      |           |          |     |          |     |          | have not | investigated |     | them | in detail, | despite | evidence | that |
detection, the attackers who launch these websites maximize sophisticated phishing websites—such as those with client-
| their return-on-investment |     |     | [43]. | Because | client-side |     | evasion |                   |     |             |     |     |            |               |     |
| -------------------------- | --- | --- | ----- | ------- | ----------- | --- | ------- | ----------------- | --- | ----------- | --- | --- | ---------- | ------------- | --- |
|                            |     |     |       |         |             |     |         | side cloaking—are |     | responsible |     | for | a majority | of real-world |     |
techniques enable complex interactions between potential vic- damage due to phishing [46].
| tims and  | phishing  | websites, | they      | may  | be more     | effective   |     | in          |     |       |           |       |               |     |          |
| --------- | --------- | --------- | --------- | ---- | ----------- | ----------- | --- | ----------- | --- | ----- | --------- | ----- | ------------- | --- | -------- |
|           |           |           |           |      |             |             |     | We discover |     | eight | different | types | of JavaScript |     | cloaking |
| hampering | automated |           | detection | than | traditional | server-side |     |             |     |       |           |       |               |     |          |
techniquesacrossthreehigh-levelcategories:UserInteraction,
cloaking, and, thus, pose a threat to potential victim users. Fingerprinting, and Bot Behavior (summarized in Table II).
B. Challenges in Analyzing Client-side Cloaking Cloaking techniques in the User Interaction category show
|     |     |     |     |     |     |     |     | phishing | content | only | if visitors |     | interact | with a | phishing |
| --- | --- | --- | --- | --- | --- | --- | --- | -------- | ------- | ---- | ----------- | --- | -------- | ------ | -------- |
Unlikeserver-sidecode,theclient-sidecode(JavaScript)of
|     |     |     |     |     |     |     |     | website | (e.g., | by moving | the | mouse | or clicking | a   | specific |
| --- | --- | --- | --- | --- | --- | --- | --- | ------- | ------ | --------- | --- | ----- | ----------- | --- | -------- |
websitescantriviallybeobtainedthroughcrawling.Therefore,
button).PhishingwebsiteswithFingerprintingidentifyvisitors
| malicious | websites  | typically | leverage  |        | code obfuscation |                 | meth- |               |          |                   |      |     |           |          |           |
| --------- | --------- | --------- | --------- | ------ | ---------------- | --------------- | ----- | ------------- | -------- | ----------------- | ---- | --- | --------- | -------- | --------- |
|           |           |           |           |        |                  |                 |       | by inspecting |          | the configuration |      | of  | browsers  | or web   | requests. |
| ods such  | as string | array     | encoding, | object | key              | transformation, |       |               |          |                   |      |     |           |          |           |
|           |           |           |           |        |                  |                 |       | Finally,      | phishing | websites          | with | Bot | Detection | identify | anti-     |
deadcodeinjection,andevenfullencryption[17,31].Attack-
|     |     |     |     |     |     |     |     | phishing | crawlers | based | on factors |     | such as | how long | the web |
| --- | --- | --- | --- | --- | --- | --- | --- | -------- | -------- | ----- | ---------- | --- | ------- | -------- | ------- |
ersalsocandynamicallygenerateandexecutecode(e.g.,using
|     |     |     |     |     |     |     |     | page stays | open | and | whether | the | web request | is  | repeated |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------- | ---- | --- | ------- | --- | ----------- | --- | -------- |
eval)tohidemaliciousbehaviors.Suchobfuscationmethods
|     |     |     |     |     |     |     |     | after failing | initially. |     | We elaborate |     | on each | cloaking | type |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------- | ---------- | --- | ------------ | --- | ------- | -------- | ---- |
poseachallengeforstaticcodeanalysisapproaches,whichare
|           |         |           |             |     |     |     |     | in Section | VI-A. |     |     |     |     |     |     |
| --------- | ------- | --------- | ----------- | --- | --- | --- | --- | ---------- | ----- | --- | --- | --- | --- | --- | --- |
| otherwise | favored | for their | efficiency. |     |     |     |     |            |       |     |     |     |     |     |     |
Weaimtocomprehensivelyunderstandandcharacterizethe
| Other              | types         | of obfuscation |               | also seek         | to prevent |            | dynamic |           |                |              |           |              |         |             |          |
| ------------------ | ------------- | -------------- | ------------- | ----------------- | ---------- | ---------- | ------- | --------- | -------------- | ------------ | --------- | ------------ | ------- | ----------- | -------- |
|                    |               |                |               |                   |            |            |         | landscape | of client-side |              | cloaking  | techniques   |         | used by     | phishing |
| analysis           | approaches    | from           | detecting     | malicious         |            | behaviors. | Ma-     |           |                |              |           |              |         |             |          |
|                    |               |                |               |                   |            |            |         | websites  | in the         | wild through |           | an automated |         | methodology | for      |
| licious JavaScript |               | code           | often targets | specific          |            | versions   | of web  |           |                |              |           |              |         |             |          |
|                    |               |                |               |                   |            |            |         | analyzing | them.          | To           | this end, | we           | design, | implement,  | and      |
| browsers           | and operating |                | systems       | by fingerprinting |            | them       | [18].   |           |                |              |           |              |         |             |          |
Suchattacksaredifficulttodiscoverbecausedetectionsystems evaluate CrawlPhish: a framework that automatically detects
|     |     |     |     |     |     |     |     | and analyzes |     | client-side | cloaking |     | within phishing |     | websites. |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------ | --- | ----------- | -------- | --- | --------------- | --- | --------- |
requireextensiveresourcestorevealtheconditionsthattrigger
Figure2providesanoverviewoftheCrawlPhisharchitecture.
| attacks | [17]. Besides, |     | external | and inter-block |     | dependencies, |     |            |     |          |     |               |             |     |     |
| ------- | -------------- | --- | -------- | --------------- | --- | ------------- | --- | ---------- | --- | -------- | --- | ------------- | ----------- | --- | --- |
|         |                |     |          |                 |     |               |     | CrawlPhish | is  | composed | of  | the following | components: |     |     |
whichrequirerecordingstatesindifferentexecutionpaths,can
be obstacles that thwart the analysis of JavaScript code [34]. 1 Crawling and pre-processing (§IV-A): CrawlPhish first
Furthermore, scripts may execute in an event-driven manner collectswebpagesourcecode(alongwithanyexternalfile
to necessitate external triggers to initiate malicious behavior inclusions)byvisitinglivephishingwebsiteURLsrecently
while otherwise appearing benign [34]. reported to anti-phishing feeds. We then filter URLs that
All of the aforementioned anti-analysis methods can po- cannotberetrievedaswellasURLswithoutanyJavaScript
| tentially | be leveraged | by  | phishing | websites’ |     | implementations |     | code. |     |     |     |     |     |     |     |
| --------- | ------------ | --- | -------- | --------- | --- | --------------- | --- | ----- | --- | --- | --- | --- | --- | --- | --- |
of client-side cloaking techniques. Given the difficulty of 2 Feature extraction (§IV-B): CrawlPhish adapts a state-
analyzing such cloaking, the security community struggles to of-the-art code analysis method, forced execution [34], to
thoroughly understand the impact and prevalence of phish- execute JavaScript regardless of branch conditions, and
ers’ tactics, and, thus, may fail to appropriately mitigate extracts all possible execution paths in which evasion
them. When we consider the scale on which phishing attacks techniques could be implemented. We then derive (1)
occur [9], the consequences of the corresponding gaps in visual features of the rendered web pages, by means of
detection and mitigation can be significant. screenshots, and (2) code structure features such as web
1111
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore.  Restrictions apply.

Manual
Live HAR Files Prune Uncloaked Cloaking Type Inspection
Phishing Blank yes yes
URLs Pages
Prune Data Forced Visual Code no
Execution Screenshots Similarity Similarity
Crawler
Engine Matches? Matches? Cloaking
User I -A Ps gents W Ph e i b sh si i t n e g s API Event AST W O e r b ig p in ag a e l Cloake n d o T D ec a h ta n b iq a u se e
Code Structure
① Crawling & Pre-processing ② Feature Extraction ③ Cloaking Detection ④ Type Categorization
Fig. 2: CrawlPhish architecture.
API calls, event listeners, and the Abstract Syntax Tree (1) APWG Dataset: CrawlPhish collected the source code of
(AST) for each path. 28,973 phishing websites from June to December 2018 and
3 Cloaking detection (§IV-C): CrawlPhishanalyzesthevi- 100,000websitesfromMaytoNovember2019usingtheAnti-
sualfeaturescorrespondingtoeachexecutionpathtodetect Phishing Working Group (APWG) URL feed [51].
if cloaking exists, and it stores the corresponding code (2) Public Dataset: Phishing website source code from
structure features of every such path. September to December 2019 from various well-known
4 Cloaking categorization (§IV-D): Using the code struc- sources, shared publicly by a security researcher [24].
ture features, CrawlPhish categorizes the cloaking tech- Ethics. We ensured that our experiments did not cause any
niquesusedbyphishingwebsitesbasedontheirsemantics. disruption to legitimate Internet infrastructure or negatively
impact any human users. Our crawling (Section IV-A) did not
After presenting CrawlPhish and the resulting analysis of
negatively affect any legitimate websites because CrawlPhish
cloaking techniques, we evaluate our approach, as described
prunedthosewebsitesbeforeinitiatinganalysis.Theuserstudy
below, to ensure that our methodology can help improve user
in Section VII-B underwent the IRB review and received
security by enhancing the ability of anti-phishing systems to
approval. During this study, we did not ask for or acquire any
detect and bypass attackers’ evasion techniques.
Personally Identifiable Information (PII) from participants. In
§V. Detection of cloaked phishing websites: We first eval-
addition,nohumanuserseversawanyoftheartificialphishing
uate the effectiveness of CrawlPhish on the dataset of
websites discussed in Section VII-A, nor were these websites
112,005 phishing websites that we crawled. We show that
configured to collect any data that may have been submitted.
CrawlPhish can detect the presence of client-side cloaking
withverylowfalse-negativeandfalse-positiverates(1.75% IV. CRAWLPHISHDESIGN
and 1.45%, respectively).
The design goal of CrawlPhish is to detect and categorize
§VI. Cloaking categorization: We measure the prevalence
client-side cloaking techniques in an automated manner while
of client-side cloaking techniques in the wild and char-
overcoming the JavaScript code analysis challenges discussed
acterizeeightdifferenttypesinthreehigh-levelcategories.
in Section II-B.
Also, we evaluate CrawlPhish to show that it can reliably
categorize the semantics of each cloaking technique. We A. Crawling & Pre-processing
compare the findings from our crawled dataset with an Tocollectthesourcecodeoflivephishingwebsitestodetect
additionaldatasetof100,000phishingwebsites.Moreover, and classify client-side evasion methods that are currently
we analyze the source code that CrawlPhish collected employedinthewild,CrawlPhishfirstobtainsURLsofknown
to identify and group related cloaking implementations. phishing websites in real-time.
Tracking the deployment and evolution of such code can Inourdeployment,CrawlPhishcontinuouslyingestedURLs
beindicativeofsophisticatedphishingkits,whichcanhelp from the APWG eCrime Exchange database—a curated clear-
security researchers pinpoint the threat actor and track the inghouse of phishing URLs maintained by various organiza-
associated attack volume. tions engaged in anti-phishing. Because this database receives
§VII. Impact of cloaking techniques: We deploy 150 arti- frequent updates and tracks phishing URLs that target a
ficial phishing websites to empirically demonstrate that diverse range of brands, it is well-suited for phishing website
all three categories of evasion can successfully bypass analysis.1 Note, however, that the inclusion of a URL in the
detectionbytheanti-phishingbackendsusedinmajorweb database does not mean that it was adequately mitigated (e.g.,
browsers.Separately,weconductauserstudytoshowthat
humanusersremainlikelytointeractwithcloakedphishing 1 Although the goal of cloaking is to evade detection by automated anti-
phishingsystems,suchevasionwilloftendelaydetectionratherthanoutright
pages.Throughtheseexperiments,weshowthatclient-side
prevent it. Phishing websites may also be detected by other means (e.g.,
cloaking poses a real-world threat. manual review) [46]. Thus, we expected the AWPG database to contain a
representativesamplingofanyclient-sidecloakingthatmightbeusedinthe
Dataset. In our evaluation, we use two different datasets. wild.
1112
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore. Restrictions apply.

through timely blacklisting) [45]. Hence, websites found to the median execution time was 13.82 seconds, the average
use sophisticated client-side cloaking still warrant scrutiny. execution time was 29.96 seconds, and the standard deviation
Next, CrawlPhish downloads source code by visiting each was 54.89 seconds. Based on this experiment, we chose a
phishing website URL (shortly after being ingested) us- finalexecutionlimitof195seconds(threestandarddeviations
ing a programmatically controlled web browser. Specifically, above the mean) so that CrawlPhish could efficiently analyze
CrawlPhish stores source code using HAR files [57], which the majority of phishing websites.
capture all HTTP requests/responses between our client and Feature extraction. To facilitate detection of (the existence
the server, and ensure that all dependencies (such as linked of) cloaking and categorization of the corresponding cloaking
scripts) are preserved for each website. In case of a failed type, CrawlPhish extracts both visual and code structure
request,CrawlPhishswitchesbetweendifferentconfigurations features from each phishing website. Each phishing website’s
of IP addresses and user-agents in an effort to circumvent visual features consist of the set of all web page screenshots
potential server-side cloaking techniques used by phishing (inourimplementation,ataresolutionof2,495×1,576pixels)
websites [44]. 4,823 of the 128,973 websites we crawled captured after every possible execution path is explored by
(3.74%) showed different response status codes after we forced execution. In our dataset, each website generated 46.3
switched request configurations. screenshots on average. CrawlPhish compares the screenshots
Finally, CrawlPhish filters out URLs that contain blank ofeachexecutionpathwithinonewebsiteagainsttheoriginal
| pages or | non-phishing | websites. | Such | websites | were | either |     |     |     |     |     |     |     |     |
| -------- | ------------ | --------- | ---- | -------- | ---- | ------ | --- | --- | --- | --- | --- | --- | --- | --- |
screenshottodetectifcloakingexists,becausethepresenceof
already taken down [7] or were false-positive detections by cloaking will result in significant visual layout changes [59].
the time of crawling. We found 0.53% of URLs within the The code structure features include web API calls, web event
APWG Dataset to be false positives. Therefore, CrawlPhish listeners, and ASTs, which can characterize different types of
excludes data in the following cases: cloaking techniques and reveal how the cloaking techniques
|          |           |         |         |      |             |     | are implemented. |     | Using | forced | execution, |     | CrawlPhish | can |
| -------- | --------- | ------- | ------- | ---- | ----------- | --- | ---------------- | --- | ----- | ------ | ---------- | --- | ---------- | --- |
| i. empty | websites: | servers | respond | with | no content. |     |                  |     |       |        |            |     |            |     |
ii. error websites: requests for URLs were denied because revealandextractthewebAPIsandeventscontainedinevery
|     |          |               |         |       |       |         | code block, | even | if the | code | is obfuscated. |     | CrawlPhish | can |
| --- | -------- | ------------- | ------- | ----- | ----- | ------- | ----------- | ---- | ------ | ---- | -------------- | --- | ---------- | --- |
| the | phishing | websites were | already | taken | down, | or used |             |      |        |      |                |     |            |     |
server-side cloaking which we could not bypass. then classify the cloaking types in a website using the code
| iii. non-phishingwebsites:mistakenlyreportedURLs,which |     |               |               |     |         |           | structure      | features. |          |       |           |     |                |     |
| ------------------------------------------------------ | --- | ------------- | ------------- | --- | ------- | --------- | -------------- | --------- | -------- | ----- | --------- | --- | -------------- | --- |
|                                                        |     |               |               |     |         |           | Code structure |           | features | used. | According |     | to preliminary |     |
| CrawlPhish                                             |     | filters based | on a manually |     | curated | whitelist |                |           |          |       |           |     |                |     |
of reputable domains. analysiswhichweconductedbymanuallyinspectingcloaking
|            |            |     |     |     |     |     | techniques | in a        | sampling | of phishing |            | websites | in our | dataset, |
| ---------- | ---------- | --- | --- | --- | --- | --- | ---------- | ----------- | -------- | ----------- | ---------- | -------- | ------ | -------- |
| B. Feature | Extraction |     |     |     |     |     |            |             |          |             |            |          |        |          |
|            |            |     |     |     |     |     | different  | client-side | cloaking |             | techniques | each     | have   | substan- |
Cloaked content detection. Client-side cloaking techniques tiallydifferentfeatures.Forexample,acloakingtechniquethat
used in phishing websites can be more diverse than server- checks mouse movement waits for an onmousemove event,
side cloaking because they can not only fingerprint visitors then performs DOM substitution or redirection. However, a
basedonconfigurationsofbrowsersandsystems,butmayalso cloaking technique that checks screen size would first access
screen.height
require visitors to interact with websites. To effectively detect the property. Therefore, as CrawlPhish
client-side cloaking techniques, CrawlPhish adapts J-Force: a executesacodeblockviaforcedexecution,itrecordstheweb
forcedexecutionframeworkimplementedintheWebKitGTK+ APIs and events that are invoked in the code block.
browserthatexecutesJavaScriptcodealongallpossiblepaths, Inaddition,wefoundthatthesamesemantictypesofclient-
crash-free, regardless of the possible branch conditions, event sidecloakingtechniqueshavemanydifferentimplementations.
handlers,andexceptions[34].WemodifiedJ-Forcetowhitelist
|     |     |     |     |     |     |     | CrawlPhish | distinguishes |     | between |     | different | implementations |     |
| --- | --- | --- | --- | --- | --- | --- | ---------- | ------------- | --- | ------- | --- | --------- | --------------- | --- |
(avoid force-executing) well-known JavaScript libraries, such of each type of cloaking technique by comparing ASTs.
as Google Analytics or jQuery, to expedite execution by Even though JavaScript code is often obfuscated, the AST
ignoring the benign content changes that such libraries could feature is still useful because most phishing websites are
introduce. deployed using phishing kits, so the corresponding websites,
| Execution | time | limit. We select | a time | limit | for each | invoca- |          |      |          |             |       |     |             |      |
| --------- | ---- | ---------------- | ------ | ----- | -------- | ------- | -------- | ---- | -------- | ----------- | ----- | --- | ----------- | ---- |
|           |      |                  |        |       |          |         | with the | same | phishing | kit origin, | share | the | same source | code |
tion of forced execution by CrawlPhish to avoid failures due structure [54]. Furthermore, by computing the AST similarity,
to long-running scrips (e.g., due to heavy branching or long- we can trace the origin of the cloaking technique by finding
runningloops).Notethatthistimelimitisinadditiontoother similar implementations earlier in phishing pages.
| anti-timeout | features | implemented |     | in the | forced | execution |     |     |     |     |     |     |     |     |
| ------------ | -------- | ----------- | --- | ------ | ------ | --------- | --- | --- | --- | --- | --- | --- | --- | --- |
framework, as discussed in Section IX-B. C. Cloaking Detection
As a starting point, we chose an execution limit of 300 CrawlPhish examines the visual similarity between force-
seconds. We conducted an experiment by force-executing executedscreenshotsandascreenshotofthewebsiterendered
2,000 randomly selected phishing websites in our crawled in an unmodified version of WebKitGTK+ (i.e., as would
dataset to record the execution time. We found that 1.75% be shown during a normal browser visit) to detect if cloak-
of phishing websites contained JavaScript code that exceeded ing exists. Because phishers implement JavaScript cloaking
thetimelimit.Executionfinishedasquicklyas12.56seconds, techniques to evade detection by anti-phishing systems, they
1113
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore.  Restrictions apply.

| remove      | suspicious |          | attributes | in     | websites | (e.g., login | forms)     |     |     |     |     |     |     |
| ----------- | ---------- | -------- | ---------- | ------ | -------- | ------------ | ---------- | --- | --- | --- | --- | --- | --- |
|             |            |          |            |        |          |              |            | 1   |     |     | 1   |     |     |
| or outright |            | redirect | to a       | benign | website. | Therefore,   | the visual |     |     |     |     |     |     |
|             |            |          |            |        |          |              |            | 0.8 |     |     | 0.8 |     |     |
contentshownwhenthecloakingconditionisnotsatisfiedwill
|        |               |          |      |            |               |           |          | etaRevitisoPeurT |     | etaRevitisoPeurT |     |     |     |
| ------ | ------------- | -------- | ---- | ---------- | ------------- | --------- | -------- | ---------------- | --- | ---------------- | --- | --- | --- |
| differ | significantly |          | from | that of    | the malicious | page.     |          |                  |     |                  |     |     |     |
|        |               |          |      |            |               |           |          | 0.6              |     |                  | 0.6 |     |     |
| For    | example,      | consider |      | a phishing | website       | that asks | visitors |                  |     |                  |     |     |     |
to click on a button in a pop-up window prior to showing 0.4 0.4
| the       | phishing | content.     | After | forced | execution, | two          | different |     |     |     |     |     |     |
| --------- | -------- | ------------ | ----- | ------ | ---------- | ------------ | --------- | --- | --- | --- | --- | --- | --- |
|           |          |              |       |        |            |              |           | 0.2 |     |     | 0.2 |     |     |
| execution |          | paths result | in    | two    | different  | screenshots: | one as    |     |     |     |     |     |     |
an initial benign-looking page (Figure 4a), and the other 0 0
|     |     |     |     |     |     |     |     | 0   | 0.5 | 1   | 0   | 0.5 | 1   |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
with phishing content (Figure 4b). Therefore, we consider a FalsePositiveRate FalsePositiveRate
| phishing |     | website | as cloaked | if  | any of | the screenshots | taken |                    |            |                                |     |     |     |
| -------- | --- | ------- | ---------- | --- | ------ | --------------- | ----- | ------------------ | ---------- | ------------------------------ | --- | --- | --- |
|          |     |         |            |     |        |                 |       | (a) Visual feature | threshold. | (b)Codestructurefeaturethresh- |     |     |     |
duringforcedexecutionnoticeablydifferfromtheoriginalone.
old.
| CrawlPhish |     | can | also reveal | phishing | content | hidden | behind |     |     |     |     |     |     |
| ---------- | --- | --- | ----------- | -------- | ------- | ------ | ------ | --- | --- | --- | --- | --- | --- |
multiple layers of cloaking. Consider a phishing website with Fig. 3: ROC curves to select thresholds for cloaking detection
|     |     |     |     |     |     |     |     | and cloaking | type categorization. |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------ | -------------------- | --- | --- | --- | --- |
acloakingtechniquethat(1)detectsmousemovementand(2)
checksthereferrersuchthatthemaliciouscontentwillappear
| only | if both   | requirements |            | are | met. CrawlPhish | will    | explore   |                  |           |          |          |      |         |
| ---- | --------- | ------------ | ---------- | --- | --------------- | ------- | --------- | ---------------- | --------- | -------- | -------- | ---- | ------- |
|      |           |              |            |     |                 |         |           | exhibited higher | detection | accuracy | (98.25%) | with | a lower |
| the  | execution | path         | that shows |     | the malicious   | content | by force- |                  |           |          |          |      |         |
executingit,regardlessofthebranchingconditions.Therefore, false-positive rate of 1.45% than what was indicated by the
|       |      |            |     |          |      |                |        | threshold in | the ROC curve. |     |     |     |     |
| ----- | ---- | ---------- | --- | -------- | ---- | -------------- | ------ | ------------ | -------------- | --- | --- | --- | --- |
| after | each | screenshot | is  | compared | with | the screenshot | of the |              |                |     |     |     |     |
originalpage,CrawlPhishdeterminesthatacloakingtechnique
|        |         |     |        |             |      |         |     | D. Cloaking | Categorization |     |     |     |     |
| ------ | ------- | --- | ------ | ----------- | ---- | ------- | --- | ----------- | -------------- | --- | --- | --- | --- |
| exists | because | one | of the | screenshots | will | differ. |     |             |                |     |     |     |     |
Removalofblankpagesafterforcedexecution.Screenshots OnceCrawlPhishdetectsthepresenceofcloakingonaweb
of pages rendered by force-executed paths may be blank, page, categorization of the specific type of cloaking allows us
|       |     |           |     |              |          |      |          | to measure | and understand | the prevalence |     | of different | high- |
| ----- | --- | --------- | --- | ------------ | -------- | ---- | -------- | ---------- | -------------- | -------------- | --- | ------------ | ----- |
| which | can | be caused | by  | (1) negative | branches | from | cloaking |            |                |                |     |              |       |
techniques (such as mouse movement detection) that require level client-side cloaking techniques used by phishers. To
user input or (2) execution paths that take longer to finish facilitate this categorization, CrawlPhish maintains a cloaking
than the execution time limit. In the latter case, CrawlPhish techniquedatabasethatcontainsthecodestructurefeaturesfor
can mislabel a website as cloaked if an initial screenshot is each instance of cloaking, annotated with the corresponding
compared to an empty page caused by unfinished execution cloaking semantics. Using the database, CrawlPhish can not
paths. For example, phishers may trigger an infinite loop if only identify known cloaking types, but also provide detailed
they identify that a visit is from an anti-phishing system. information about emerging cloaking techniques.
In this case, CrawlPhish cannot finish forced execution and Initial database. We first obtained 1,000 cloaked phishing
hencethescreenshotremainsempty.Thus,acurrentlimitation websites (true positives), for which we used CrawlPhish to
of CrawlPhish is that it cannot detect cloaked websites with determine the existence of client-side cloaking. Then, we
very long execution times, which we explain in Section IX. manuallyexaminedthesourcecodeofthephishingwebsitesto
However, according to our evaluation, this situation does not labelthecorrespondingcloakingtechniques.Wealsorecorded
happen often: only in 1.75% of the websites we considered. code structure features as ground truth.
Detection algorithm. To perform visual similarity checks For example, we labeled one type of cloaking tech-
between the screenshots, we implement the pHash algo- nique as Mouse Detection if the recorded code features
rithm [42], which compares visual similarity with robustness have the onmousemove event and use the window.
and good discrimination. We calculate pHash scores between location.hrefAPI.Overtime,asCrawlPhishexecutes,if
the original screenshot and those captured after each path the presence of cloaking is detected on a website but the code
finishes execution. features do not sufficiently closely match any of the records
inthedatabase,thewebsiteisflaggedformanualreviewsuch
|     | score=pHash(S |     |     | original | ,S i ),i∈[1,2,...,n] |     | (1) |     |     |     |     |     |     |
| --- | ------------- | --- | --- | -------- | -------------------- | --- | --- | --- | --- | --- | --- | --- | --- |
thatthemissingfeatures(and,potentially,newcloakingtypes)
In Formula 1, S represents each screenshot and n is the can be populated. Otherwise, the website is automatically
number of screenshots captured from forced execution. We labeledwiththecorrespondingsemanticcloakingtype.Within
consider two screenshots to be similar (no cloaking) if the the dataset we crawled, manual effort was rarely needed after
pHash score is less than a threshold (5.0) that we set based we populated the initial database. Thus, this requirement does
on preliminary testing results on 1,000 phishing websites. not impede the automated operation of our framework.
Differing screenshots will have a score of 5.0 or greater. Categorization algorithm. CrawlPhish employs the Ham-
Figure 3a shows the ROC curve for selecting the visual mingDistance(HD)algorithm[26] tocomputethesimilarity
similarity threshold. We selected the threshold that provides a of the API calls and web events. To this end, we use an
92.00%true-positiveratewitha6.77%false-positiverate.We array data structure with one position for each of the 4,012
note that our evaluation in Section V shows that CrawlPhish types of web API calls or events as defined by the Mozilla
1114
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore.  Restrictions apply.

MDN [3,20], which documents currently available web APIs. CrawledPhishing Analyzed
WebsitesFromAPWG
At each position in the array, we store the number of corre- Cloaked Non-cloaked
sponding API calls or events as observed by CrawlPhish. We TP FN
Cloaked
then convert this array to a fixed-length string (e.g., string[0] 1,965 98.25% 35 1.75%
Actual
is the number of ActiveXObject in the code block and FP TN
Non-cloaked
string[1]storestheamountofDateAPIcalls)sothatwecan 29 1.45% 1,971 98.55%
apply the HD algorithm. Thus, the result of the HD algorithm TABLE III: Accuracy of cloaking detection by CrawlPhish.
on a pair of strings represents the similarity of web APIs and
events between two code blocks. Lower HD values indicate
higher similarity.
to do so, because the goal of our detection is to study the
We also leverage JSInspect [4] to find structurally similar
nature of client-side cloaking, rather than to detect a phishing
code snippets based on the AST. This will identify code
attack. If CrawlPhish trades higher false negatives for lower
with a similar structure based on the AST node types (e.g.,
or even zero false positives, the study might be less complete
BlockStatement, VariableDeclaration, and ObjectExpression).
because we might miss many relevant instances of cloaking.
Wecombinetheseapproachestoovercomelimitationsofcode
Therefore, the detection of CrawlPhish should balance false
similarity checkers based solely on either ASTs or API calls.
positives with false negatives.
Consequently, by comparing the code structure similarity of
Eachofthe29false-positivecaseswascausedbyoneoftwo
all suspicious code blocks against records in the database, all
errors. The first error was due to the rending overhead of the
knowncloakingtypescanbeidentifiedinonewebsite(evenif
unmodified browser which loaded the original phishing page.
there are multiple types). If the features of a suspicious code
WebKitGTK+, the web browser we used in the CrawlPhish
blockarenotsufficientlysimilartoanyrecordinthedatabase,
framework, failed to render the original websites within an
wewillmanuallyexamineit,labelthecloakingtype,andthen
allottedtimelimitduetoalargenumberofCSSandJavaScript
add it to the database, which is the only process that requires
files included by the website. As a result, the original screen-
manual effort in the CrawlPhish framework.
shot of each website was blank, but the screenshots after
Similar to the visual similarity check, we empirically set a
forced execution were not blank, so CrawlPhish mislabeled
threshold for the code similarity check based on preliminary
thecorrespondingwebsitesascloakedbecausethescreenshots
manual analysis of 1,000 cloaked phishing websites. We
differed before and after forced execution. The second error
consider only two categories to find a threshold: correctly
was caused by inaccuracies in our image similarity checks.
labeled cloaking types and mislabeled cloaking types. Per
The image similarity check module erroneously distinguished
Figure 3b, we selected a code structure threshold with a true-
betweenscreenshotsofidenticalpagesduetoslightvariations
positive rate of 95.83% and a false-positive rate of 0.79%.
in the page layout generated by the browser with and without
When CrawlPhish compares the code structure features of
forced execution.
a new phishing website to ones in our database, the AST
In terms of the false negatives, we found that 32 out of the
similarity score must be greater than 0.74 and the Hamming
35 stemmed from a long execution time of cloaked phishing
DistanceofwebAPIsandeventsmustbewithin34foranew
websites(similartothefirstreasonforfalsepositives).Forced
websitetobemarkedwithaknowntypeofcloakingtechnique.
executed screenshots are not taken if an execution path takes
too long to finish execution. We used a 195-second execution
V. EVALUATION:
time window for each execution path. However, the paths
DETECTIONOFCLOAKEDPHISHINGWEBSITES
that CrawlPhish does not execute due to a timeout may
Inthissection,weevaluatetheclient-sidecloakingdetection
contain cloaking technique implementations. Without those
accuracyofCrawlPhish.Inthisexperiment,wefirstrandomly
screenshots, CrawlPhish cannot detect the cloaking technique,
sampled and manually labeled 2,000 phishing websites that
so it mislabels the corresponding website as uncloaked.
didnotcontainJavaScriptcloakingtechniquesaswellas2,000
In three rare cases, real phishing websites appeared nearly
phishing websites with various types of client-side cloaking.
blank due to low page contrast. For example, if phishing
WethenranCrawlPhishtodetectifclient-sidecloakingexists.
websites have a white background with light text, CrawlPhish
Finally,wecomparedtheautomatedcloakingdetectionresults
would not distinguish between the corresponding screenshot
against our manually labeled ground truth dataset to calculate
andablankone.Wemanuallyexaminedthesecasesandfound
the detection accuracy.
that CSS inclusions were missing from those websites (i.e.,
Table III shows the confusion matrix of CrawlPhish’s
they could not be retrieved by our crawler).
detections. Within the 4,000 phishing websites, CrawlPhish
correctly detected 1,965 phishing websites as cloaked and Client-sidecloakingoccurrencestatistics.Withinourdataset
1,971 as uncloaked, with a false-negative rate of 1.75% (35) of 112,005 phishing websites, CrawlPhish found that 35,067
and a false-positive rate of 1.45% (29). Note that unlike a (31.31%) phishing websites implement client-side cloaking
general phishing detection tool that should prioritize false techniques in total: 23.32% (6,024) in 2018 and 33.70%
positives over false negatives [61], the client-side cloaking (29,043) in 2019. We note that cloaking implementations
detection component in CrawlPhish does not critically need in phishing grew significantly in 2019. We hypothesize that
1115
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore. Restrictions apply.

| (a) Initial     | appearance. |                |     | (b) Force-executed |     | appearance. |          |     |     |     |     |     |     |     |
| --------------- | ----------- | -------------- | --- | ------------------ | --- | ----------- | -------- | --- | --- | --- | --- | --- | --- | --- |
| Fig. 4: Initial | and         | force-executed |     | appearance         |     | of a        | phishing |     |     |     |     |     |     |     |
Pop-up
| website | with | cloaking. |     |     |     |     |     |           |          |         |      |                    |            |     |
| ------- | ---- | --------- | --- | --- | --- | --- | --- | --------- | -------- | ------- | ---- | ------------------ | ---------- | --- |
|         |      |           |     |     |     |     |     | Fig. 5: A | phishing | website | with | the evolved Pop-up | (Notifica- |     |
phishers are either leveraging such cloaking because it in- tion)cloakingtechnique,inwhichthewebpagedirectshuman
|               |               |         |            |           |          |           |      | visitors to | click | on the | “Allow” | button by showing | an  | arrow. |
| ------------- | ------------- | ------- | ---------- | --------- | -------- | --------- | ---- | ----------- | ----- | ------ | ------- | ----------------- | --- | ------ |
| creases their | profitability |         | or because | improving |          | detection | sys- |             |       |        |         |                   |     |        |
| tems make     | advanced      | evasion | necessary, |           | or both. |           |      |             |       |        |         |                   |     |        |
VI. EVALUATION:CLOAKINGCATEGORIZATION not evaluate the extent of such abuse). Through this, we show
Inthissection,weelaborateontheeighttypesofclient-side thatcriminalsareusingcutting-edgebrowserfeaturestoevade
cloaking techniques detected by CrawlPhish (as previously existing detection systems.
UserInteraction:MouseDetection.Thiscloakingtypeseeks
| introduced | in Table | II). | We  | also evaluate | the | accuracy | of  |     |     |     |     |     |     |     |
| ---------- | -------- | ---- | --- | ------------- | --- | -------- | --- | --- | --- | --- | --- | --- | --- | --- |
CrawlPhish’ssemanticcloakingcategorization,tracktrendsin to identify whether a website visitor is a person or an
|                |     |           |     |           |                 |     |     | anti-phishing | bot | by  | waiting for | mouse movement |     | before |
| -------------- | --- | --------- | --- | --------- | --------------- | --- | --- | ------------- | --- | --- | ----------- | -------------- | --- | ------ |
| the deployment | and | evolution | of  | different | implementations |     | of  |               |     |     |             |                |     |        |
these cloaking techniques, and analyze how frequently they displaying the phishing content. Specifically, the cloaking
| are used. |     |     |     |     |     |     |     | code listens | for | the onmousemove, |     | onmouseenter, |     | or  |
| --------- | --- | --- | --- | --- | --- | --- | --- | ------------ | --- | ---------------- | --- | ------------- | --- | --- |
onmouseleaveevents.Thistechniqueisusedfrequentlyby
| A. Categorization |     | of Cloaking |     | Types |     |     |     |           |              |     |            |                 |           |     |
| ----------------- | --- | ----------- | --- | ----- | --- | --- | --- | --------- | ------------ | --- | ---------- | --------------- | --------- | --- |
|                   |     |             |     |       |     |     |     | phishers, | and accounts |     | for 16.53% | of all cloaking | technique |     |
User Interaction: Pop-up. With this technique, phishing implementationsinTableV,becausemostpeoplehaveahabit
content remains hidden until a button in a pop-up window is of moving the mouse while a website is rendering in the
| clicked. | Specifically,       | JavaScript |       | code   | listens for | an onclick |         | browser           | [50]. |       |          |               |          |     |
| -------- | ------------------- | ---------- | ----- | ------ | ----------- | ---------- | ------- | ----------------- | ----- | ----- | -------- | ------------- | -------- | --- |
|          |                     |            |       |        |             |            |         | User Interaction: |       | Click | Through. | Some phishing | websites |     |
| event to | evade anti-phishing |            | bots. | Figure | 4 shows     | an         | example |                   |       |       |          |               |          |     |
of a phishing website that implements this technique. The require visitors to click on a specific location on the page
website in Figure 4a initially shows an alert window to an beforedisplayingphishingcontent[60].Simplevariantsofthis
anti-phishing bot or a real user. Thus, this phishing website cloaking technique require visitors to click on a button on the
seeks to evade detection by anti-phishing bots because no pageandare,thus,similartoalertcloaking.However,more
|          |         |            |            |     |          |         |      | sophisticated | variants |     | display fake | CAPTCHAs | that | closely |
| -------- | ------- | ---------- | ---------- | --- | -------- | ------- | ---- | ------------- | -------- | --- | ------------ | -------- | ---- | ------- |
| phishing | content | or typical | attributes |     | (such as | a login | form |               |          |     |              |          |      |         |
or logos of a legitimate organization) are found on the page. mimicthelookandfeelofGoogle’sreCAPTCHA[56].Given
However, CrawlPhish reveals the phishing content hidden the common use of reCAPTCHA by legitimate websites,
behind the popup window as shown in Figure 4b. phishing websites with fake CAPTCHAs make it difficult for
Figure 5 shows a more advanced version of the pop-up potentialvictimstoidentifythattheyarefake.Ifanti-phishing
cloaking techniques that CrawlPhish detected. Because an systems cannot access phishing content because of the Click
alertwindowcaneasilybeclosedthroughcommonbrowser Through technique, they may fail to mark the websites as
| automation | frameworks |     | such as | Selenium | [28] | or Katalon | [5], | phishing. |     |     |     |     |     |     |
| ---------- | ---------- | --- | ------- | -------- | ---- | ---------- | ---- | --------- | --- | --- | --- | --- | --- | --- |
some phishers instead use the Web Notification API [58]. Bot Behavior: Timing. Some phishing websites show
We observed that due to technical limitations, top automation phishing content only at a certain time, or deliberately
frameworks [8] do not currently support interaction with make rendering slow by using the setTimeout() or
web notifications. These automated browsers opt to disable Date.getTime() APIs. If phishing websites take a longer
the notification window to avoid such interactions. Phishers, time to render than thresholds set by detection systems, such
however, only allow visitors who actually click the “Allow” websites can evade detection. Actual visitors, however, might
button to access the phishing content. Therefore, because the wait for the completion of web page rendering [19].
phishing website will not show any phishing content until a Bot Behavior: Randomization. Some phishers try to evade
visitor clicks the “Allow” button in the notification window, it detectionbyusinganon-deterministicmechanism:suchphish-
will evade detection. Phishers use a deceptive web page that ing websites generate a random number before the page is
asks visitors to click the button on the notification window, as rendered,andonlyshowphishingcontentifacertainthreshold
shown in Figure 5. As an added benefit to attackers, by using is met. Anti-phishing crawlers or human inspectors may not
a notification window, cloaked phishing websites could also visitthesamewebsiteagainifitinitiallyshowsbenigncontent.
directly send spam to visitors through their browsers (we do Therefore, this technique may appear to be a “dumb” way to
1116
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore.  Restrictions apply.

PublicDataset APWGDataset
CloakingTechnique Identical
Unique TopGroup Unique TopGroup Earliest GroupsUsed
Groups
Category Type Groups Count Percentage Groups Count Percentage Impl. From2018
Cookie 43 437 15.01% 28 325 7.39% 09/2018 12 14
Fingerprinting Referrer 27 156 5.85% 37 92 3.92% 08/2018 21 9
User-Agent 65 563 53.31% 33 181 12.97% 07/2018 24 20
Alert 424 249 3.26% 335 73 1.21% 06/2018 276 127
Pop-up
User Notification 29 52 4.22% 17 284 18.67% 11/2018 7 11
Interaction ClickThrough 105 1,541 22.88% 51 1,275 16.45% 10/2018 13 31
MouseDetection 87 138 6.81% 108 500 8.63% 06/2018 47 37
Bot Randomization 73 42 16.03% 125 58 3.57% 09/2018 62 43
Behavior Timing 597 387 7.76% 394 416 5.99% 06/2018 303 197
TABLE IV: Overview of the number of distinct groups of cloaking code implementations in the APWG and Public Datasets.
cloakingtechniquesareoccasionallyusedtogetherbyphishing
websites, as doing so may further increase evasiveness. For
example, CrawlPhish found 503 instances of Click Through
andReferrerusedtogether.Also,wefoundTimingandCookie
in 476 cloaked phishing websites.
B. Accuracy of Cloaking Categorization
(a) Benign page shown when (b) Force-executed version, To evaluate the accuracy of CrawlPhish’s categorization of
cookies are disabled. which reveals the login form. cloaking types, we selected the same 2,000 cloaked phishing
websites as in Section V (this set contains all three categories
Fig. 6: Appearance of a phishing website with the Cookie
of client-side cloaking techniques) and manually labeled the
cloaking technique.
correct cloaking type based on their code structure features.
evade detection by anti-phishing systems. However, its use in We, then, sent these websites through the feature extraction
the wild suggests that it may be worthwhile: we suspect that (2) and the cloaking detection (3) phases of CrawlPhish to
phishers who use this technique are aware of the conditions locate the code blocks in which each cloaking technique is
for detection by anti-phishing entities and try to trick anti- implemented. CrawlPhish checked the code structure feature
phishing bots with a non-deterministic approach to cloaking. similarity as populated over the course of our deployment
Fingerprinting: Cookie. Similar to server-side cloaking tech- (4). As stated in Section IV-D, CrawlPhish compares the
niques,client-sidecloakingtechniquescanalsocheckvisitors’ codestructurefeaturesofallsnippetsflaggedbyStep 3 with
request attributes to fingerprint them. Figure 6 illustrates a the records in the database to discover all possible cloaking
phishingwebsitethatfingerprintswhetheravisitorisaperson techniques in a given phishing website.
or an anti-phishing bot by checking if cookies are disabled in We found that CrawlPhish correctly categorized the cloak-
thebrowser.Whencookiesaredisabled,thephishingwebsites ingtypewith100%accuracy.Thishighaccuracystemsinpart
willdisplaybenigncontent,asshowninFigure6a.Someanti- from the manual inspection involved when the code structure
phishing crawlers disable cookies to avoid being bound to a features of the examined snippet do not match any existing
single session. However, CrawlPhish detects cloaked phishing records in the database, as discussed in Section IV-D. Thus,
content as shown in Figure 6b. Similarly, this cloaking tech- weconcludethatwebAPIcalls,webevents,andASTssuffice
nique may also test if the browser cache is enabled [47]. fordistinguishingbetweendifferentcloakingtypes,evenwhen
Fingerprinting: Referrer. Phishing websites can check the underlying implementations vary.
whether incoming traffic originates from phishers’ lures or
C. Grouping of Implementations
other unwanted sources. Therefore, some phishing websites
display benign content to visitors with a blank Referer [21], Because phishing kits directly enable the scalability of
which could indicate that a URL was directly typed in. phishingattacksandarereadilyavailablethroughunderground
Similarly, referrals from search engines or known security markets[41,53,54],trackingthedeploymentandevolutionof
domains can be blocked. kits can help researchers and investigators pinpoint the threat
Fingerprinting: User-agent. Some phishing websites seek actor (i.e., a kit author or criminal group) behind a series of
to identify anti-phishing crawlers based on their user-agent phishingwebsitesandidentifytheprevalencephishingattacks
strings. The navigator.userAgent property stores in- attributable to the same author. The web page source code
formation about the browser and operating system (e.g., collected by CrawlPhish is suitable for this purpose because
Mozilla/5.0 (X11; Linux x86 64)). Therefore, anti-phishing such source code can be obtained for virtually any phishing
bots such as Googlebot can be blocked as their userAgent URL—unlike server-side code [44].
property is a known value. By comparing code similarity between JavaScript snippets
Combinations of cloaking techniques. Multiple client-side used by cloaked phishing websites, over time, we can group
1117
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore. Restrictions apply.

stillhavethehighestoverallnumberofgroups,whichmatches
100%
|     |     |     |     |     |     |     |     | the findings | from | the | APWG | dataset. | The number | of  | groups |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------ | ---- | --- | ---- | -------- | ---------- | --- | ------ |
80% for Click Through cloaking, however, increases from 51 to
sLRU  fo  egatnecreP 105. We suspect that different phishers are developing more
|     | 60% |     |     |     |     |     |     | phishingkitswiththiscloakingtechniquebecausetheyrealize |     |     |     |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------------------------------------------------- | --- | --- | --- | --- | --- | --- | --- |
thatitcaneffectivelyevadedetectionbyanti-phishingsystems.
|     | 40% |     |     |     |     |     |     | In addition, |             | by comparing |          | the AST        | similarity | of       | imple- |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------ | ----------- | ------------ | -------- | -------------- | ---------- | -------- | ------ |
|     |     |     |     |     |     |     |     | mentation    | groups      | between      | the      | Public Dataset | and        | the      | APWG   |
|     |     |     |     |     |     |     |     | Dataset,     | we discover |              | that the | same groups    | of         | cloaking | tech-  |
20%
niquetypesexistinbothdatasets.11outof17distinctgroups
|     |     |     |     |     |     |      |     | of the Notification |     | cloaking |     | technique | in the APWG |     | Dataset |
| --- | --- | --- | --- | --- | --- | ---- | --- | ------------------- | --- | -------- | --- | --------- | ----------- | --- | ------- |
|     | 0%  | 20% | 40% | 60% | 80% | 100% |     |                     |     |          |     |           |             |     |         |
Percentage  of  Implementations also appear in the Public Dataset. Additionally, the Alert and
|       |             |                |     |        |         |          |      | Timing  | cloaking | techniques |      | have the | most identical |      | groups   |
| ----- | ----------- | -------------- | --- | ------ | ------- | -------- | ---- | ------- | -------- | ---------- | ---- | -------- | -------------- | ---- | -------- |
| Fig.  | 7: CDF of   | implementation |     | groups | for all | phishing | web- |         |          |            |      |          |                |      |          |
|       |             |                |     |        |         |          |      | between | the two  | datasets.  | This | result   | indicates      | that | phishing |
| sites | in the APWG | Dataset.       |     |        |         |          |      |         |          |            |      |          |                |      |          |
kitsleveragingclient-sitecloakingtechniquesarewidelyused.
related cloaking technique implementations (i.e., implemen- Evolutionofcloakinggroupsovertime.Becausewecrawled
| tations | attributable | to the | same | origin) | together. | Specifically, |     |          |         |      |          |           |      |       |      |
| ------- | ------------ | ------ | ---- | ------- | --------- | ------------- | --- | -------- | ------- | ---- | -------- | --------- | ---- | ----- | ---- |
|         |              |        |      |         |           |               |     | phishing | data in | both | 2018 and | 2019 from | APWG | feed, | this |
wecomparetheASTsimilarityamongcloakingtechniqueim- datasetenablesustotracetheoriginofeachcloakingtype.The
plementation code blocks to find matches using JSInspect [4] Timing,Alert,andMouseDetectioncloakingtechniqueswere
(the same technique we leveraged to check the code structure first used in phishing websites from June 2018 in our dataset.
similarity).InTableIV,weprovideanoverviewofthenumber The (more advanced) Notification technique first appeared
of implementation groups that we found for each cloaking in November 2018. The early occurrence of these evasion
technique within the APWG Dataset and the Public Dataset. methods reminds us that phishers are trying to stay one step
Inaddition,wecomparetheoverlapingroupsbetweenthetwo ahead of the anti-phishing ecosystem. While researchers and
datasets,andwedeterminetheearliestdatethateachtechnique anti-phishing entities were working on mitigations against
was observed. server-side cloaking techniques [30,44], those attackers had
Implementation groups in the APWG Dataset. We found already turned their focus toward implementing client-side
that the earliest implementation of each cloaking type was in evasion methods. We suspect that those client-side cloaking
2018. Also, we found that 1,128 groups account for 35,067 techniques may have already been employed well before June
cloaked phishing websites detected by CrawlPhish. Figure 7 2018 [30,34] (the date we started crawling).
shows the cumulative distribution function (CDF) of unique We also observe the evolution of cloaking techniques from
implementation groups in the APWG Dataset: 20% of unique the perspective of obfuscation. From our crawling process,
cloaking implementation groups account for 74.65% of all we found that the code obfuscation rate on phishing websites
phishing websites. This shows that a small number of phish- increased from 20.79% in 2018 to 24.04% in 2019. For
| ing kits | is likely | responsible |     | for a significant |     | proportion | of  |          |         |        |          |            |     |          |       |
| -------- | --------- | ----------- | --- | ----------------- | --- | ---------- | --- | -------- | ------- | ------ | -------- | ---------- | --- | -------- | ----- |
|          |           |             |     |                   |     |            |     | example, | for the | Pop-up | cloaking | technique, | the | earliest | vari- |
sophisticated phishing websites in the wild. We discover that ant from June 2018 was not obfuscated. Gradually, phishers
theTimingcloakingtypehasthemostgroups(394)amongall started to obfuscate their cloaking technique implementations:
cloakingtypes.Becausethiscloakingtechniqueislesspopular in October 2018, they added an encoding algorithm, while
according to our findings, we suspect that prominent phishing the AST structure remained highly similar to unobfuscated
| kit developers |     | do not | deploy | it, though | individual | criminals |     |                  |     |        |          |         |                  |     |     |
| -------------- | --- | ------ | ------ | ---------- | ---------- | --------- | --- | ---------------- | --- | ------ | -------- | ------- | ---------------- | --- | --- |
|                |     |        |        |            |            |           |     | implementations. |     | Later, | phishers | started | to symmetrically |     | en- |
may still want to leverage it. Among the largest groups, we cryptclient-sidecloakingtechniques(e.g.,byusingAES)and
observe that one group of Click Through cloaking accounted included decryption keys only as request parameters. In such
for16.45%(1,275)ofcodevariants.Asmanyas18.67%(284) cases, the AST of the same cloaking technique would differ
of the Notification Window occurrences were within a single from an existing group, so we place them in a new group.
group.
|     |     |     |     |     |     |     |     | However, | with | CrawlPhish, |     | we still | find similar | web | API |
| --- | --- | --- | --- | --- | --- | --- | --- | -------- | ---- | ----------- | --- | -------- | ------------ | --- | --- |
Implementation groups in the Public Dataset. We also calls, so we consider this group to be an evolution of a prior
compare the cloaking groups within the Public Dataset [24], group(itsorigin).Fromthisfinding,wegaintheintuitionthat
which was sourced from OpenPhish [6], PhishTank [49], cybercriminals are improving client-side cloaking techniques
PhishStats [48], and other phishing URL archives. Using this in phishing to make the latest implementations more difficult
| additionaldataset,wecanvalidatethattheAPWGdatasetwas |          |                  |      |              |      |               |     | to analyze. |             |     |       |     |     |     |     |
| ---------------------------------------------------- | -------- | ---------------- | ---- | ------------ | ---- | ------------- | --- | ----------- | ----------- | --- | ----- | --- | --- | --- | --- |
| representative                                       |          | of the ecosystem |      | and evaluate |      | the existence | of  |             |             |     |       |     |     |     |     |
|                                                      |          |                  |      |              |      |               |     | D. Trends   | in Cloaking |     | Usage |     |     |     |     |
| other                                                | cloaking | techniques       | that | may not      | have | been present  | in  |             |             |     |       |     |     |     |     |
the APWG dataset. Table IV shows detailed statistics on the Table V shows the prevalence of each client-side cloaking
cloaking group distributions between the two datasets. The technique type that CrawlPhish detected. Note that the sum
number of groups found for each cloaking type from both of each cloaking technique’s occurrence may exceed 100%
datasets is similar. The Timing and Alert cloaking techniques because some phishing websites implement multiple cloaking
1118
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore.  Restrictions apply.

|     |                   |     |     |     |      |      |       |       |     | 2018 |     |     |     | 2019 |     |
| --- | ----------------- | --- | --- | --- | ---- | ---- | ----- | ----- | --- | ---- | --- | --- | --- | ---- | --- |
|     | CloakingTechnique |     |     |     | 2018 | 2019 | Total | Share |     |      |     |     |     |      |     |
Count Count Count TargetedBrand Count Share TargetedBrand Count Share
|     | Category |     | Type   |     | (%) | (%) | (%)           | Count(%) |          |     |              |       |     |       |        |
| --- | -------- | --- | ------ | --- | --- | --- | ------------- | -------- | -------- | --- | ------------ | ----- | --- | ----- | ------ |
|     |          |     |        |     |     |     |               |          | LinkedIn |     | 2,317 38.46% | Apple |     | 6,298 | 21.69% |
|     |          |     | Cookie |     |     |     | 4,395(12.53%) |          |          |     |              |       |     |       |        |
1,295 6,842 8,137 PayPal 1,104 18.33% BankofAmerica 3,572 12.30%
Fingerprinting Referrer (21.50%) (23.56%) (23.20%) 2,346(6.69%) Microsoft 646 10.72% Facebook 2,230 7.68%
|     |             |              | User-Agent   |          |          |        |                        | 1,396(3.98%) |               |     |           |           |     |       |           |
| --- | ----------- | ------------ | ------------ | -------- | -------- | ------ | ---------------------- | ------------ | ------------- | --- | --------- | --------- | --- | ----- | --------- |
|     |             |              |              |          |          |        |                        |              | BankofAmerica |     | 309 5.13% | PayPal    |     | 1,841 | 6.34%     |
|     |             |              | Alert        |          |          |        | 6,027(17.19%)          |              | Apple         |     | 153 2.54% | Microsoft |     |       | 987 3.40% |
|     | User        | Pop-up       | Notification |          | 2,416    | 17,782 | 20,198                 | 1,521(4.34%) |               |     |           |           |     |       |           |
|     | Interaction | ClickThrough |              | (40.11%) | (61.23%) |        | (57.60%) 7,753(22.11%) |              |               |     |           |           |     |       |           |
TABLEVII:Topbrandstargetedbycloakedphishingwebsites
|     |                              | MouseDetection |        |          |          |        | 5,797(16.53%)          |              |             |          |     |     |     |     |     |
| --- | ---------------------------- | -------------- | ------ | -------- | -------- | ------ | ---------------------- | ------------ | ----------- | -------- | --- | --- | --- | --- | --- |
|     |                              |                |        |          |          |        |                        |              | in the APWG | Dataset. |     |     |     |     |     |
|     | Bot                          | Randomization  |        |          | 2,427    | 6,141  | 8,568                  | 1,623(4.63%) |             |          |     |     |     |     |     |
|     | Behavior                     |                | Timing | (40.29%) | (21.14%) |        | (24.43%) 6,945(19.80%) |              |             |          |     |     |     |     |     |
|     | TotalCloakingImplementations |                |        |          | 6,138    | 30,765 | 36,903                 | -            |             |          |     |     |     |     |     |
TABLE V: Cloaking technique types in the APWG Dataset, websites were the most prevalent. Overall, four of the top five
brandsin2018werealsointhetopfivein2019.Nevertheless,
| as  | detected | by CrawlPhish. |     |     |     |     |     |     |     |     |     |     |     |     |     |
| --- | -------- | -------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
becauseofchangeswithinthephishinglandscapebetweenthe
|     |                   |     |        |     |       |            |       |            | two years, | our findings | regarding |        | the relative | distribution | of  |
| --- | ----------------- | --- | ------ | --- | ----- | ---------- | ----- | ---------- | ---------- | ------------ | --------- | ------ | ------------ | ------------ | --- |
|     | CloakingTechnique |     |        |     | Total |            |       | Share      |            |              |           |        |              |              |     |
|     |                   |     |        |     |       |            |       |            | cloaking   | phishing     | websites  | may be | skewed.      |              |     |
|     | Category          |     | Type   |     | Count | Percentage | Count | Percentage |            |              |           |        |              |              |     |
|     |                   |     | Cookie |     |       |            | 2,912 | 9.87%      |            |              |           |        |              |              |     |
VII. EVALUATION:IMPACTOFCLOAKINGTECHNIQUES
| Fingerprinting |     |     | Referrer   |       | 6,633 | 24.28% | 2,665 | 9.03%  |          |      |            |               |     |          |          |
| -------------- | --- | --- | ---------- | ----- | ----- | ------ | ----- | ------ | -------- | ---- | ---------- | ------------- | --- | -------- | -------- |
|                |     |     | User-Agent |       |       |        | 1,056 | 3.58%  |          |      |            |               |     |          |          |
|                |     |     |            |       |       |        |       |        | We have, | thus | far, shown | that phishing |     | websites | make ex- |
|                |     |     |            | Alert |       |        | 7,641 | 25.89% |          |      |            |               |     |          |          |
Pop-up tensive use of client-side cloaking techniques. To demonstrate
|     | User |     | Notification |     | 17,634 | 64.55% | 1,233 | 4.18% |     |     |     |     |     |     |     |
| --- | ---- | --- | ------------ | --- | ------ | ------ | ----- | ----- | --- | --- | --- | --- | --- | --- | --- |
Interaction
ClickThrough 6,735 22.82% that this cloaking represents a significant threat to users, we
|     |     |     | MouseDetection |     |       |        | 2,025 | 6.86% |          |                 |     |           |            |            |     |
| --- | --- | --- | -------------- | --- | ----- | ------ | ----- | ----- | -------- | --------------- | --- | --------- | ---------- | ---------- | --- |
|     |     |     |                |     |       |        |       |       | deployed | two experiments |     | to verify | that these | techniques | can |
|     | Bot |     | Randomization  |     |       |        | 262   | 0.89% |          |                 |     |           |            |            |     |
|     |     |     |                |     | 5,294 | 19.38% |       |       |          |                 |     |           |            |            |     |
Behavior Timing 4,987 16.90% truly evade detection by anti-phishing systems, and that they
TotalCloakingImplementations 29,561 - - - generallydonotdiscouragevictimvisits—thetwokeyfactors
|            |     |             |     |           |             |        |                |         | to increasing    | attackers’ | return-on-investment. |             |          |     |            |
| ---------- | --- | ----------- | --- | --------- | ----------- | ------ | -------------- | ------- | ---------------- | ---------- | --------------------- | ----------- | -------- | --- | ---------- |
| TABLE      | VI: | Cloaking    |     | technique | types       | in the | Public         | Dataset |                  |            |                       |             |          |     |            |
| (September |     | to December |     | 2019),    | as detected |        | by CrawlPhish. |         |                  |            |                       |             |          |     |            |
|            |     |             |     |           |             |        |                |         | A. Effectiveness |            | Against Anti-Phishing |             | Entities |     |            |
|            |     |             |     |           |             |        |                |         | We evaluate      | how        | effective             | client-side | cloaking |     | techniques |
techniques. In the table, the percentage under the “2018”, are against real-world anti-phishing systems. Using a testbed
| “2019”, |     | and “Total” | columns |     | represents | the | share | of each |     |     |     |     |     |     |     |
| ------- | --- | ----------- | ------- | --- | ---------- | --- | ----- | ------- | --- | --- | --- | --- | --- | --- | --- |
forempiricallymeasuringanti-phishingblacklists[43],wefirst
category of JavaScript cloaking technique implementation in deployed 150 carefully-controlled artificial PayPal-branded
| the | respective | time | period. | The | percentage |     | under | the Share |          |          |           |     |            |        |        |
| --- | ---------- | ---- | ------- | --- | ---------- | --- | ----- | --------- | -------- | -------- | --------- | --- | ---------- | ------ | ------ |
|     |            |      |         |     |            |     |       |           | phishing | websites | using new | and | previously | unseen | domain |
column refers to the percentage of each type of cloaking names: 50 for each of the top three User Interaction cloaking
technique in all the cloaked phishing websites we detected. types we found in the wild (Notification, Click Through
| Wecategorizethe |     |     | cloakingtypesin |     |     | phishingwebsitesfrom |     |     |             |          |     |           |             |     |         |
| --------------- | --- | --- | --------------- | --- | --- | -------------------- | --- | --- | ----------- | -------- | --- | --------- | ----------- | --- | ------- |
|                 |     |     |                 |     |     |                      |     |     | with a fake | CAPTCHA, |     | and Mouse | Detection). |     | We then |
both the APWG Dataset and the Public Dataset. As shown simultaneouslyreportedtheURLstokeyanti-phishingentities
| in  | Table | V, the | User | Interaction | cloaking |     | category | has the |            |           |         |      |           |     |            |
| --- | ----- | ------ | ---- | ----------- | -------- | --- | -------- | ------- | ---------- | --------- | ------- | ---- | --------- | --- | ---------- |
|     |       |        |      |             |          |     |          |         | across the | ecosystem | (Google | Safe | Browsing, |     | PhishTank, |
mostimplementationsamongphishingwebsitesintheAPWG Netcraft, APWG, PayPal, and US CERT [44]) to evaluate if
Dataset. In 2018, 2,416 phishing websites (40.11%) leveraged the ecosystem can collectively detect our cloaked websites.
| cloaking |     | within | the User | Interaction |     | category, | while | in 2019, |            |           |               |     |               |               |     |
| -------- | --- | ------ | -------- | ----------- | --- | --------- | ----- | -------- | ---------- | --------- | ------------- | --- | ------------- | ------------- | --- |
|          |     |        |          |             |     |           |       |          | Lastly, we | monitored | the detection |     | status (i.e., | blacklisting) | of  |
the usage ratio of User Interaction cloaking grew to 61.23%. our websites in major web browsers (Google Chrome, Opera,
The usage ratio of cloaking techniques in the Fingerprinting and Microsoft Edge, each powered by different detection
category over two years is almost the same. Within the Bot backends) over seven days.
Behavior category, the usage ratio dropped significantly, from Attheconclusionoftheseexperiments,wefoundthatnone
| 40.29% | to  | 21.14%. | We  | find | that phishing | websites |     | rely more |     |     |     |     |     |     |     |
| ------ | --- | ------- | --- | ---- | ------------- | -------- | --- | --------- | --- | --- | --- | --- | --- | --- | --- |
ofourphishingwebsiteswereblacklistedinanybrowser,with
on cloaking techniques in the User Interaction category than the exception of Click Through websites, 21 (42%) of which
theothers.Webelievethatthisisbecauseitismoredifficultfor were blocked in Microsoft Edge a median of 3 hours after
anti-phishingcrawlerstoimpersonatehumanbehaviorsthanto we reported them. The detection occurred because Microsoft
bypass other types of cloaking. SmartScreenclassifiedtheobfuscationintheJavaScriptsource
| Table |     | VI demonstrates |     | the | usage | of each | cloaking | type |         |          |             |     |             |     |           |
| ----- | --- | --------------- | --- | --- | ----- | ------- | -------- | ---- | ------- | -------- | ----------- | --- | ----------- | --- | --------- |
|       |     |                 |     |     |       |         |          |      | code as | malware, | not because | it  | was capable | of  | bypassing |
CrawlPhish detected from the Public Dataset. Just as we ob- the cloaking technique itself. The fact that so many of our
served from the 2019 portion of the APWG Dataset, the User websitesremainedunmitigatedafteraseven-dayperiodshows
Interactioncategorywasalsothemostfrequentlyimplemented thatclient-sideevasionmethodsareindeedeffectiveatevading
in the Public Dataset. detection by modern anti-phishing systems.
Brand distribution. Among the 6,024 cloaked phishing sites Manual inspection is used by some anti-phishing enti-
in 2018, LinkedIn and PayPal were the most frequently ties[23].Recurringsuspiciouswebsitesthatcannotbedetected
impersonated brands, as shown in Table VII. In 2019, the by automated systems should go to manual inspection for
distribution changed: Apple and Bank of America phishing further analysis. With specialists’ inspection, any malicious
1119
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore.  Restrictions apply.

Mouse Click Notification impact on phishing success rates against potential victims.
|        |     | Detection    |     | Through     |     | Window      |     |          |                 |              |              |         |             |     |       |
| ------ | --- | ------------ | --- | ----------- | --- | ----------- | --- | -------- | --------------- | ------------ | ------------ | ------- | ----------- | --- | ----- |
|        |     |              |     |             |     |             |     | However, | had these users | been         | successfully |         | deceived    |     | by a  |
|        |     | Count(%)     |     | Count(%)    |     | Count(%)    |     |          |                 |              |              |         |             |     |       |
|        |     |              |     |             |     |             |     | phishing | lure (e.g., one | that conveys |              | a sense | of urgency) |     | prior |
| CanSee |     | 879(100.00%) |     | 859(97.72%) |     | 374(42.55%) |     |          |                 |              |              |         |             |     |       |
tovisitingthepage,webelievethattheywouldhavebeenmore
| CannotSee |     | 0(0.00%) |     | 20(2.28%) |     | 505(57.45%) |     |     |     |     |     |     |     |     |     |
| --------- | --- | -------- | --- | --------- | --- | ----------- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
likelytoallownotifications[55].Moreover,giventhefactthat
TABLE VIII: Experimental results on the effect of cloaking websites with this cloaking technique were not detectable by
| techniques | on users’ | ability | to  | see | phishing | content. |     |                   |           |           |         |        |            |          |       |
| ---------- | --------- | ------- | --- | --- | -------- | -------- | --- | ----------------- | --------- | --------- | ------- | ------ | ---------- | -------- | ----- |
|            |           |         |     |     |          |          |     | the anti-phishing | ecosystem | (as       | we      | showed | in Section |          | VII), |
|            |           |         |     |     |          |          |     | we still believe  | that this | technique | remains |        | viable     | overall. | In    |
fact,thewebsiteshowninFigure5wasstillonlineinJanuary
| websites | therein | should | be labeled |     | as phishing | and | be black- |     |     |     |     |     |     |     |     |
| -------- | ------- | ------ | ---------- | --- | ----------- | --- | --------- | --- | --- | --- | --- | --- | --- | --- | --- |
2020eventhoughwefirstobservedthephishingURLinMay
| listed to | protect          | users.   | Our observations, |      | however,  |      | imply that | 2019.         |                      |     |                  |        |          |     |       |
| --------- | ---------------- | -------- | ----------------- | ---- | --------- | ---- | ---------- | ------------- | -------------------- | --- | ---------------- | ------ | -------- | --- | ----- |
| our test  | phishing         | websites | may               | have | simply    | been | classified |               |                      |     |                  |        |          |     |       |
|           |                  |          |                   |      |           |      |            | Consequently, | we conclude          |     | that client-side |        | cloaking |     | tech- |
| as benign | by anti-phishing |          | systems           |      | and never | sent | for manual |               |                      |     |                  |        |          |     |       |
|           |                  |          |                   |      |           |      |            | niques in     | the User Interaction |     | category         | enable | phishing |     | web-  |
review.Webelievethatthisisaclearlimitationofcurrentanti- sitestomaintainprofitabilitythroughamuchlongerlifespan,
| phishing      | mitigations. | Therefore, |               | it         | is important | for              | the whole  |                 |                      |      |        |         |       |     |      |
| ------------- | ------------ | ---------- | ------------- | ---------- | ------------ | ---------------- | ---------- | --------------- | -------------------- | ---- | ------ | ------- | ----- | --- | ---- |
|               |              |            |               |            |              |                  |            | generally       | without discouraging |      | victim | visits, | which | in  | turn |
| anti-phishing | ecosystem    |            | to understand |            | the          | nature           | and preva- |                 |                      |      |        |         |       |     |      |
|               |              |            |               |            |              |                  |            | allows phishers | to harm              | more | users. |         |       |     |      |
| lence of      | client-side  | cloaking   |               | techniques | used         | by sophisticated |            |                 |                      |      |        |         |       |     |      |
phishing websites, especially when we consider the growth of C. Responsible Disclosure
such websites [46]. Onceweestablishedthatthecloakingtechniquesdiscovered
|              |     |        |              |     |     |     |     | by CrawlPhish | were capable | of  | evading | anti-phishing |     | systems |     |
| ------------ | --- | ------ | ------------ | --- | --- | --- | --- | ------------- | ------------ | --- | ------- | ------------- | --- | ------- | --- |
| B. Hampering |     | Victim | User Traffic |     |     |     |     |               |              |     |         |               |     |         |     |
whileremainingeffectiveagainsthumanvictims,wedisclosed
To verify that client-side cloaking techniques in the User our findings, and the corresponding JavaScript code for each
Interaction category do not significantly prevent users from techniquetested,tothemajoranti-phishingblacklistoperators:
being exposed to phishing content on cloaked phishing web- Google, Microsoft, and Opera. All companies acknowledged
| sites, we | conducted |     | an IRB-approved |     | user | study | through |            |                 |        |          |     |       |            |     |
| --------- | --------- | --- | --------------- | --- | ---- | ----- | ------- | ---------- | --------------- | ------ | -------- | --- | ----- | ---------- | --- |
|           |           |     |                 |     |      |       |         | receipt of | our disclosure. | Google | followed |     | up by | requesting |     |
Amazon Mechanical Turk [2]. Using a free hosting provider, more information on the semantics and prevalence of the
we generated three websites: one with each of the same cloaking techniques, and concurred with our finding that
three types of cloaking as considered in the previous section such techniques could potentially bypass detection by current
(Notification, Click Through with a fake CAPTCHA, and automated anti-phishing systems.
MouseDetection).Ratherthanhidingphishingcontentbehind
VIII. COUNTERINGCLIENT-SIDECLOAKINGTECHNIQUES
| the cloaking, | however, |     | we simply | hid | the | text “Hello | World”. |     |     |     |     |     |     |     |     |
| ------------- | -------- | --- | --------- | --- | --- | ----------- | ------- | --- | --- | --- | --- | --- | --- | --- | --- |
By default, a blank page would be shown. We then hired As we have observed, phishers make extensive use of
1,000 workers in Amazon Mechanical Turk and requested sophisticated evasion techniques in their phishing attacks.
them to report what they saw after visiting each of the The unique feature of client-side cloaking techniques is to
three websites [1]. We choose these three cloaking techniques require visitors to interact with the website or browser, such
becausetheyareuniquetoclient-side(ratherthanserver-side) as through a button click or mouse movement. Phishers adopt
cloaking implementations, and because the other techniques such strategies because they believe that their victims will
| have been | tested | in a | server-side | context | [43]. |     |     |               |           |      |          |           |     |       |        |
| --------- | ------ | ---- | ----------- | ------- | ----- | --- | --- | ------------- | --------- | ---- | -------- | --------- | --- | ----- | ------ |
|           |        |      |             |         |       |     |     | exhibit these | behaviors | when | visiting | a website |     | [50]. | If the |
Table VIII shows the detailed experimental results. 121 of website is in the process of rendering and shows a blank
the 1,000 workers could not view our phishing websites due page, most people tend to move their mouse subconsciously.
to a technical problem: their browsers automatically added Similarly, out of habit, users will click a button from a pop-
“www” in front of the sub-domains in our URLs, which up or notification window to make web page content appear.
may occur in older versions of web browsers [14]. Thus, the We expect that phishers’ degree of sophistication will only
responses of 879 workers were suitable for analysis. continue to grow. Therefore, the ecosystem should ensure
For the Mouse Movement cloaking technique, 100% of the that existing detection and mitigation systems are capable of
workerssawthe“HelloWorld”text,andthuswouldhavealso adapting to such evasion techniques.
seen phishing content had they visited a malicious website. Todetectadvancedphishingwebsiteswithclient-sidecloak-
For the Click Through websites, 97.72% saw the text, which ing techniques, anti-phishing crawlers should match the be-
shows that this cloaking technique is also effective against haviors that sophisticated phishing kits expect. Specifically,
users. However, only 42.55% of the users saw the text on crawlersneedtoimpersonatehumanbehaviorssuchasmouse
websites with the Notification Window cloaking technique. movementandbuttonclicks.Toexamineagivenwebsite,anti-
Nearly all users who did not see the text (94.94%) opted to phishingsystemscanemulatesuchbehaviorsusingautomated
| deny notifications; |     | the | rest had | incompatible |     | browsers. |     |           |              |       |          |     |               |     |     |
| ------------------- | --- | --- | -------- | ------------ | --- | --------- | --- | --------- | ------------ | ----- | -------- | --- | ------------- | --- | --- |
|                     |     |     |          |              |     |           |     | browsers. | In addition, | as we | observed | in  | our analysis, |     | the |
Although two of the cloaking techniques did not signifi- Notification Window technique seems to exploit the lack of
cantly prevent users from viewing the content, we found that support for web notifications by current automated browsers.
the Notification Window cloaking technique has a negative Thus,itisimportantforanti-phishingsystemstoclosethisgap
1120
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore.  Restrictions apply.

and ensure that the browsers being used for detection support shown in our evaluation in Section VI-B, we did not observe
the same features as those used by potential victims. such failures in our analysis.
| Also, | CrawlPhish | can be | directly | incorporated | into | existing |     |     |     |     |     |     |     |     |
| ----- | ---------- | ------ | -------- | ------------ | ---- | -------- | --- | --- | --- | --- | --- | --- | --- | --- |
anti-phishing crawlers. With the hidden web page content B. Cloaking Detection
revealed by CrawlPhish alongside traditional attributes such Execution time. Forced execution of a small percentage
as URLs, we believe that current anti-phishing systems could (1.75%) of websites in our dataset could not be completed
|          |           |          |            |           |       |     | within a | reasonably | short | time | period, | and, thus, | resulted | in  |
| -------- | --------- | -------- | ---------- | --------- | ----- | --- | -------- | ---------- | ----- | ---- | ------- | ---------- | -------- | --- |
| identify | malicious | websites | that would | otherwise | evade | de- |          |            |       |      |         |            |          |     |
tection. Furthermore, by implementing CrawlPhish analysis, false-negative detections of cloaking. Across our deployment,
crawlerswouldbeabletomoreaccuratelyclassifyandfinger- we chose a 195-second idle timeout: the maximum period
print new variants of evasion techniques employed phishing without a change to the execution path, after which execu-
websites, or even discover entirely new types of cloaking. tion is halted. This timeout allowed 98% of websites (three
|               |     |                       |     |         |               |     | standard | deviations | above | the mean) | to  | finish, | as determined |     |
| ------------- | --- | --------------------- | --- | ------- | ------------- | --- | -------- | ---------- | ----- | --------- | --- | ------- | ------------- | --- |
| Such analysis |     | would be particularly |     | helpful | in countering |     |          |            |       |           |     |         |               |     |
phishingwebsitesthatcannotcurrentlybeclassifiedwithhigh bythesamplinginSectionIV-B. Anotherlimitationofsetting
confidence. an execution time limit is that some execution paths may be
IX. LIMITATIONS omitted if the time limit is reached. A future implementation
|     |     |     |     |     |     |     | of CrawlPhish |     | could ensure | that | all paths | of  | a code | snippet |
| --- | --- | --- | --- | --- | --- | --- | ------------- | --- | ------------ | ---- | --------- | --- | ------ | ------- |
Even though CrawlPhish uncovered a diverse array of have finished examination by comparing the actual paths in
| sophisticated | client-side | evasion | techniques |     | used in | the wild, |            |          |           |      |                 |     |     |     |
| ------------- | ----------- | ------- | ---------- | --- | ------- | --------- | ---------- | -------- | --------- | ---- | --------------- | --- | --- | --- |
|               |             |         |            |     |         |           | the script | to those | that have | been | force-executed. |     |     |     |
ourfindingsshouldbeconsideredalongsidecertainlimitations.
Wefoundthatthewebsiteswhichfailedtobefullyexecuted
|               |     |            |     |     |     |     | contained | long-running |                 | code within | individual   |     | loops.       | J-Force |
| ------------- | --- | ---------- | --- | --- | --- | --- | --------- | ------------ | --------------- | ----------- | ------------ | --- | ------------ | ------- |
| A. CrawlPhish |     | Deployment |     |     |     |     |           |              |                 |             |              |     |              |         |
|               |     |            |     |     |     |     | seeks to  | mitigate     | this limitation |             | by enforcing |     | (by default) | a       |
Data sources. The CrawlPhish framework is not a phishing cutoff of 80,000 iterations for each loop. Although this cutoff
cloaking
classification system. Rather, it detects and classifies proved insufficient in the aforementioned 1.75% of cases,
within known phishing websites. Thus, as its primary input, given the low false-negative rate, we do not consider it as
| CrawlPhish | requires | a curated | feed | of phishing | URLs | (i.e., |               |        |             |     |         |      |         |       |
| ---------- | -------- | --------- | ---- | ----------- | ---- | ------ | ------------- | ------ | ----------- | --- | ------- | ---- | ------- | ----- |
|            |          |           |      |             |      |        | a significant | issue: | fine-tuning | the | J-Force | loop | timeout | could |
detected by an existing anti-phishing system, whether manual be used to further optimize execution times.
orautomated).However,ourframeworkcouldalsobeadapted Nevertheless, adversaries with knowledge of our analysis
foruseonunconfirmedphishingURLswithtargetedadditions
|     |     |     |     |     |     |     | technique | could | design | code to | bypass | it by | introducing | a   |
| --- | --- | --- | --- | --- | --- | --- | --------- | ----- | ------ | ------- | ------ | ----- | ----------- | --- |
to the visual similarity check of the framework [63], such large number of individual loops ahead of the path which
| that benign | website | screenshots | could | be differentiated |     | from |            |          |          |          |     |         |          |      |
| ----------- | ------- | ----------- | ----- | ----------------- | --- | ---- | ---------- | -------- | -------- | -------- | --- | ------- | -------- | ---- |
|             |         |             |       |                   |     |      | ultimately | displays | phishing | content. | To  | further | overcome | this |
deceptive ones. and other types of deliberate circumvention, additional code
Data collection. Due to infrastructure limitations, we were analysis techniques, such as symbolic execution [35], could
only able to crawl live phishing websites over a total of 14 be applied in cases in which forced execution fails.
months from June to December 2018 and May to November Execution environment. We force-executed phishing web-
2019, with a 4-month gap in between. Differences in brand sites’ JavaScript using the WebKitGTK+ web browser [34].
distributionbetweenthetwoyearsmayskewourfindingswith Historically, there has been evidence of malicious JavaScript
respect to the commonality of cloaking techniques. Although thatonlytargetsaspecificwebbrowser(orengine)[32].Thus,
additional crawling would be desirable for a more thorough CrawlPhish may have failed to correctly classify code tar-
longitudinal evaluation, we mitigated this limitation by also geted at other browsers. To overcome this limitation, websites
evaluatingCrawlPhishonapublicdatasetof100,000phishing markedasuncloaked bythecurrentimplementationofCrawl-
websitesfrom2019,andbyanalyzingdistinctimplementations Phish could be force-executed in additional environments.
of each cloaking technique, as discussed in Section VI-C. Asynchronous content delivery. CrawlPhish does not con-
Phishing websites may leverage server-side cloaking with sider cases where asynchronous web requests (i.e., AJAX)
variousdegreesofsophistication[44,46].Althoughwesought submit data about the client to the server and so that the
to defeat simple IP and geolocation cloaking potentially server can determine whether phishing web page content
implemented by the phishing websites which we crawled, should be sent back to the client (this equates to server-
other techniques may have evaded our crawler, and, thus, the side cloaking with the prerequisite of client-side JavaScript
corresponding phishing website client-side source code would execution, and has been previously studied [43]). Also there
be absent from our dataset. wasnoevidenceinourdatasetthatclient-sidecloakingis(yet)
Semanticcloakingcategorization.WhenqueryingtheCrawl- beingcombinedwithAJAXandserver-sidecloakingbyphish-
Phish cloaking technique database to determine the type of ing websites. However, CrawlPhish could still be enhanced
cloaking used by a phishing website, we set fixed similarity to automatically analyze the malicious use of asynchronous
thresholds for different classes of cloaking techniques. As a requests. For example, during forced execution, CrawlPhish
result, our approach may misclassify evasion code which could mutate the configurations of browser profiles before
combinesmultiplecloakingtechniques,orfailtotriggerman- the JavaScript code sends an XMLHttpRequest to check
ualanalysisofcertainnovelcloakingtechniques.However,as for potential divergent responses. Hence, the corresponding
1121
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore.  Restrictions apply.

screenshots after mutation and forced execution would be based obfuscation, Coogan et al. proposed a de-obfuscation
differentifcloakingtechniquesweredependentonAJAX,and approachthatidentifiesbehaviorsofmaliciousprogramsbased
CrawlPhish could subsequently identify the existence of such on the flow of values to system calls [15]. BEAGLE assigns
evasion. semantics to malware by dynamically monitoring system and
|         |             |     |              |     |             |     |             | API calls | that malware uses | to compare     | versions | of malicious  |
| ------- | ----------- | --- | ------------ | --- | ----------- | --- | ----------- | --------- | ----------------- | -------------- | -------- | ------------- |
|         |             | X.  | RELATEDWORK  |     |             |     |             |           |                   |                |          |               |
|         |             |     |              |     |             |     |             | code and  | quantify their    | differences—to | observe  | the evolution |
| Studies | on phishing |     | and cloaking |     | techniques: |     | Oest et al. |           |                   |                |          |               |
ofaseriesofmalware[39].Zhangetal.introducedasemantic-
analyzed server-side cloaking techniques within a dataset of based static analysis approach to reveal malicious Android
2,313 phishing kits and proposed a taxonomy of five different applications’ behaviors regardless of minor implementation
types of cloaking [44]. These authors also showed that cloak- differences [66]. The authors leveraged an API dependency
ingtechniques,includingbasicJavaScriptcloaking,caneffec- graph to determine the semantics of the program to classify
| tively bypass | detection |     | by anti-phishing |     | blacklists | [43]. | Based |         |                      |           |     |     |
| ------------- | --------- | --- | ---------------- | --- | ---------- | ----- | ----- | ------- | -------------------- | --------- | --- | --- |
|               |           |     |                  |     |            |       |       | malware | and identify malware | variants. |     |     |
onanend-to-endanalysisoflarge-scalephishingattacks,Oest
|                   |     |      |          |          |      |               |     |     | XI. | CONCLUSION |     |     |
| ----------------- | --- | ---- | -------- | -------- | ---- | ------------- | --- | --- | --- | ---------- | --- | --- |
| et al. discovered |     | that | phishing | websites | with | sophisticated |     |     |     |            |     |     |
evasion techniques are prevalent in the wild but the anti- Through the first in-depth analysis of the client-side
phishing ecosystem has not effectively mitigated them [46]. JavaScriptcodeusedbyphishingwebsites,wehaveuncovered
In this work, we have presented the first in-depth analysis a wide gamut of sophisticated evasion techniques used by
of client-side cloaking techniques in the context of phishing attackers. In addition to categorizing such evasion techniques
based on a dataset of 112,005 live phishing websites. based on their semantics, our approach enabled us to measure
Invernizzietal.studiedserver-sidewebcloakingtechniques the prevalence of each technique in the wild. In doing so,
against search engines, and proposed mechanisms to identify we observed that client-side evasion is becoming increasingly
| and bypass | such | cloaking | [30]. | CrawlPhish |     | leverages | these | common. |     |     |     |     |
| ---------- | ---- | -------- | ----- | ---------- | --- | --------- | ----- | ------- | --- | --- | --- | --- |
methods to overcome server-side cloaking during crawling. Client-side JavaScript enables website developers to imple-
The authors rooted their study in black markets and built a mentcomplexinteractionsbetweentheirwebsitesandvisitors.
classifier to detect cloaking techniques implemented on the Thus, evasion techniques implemented in this manner pose a
server side that returned different content to distinct browsing particular threat to the ecosystem: websites that use them can
clients. This work mainly focused on the mutation of browser effectively discriminate between automated crawler visits and
profiles to bypass server-side cloaking techniques to discover potential human victims. Unfortunately, client-side evasion
divergent web content. The authors found that 11.7% of techniques are difficult to analyze due to the dynamic nature
|                |      |          |     |             |            |     |          | of JavaScript | code. CrawlPhish | addresses |     | this difficulty in |
| -------------- | ---- | -------- | --- | ----------- | ---------- | --- | -------- | ------------- | ---------------- | --------- | --- | ------------------ |
| search results | were | cloaked. |     | The authors | considered |     | cloaking |               |                  |           |     |                    |
techniquesusedforSearchEngineOptimization(SEO),adver- a scalable manner. In addition to being able to detect and
tisements, and drive-by download attacks. However, they did categorizeclient-sideevasionwithhighaccuracy,ourapproach
not investigate client-side cloaking techniques implemented can also track the origin of different implementations.
in JavaScript (i.e., that execute in the browser). In contrast, Given the rise of sophisticated phishing websites in the
we discovered diverse client-side cloaking techniques and wild, we believe that automated analysis systems such as
analyzed them from the perspective of phishing attacks. CrawlPhish are essential to maintaining an understanding of
JavaScript analysis techniques: Althougha numberofstatic phishers’ evolving tactics. Methodology such as ours can be
analysis[18,32,65]anddynamicanalysis[34,36]approaches incorporatedbytheecosystemtomoreexpeditiouslyandmore
have been proposed to analyze malicious JavaScript code, reliablydetectsophisticatedphishing,which,inturn,canhelp
there has been no attempt to automatically extract JavaScript prevent users from falling victim to these attacks through the
code semantics for identifying and classifying cloaking tech- continuous enhancement of the appropriate mitigations.
| niques. | Arrow | and Zozzle |     | are static | analysis | methods |     | to  |     |     |     |     |
| ------- | ----- | ---------- | --- | ---------- | -------- | ------- | --- | --- | --- | --- | --- | --- |
ACKNOWLEDGMENTS
| classify | JavaScript | malware |     | based | on previously |     | discovered |     |     |     |     |     |
| -------- | ---------- | ------- | --- | ----- | ------------- | --- | ---------- | --- | --- | --- | --- | --- |
malicious scripts [18,65]. Revolver tried to detect evasive We would like to thank our shepherd, Giancarlo Pellegrino,
JavaScriptcodethroughsimilaritychecksagainstknownmali- and the anonymous reviewers for their valuable feedback.
ciousmatters[32].Rozzleisamulti-executionvirtualmachine This material is based upon work supported partially by the
to explore multiple execution paths in parallel for enhancing National Science Foundation (NSF) under Grant No. CNS-
the efficiency of dynamic analysis so that it can be used 1703644 and CNS-1703375, the Defense Advanced Research
in large-scale experiments [36]. J-Force enhanced dynamic Projects Agency (DARPA) under Grant No. HR001118C0060
analysismethodstofindhiddenmaliciousbehaviorsbyforce- andFA875019C0003,theInstituteforInformation&commu-
executing JavaScript code, regardless of the conditions, to nications Technology Promotion (IITP) grant funded by the
exploreallpossibleexecutionpathsinanautomatedway[34]. Korean government (MSIT) (No. 2017-0-00168, Automatic
Hence, J-Force lends itself well to revealing content hidden Deep Malware Analysis Technology for Cyber Threat Intelli-
behind JavaScript cloaking code. gence), the NSF Center for Accelerated Real Time Analytics
Analysis of program semantics similar to ours has been - NCSU, and a grant from the Center for Cybersecurity and
performed within other contexts. To deal with virtualization- Digital Forensics (CDF) at Arizona State University.
1122
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore.  Restrictions apply.

REFERENCES [30] L.Invernizzi, K.Thomas,A. Kapravelos,O.Comanescu, J.-M.Picod,
andE.Bursztein,“Cloakofvisibility:Detectingwhenmachinesbrowse
[1] “000webhost: Free web hosting,” https://www.000webhost.com/ a different web,” in 2016 IEEE Symposium on Security and Privacy
migrate?static=true. (SP). IEEE,2016,pp.743–758.
[2] “Amazonmechanicalturk,”https://www.mturk.com/. [31] T. Kachalov and zamotkin, “Javascript obfuscator,” https://github.com/
[3] “Event reference,” https://developer.mozilla.org/en-US/docs/Web/ javascript-obfuscator/javascript-obfuscator.
Events. [32] A.Kapravelos,Y.Shoshitaishvili,M.Cova,C.Kruegel,andG.Vigna,
[4] “Jsinspect: Detect copy-pasted and structurally similar code,” https:// “Revolver:Anautomatedapproachtothedetectionofevasiveweb-based
github.com/danielstjules/jsinspect. malware,”inPresentedaspartofthe22ndUSENIXSecuritySymposium,
[5] “Katalonstudio,”https://www.katalon.com/katalon-studio/. 2013,pp.637–652.
[6] “OpenPhish,”https://openphish.com. [33] M.Khonji,A.Jones,andY.Iraqi,“Anovelphishingclassificationbased
[7] E.Alowaisheq,P.Wang,S.Alrwais,X.Liao,X.Wang,T.Alowaisheq, onurlfeatures,”in2011IEEEGCCconferenceandexhibition(GCC).
X.Mi,S.Tang,andB.Liu,“Crackingthewallofconfinement:Under- IEEE,2011,pp.221–224.
standing and analyzing malicious domain take-downs,” in Proceedings [34] K. Kim, I. L. Kim, C. H. Kim, Y. Kwon, Y. Zheng, X. Zhang, and
of the Network and Distributed System Security Symposium (NDSS), D.Xu,“J-force:Forcedexecutiononjavascript,”inProceedingsofthe
2019. 26thinternationalconferenceonWorldWideWeb. InternationalWorld
[8] B.Anderson,“Bestautomationtestingtoolsfor2018(top10reviews),” WideWebConferencesSteeringCommittee,2017,pp.897–906.
2017, https://medium.com/@briananderson2209/best-automation- [35] J.C.King,“Symbolicexecutionandprogramtesting,”Communications
testing-tools-for-2018-top-10-reviews-8a4a19f664d2. oftheACM,vol.19,no.7,pp.385–394,1976.
[9] APWG, “Phishing Activity Trends Report 3rd Quarter 2019,” 2019, [36] C.Kolbitsch,B.Livshits,B.Zorn,andC.Seifert,“Rozzle:De-cloaking
https://docs.apwg.org/reports/apwg trends report q3 2019.pdf. internet malware,” in 2012 IEEE Symposium on Security and Privacy.
[10] L. Bilge, E. Kirda, C. Kruegel, and M. Balduzzi, “Exposure: Finding IEEE,2012,pp.443–457.
maliciousdomainsusingpassivednsanalysis.”inNdss,2011,pp.1–17. [37] N. Leontiadis, T. Moore, and N. Christin, “Measuring and analyzing
[11] S. Bin, W. Qiaoyan, and L. Xiaoying, “A dns based anti-phishing ap- search-redirection attacks in the illicit online prescription drug trade.”
proach,”in2010SecondInternationalConferenceonNetworksSecurity, inUSENIXSecuritySymposium,vol.11,2011.
WirelessCommunicationsandTrustedComputing,vol.2. IEEE,2010, [38] B. Liang, M. Su, W. You, W. Shi, and G. Yang, “Cracking classifiers
pp.262–265. for evasion: a case study on the google’s phishing pages filter,” in
[12] A.Blum,B.Wardman,T.Solorio,andG.Warner,“Lexicalfeaturebased Proceedingsofthe25thInternationalConferenceonWorldWideWeb,
phishingurldetectionusingonlinelearning,”inProceedingsofthe3rd 2016,pp.345–356.
ACM Workshop on Artificial Intelligence and Security. ACM, 2010, [39] M.Lindorfer,A.DiFederico,F.Maggi,P.M.Comparetti,andS.Zanero,
pp.54–60. “Linesofmaliciouscode:insightsintothemalicioussoftwareindustry,”
[13] D. Canali, D. Balzarotti, and A. Francillon, “The role of web hosting in Proceedings of the 28th Annual Computer Security Applications
providers in detecting compromised websites,” in Proceedings of the Conference,2012,pp.349–358.
22nd international conference on World Wide Web. ACM, 2013, pp. [40] “Windows defender smartscreen,” 2019, https://github.com/
177–188. MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/
[14] T.W.Club,“Webbrowserautomaticallyaddswwwtourl,”2016,https: threat-protection/windows-defender-smartscreen/windows-defender-
//www.thewindowsclub.com/browser-automatically-adds-www-to-url. smartscreen-overview.md.
[15] K. Coogan, G. Lu, and S. Debray, “Deobfuscation of virtualization- [41] A. Modi, Z. Sun, A. Panwar, T. Khairnar, Z. Zhao, A. Doupe´, G.-J.
obfuscated software: a semantics-based approach,” in Proceedings of Ahn, and P. Black, “Towards automated threat intelligence fusion,” in
the 18th ACM conference on Computer and communications security, 2016IEEE2ndInternationalConferenceonCollaborationandInternet
2011,pp.275–284. Computing(CIC). IEEE,2016,pp.408–416.
[16] M.Cova,C.Kruegel,andG.Vigna,“Thereisnofreephish:Ananalysis [42] X.-m. Niu and Y.-h. Jiao, “An overview of perceptual hashing,” Acta
of”free”andlivephishingkits.”WOOT,vol.8,pp.1–8,2008. ElectronicaSinica,vol.36,no.7,pp.1405–1411,2008.
[17] ——, “Detection and analysis of drive-by-download attacks and mali- [43] A. Oest, Y. Safaei, A. Doupe´, G.-J. Ahn, B. Wardman, and K. Tyers,
ciousjavascriptcode,”inProceedingsofthe19thinternationalconfer- “Phishfarm: A scalable framework for measuring the effectiveness of
enceonWorldwideweb,2010,pp.281–290. evasiontechniquesagainstbrowserphishingblacklists,”inProceedings
[18] C.Curtsinger,B.Livshits,B.G.Zorn,andC.Seifert,“Zozzle:Fastand of the 40th IEEE Symposium on Security and Privacy (Oakland),
precise in-browser javascript malware detection.” in USENIX Security Oakland,CA,May2019,pp.764–781.
Symposium. SanFrancisco,2011,pp.33–48. [44] A.Oest,Y.Safaei,A.Doupe´,G.-J.Ahn,B.Wardman,andG.Warner,
[19] R. Dhamija, J. D. Tygar, and M. Hearst, “Why phishing works,” in “Inside a phisher’s mind: Understanding the anti-phishing ecosystem
ProceedingsoftheSIGCHIconferenceonHumanFactorsincomputing throughphishingkitanalysis,”in2018APWGSymposiumonElectronic
systems. ACM,2006,pp.581–590. CrimeResearch(eCrime). IEEE,2018,pp.1–12.
[20] M. W. Docs, “Mozilla web apis,” https://developer.mozilla.org/en-US/ [45] A.Oest,Y.Safaei,P.Zhang,B.Wardman,K.Tyers,Y.Shoshitaishvili,
docs/Web/API. A. Doupe´, and G.-J. Ahn, “PhishTime: Continuous longitudinal mea-
[21] R.Fielding,J.Gettys,J.Mogul,H.Frystyk,L.Masinter,P.Leach,and surementoftheeffectivenessofanti-phishingblacklists,”inProceedings
T.Berners-Lee,“Rfc2616:Hypertexttransferprotocol–http/1.1,”1999. ofthe29thUSENIXSecuritySymposium,2020.
[22] Google, “Google transparency report,” 2019, https:// [46] A. Oest, P. Zhang, B. Wardman, E. Nunes, J. Burgis, A. Zand,
transparencyreport.google.com/safe-browsing/overview?hl=en. K. Thomas, A. Doupe´, and G.-J. Ahn, “Sunrise to sunset: Analyzing
[23] ——, “Manual actions report,” 2020, https://support.google.com/ theend-to-endlifecycleandeffectivenessofphishingattacksatscale,”
webmasters/answer/9044175?hl=en&ref topic=4596795. inProceedingsofthe29thUSENIXSecuritySymposium,2020.
[24] C.Guarnieri,“TheYearofthePhish,”2019,https://nex.sx/blog/212/15/ [47] I. C. Paya and T. Chow, “Combining a browser cache and cookies to
the-year-of-the-phish.html. improve the security of token-based authentication protocols,” Jul. 3
[25] Z.Guo,“World-widecloakingphishingwebsitesdetection,”2017. 2007,USPatent7,240,192.
[26] R.W.Hamming,“Errordetectinganderrorcorrectingcodes,”TheBell [48] “PhishStats,”https://phishstats.info/.
systemtechnicaljournal,vol.29,no.2,pp.147–160,1950. [49] “PhishTank,”https://phishtank.com.
[27] G.Ho,A.Cidon,L.Gavish,M.Schweighauser,V.Paxson,S.Savage, [50] T. Rotolo, “Mouse movement patterns and user frustration,” 2016,
G. M. Voelker, and D. Wagner, “Detecting and characterizing lateral https://www.trymyui.com/blog/2016/10/28/mouse-movement-patterns-
phishingatscale,”in28thUSENIXSecuritySymposium,2019,pp.1273– and-user-frustration/.
1290. [51] F.Shiver,“Apwgandtheecrimeexchange:Amembernetworkproviding
[28] A. Holmes and M. Kellogg, “Automating functional tests using sele- collaborativethreatdatasharing,”2016,https://www.first.org/resources/
nium,”inAGILE2006(AGILE’06). IEEE,2006,pp.6–pp. papers/valencia2017/shiver-foy slides.pdf.
[29] H. Huang, L. Qian, and Y. Wang, “A svm-based technique to detect [52] V.E.Solutions,“Databreachinvestigationsreport(dbir),”2019.
phishingurls,”InformationTechnologyJournal,vol.11,no.7,pp.921– [53] Z. Sun, C. E. Rubio-Medrano, Z. Zhao, T. Bao, A. Doupe´, and G.-J.
925,2012. Ahn,“Understandingandpredictingprivateinteractionsinunderground
1123
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore. Restrictions apply.

forums,” in Proceedings of the Ninth ACM Conference on Data and
ApplicationSecurityandPrivacy(CODASPY). ACM,2019.
[54] K. Thomas, F. Li, A. Zand, J. Barrett, J. Ranieri, L. Invernizzi,
Y.Markov,O.Comanescu,V.Eranti,A.Moscickietal.,“Databreaches,
phishing, or malware?: Understanding the risks of stolen credentials,”
inProceedingsofthe2017ACMSIGSACconferenceoncomputerand
communicationssecurity. ACM,2017,pp.1421–1434.
[55] A. Van Der Heijden and L. Allodi, “Cognitive triaging of phishing
attacks,”in28thUSENIXSecuritySymposium,2019,pp.1309–1326.
[56] L.VonAhn,B.Maurer,C.McMillen,D.Abraham,andM.Blum,“re-
captcha:Human-basedcharacterrecognitionviawebsecuritymeasures,”
Science,vol.321,no.5895,pp.1465–1468,2008.
[57] W3C, “Http archive (har) format,” https://w3c.github.io/web-
performance/specs/HAR/Overview.html.
[58] ——,“Webnotifications,”2015,https://www.w3.org/TR/notifications/.
[59] D.Y.Wang,S.Savage,andG.M.Voelker,“Cloakanddagger:dynamics
of web search cloaking,” in Proceedings of the 18th ACM Conference
on Computer and Communications Security (CCS). ACM, 2011, pp.
477–490.
[60] Y.-M. Wang and M. Ma, “Detecting stealth web pages that use click-
through cloaking,” in Microsoft Research Technical Report, MSR-TR,
2006.
[61] C. Whittaker, B. Ryner, and M. Nazif, “Large-scale automatic classi-
fication of phishing pages,” in Proceedings of the 28th Network and
DistributedSystemSecuritySymposium(NDSS),2010.
[62] M. Wu, R. C. Miller, and G. Little, “Web wallet: preventing phishing
attacks by revealing user intentions,” in Proceedings of the second
symposium on Usable privacy and security. ACM, 2006, pp. 102–
113.
[63] G.Xiang,J.Hong,C.P.Rose,andL.Cranor,“Cantina+:Afeature-rich
machine learning framework for detecting phishing web sites,” ACM
Transactions on Information and System Security (TISSEC), vol. 14,
no.2,p.21,2011.
[64] H.Zhang,G.Liu,T.W.Chow,andW.Liu,“Textualandvisualcontent-
basedanti-phishing:abayesianapproach,”IEEETransactionsonNeural
Networks,vol.22,no.10,pp.1532–1546,2011.
[65] J. Zhang, C. Seifert, J. W. Stokes, and W. Lee, “Arrow: Generating
signatures to detect drive-by downloads,” in Proceedings of the 20th
international conference on World wide web. ACM, 2011, pp. 187–
196.
[66] M.Zhang,Y.Duan,H.Yin,andZ.Zhao,“Semantics-awareandroidmal-
ware classification using weighted contextual api dependency graphs,”
inProceedingsofthe2014ACMSIGSACconferenceoncomputerand
communicationssecurity,2014,pp.1105–1116.
[67] Y. Zhang, J. I. Hong, and L. F. Cranor, “Cantina: a content-based
approach to detecting phishing web sites,” in Proceedings of the 16th
internationalconferenceonWorldWideWeb. ACM,2007,pp.639–648.
1124
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 29,2026 at 12:33:05 UTC from IEEE Xplore. Restrictions apply.