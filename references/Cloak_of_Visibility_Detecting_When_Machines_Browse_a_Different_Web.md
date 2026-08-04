22001166  IIEEEEEE  SSyymmppoossiiuumm  oonn  SSeeccuurriittyy  aanndd  PPrriivvaaccyy
|     | Cloak |         | of   | Visibility:  |            |             | Detecting       |               | When                |     | Machines |     |     |     |
| --- | ----- | ------- | ---- | ------------ | ---------- | ----------- | --------------- | ------------- | ------------------- | --- | -------- | --- | --- | --- |
|     |       |         |      | Browse       |            |             | A Different     |               | Web                 |     |          |     |     |     |
|     |       |         |      |              |            | ∗           |                 | ∗             |                     | †   |          |     |     |     |
|     |       |         |      | Luca         | Invernizzi |             | , Kurt Thomas   | , Alexandros  | Kapravelos          | ,   |          |     |     |     |
|     |       |         |      | Oxana        | Comanescu  |             | ∗ , Jean-Michel | Picod ∗ ,     | and Elie Bursztein  |     | ∗        |     |     |     |
|     |       | ∗       |      | {invernizzi, |            |             |                 |               | jmichel}@google.com |     |          |     |     |     |
|     |       | Google, | Inc. |              |            | kurtthomas, |                 | elieb, oxana, |                     |     |          |     |     |     |
†
|     |     |     |     | North | Carolina |     | State University | kapravelos@ncsu.edu |     |     |     |     |     |     |
| --- | --- | --- | --- | ----- | -------- | --- | ---------------- | ------------------- | --- | --- | --- | --- | --- | --- |
Abstract—The contentious battle between web services and [27], [33], [34] or search visitor profiling based on the
miscreants involved in blackhat search engine optimization and User-Agent and Referer of HTTP requests [32], [35].
maliciousadvertisementshasdriventheundergroundtodevelop Anopenquestionremainsastowhatcompaniesandcrawlers
| increasingly |     | sophisticated | techniques |          | that hide  | the | true nature |                   |          |          |     |              |           |     |
| ------------ | --- | ------------- | ---------- | -------- | ---------- | --- | ----------- | ----------------- | -------- | -------- | --- | ------------ | --------- | --- |
|              |     |               |            |          |            |     |             | blackhat cloaking | software | targets, | the | capabilities | necessary |     |
| of malicious |     | sites. These  | web        | cloaking | techniques |     | hinder the  |                   |          |          |     |              |           |     |
effectivenessofsecuritycrawlersandpotentiallyexposeInternet for security practitioners to bypass state of the art cloaking,
users to harmful content. In this work, we study the spectrum and ultimately whether blackhat techniques generalize across
ofblackhatcloakingtechniquesthattargetbrowser,network,or traffic sources including search results and advertisements.
contextualcuestodetectorganicvisitors.Asastartingpoint,we
|             |     |                  |     |               |     |          |          | In this paper, | we marry | both | an underground |     | and empirical |     |
| ----------- | --- | ---------------- | --- | ------------- | --- | -------- | -------- | -------------- | -------- | ---- | -------------- | --- | ------------- | --- |
| investigate |     | the capabilities | of  | ten prominent |     | cloaking | services |                |          |      |                |     |               |     |
perspectiveofblackhatcloakingtostudyhowmiscreantsscru-
| marketed    |        | within the    | underground.   | This    | includes | a             | first look |                    |               |          |           |        |                |     |
| ----------- | ------ | ------------- | -------------- | ------- | -------- | ------------- | ---------- | ------------------ | ------------- | -------- | --------- | ------ | -------------- | --- |
|             |        |               |                |         |          |               |            | tinize an incoming | client’s      | browser, | network,  |        | and contextual |     |
| at multiple |        | IP blacklists | that           | contain | over 50  | million       | addresses  |                    |               |          |           |        |                |     |
|             |        |               |                |         |          |               |            | setting and        | the impact it | has on   | polluting | search | results        | and |
| tied        | to the | top five      | search engines | and     | tens     | of anti-virus | and        |                    |               |          |           |        |                |     |
securitycrawlers.Weuseourfindingstodevelopananti-cloaking
advertisements.Werootourstudyintheblackmarket,directly
| system | that | detects | split-view | content | returned | to two | or more |               |             |         |          |           |     |           |
| ------ | ---- | ------- | ---------- | ------- | -------- | ------ | ------- | ------------- | ----------- | ------- | -------- | --------- | --- | --------- |
|        |      |         |            |         |          |        |         | engaging with | specialists | selling | cloaking | software. |     | In total, |
distinctbrowsingprofileswithanaccuracyof95.5%andafalse
weobtaintencloakingpackagesthatrangeinpricefrom$167
| positive | rate | of 0.9%   | when tested | on a  | labeled   | dataset | of 94,946  |             |                   |     |         |               |     |          |
| -------- | ---- | --------- | ----------- | ----- | --------- | ------- | ---------- | ----------- | ----------------- | --- | ------- | ------------- | --- | -------- |
|          |      |           |             |       |           |         |            | to $13,188. | Our investigation |     | reveals | that cloaking |     | software |
| URLs.    | We   | apply our | system      | to an | unlabeled | set     | of 135,577 |             |                   |     |         |               |     |          |
search and advertisement URLs keyed on high-risk terms (e.g., spanssimpleWordpresspluginswritteninPHPthatcheckthe
luxury products, weight loss supplements) to characterize the User-Agent of incoming clients, to fully customized forks of
prevalenceofthreatsinthewildandexposevariationsincloaking theNginxwebserverwithbuilt-incapabilitiesforblacklisting
| techniques |     | across traffic | sources. | Our | study | provides | the first |     |     |     |     |     |     |     |
| ---------- | --- | -------------- | -------- | --- | ----- | -------- | --------- | --- | --- | --- | --- | --- | --- | --- |
broad perspective of cloaking as it affects Google Search and clients based on IP addresses, reverse DNS, User-Agents,
GoogleAdsandunderscorestheminimumcapabilitiesnecessary HTTPheaders,andtheorderofactionsaclienttakesuponvis-
of security crawlers to bypass the state of the art in mobile, itingacloakedwebpage.WealsoobtainaccesstomultipleIP
rDNS, and IP cloaking. blacklist databases, one of which covers 54,166 IP addresses
|     |     |     |     |     |     |     |     | associated | with Bing, Yahoo, |     | Google, | Baidu, | and | Yandex, |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------- | ----------------- | --- | ------- | ------ | --- | ------- |
I. INTRODUCTION
|     |     |     |     |     |     |     |     | and a second | that contains | over | 50  | million | IP addresses |     |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------ | ------------- | ---- | --- | ------- | ------------ | --- |
The arms race nature of abuse has spawned a contentious from universities (e.g., MIT, Rutgers), security products (e.g.,
battle in the realm of web cloaking. Here, miscreants seeking Kaspersky,McAfee),VPNs,andcloudproviders.Ouranalysis
to short-circuit the challenge of acquiring user traffic turn yields a unique perspective of which web services miscreants
to search engines and advertisement networks as a vehicle seek to evade and the technical mechanisms involved.
for delivering scams, unwanted software, and malware to We leverage our tear-down of blackhat cloaking techniques
browsingclients.Althoughcrawlersattempttovetcontentand
|     |     |     |     |     |     |     |     | to build a | scalable de-cloaking |     | crawler | and | classifier | that |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------- | -------------------- | --- | ------- | --- | ---------- | ---- |
expunge harmful URLs, there is a fundamental limitation to detects when a web server returns divergent content to two
browsingtheweb:noteveryclientobservesthesamecontent. or more distinct browsing clients. We fetch content from 11
While split views occur naturally due to personalization, geo increasingly sophisticated user emulators that cover a com-
optimization, and responsive web design, miscreants employ bination of Chrome, Android, and a simple robot accessing
similar targeting techniques in a blackhat capacity to serve the Internet via residential, mobile, and data center networks
enticing and policy-abiding content exclusively to crawlers including one associated with Google’s crawling infrastruc-
while simultaneously exposing victims to attacks. ture.Intotal,wecrawl94,946labeledtrainingURLsmultiple
Where as a wealth of prior work focused on understanding times from each profile, totaling over 3.5 million fetches. We
the prevalence of cloaking and the content behind cloaked then build a classifier that detects deviations in the content,
doorways, none precisely measured the spectrum of cloaking structure, rendering, linguistic topics, and redirect graph be-
techniques in the wild as it affects search engines and ad tween all pairs of crawlers, accurately distinguishing blackhat
networks. Indeed, earlier studies predicated their analysis on cloaking from mobile and geo targeting with 95.5% accuracy
a limited set of known cloaking techniques. These include and a false positive rate of 0.9%. We analyze in depth which
redirect cloaking in search engine results [16], [18], [24], featuresandbrowserprofilesarecriticaltodetectingcloaking,
| 2©3 7250-1162, 0L7u/1ca6  I$n3v1e.r0n0i z©zi .2 U01n6d eIEr lEicEense to IEEE. |     |     |     |     |     |     |     | 774433 |     |     |     |     |     |     |
| ------------------------------------------------------------------------------ | --- | --- | --- | --- | --- | --- | --- | ------ | --- | --- | --- | --- | --- | --- |
DDOOII  1100..11110099//SSPP..22001166..5500
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore.  Restrictions apply.

finding no single approach covers all cloaking techniques. (e.g., m.nytimes.com) as opposed to content-rich desktop
Weapplyoursystemtoanunlabeledsetof135,577Google equivalents. The more insidious variety involves serving en-
SearchandGoogleAdsURLskeyedonhigh-risktermscom- tirely distinct content to (security) crawlers in order to inflate
monly targeted by miscreants (e.g., luxury products, weight apage’ssearchrankingtodrivetraffic,evadeadqualityscan-
losssupplements)andfind11.7%ofthetop100searchresults ners, or stealthily deliver drive-by exploits only to vulnerable
and 4.9% of ads cloak against the Googlebot crawler. Of clients.Thesetechniquescreateadiscrepancyinhowtheweb
these, the most popular blackhat cloaking techniques involve isobservedbybotsandhowitisperceivedbyorganicclients.
detectingJavaScript,blacklistingGooglebot’sUser-Agentand There are many areas where blackhat cloaking can be
IP, and requiring that visitors interact with content before beneficial for miscreants, but here we focus on the following
the server finally delivers the de-cloaked payload. Despite three categories: search results, advertisements and drive-by
| a menagerie | of               | cloaking | techniques |      | in the     | wild          | that vary | downloads.      |            |     |             |        |              |          |
| ----------- | ---------------- | -------- | ---------- | ---- | ---------- | ------------- | --------- | --------------- | ---------- | --- | ----------- | ------ | ------------ | -------- |
| drastically | between          | search   | and        | ads, | our system | nevertheless  |           |                 |            |     |             |        |              |          |
|             |                  |          |            |      |            |               |           | Search results: | Cloaking   |     | is one tool | in an  | arsenal      | of tech- |
| succeeds    | at generalizable |          | detection. | We   | dig        | into specific | case      |                 |            |     |             |        |              |          |
|             |                  |          |            |      |            |               |           | niques that     | miscreants | use | for Search  | Engine | Optimization |          |
studiesandtheirmonetizationapproaches,revealingathriving
|        |               |     |               |     |               |     |          | (SEO). Servers | will     | manipulate  | fake  | or compromised |          | pages |
| ------ | ------------- | --- | ------------- | --- | ------------- | --- | -------- | -------------- | -------- | ----------- | ----- | -------------- | -------- | ----- |
| market | that attempts |     | to capitalize |     | on legitimate |     | consumer |                |          |             |       |                |          |       |
|        |               |     |               |     |               |     |          | to appear      | enticing | to crawlers | while | organic        | visitors | are   |
interestinnutraceuticals,mobilegaming,andonlineshopping.
shepherdedto(illegal)profit-generatingcontentsuchasstore-
| Finally,    | we     | explore | the fragility |        | of de-cloaking |       | systems,  |                |             |       |                  |       |                  |     |
| ----------- | ------ | ------- | ------------- | ------ | -------------- | ----- | --------- | -------------- | ----------- | ----- | ---------------- | ----- | ---------------- | --- |
|             |        |         |               |        |                |       |           | fronts selling | counterfeit |       | luxury products, |       | pharmaceuticals, |     |
| including   | our    | own, to | miscreant’s   |        | adapting       | their | cloaking  |                |             |       |                  |       |                  |     |
|             |        |         |               |        |                |       |           | and dietary    | supplements | [16], | [31],            | [32]. |                  |     |
| techniques. | Rather | than    | persist       | in the | arms           | race  | to defeat |                |             |       |                  |       |                  |     |
increasingly sophisticated browser fingerprinting techniques, Advertisements: As an alternative to duping crawlers for
we argue our approach of comparing the content that cloaked free exposure, miscreants will pay advertising networks to
servers deliver to multiple browsing clients naturally extends display their URLs. Miscreants rely on cloaking to evade
| to real rather | than | emulated | clients. |     | We discuss | the | potential |             |               |          |     |                |     |           |
| -------------- | ---- | -------- | -------- | --- | ---------- | --- | --------- | ----------- | ------------- | -------- | --- | -------------- | --- | --------- |
|                |      |          |          |     |            |     |           | ad policies | that strictly | prohibit |     | dietary scams, |     | trademark |
for client-side detection of cloaking as well as centralized infringing goods, or any form of deceptive advertisements–
reporting and scoring. Both of these approaches hinder the including malware [9], [36]. Ad scanners see a benign page
abilityofmaliciousserverstoshowbenigncontentexclusively
|     |     |     |     |     |     |     |     | while organic | visitors | land | on pages | hosting | scams | and |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------- | -------- | ---- | -------- | ------- | ----- | --- |
to crawlers, though their adoption must overcome potential malware. Time of check versus time of use (e.g., delayed
privacy concerns. URLmaliciousness)mayalsoplayintoamiscreant’scloaking
| In summary, |     | we frame | our | contributions | as  | follows: |     | strategy. |     |     |     |     |     |     |
| ----------- | --- | -------- | --- | ------------- | --- | -------- | --- | --------- | --- | --- | --- | --- | --- | --- |
• We provide the first broad study of blackhat cloaking Drive-by downloads: Miscreants compromise popular web-
techniques and the companies affected. sites and laden the pages with drive-by exploits. In order to
|     |       |               |         |     |            |      |         | evade security | crawlers | like | Wepawet | or Safe | Browsing | that |
| --- | ----- | ------------- | ------- | --- | ---------- | ---- | ------- | -------------- | -------- | ---- | ------- | ------- | -------- | ---- |
| We  | build | a distributed | crawler | and | classifier | that | detects |                |          |      |         |         |          |      |
•
|     |          |         |         |     |         |           |      | visit pages | with vulnerable |     | browsers | [6], [26], | these | payloads |
| --- | -------- | ------- | ------- | --- | ------- | --------- | ---- | ----------- | --------------- | --- | -------- | ---------- | ----- | -------- |
| and | bypasses | mobile, | search, |     | and ads | cloaking, | with |             |                 |     |          |            |       |          |
willfirstfingerprintaclientandonlyattackvulnerable,organic
| 95.5% | accuracy | and | a false | positive | rate | of 0.9%. |     |     |     |     |     |     |     |     |
| ----- | -------- | --- | ------- | -------- | ---- | -------- | --- | --- | --- | --- | --- | --- | --- | --- |
visitors.Whileweincludethisforcompleteness,wefocusour
We measure the most prominent search and ad cloaking study on search and ad cloaking.
•
| techniques |     | in the | wild; we | find | 4.9% of | ads and | 11.7% |     |     |     |     |     |     |     |
| ---------- | --- | ------ | -------- | ---- | ------- | ------- | ----- | --- | --- | --- | --- | --- | --- | --- |
of search results cloak against Google’s generic crawler. B. Prevalence of Cloaking
• We determine the minimum set of capabilities required Previousstudieshaveshownthatfindinginstancesofcloak-
|             |     |          |            |     |               |        |     | ing in the | wild requires | intimate |     | knowledge | of  | the search |
| ----------- | --- | -------- | ---------- | --- | ------------- | ------ | --- | ---------- | ------------- | -------- | --- | --------- | --- | ---------- |
| of security |     | crawlers | to contend |     | with cloaking | today. |     |            |               |          |     |           |     |            |
keywordsorthevulnerablepagesthatmiscreantstarget.Wang
II. BACKGROUND&RELATEDWORK
|     |     |     |     |     |     |     |     | et al. estimated | only | 2.2% | of Google | searches | for | trending |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------------- | ---- | ---- | --------- | -------- | --- | -------- |
We begin by outlining the incentives that bad actors have keywordscontainedcloakedresults[32].Abroadermethodfor
|            |       |          |      |           |     |                |     | finding cloaked | URLs | involved | targeted | searches | for | specific |
| ---------- | ----- | -------- | ---- | --------- | --- | -------------- | --- | --------------- | ---- | -------- | -------- | -------- | --- | -------- |
| to conceal | their | webpages | from | crawlers. | We  | also summarize |     |                 |      |          |          |          |     |          |
existing techniques that websites employ to distinguish be- cocktails of terms such as “viagra 50mg canada” where
tween crawlers and organic traffic. For the purposes of our 61% of search results contained some form of cloaking [32].
study, we consider websites that deliver optimized content to Leontiadis et al. reported a complementary finding where
|               |     |           |          |     |               |     |          | 32% of searches | for | pharmaceutical |     | keywords | advertised | in  |
| ------------- | --- | --------- | -------- | --- | ------------- | --- | -------- | --------------- | --- | -------------- | --- | -------- | ---------- | --- |
| small screens | or  | localized | visitors | to  | be benign—our |     | focus is |                 |     |                |     |          |            |     |
exclusively on blackhat cloaking. spam emails led to cloaked content [16]. Keyword targeting
|     |     |     |     |     |     |     |     | extends to | other realms | of  | fraud: Wang | et al. | found | 29.5% of |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------- | ------------ | --- | ----------- | ------ | ----- | -------- |
A. Web Cloaking Incentives search results for cheap luxury products contained URLs that
Web cloaking refers to the set of techniques that a web redirected visitors to a cloaked storefront [31]. Our strategy
server uses to fingerprint incoming visitors in order to cus- for selecting URLs to crawl is built on top of these previous
tomize page content. Benign examples include servers that findings in order to minimize the bandwidth wasted fetching
| redirect | mobile | clients | to pages | optimized |     | for small | screens | benign content. |     |     |     |     |     |     |
| -------- | ------ | ------- | -------- | --------- | --- | --------- | ------- | --------------- | --- | --- | --- | --- | --- | --- |
774444
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore.  Restrictions apply.

C. Cloaking Detection Techniques TABLE I: Cloaking fingerprinting capabilities reverse engi-
Researchers have responded to the steady adaptation of neered from the most sophisticated six samples of cloaking
software.
| cloaking         | techniques | over         | time       | with  | a medley   | of  | anti-cloaking |            |     |              |     |         |         |                 |                 |
| ---------------- | ---------- | ------------ | ---------- | ----- | ---------- | --- | ------------- | ---------- | --- | ------------ | --- | ------- | ------- | --------------- | --------------- |
| (or de-cloaking) |            | techniques.  |            | Early | approaches |     | by Wang et    |            |     |              |     |         |         |                 |                 |
|                  |            |              |            |       |            |     |               | Capability |     | CloakingType |     | C1      | C2 C3   | C4              | C5 C6           |
| al. relied       | on         | a cross-view | comparison |       | between    |     | search re-    |            |     |              |     |         |         |                 |                 |
|                  |            |              |            |       |            |     |               |            |     |              |     | (cid:2) | (cid:2) | (cid:2) (cid:2) | (cid:2) (cid:2) |
sults fetched by a browser configured like a crawler and a IPAddress Network
|     |     |     |     |     |     |     |     | rDNS |     |     | Network |     | – (cid:2) | (cid:2) (cid:2) | – (cid:2) |
| --- | --- | --- | --- | --- | --- | --- | --- | ---- | --- | --- | ------- | --- | --------- | --------------- | --------- |
second fetch via a browser that emulated a real user [33], Geolocation Network (cid:2) – (cid:2) (cid:2) – (cid:2)
[34]. They classified a page as cloaking if the redirect chain (cid:2) (cid:2) (cid:2) (cid:2) (cid:2) (cid:2)
|     |     |     |     |     |     |     |     | User-Agent |     |     | Browser |     |     |     |     |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------- | --- | --- | ------- | --- | --- | --- | --- |
deviated across fetches. This same approach dominates sub- JavaScript Browser (cid:2) – (cid:2) – – (cid:2)
sequent cloaking detection strategies that fetch pages via Flash Browser – – – – – –
multiple browser profiles to examine divergent redirects (in- HTTPReferer Context (cid:2) (cid:2) (cid:2) (cid:2) (cid:2) (cid:2)
|     |     |     |     |     |     |     |     |     |     |     |     | (cid:2) |     | (cid:2) |     |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ------- | --- | ------- | --- |
cluding JavaScript, 30X, and meta-refresh tags) [16], [17], Keywords Context – – – –
|                |                |                 |            |                 |            |         |             | Timewindow        |           |            | Context  |            | – –         | (cid:2) – | (cid:2) – |
| -------------- | -------------- | --------------- | ---------- | --------------- | ---------- | ------- | ----------- | ----------------- | --------- | ---------- | -------- | ---------- | ----------- | --------- | --------- |
| [32], inspect  |                | the redirection |            | chains          | that       | lead    | to poisoned |                   |           |            |          |            |             |           |           |
|                |                |                 |            |                 |            |         |             | Orderofoperations |           |            | Context  |            | – –         | (cid:2) – | – (cid:2) |
| search results |                | [18], isolate   | variations |                 | in content |         | between two |                   |           |            |          |            |             |           |           |
| fetches        | (e.g., topics, | URLs,           |            | page structure) |            | [31],   | [32], [35], |                   |           |            |          |            |             |           |           |
| or apply       | cloaking       | detection       |            | to alternative  |            | domains | such as     |                   |           |            |          |            |             |           |           |
|                |                |                 |            |                 |            |         |             | capabilities      | such      | as content | spinning |            | and keyword |           | stuffing. |
| spammed        | forum          | URLs            | [24].      | Other           | approaches |         | exclusively |                   |           |            |          |            |             |           |           |
|                |                |                 |            |                 |            |         |             | We use            | this tear | down       | later    | in Section | IV          | to design | an        |
targetcompromisedwebserversandidentifyclustersofURLs
|               |          |           |             |          |           |       |               | anti-cloaking | system | capable   | of      | defeating | all        | of the        | cloaking |
| ------------- | -------- | --------- | ----------- | -------- | --------- | ----- | ------------- | ------------- | ------ | --------- | ------- | --------- | ---------- | ------------- | -------- |
| all with      | trending | keywords  |             | that are | otherwise |       | irrelevant to |               |        |           |         |           |            |               |          |
|               |          |           |             |          |           |       |               | techniques    | we     | discover. | We make | no        | claim our  | investigation |          |
| other content | hosted   | on        | the domain  |          | [14]. Our | study | improves      |               |        |           |         |           |            |               |          |
|               |          |           |             |          |           |       |               | exhaustively  | covers | cloaking  |         | software  | or whether |               | our ten  |
| upon these    | prior    | detection | strategies. |          | To        | wit,  | we build an   |               |        |           |         |           |            |               |          |
particularprogramsarewidelyusedbymiscreants.Indeed,the
| anti-cloaking | pipeline |     | that addresses |     | previously |     | unexplored |     |     |     |     |     |     |     |     |
| ------------- | -------- | --- | -------------- | --- | ---------- | --- | ---------- | --- | --- | --- | --- | --- | --- | --- | --- |
priceandskillsetrequiredtooperatesomeofthepackagesen-
cloakingtechniquesasgleanedfromtheunderground;andwe
surestheirexclusivitytoonlythemostaffluentorsophisticated
exploreadditionalapproachesforcross-viewcomparisonsthat
miscreants.Thatsaid,inconductingouranalysis,weobserved
| contends  | with | page dynamism, |     | interstitial |          | ads, network-based |            |          |        |          |            |       |     |          |     |
| --------- | ---- | -------------- | --- | ------------ | -------- | ------------------ | ---------- | -------- | ------ | -------- | ---------- | ----- | --- | -------- | --- |
|           |      |                |     |              |          |                    |            | that the | set of | cloaking | techniques | among | the | packages | we  |
| cloaking, | and  | the absence    | of  | divergent    | redirect |                    | paths. Our |          |        |          |            |       |     |          |     |
analyzedquicklyconvergedtoafixedsetofsignals.Thismay
pipelinealsoimprovesonpriorworkasitdiscernsadversarial
|          |      |               |     |     |         |              |     | indicate | that while | our coverage |     | of cloaking | software |     | may be |
| -------- | ---- | ------------- | --- | --- | ------- | ------------ | --- | -------- | ---------- | ------------ | --- | ----------- | -------- | --- | ------ |
| cloaking | from | geo targeting |     | and | content | optimization | for |          |            |              |     |             |          |     |        |
incomplete,thebestcloakingtechniquesarefrequentlyshared
| small screens. |           | It does  | so by        | comparing | across | views         | both in  |             |          |              |       |              |     |          |      |
| -------------- | --------- | -------- | ------------ | --------- | ------ | ------------- | -------- | ----------- | -------- | ------------ | ----- | ------------ | --- | -------- | ---- |
|                |           |          |              |           |        |               |          | (or copied) | much     | like exploit | kits. |              |     |          |      |
| terms of       | textual   | topic    | and entities | detected  |        | in images.    | These    |             |          |              |       |              |     |          |      |
| improvements   |           | allow us | to measure   |           | the    | dominant      | cloaking |             |          |              |       |              |     |          |      |
| strategies     | in the    | wild,    | and in       | turn,     | inform | search,       | ad, and  |             |          |              |       |              |     |          |      |
|                |           |          |              |           |        |               |          | A. Cloaking | Software | Analysis     |       |              |     |          |      |
| malware        | pipelines | that     | must contend |           | with   | web cloaking. |          |             |          |              |       |              |     |          |      |
|                |           |          |              |           |        |               |          | Of the      | cloaking | applications |       | we analyzed, |     | only one | (co- |
III. UNDERGROUNDPERSPECTIVEOFCLOAKING
|     |     |     |     |     |     |     |     | incidentally, | the | most expensive) |     | protected | itself | with | a tool |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------- | --- | --------------- | --- | --------- | ------ | ---- | ------ |
Cloaking—like the commoditization of exploits, proxies, withnopubliclyavailableunpacker.Languagesforthevarious
and hosting [2], [28]—is an infrastructure component for sale cloaking applications ranged from C++, Perl, JavaScript, and
withintheunderground.Toidentifypotentialcloakingservices PHP. Sophistication ranged from drop-in scripts and plugins
and software, we first exhaustively crawled and indexed a for Wordpress pages, while others included a custom compi-
selection of underground forums. We then ranked forum lation of Nginx for serving cloaked content. For each of the
discussions based on the frequency of keywords related to applications,wemanuallyinvestigatedtheunderlyingcloaking
cloaking software. The most discussed cloaking package was logic and any embedded blacklists.
mentioned623times,withtheauthorofthesoftwareengaging
| with the | community |     | to provide | support |     | and advertise | new |     |     |     |     |     |     |     |     |
| -------- | --------- | --- | ---------- | ------- | --- | ------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
deals. The least popular service was mentioned only 2 times. B. Cloaking Techniques
Through manual analysis and labor, we successfully obtained Cloakingtechniquesamongtheservicesweanalyzedspana
| the top | ten most | popular | cloaking | packages |     | which | ranged in |          |          |          |     |            |                 |     |     |
| ------- | -------- | ------- | -------- | -------- | --- | ----- | --------- | -------- | -------- | -------- | --- | ---------- | --------------- | --- | --- |
|         |          |         |          |          |     |       |           | gamut of | network, | browser, | and | contextual | fingerprinting. |     | We  |
pricefrom$167forentrylevelproductsupto$13,188forthe
|                    |     |            |     |           |     |           |           | present          | a detailed | breakdown    |     | of key      | capabilities | in      | Table I. |
| ------------------ | --- | ---------- | --- | --------- | --- | --------- | --------- | ---------------- | ---------- | ------------ | --- | ----------- | ------------ | ------- | -------- |
| most sophisticated |     | advertised |     | features. | We  | note that | for legal |                  |            |              |     |             |              |         |          |
|                    |     |            |     |           |     |           |           | These techniques |            | only scratch |     | the surface | of           | browser | finger-  |
protectionandtoavoidanypotentialde-anonymizationofour printing that can otherwise enumerate screen size, font lists,
undergroundidentities,wecannotpubliclydisclosethenames
|                    |     |        |     |            |     |     |              | header orders, |      | and divergent |            | JavaScript | and          | HTML | imple-   |
| ------------------ | --- | ------ | --- | ---------- | --- | --- | ------------ | -------------- | ---- | ------------- | ---------- | ---------- | ------------ | ---- | -------- |
| of the underground |     | forums | we  | harvested, | or  | the | names of the |                |      |               |            |            |              |      |          |
|                    |     |        |     |            |     |     |              | mentations     | [3], | [7], [8],     | [20]–[23], | [29].      | Intuitively, |      | cloaking |
cloaking software under analysis. services need only to deliver a fingerprinting technique to
| We analyzed |          | all ten        | cloaking | packages      |     | in order | to gain an   |           |      |                |     |          |           |       |       |
| ----------- | -------- | -------------- | -------- | ------------- | --- | -------- | ------------ | --------- | ---- | -------------- | --- | -------- | --------- | ----- | ----- |
|             |          |                |          |               |     |          |              | consumers | that | works. Without |     | external | pressure, | there | is no |
| insight     | into (1) | fingerprinting |          | capabilities; |     | (2)      | switch logic |           |      |                |     |          |           |       |       |
reasonforcloakingdeveloperstoadapttowardmorecomplex
| for displaying |     | targeted | content; | and | (3) | other built-in | SEO |            |          |     |           |     |     |     |     |
| -------------- | --- | -------- | -------- | --- | --- | -------------- | --- | ---------- | -------- | --- | --------- | --- | --- | --- | --- |
|                |     |          |          |     |     |                |     | approaches | proposed | in  | research. |     |     |     |     |
774455
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore.  Restrictions apply.

TABLE II: Breakdown of crawling bots covered by the TABLE III: Breakdown of the types of businesses targeted
blacklist-as-a-service. The top five search engines include bythestaticblacklist,includingthenumberofsubnetsandIP
Bing, Yahoo, Google, Baidu, and Yandex. addresses in those ranges.
Crawler Operator BlacklistedIPs Overall EntityType DistinctEntities Subnets IPCoverage
msn.com Bing 21,672 40.01% Hostingproviders 42 508 12,079,768
yahoo.com Yahoo 15,069 27.82% Securitycompanies 30 346 541,860
googlebot.com Google 5,398 9.97% Internetserviceproviders 27 49 1,419,600
| baidu.com    |                | Baidu          |        |          | 2,846       | 5.25%         | Searchcompanies      |     |     |     | 9   | 32  | 1,392,640  |
| ------------ | -------------- | -------------- | ------ | -------- | ----------- | ------------- | -------------------- | --- | --- | --- | --- | --- | ---------- |
| yandex.com   |                | Yandex         |        |          | 1,092       | 2.02%         | Othercompanies       |     |     |     | 3   | 12  | 34,628     |
|              |                |                |        |          |             |               | Proxynetworks        |     |     |     | 3   | 10  | 1,334      |
| Other        |                | Ask,Lycos,etc. |        |          | 1,117       | 2.06%         |                      |     |     |     |     |     |            |
|              |                |                |        |          |             |               | Academicinstitutions |     |     |     | 2   | 14  | 17,106,682 |
| Unknown      |                | –              |        |          | 6,972       | 12.87%        |                      |     |     |     |     |     |            |
|              |                |                |        |          |             |               | Hackercollectives    |     |     |     | 2   | 4   | 60         |
|              |                |                |        |          |             |               | Individuals          |     |     |     | 2   | 4   | 780        |
|              |                |                |        |          |             |               | Registrars           |     |     |     | 2   | 4   | 19,136,508 |
| 1) Network   | Fingerprinting |                |        |          |             |               |                      |     |     |     |     |     |            |
|              |                |                |        |          |             |               | Total                |     |     |     | 122 | 983 | 51,713,860 |
| IP Address:  | Some           | crawlers       | make   | no       | effort to   | obfuscate the |                      |     |     |     |     |     |            |
| IP addresses | ranges         | they           | appear | from.    | This allows | cloaking      |                      |     |     |     |     |     |            |
| services     | to enumerate   | the            | set of | bot IPs. | Of the      | ten cloaking  |                      |     |     |     |     |     |            |
services we examine, four embed an IP blacklist; the others the crawlers for some security companies. Finally, the list
allowedoperatorstouploadtheirownIPblacklist.Ofthefour contains a few academic institutions (e.g., MIT, Rutgers),
| IP blacklists, | three | mirrored | the | same | blacklist-as-a-service |     |                    |     |        |           |       |          |        |
| -------------- | ----- | -------- | --- | ---- | ---------------------- | --- | ------------------ | --- | ------ | --------- | ----- | -------- | ------ |
|                |       |          |     |      |                        |     | hacker collectives |     | (e.g., | Germany’s | Chaos | Computer | Club), |
available for a $350 annual fee. The list, updated twice daily, and individual researchers. We note that the abnormally large
contained 54,166 unique IP addresses tied to popular search number of IP addresses associated with academic institutions
engines and crawlers at the time of our analysis. This same results from universities such as MIT controlling an entire
| service  | provided     | a capability | for  | cloaking | clients | to report   |         |        |                    |     |             |     |        |
| -------- | ------------ | ------------ | ---- | -------- | ------- | ----------- | ------- | ------ | ------------------ | --- | ----------- | --- | ------ |
|          |              |              |      |          |         |             | Class A | subnet | that the blacklist |     | owner opted | to  | cover. |
| back all | IP addresses | and          | HTTP | headers  | tied    | to incoming |         |        |                    |     |             |     |        |
Interestingly,whencomparingtheblacklist-as-a-serviceand
| visitors | to a centralized |     | server | which | the blacklist | service |     |     |     |     |     |     |     |
| -------- | ---------------- | --- | ------ | ----- | ------------- | ------- | --- | --- | --- | --- | --- | --- | --- |
recommended for timely detection of new crawling activities. thestaticlistofIPs,wefindonlytwosubnetsincommon,both
We note that, despite us crawling sites that we later learned ofwhichbelongtoGoogle.Thisindicatesthattheblacklist-as-
|                   |                  |                        |            |            |            |                | a-service        | is geared  | toward    | targeting | search | engines  | for SEO,  |
| ----------------- | ---------------- | ---------------------- | ---------- | ---------- | ---------- | -------------- | ---------------- | ---------- | --------- | --------- | ------ | -------- | --------- |
| via side-channels |                  | relied                 | on this    | blacklist, | our IPs    | were never     |                  |            |           |           |        |          |           |
|                   |                  |                        |            |            |            |                | whereas          | the second | blacklist | focuses   | on     | security | companies |
| identified        | (potentially     | due                    | to limited | crawling   |            | or ineffective |                  |            |           |           |        |          |           |
| detection         | on the service’s |                        | part).     |            |            |                | and researchers. |            |           |           |        |          |           |
| Examining         | the              | blacklist-as-a-service |            |            | in detail, | we find that   |                  |            |           |           |        |          |           |
reverse DNS queries on the IP addresses surface crawlers Reverse DNS: In the event a crawler appears from a non-
from Bing, Yahoo, Google, Baidu, and Yandex as detailed blacklisted IP, four of the ten cloaking services perform a
in Table II—the top five search engines based on Alexa rDNSlookupofavisitor’sIP.IntheabsenceofaNXDOMAIN
|         |             |          |        |        |         |            | error, the | software | compares | the | rDNS record | against | a list |
| ------- | ----------- | -------- | ------ | ------ | ------- | ---------- | ---------- | -------- | -------- | --- | ----------- | ------- | ------ |
| ranking | [1]. A tiny | fraction | of IPs | relate | to Ask, | Lycos, and |            |          |          |     |             |         |        |
smallersearchengines.Consequently,anyattempttode-cloak of domains substrings belonging to Google (1e100, google),
contentfromtheseIPs—evenwithseeminglyorganicbrowser Microsoft, Yahoo, Baidu, Yandex, Ask, Rambler, DirectHit,
profiles—will fail. Another 6,972 IPs (12.9%) have no rDNS and Teoma. Some of the cloaking services in turn add newly
|             |            |     |        |          |          |            | identified | crawler | IPs to | their embedded |     | blacklists. | As such, |
| ----------- | ---------- | --- | ------ | -------- | -------- | ---------- | ---------- | ------- | ------ | -------------- | --- | ----------- | -------- |
| information | and appear |     | from a | distinct | /16 CIDR | block than |            |         |        |                |     |             |          |
the top five search engines (which operate out of 77 CIDR anyanti-cloakingpipelinemustataminimumcrawlfromIPs
/16 blocks). We examine whether any of these overlap with with non-overlapping (or completely absent) rDNS informa-
tion.
| contemporaneous |        | lists of  | proxies | including | 1,095   | Tor exit    |     |     |     |     |     |     |     |
| --------------- | ------ | --------- | ------- | --------- | ------- | ----------- | --- | --- | --- | --- | --- | --- | --- |
| nodes and       | 28,794 | HideMyAss |         | IPs. We   | find no | evidence of |     |     |     |     |     |     |     |
Tor or HideMyAss blacklisting. Geolocation: We find that four of the ten cloaking services
The last of the four blacklists contained a significant static allowgeographictargetingatacountrylevelgranularitybased
list of CIDR blocks encompassing 51,713,860 IP addresses on mappings. One goes so far as to embed a duplicate of
from 122 business entities as annotated in the blacklist the MaxMind public GeoIP list for live querying. We do
(shown in Table III). The coverage advertised by the blacklist not observe any pre-configured list of blocked geo origins;
includes 30 security and anti-virus companies (e.g., Avira, all targeting is left to the software’s operator. This poses
Comodo, Kaspersky) as well as 9 popular search engines a significant challenge to anti-cloaking pipelines as network
(e.g.,Google,Microsoft,Yahoo).Thelistalsocoversmultiple infrastructure must support arbitrary network vantage points
hosting providers, public clouds (e.g., Amazon), registrars, around the globe. However, as we previously discussed, most
and proxy networks such as TOR that are unlikely sources cloaking services fail to block Tor or major proxy providers.
of organic traffic. We also find CIDR blocks that blacklist Assuch,weconsidertheseservicesasapotentiallyacceptable
entire ISPs, which as the blacklist author annotates, serve sources of IP diversity.
774466
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore.  Restrictions apply.

TABLEIV:User-Agentsubstringsusedbycloakingsoftware purported visitor to a miscreant’s page. Mechanistically, the
to identify crawlers. cloaking software extracts the list of search terms embedded
in the HTTP Referer using a set of customized regular
CrawlerUser-Agentsubstrings expressions for each search portal and then compares the
altavista aol askj baidu bingbot crawler terms against an operator-provided list of negative keywords
gigablast google jeeves lycos msn slurp
and positive keywords (e.g., viagra, Tiffany) associated with
sogou spider teoma yahoo yandex
a page. The software triggers cloaking logic if a HTTP
Referer contains any negative keywords or lacks any pos-
itive keywords. We adapt to this technique by embedding
2) Browser Fingerprinting
expectedkeywordsinourHTTPReferer—derivedfromad
targeting criteria or page content. We note that since Google
User-Agent:Well-behavingsearchandadvertisementcrawlers has been serving search results over TLS to logged-in users
announce their presence with specialized User-Agent strings since 2013, and therefore not passing keywords in the HTTP
commonly advertised on the operator’s website. Examples referrer,theeffectivenessofkeywordcloakinghasdiminished.
include Google’s googlebot; Microsoft’s bingbot and msnbot; We have found that keyword cloaking is no longer pivotal, as
andYahoo’sslurp.Wefindcloakingservicesubiquitouslyrely it has been in previous works [32].
on User-Agent comparisons to explicitly block Google, Bing,
Yahoo,Ask,Baidu,Teoma,andYandex.Thecloakingservices TimeWindow:Timing-basedcloakingprohibitsvisitorsfrom
also carve out generic exceptions for crawler and spider accessinguncloakedcontentmorethanonceinaspecifictime
to trigger cloaking logic. We provide a detailed breakdown window.Thetwoserviceswefindofferingthiscapabilityrely
of the exact substring matching patterns in Table IV. Some onserversidelogsofavisitor’sIPaddress.Anyrepeatvisitors
substrings capture overly broad applications. One cloaking within 24 hours are redirected to cloaked content as if they
productcontendswiththisfactbyincludingawhitelistcover- were a crawler. This raises a potential issue of false negatives
ingcode.google.com/appengine(third-partyservicesoperating for an anti-cloaking pipeline without a sufficiently large IP
on Google’s infrastructure) and via translate.google.com (in- pool.
coming translation requests likely from users); however, all Order of Operations: While most of the cloaking services
other services make no exception. we study rely on a single doorway page through which all
cloaking logic triggers, two of the services supports multiple
JavaScript&Flash:JavaScriptandFlash(orthelackthereof)
hops. Upon visiting a page, the software sets a short lived
canserveasbothacrawlerfingerprintingtechniqueaswellas
cookie (e.g., seconds). When legitimate users interact with
aredirectiondeliverymethod.Wefindthreecloakingservices
the page, such as clicking on a URL, the next doorway
rely on JavaScript execution as a technique for blocking
checkswhetherthiscookieispresentandwithintheexpiration
rudimentary crawlers. We find no support for Flash-based
window. This allows cloaked websites to enforce a specific
cloaking, though there is evidence of such attacks in the
sequence of actions (e.g., visit, click) where crawlers would
past[9].Oneservicealsoallowsforoperatorstoinputcustom
likely enqueue the URL for visiting at a later time or on
JavaScript fingerprinting logic executed on each visit—a po-
an entirely different machine. Our pipeline consolidates all
tential route to configure SEO-focused cloakers for drive-by
crawling of a domain to a single short window.
exploittargeting,thoughwearguesuchattacksareorthogonal
and more likely to come via exploit kits [12]. For our study,
C. Redirection Techniques
weopttosupportbothJavaScriptandFlashwhencrawlingto
Weobservethreetechniquesthatcloakingapplicationsrely
cover all possible bases.
on to deliver split-view content upon successfully fingerprint-
3) Contextual Fingerprinting ing a client. The first involves redirecting clients via meta-
refresh,JavaScript,or30Xcodes.Crawlersareeitherstopped
HTTP Referer: The final ubiquitous cloaking technique
atadoorwayorredirectedtoanentirelydifferentdomainthan
we observe across blackhat applications involves scanning
legitimate clients. Alternatively, websites dynamically render
the HTTP Referer of incoming visitors to verify users
content via server-side logic to include new page elements
originate from search portals. The default whitelist matches
(e.g., embedding an iframe) without changing the URL that
major crawlers (previously discussed in Table IV), though
appearsinabrowser’saddressbar.Thelasttechniqueinvolves
miscreants can disable this feature. This technique prevents
servingonlycrawlersa40Xor50Xerror.Weaccountforeach
crawlers from harvesting URLs and visiting them outside the
ofthesetechniqueswhendesigningouranti-cloakingpipeline.
context they first appeared. We contend with this cloaking
approach by always spoofing a HTTP Referer, the details D. Built-in SEO Services
of which we expand on in Section IV. All but one (C6) of the cloaking software under analysis
supports automatic content generation aimed at SEO either
Incoming Keywords: Keyword cloaking—supported by two
nativelyorthroughthird-partyplugins(e.g.,SEnuke,XRumer
services—takes HTTP Referer cloaking a step further and
which are content spinning programs that create topically
checks the validity of the search keywords that brought a
774477
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore. Restrictions apply.

related documents [37]). The most advanced built-in solution TABLE V: Breakdown of labeled data we use for training
takes a set of targeted search terms from the software’s and evaluating our classifier.
operator, after which the program will automatically query
popular search engines for related content, scrape top-ranked LabeledDataset Source Volume
links, and synthesize the content into a seemingly relevant Legitimatewebsites Alexa 75,079
Cloakedstorefronts SEOabuse[31] 19,867
document from a crawler’s perspective. Furthermore, these
systems automatically detect and exclude copyright infring- Total 94,946
ing content and trademarked names to avoid penalization
TABLE VI: Breakdown of unlabeled data that we classify to
or removal by search ranking algorithms. As part of this
study cloaking in the wild.
document construction, the software will intersperse targeted
search terms with stolen content to increase the frequency of
UnlabeledDataset Source Volume
related terms. We rely on this observation later in Section IV
Luxurystorefronts GoogleSearch 115,071
in order to detect contextual cloaking that requires a visitor’s
Health,softwareads GoogleAds 20,506
HTTP Referer to contain specific keywords as previously
Total 135,577
discussed in this section.
IV. DETECTINGCLOAKING
dataset has a class imbalance toward non-cloaked content
We leverage our tear-down of blackhat cloaking techniques
which helps to emphasize false negatives over false positives.
tobuildascalableanti-cloakingpipelinethatdetectswhentwo
For studying blackhat fingerprinting techniques, we rely on
or more distinct browsers are shown divergent content. We
asampleofunlabeledURLstiedtoGoogleSearchandGoogle
preview our system’s design in Figure 1. We start by aggre-
Adstargetingmobileusers.2 Unlikeourtrainingcorpus,these
gatingadiversesampleofURLstoscanforcloaking((cid:3)).We
carry no biases from previous de-cloaking systems. Due to
thenfetcheachoftheseURLsviamultiplebrowserprofilesas
the targeted nature of cloaking as previously explored by
well as network vantage points to trigger any cloaking logic
Wang et al. [32], we predicate our searches on high-value
((cid:4)). We finally compare the content, structure, and redirect
keywords related to luxury products (e.g., gucci, prada, nike,
graph associated with each fetch ((cid:5)) before feeding these
abercrombie) and ad selection on keywords related to weight
features into a classifier to detect the presence of blackhat
loss(e.g.,garcinia,keatone,acai)andpopularmobilesoftware
cloaking ((cid:6)). Whereas we note multiple prior studies have
applications (e.g., whatsapp, mobogenie). While it is possible
proposed techniques to de-cloak URLs in specific settings—
this targeting biases our evaluation, we argue that the content
particularlyredirectioncloaking—ourgoalwiththissystemis
that miscreants serve is independent from the underlying
tounderstandwhichanti-cloakingtechniquesgeneralizeacross
technology used to fingerprint crawlers. In total, we collect
web cloaking (including mobile and reverse-proxy cloaking),
135,577 URL samples, only a fraction of which we assume
and similarly, to understand the minimum set of capabilities
will actually cloak.
required of security scanners to contend with the current
cloaking arms race. We defer concrete implementation details B. Browser Configuration
till Section V.
While our dataset may appear small, this is because we
crawleachURLwith11distinctbrowserandnetworkconfig-
A. Candidate URL Selection
urations in an attempt to trigger any cloaking logic, repeating
To conduct our study we aggregate a stream of URLs
eachcrawlthreetimestoruleoutnoiseintroducedbydynamic
from popular websites, search results, and mobile-targeted
content or network errors. In total, we perform over 7 million
advertisements. We split our dataset into two: one part for
crawls. We detail each crawl configuration in Table VII. We
trainingaclassifierbasedonlabeleddatafrompreviousstudies
chose this set based on our domain knowledge of reversed
of cloaking outlined in Table V; and a second sample that we
blackhatserviceswhichtargetvariousplatforms,environment
feed into our classifier to analyze an unbiased perspective of
variables, JavaScript, Flash, and cookie functionality. Also,
cloaking in the wild shown in Table VI.
these configurations cover the three possible vantage points
Our training corpus of benign URLs consists of a random
of anti-cloaking deployments: a search engine advertising its
sample of pages appearing in the Alexa Top Million, all of
crawlers with their User Agents and IP addresses, a browser
which we assume to be non-cloaked.1 We later validate this
farm deployed in the cloud, and a stealthy deployment using
assumption in Section VII. For labeled instances of cloaked
mobileandresidentialnetworks.InsectionVI-D,weevaluate
domains we rely on a feed of counterfeit luxury storefronts
how each of these vantage points contribute to our overall
that fingerprint Google’s search bot, maintained by Wang et
cloaking detection performance.
al.[31],collectedbetweenFebruary,2015–May,2015.Intotal,
In total, we provide three native platforms for fetching
we rely on 94,946 URLs for training. We note our labeled
content: Chrome on Desktop; Chrome on Android; and a
1We reiterate that we treat personalization, geo targeting, and reactive 2WeassumethatGoogledeployssomedefensesagainstcloaking.Assuch,
designasbenignandthusnon-cloaking.Manyofthesetechniquesarepresent
ourdatasetwillcaptureonlymaturecloakingtechniquesthatevadeimmediate
intheAlexaTopMillion.Weuseacloakinglabelonlyforblackhattechniques.
detectionbyGooglecrawlers.
774488
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore. Restrictions apply.

((cid:3)).
Fig. 1: Cloaking detection pipeline. We crawl URLs from the Alexa Top Million, Google Search, and Google Ads
We dispatch requests to a farm of stratified browser profiles covering mobile, desktop, and simple crawlers and network
configurationsthatencompassresidential,mobile,andcloudIPaddressestofetchcontent((cid:4)).Wethencomparethesimilarity
of content returned by each crawl ((cid:5)), feeding the resulting metrics into a classifier that detects divergent content indicative
((cid:6)).
of cloaking
TABLE VII: List of browser, network, and contextual configurations supported by our system.
| ProfileName |     |     |     |     |     | Platform |     | User-Agent |     |     | Network | Referrer |     | Click |
| ----------- | --- | --- | --- | --- | --- | -------- | --- | ---------- | --- | --- | ------- | -------- | --- | ----- |
GooglebotBasic HTTPRequestonly Googlebot Google (cid:7) (cid:7)
GooglebotDesktop ChromeDesktop Googlebot Google (cid:7) (cid:2)
|                       |     |     |     |     |     |                 |     |           |     |     |        |     | (cid:7) | (cid:2) |
| --------------------- | --- | --- | --- | --- | --- | --------------- | --- | --------- | --- | --- | ------ | --- | ------- | ------- |
| GooglebotAndroid      |     |     |     |     |     | ChromeAndroid   |     | Googlebot |     |     | Google |     |         |         |
|                       |     |     |     |     |     |                 |     |           |     |     |        |     | (cid:7) | (cid:7) |
| BasicCloud(noreferer) |     |     |     |     |     | HTTPRequestonly |     | ChromeOSX |     |     | Cloud  |     |         |         |
| BasicCloud            |     |     |     |     |     | HTTPRequestonly |     | ChromeOSX |     |     | Cloud  |     | (cid:2) | (cid:7) |
ChromeDesktopCloud(noreferer) ChromeDesktop ChromeOSX Cloud (cid:7) (cid:2)
|                    |     |     |     |     |     |               |     |           |     |     |       |     | (cid:2) | (cid:2) |
| ------------------ | --- | --- | --- | --- | --- | ------------- | --- | --------- | --- | --- | ----- | --- | ------- | ------- |
| ChromeDesktopCloud |     |     |     |     |     | ChromeDesktop |     | ChromeOSX |     |     | Cloud |     |         |         |
ChromeMobileCloud(noreferer) ChromeAndroid ChromeAndroid4.4 Cloud (cid:7) (cid:2)
ChromeMobile ChromeAndroid ChromeAndroid4.4 Cloud (cid:2) (cid:2)
|             |     |     |     |     |     |               |     |           |     |     |             |     | (cid:2) | (cid:2) |
| ----------- | --- | --- | --- | --- | --- | ------------- | --- | --------- | --- | --- | ----------- | --- | ------- | ------- |
| DesktopUser |     |     |     |     |     | ChromeDesktop |     | ChromeOSX |     |     | Residential |     |         |         |
MobileUser ChromeAndroid ChromeAndroid4.4 Mobile (cid:2) (cid:2)
HTMLtoincludeonlyvisible,non-stopwordtext,afterwhich
basicHTTPfetchthatsupportscookiesand30Xredirects,but
|     |     |     |     |     |     |     | we  | select the | top three | most | frequent | words. | Due | to how |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------- | --------- | ---- | -------- | ------ | --- | ------ |
doesnothandleFlash,JavaScript,metaredirects,orembedded
|     |     |     |     |     |     |     | miscreants |     | spin content | to achieve | a   | high | search rank | (as |
| --- | --- | --- | --- | --- | --- | --- | ---------- | --- | ------------ | ---------- | --- | ---- | ----------- | --- |
content(e.g.,iframes,images).WethenconfiguretheUser-
discussedinSectionIII),thesekeywordsareidenticaltothose
AgentofeachplatformtomirrorthelatestversionofChrome
miscreantsexpectfromlegitimateclients.Forad-basedURLs,
| on Mac OSX; | Chrome |     | on a Nexus | 5 Android |     | device; or the |     |     |     |     |     |     |     |     |
| ----------- | ------ | --- | ---------- | --------- | --- | -------------- | --- | --- | --- | --- | --- | --- | --- | --- |
theprocessissimpler:werelyonthekeywordstheadvertiser
| Google search | bot. | Finally, | we  | wire the | browser | to proxy all |     |     |     |     |     |     |     |     |
| ------------- | ---- | -------- | --- | -------- | ------- | ------------ | --- | --- | --- | --- | --- | --- | --- | --- |
requests through a pre-defined network (e.g., mobile, cloud) bids on for targeting (gathered from Google AdWords).
described shortly. After a successful fetch, we save both the Since browsers have complex policies on when to set the
HTML content of a page along with a screenshot. Due to the referrer (depending on whether the source and destination
possibility of URL visits introducing browser state, we tear URLs are over TLS, and the type of redirect [30], [33]), we
down our environment and clear all cookies between fetches. haveoptednottospoofacrawler’spathbysimplyoverwriting
AsweshowlaterinSectionVII,inpracticeonlyafewofthese the Referer field, as the difference in referrer handling
profiles are necessary to detect all cloaked content (though might not trigger the uncloaking of a target website. Instead,
not measure the precise cloaking logic). Security crawlers we first load a Google search page and explicitly create a
|     |     |     |     |     |     |     | new | element | on the page | via | JavaScript | that | directs | to the |
| --- | --- | --- | --- | --- | --- | --- | --- | ------- | ----------- | --- | ---------- | ---- | ------- | ------ |
canadoptthisslimmed-downconfigurationtoincreaseoverall
throughput. destination URL along with the aforementioned keywords
|     |     |     |     |     |     |     | embedded | in  | the URL’s | parameters, | after | which | we click | the |
| --- | --- | --- | --- | --- | --- | --- | -------- | --- | --------- | ----------- | ----- | ----- | -------- | --- |
Context Selection: We support spoofing three contextual element. We support this approach for all types of URLs.
| features when | fetching |         | URLs: | the keywords | a             | user searches |          |     |              |       |      |        |              |     |
| ------------- | -------- | ------- | ----- | ------------ | ------------- | ------------- | -------- | --- | ------------ | ----- | ---- | ------ | ------------ | --- |
|               |          |         |       |              |               |               | Finally, | to  | handle click | walls | that | appear | due to order | of  |
| for; the path | our      | crawler | takes | to reach     | a destination | (e.g.,        |          |     |              |       |      |        |              |     |
theHTTPReferer);anduseractionstakenuponreachinga operation-style cloaking, upon reaching a URL’s final landing
pagewewaitafewsecondsandthenselectthelargestelement
| page (e.g., | clicking). | To  | determine | which | keywords | to spoof, |     |          |              |        |        |       |                |     |
| ----------- | ---------- | --- | --------- | ----- | -------- | --------- | --- | -------- | ------------ | ------ | ------ | ----- | -------------- | --- |
|             |            |     |           |       |          |           | and | simulate | a user click | event. | If the | click | fails to cause | the |
wefirstfetcheverynonad-basedURLwithabasicGooglebot
|            |      |         |     |          |         |               | browser | to  | load a different | URL, | we  | ignore | the element | and |
| ---------- | ---- | ------- | --- | -------- | ------- | ------------- | ------- | --- | ---------------- | ---- | --- | ------ | ----------- | --- |
| absent any | HTTP | Referer |     | and then | extract | the (stuffed) |         |     |                  |      |     |        |             |     |
keywords on the page. Methodologically, we filter a page’s repeattheprocessuntilaloadingeventoccursornoelements
774499
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore.  Restrictions apply.

arelefttoconsider.Inthisfashionwecreatearealisticcontext Screenshot Similarity: Our second similarity score estimates
in which a user visits a search engine, enters an appropriate visualdifferencesinthelayoutandmediapresentedtobrows-
searchquery,clicksonthecloakedpage’ssearch,ad,ordrive- ing profiles of the same window dimensions (e.g., Mobile,
by URL; and ultimately interacts with the cloaked page’s Desktop). This approach helps cover syntactically insignifi-
content.NotethatweonlyclickwhenusingChromeDesktop cant HTML changes, such as introducing an iframe, that
or Mobile, and not when using the simple HTTP fetcher (per significantly change a page’s visible content. During each
Googlebot’s typical behavior). crawl, we take a screenshot both upon visiting a URL and
after clicking on the largest hotlinked element. We convert
NetworkSelection:Weproxynetworkrequeststhroughatap these screenshots from RGB into a grayscale n×m array,
that records all inbound and outbound traffic. Additionally,
afterwhichwenormalizeeachcell’spixelintensitytoarange
this tap provides a configurable exit IP belonging to either [0,255]. We then calculate the per-pixel differences between
Google’s network; a mobile gateway in the United States be- two screenshots S 1 and S 2, opting to measure the total pixels
longing to AT&T or Verizon; a datacenter network belonging
that differ rather than the absolute value of their difference:
toGoogleCloud;oraresidentialIPaddressesbelongingtothe
researchersinvolvedinthisproject.Assomeofourmobileand (cid:2)n (cid:2)m
residential IPs exist behind NATs with dynamically allocated diff = S x1,y1 (cid:2)=S x2,y2 (1)
IP addresses, we establish a reverse tunnel to an entry point x=0y=0
with a statically allocated IP address that forwards requests
A high score in this regard indicates a substantially different
on to the exit node. Our diverse IP address pool allows us to
visual layout.
evade or trigger network-based cloaking on demand.
ElementSimilarity:Whiletextualdifferencesbetweencrawls
may arise due to dynamic advertisements or newly generated
C. Features
comments,deviationsbetweenawebsite’stemplateshouldbe
Deviations in page content introduced by cloaking include lesslikely.Tocapturethisintuition,weextractthesetofURIs
entirelyuniqueHTML,distinctlinklocations,alternatecross- E associated with all embedded images per document. We
origin content, or only a new button appearing on a page. We then calculate the difference in media content between two
compare the textual, visual, topical, and structural similarity documents by using the Jaccard similarity coefficient:
ofcontentbetweenallpossiblepairsofbrowserconfigurations
|E ∩E |
(e.g., Googlebot, Mobile User). Given we crawl every URL 1− 1 2 (2)
three times per candidate profile, we heuristically select the |E 1 ∪E 2 |
fetchthatgeneratedthelargestvolumeofHTTPlogstoserve
Ahighscoreindicatesthereweremultipleembeddedimages
as the representative sample. We make no assumptions on
absent from one or another crawl. To measure the similarity
howsignificantlydocumentsmustdiffertoconstituteblackhat
in the page HTML structure, we repeat this same process
cloaking.Instead,werelyonclassificationtolearnanoptimal
with divs and iframes, first stripping the elements of any
cut that differentiates divergent content due solely to blackhat
attributes,andthencalculatingthefractionofoverlappingtags
cloakingversusbenigndynamism(e.g.,breakingnews,mobile
as an additional measure of structural similarity.
optimization).
Request Tree Similarity: We compare the network requests
1) Pairwise Similarity Features generated while crawling to detect divergent redirects, mis-
matched network errors, and additional content. We begin
Content Similarity: We detect cloaking that returns entirely
by representing a sequence of network events (e.g., GET,
distinct content by estimating the similarity of each docu-
POST requests) as E = {e 1 ,e 2 ,...e n } where an event e i
ment’svisibletextandoverallHTML.Webeginbyremoving
consists of a tuple (cid:5)Method, Domain, Response Code, Path(cid:6).
all whitespace and non-alphanumeric content (e.g., punctua-
For two sequences E 1 and E 2 of potentially variable length,
tion,formatting).Wethentokenizethecontentusingasliding
we calculate the number of differing requests independent of
window that generates successive ngrams of four characters.
anytiminginformationusingtheJaccardsimilaritycalculation
Finally, we calculate a 64-bit simhash of all of the tokens
previously outlined in Equation 2. A high score indicates that
which converts high-dimensional text into a low-dimensional
crawlstriggereddivergentnetworkbehavior.Asanextension,
representation amenable to quick comparison, originally pi-
weseparatelycalculatethedifferenceintotalresponsepacket
oneered for de-duping documents in search indexes [5]. To
size between two browsing profiles.
measure the similarity of two documents, we calculate the
Hamming distance between two simhashes which is propor- Topic Similarity: As an alternative to the previous fine-
tional to the number of document tokens that failed to match. grained similarity metrics which may suffer in the presence
A high score indicates two documents differ significantly. We of dynamic website content, we compare the overall semantic
runthiscalculationtwice,onceforonlyparagraphandheading similarity of webpage content by extracting representative
text (that is, visible text in the page) and again for all HTML topics based on visible text. Mechanistically, we rely on an
content. Latent Dirichlet allocation (LDA) implementation to extract
775500
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore. Restrictions apply.

| a set of | at most | ten | topics | T per | document | [10], | [13]. We | D. Classification |     |     |     |     |     |     |     |
| -------- | ------- | --- | ------ | ----- | -------- | ----- | -------- | ----------------- | --- | --- | --- | --- | --- | --- | --- |
then calculate the similarity between two document’s topics We employ Extremely Randomized Trees—an ensemble,
| T 1 ,T 2, | repeating | the        | Jaccard   | index | calculation | presented | in    |             |            |     |          |       |             |          |     |
| --------- | --------- | ---------- | --------- | ----- | ----------- | --------- | ----- | ----------- | ---------- | --- | -------- | ----- | ----------- | -------- | --- |
|           |           |            |           |       |             |           |       | non-linear, | supervised |     | learning | model | constructed | from     | a   |
| Equation  | 2. A      | high score | indicates |       | the topics  | between   | pages |             |            |     |          |       |             |          |     |
|           |           |            |           |       |             |           |       | collection  | of random  |     | forests  | where | candidate   | features | and |
differs significantly. thresholds are selected entirely at random [11]. For training,
|     |     |     |     |     |     |     |     | we rely | on our | labeled | dataset | of benign | URLs | from | Alexa |
| --- | --- | --- | --- | --- | --- | --- | --- | ------- | ------ | ------- | ------- | --------- | ---- | ---- | ----- |
ScreenshotTopicSimilarity:Finally,duetopotentiallyheavy
reliance on media rather than text, we also compare the topic and cloaked search (discussed earlier in this section). Prior to
|            |              |     |             |     |           |               |     | classification, | we                 | normalize |     | all features | into    | a range [0,1] | to       |
| ---------- | ------------ | --- | ----------- | --- | --------- | ------------- | --- | --------------- | ------------------ | --------- | --- | ------------ | ------- | ------------- | -------- |
| similarity | of documents |     | as detected |     | by a deep | convolutional |     |                 |                    |           |     |              |         |               |          |
|            |              |     |             |     |           |               |     | simplify        | the interpretation |           | of  | which        | signals | are most      | salient. |
neuralnetworkthatusesscreenshotsasaninput[15].Aswith
ourtext-basedapproach,foreachscreenshotwedetermineup Duringclassification,werelyonten-foldcrossvalidation.We
totentopicsT thatdescribethevisualcontent.Wethenrepeat discuss the overall performance of this classifier in Section V
|     |     |     |     |     |     |     |     | and its | application | to  | a holdout | testing | set | for analysis | in  |
| --- | --- | --- | --- | --- | --- | --- | --- | ------- | ----------- | --- | --------- | ------- | --- | ------------ | --- |
thesamesimilaritycalculationasoutlinedwithtext-basedtop-
|         |          |        |          |       |      |         |            | Section | VII. |     |     |     |     |     |     |
| ------- | -------- | ------ | -------- | ----- | ---- | ------- | ---------- | ------- | ---- | --- | --- | --- | --- | --- | --- |
| ics. We | use this | method | to catch | pages | that | display | additional |         |      |     |     |     |     |     |     |
spamimages(typicallywithsexualorpharmaceuticalcontent)
V. IMPLEMENTATION
| that drastically |     | changes  | a page’s | perceived |     | topic. |     |               |     |               |        |             |       |           |        |
| ---------------- | --- | -------- | -------- | --------- | --- | ------ | --- | ------------- | --- | ------------- | ------ | ----------- | ----- | --------- | ------ |
|                  |     |          |          |           |     |        |     | We implement  |     | our           | system | on Google   |       | Compute   | Engine |
|                  |     |          |          |           |     |        |     | with crawling | and | featurization |        | distributed | among | 20 Ubuntu |        |
| 2) Per-page      |     | Dynamism | Features |           |     |        |     |               |     |               |        |             |       |           |        |
machines.Theclassificationisperformedonasingleinstance.
| We estimate |     | the natural, |     | potentially | legitimate |     | dynamism |     |     |     |     |     |     |     |     |
| ----------- | --- | ------------ | --- | ----------- | ---------- | --- | -------- | --- | --- | --- | --- | --- | --- | --- | --- |
of individual pages per browser configuration to help our Our scheduler is built on top of Celery backed by Redis.
|     |     |     |     |     |     |     |     | We compose | crawling |     | tasks | as a tuple | of a | URL and | profile |
| --- | --- | --- | --- | --- | --- | --- | --- | ---------- | -------- | --- | ----- | ---------- | ---- | ------- | ------- |
classifieridentifyaminimumthresholdabovewhichdivergent
|     |     |     |     |     |     |     |     | that includes | the | target | browser, | network | vantage | point, | and |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------- | --- | ------ | -------- | ------- | ------- | ------ | --- |
contentislikelyindicativeofblackhatcloaking.Aspreviously
noted, we crawl each URL three times per browsing profile context to appear from. Celery handles distributing tasks to
which we denote C ,C ,C for clarity. We recompute all of workers, monitoring success, and resubmitting failed jobs to
|              |         | 1      | 2 3       |          |          |              |               |                                                       |     |         |     |     |        |          |          |
| ------------ | ------- | ------ | --------- | -------- | -------- | ------------ | ------------- | ----------------------------------------------------- | --- | ------- | --- | --- | ------ | -------- | -------- |
|              |         |        |           |          |          | C ,C         | i (cid:2)= j, | liveworkers.Weoperatethreetypesofcrawlers:abasicrobot |     |         |     |     |        |          |          |
| the previous | metrics | for    | each      | possible | pair     | i j          | for           |                                                       |     |         |     |     |        |          |          |
|              |         |        |           |          |          |              |               | that fetches                                          | URL | content | via | the | Python | Requests | library, |
| averaging    | each    | metric | to arrive | at       | a single | per-feature, | per-          |                                                       |     |         |     |     |        |          |          |
page dynamism estimate. Finally, we provide the classifier akin to wget; a headless instantiation of Chrome controlled
|            |            |            |         |         |         |          |          | via Selenium,  | configured  |           | with    | a User-Agent |              | for Mac          | OSX;   |
| ---------- | ---------- | ---------- | ------- | ------- | ------- | -------- | -------- | -------------- | ----------- | --------- | ------- | ------------ | ------------ | ---------------- | ------ |
| both these | similarity |            | scores  | as well | as the  | previous | cross-   |                |             |           |         |              |              |                  |        |
|            |            |            |         |         |         |          |          | and the        | same Chrome |           | browser | except       | in           | mobile emulation |        |
| browser    | pairwise   | similarity | metrics |         | divided | by our   | dynamism |                |             |           |         |              |              |                  |        |
|            |            |            |         |         |         |          |          | mode mimicking |             | the Nexus |         | 5 device     | with version | 4.4              | of the |
estimatesforthatsamefeature(effectivelycalculatingtheratio
of cross-profile dynamism with intra-profile dynamism). Androidoperatingsystem.Ournetworkvantagepointsinclude
|     |     |     |     |     |     |     |     | the authors’ | residential |     | networks, | Google’s |     | cloud network, |     |
| --- | --- | --- | --- | --- | --- | --- | --- | ------------ | ----------- | --- | --------- | -------- | --- | -------------- | --- |
3) Domain-specific Features Google’s internal network, and mobile gateways belonging
We extend our feature set with domain-specific signals that to AT&T and Verizon as purchased via pre-paid plans. We
target the entire collection of content crawled per URL (as capture and log all network requests via mitmproxy. Finally,
opposed to pairwise metrics), outlined below. We use these forfeaturizationandclassificationwerelyonscikit-learn[25],
|          |                |     |         |     |             |          |     | Pandas [19], | and | a mixture | of  | libraries | previously | mentioned |     |
| -------- | -------------- | --- | ------- | --- | ----------- | -------- | --- | ------------ | --- | --------- | --- | --------- | ---------- | --------- | --- |
| for both | classification |     | as well | as  | to simplify | analysis | by  |              |     |           |     |           |            |           |     |
embedding meta-data about how miscreants cloak. in Section IV for estimating content similarity and topic
modeling.
| JavaScript, | Meta, | Flash | Redirection: |     | We  | include | a single |     |     |     |     |     |     |     |     |
| ----------- | ----- | ----- | ------------ | --- | --- | ------- | -------- | --- | --- | --- | --- | --- | --- | --- | --- |
boolean feature for whether a server redirects our crawler VI. EVALUATION
| via JavaScript, |           | meta-refresh |       | tag,    | or Flash | to            | a domain |             |          |          |            |             |             |                   |        |
| --------------- | --------- | ------------ | ----- | ------- | -------- | ------------- | -------- | ----------- | -------- | -------- | ---------- | ----------- | ----------- | ----------------- | ------ |
|                 |           |              |       |         |          |               |          | In this     | section, | we       | explore    | the overall | performance |                   | of our |
| that does       | not match | the          | final | landing | page.    | Such behavior | is       |             |          |          |            |             |             |                   |        |
|                 |           |              |       |         |          |               |          | classifier, | sources  | of false | positives, |             | the most    | salient features, |        |
common for (compromised) doorway pages where cloaking and the feasibility of unsupervised clustering. To conduct our
logic operates. evaluation,wefirsttrainandtestadecisiontreeclassifierusing
Googlebot Errors: We compare the size of requests returned 10-foldcrossvalidationoverourimbalanceddatasetof75,079
|              |           |     |         |         |     |       |             | non-cloaked | URLs | and | 19,867 | cloaked | URLs | previously | de- |
| ------------ | --------- | --- | ------- | ------- | --- | ----- | ----------- | ----------- | ---- | --- | ------ | ------- | ---- | ---------- | --- |
| to our basic | Googlebot |     | profile | against | all | other | profiles to |             |      |     |        |         |      |            |     |
tailedinSectionIV.Werelyonagridsearchtotuneclassifier
| determine | whether | a   | server | provides | the | crawler | an error. |     |     |     |     |     |     |     |     |
| --------- | ------- | --- | ------ | -------- | --- | ------- | --------- | --- | --- | --- | --- | --- | --- | --- | --- |
parametersrelatedtoourdecisionforest(e.g.,numberoftrees,
| Several | of the cloaking |     | packages | we  | reverse | engineered | offer |     |     |     |     |     |     |     |     |
| ------- | --------------- | --- | -------- | --- | ------- | ---------- | ----- | --- | --- | --- | --- | --- | --- | --- | --- |
an option of serving Googlebot a page aimed at downplaying depth of trees), ultimately electing the configuration with the
|               |      |              |              |     |         |        |              | optimum    | overall    | accuracy. |             |     |     |     |     |
| ------------- | ---- | ------------ | ------------ | --- | ------- | ------ | ------------ | ---------- | ---------- | --------- | ----------- | --- | --- | --- | --- |
| the relevance | of   | the page.    | Examples     |     | include | a 404  | interstitial |            |            |           |             |     |     |     |     |
| (e.g., “this  | site | is no longer | available”), |     | parked  | domain | page,        |            |            |           |             |     |     |     |     |
|               |      |              |              |     |         |        |              | A. Overall | Supervised |           | Performance |     |     |     |     |
orfakesecuritymessagesuchas“thissitehasbeenbanned”).
WepresenttheoverallaccuracyofoursysteminTableVIII.
Landing Domains: We annotate each URL with the total We correctly detect 99.1% of Alexa URLs as non-cloaked
number of landing page domains reached during all 33 visits, with a false positive rate of 0.9%. To achieve this degree of
with an intuition that divergent landing sites are suspicious. accuracy,weoverlook18.0%ofpotentiallycloakedcounterfeit
775511
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore.  Restrictions apply.

TABLE VIII: Performance of the supervised-learning classi- False Negatives: We execute a similar qualitative analysis
fier on the labeled train/test set, with 10-fold stratified cross for false negatives, finding the majority of errors arise due
validation. to stability issues tied to cloaked websites. In particular,
while crawling pages multiple times from the same profile
Accuracy TNRate TPRate FNRate FPRate weoftenfindthatthestorefrontsinvolvedwillthrowtransient
95.5% 99.1% 82.0% 18.0% 0.9% errors. This causes intra-profile similarity metrics to deviate
as strongly as cross-profile metrics, preventing an accurate
assessment.Weinvestigatewhethercloakingserversintroduce
these errors intentionally (e.g., potentially blacklisting our
crawler’s IP address), but we find no correlation between a
successfulcrawlandrepeatederrorsafterward.Instead,errors
appear randomly during any crawl. Similarly, we find some
of the URLs were taken down or expired by the time we
crawled them. These pages return the same error regardless
of profile, thus leading the classifier to believe they are not
cloaking.Wealsofindahighvolumeofcounterfeitstorefronts
thatdonotcloak,indicatingthatourlabeleddatasetisnoisier
than expected from a cloaking perspective (while its original
collection was to study scams). These latter two sources of
errors indicate that our false negative rate is likely lower in
practice, though non-negligible.
Fig. 2: Receiver operating characteristic curve for the super- ComparisontoPreviousWork:Wenotethatourdefinitionof
vised classifier (log-scale). cloaking is the most comprehensive to date, including mobile
cloaking,graphical-onlycloaking,andtestingadvancedcloak-
ing techniques such as rDNS cloaking. Because of this, the
storefronts. If we examine the trade-off our system achieves
performance of our classifier is not comparable with previous
between true positives and false positives, presented in Fig-
worksthattargetspecifictypesofcloaking,suchasredirection
ure2,wefindnoinflectionpointtoserveasaclearoptimum.
cloaking[18],[27]orreferreranduseragentcloaking[32].If
Assuch,operatorsofde-cloakingpipelinesmustdeterminean
we restrict our detection to a specific type of cloaking, such
acceptable level of false positives. For the remainder of our
as redirection cloaking, our classifier exhibits low to no false
study we rely on a false positive rate of 0.9%.
positives. However, such technique-specific restrictions yield
B. Source of Errors alowrecallthatoverlooksophisticatedcloakingtypessuchas
when cloaking software replaces a single embedded image’s
False Positives: We manually investigate a random sample content to deliver a cloaked ad offering. As our study aims
of URLs our classifier mislabeled to understand the principle to give a comprehensive overview of cloaking techniques in
cause of errors. Qualitatively, we find three sources of false thewild,weoptedtofavorhighrecallattheexpenseofsome
positives: (1) websites revising content between crawls, (2) false positives.
connectivity issues, and (3) noisy labels where some Alexa
Additionally, our work is the first to distinguish between
URLs in fact cloak. In our current crawler implementation,
benign cloaking (e.g., mobile optimization, geolocalization,
we fail to enforce a time window during which all crawls
personalizedresults)fromblackhatcloaking.Forexample,our
must complete. This raises the risk that content substantially
detectoriscapableofdeterminingthatthemobileanddesktop
changesbetweensuccessivefetches,incorrectlytriggeringour
versionofcnn.comdifferincontent,butthatdifferenceresults
detection. We can solve this problem moving forward by
exclusively from content optimization and should not be
enforcinganSLAontime-to-crawl.Asimilarproblemarisesif
labeled as blackhat cloaking. This challenge leads to a higher
ourcrawlerreceivesa40Xerrororifapageisnotfullyloaded
degree of false negatives as we favor precision over recall to
whenwetakeascreenshot,resultingindivergentimage-based
reduce false positives from polluting our subsequent analysis.
and network-based similarity scores. Along this vein, we also
find instances where CloudFlare DDoS protection automati-
C. Salient Features
cally blocks a fraction of our crawls, instead displaying an
We rank the importance of the top 20 features that impact
interstitial “checking your browser” which we mistake for
the accuracy of our classifier according to their Gini impor-
a malicious interstitial. Finally, in rare cases, we find that
tance [4], effectively calculating the weight of the feature
some of the top Alexa sites serve cloaked ads that swap
acrossalltreesinourdecisionforest.Wepresentourfindings
content when presenting to a crawler, likely unbeknownst to
in Figure 3. The classifier associates the highest weight with
the site embedding the ad. These instances, as observed from
JavaScript redirects that cross an origin boundary. Indeed,
our classifier, are in fact true positives, thus our overall false
41.8% of labeled cloaking URLs rely on this technique
positive rate will be lower in practice.
775522
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore. Restrictions apply.

compared to 0.62% of presumed non-cloaking URLs. The TABLE IX: Performanceoftheunsupervised-learningclassi-
remainingtop19featuresspanaspectrumoffeaturecategories fier on the labeled train/test set.
coveringcontent,networkrequest,topic,andscreenshotsimi-
larityamongmultiplecombinationsofbrowsingprofiles.This Accuracy TNRate TPRate FNRate FPRate
indicates all of our similarity metrics and profiles contribute 84.6% 90.3% 61.1% 38.9% 9.7%
to classification results, each covering a non-overlapping ap-
proach to cloaking. TABLEX:PrevalenceofcloakinginGoogleSearchandAds
Exploring feature salience in more detail, we examine the for URLs tied to high-risk keywords.
overall accuracy of our system when trained only a single
class of similarity metrics. Figure 4 indicates that comparing Source KeywordCategory %Cloaking
the structure of pages is the most effective technique for GoogleAds Health,softwareads 4.9%
GoogleSearch Luxurystorefronts 11.7%
minimizingfalsenegatives,whereastopic,embeddedelement,
and screenshot-based similarity metrics perform the worst in
isolation.WerecastthissamemeasurementinFigure5,except
this time removing only a single comparison method from measure accuracy based on the cluster’s separation of our la-
training. We find that a model with no screenshot similarity beleddataset.WepresentourresultsinTableIX.Unsupervised
introduces the most false negatives, while removing page learningachievesanoverallaccuracy84.6%andfalsepositive
structure alone has the least impact. Our findings reiterate rate of 9.7% compared to supervised learning which achieves
that an ensemble of comparison techniques are required to an accuracy of 95.5% with 0.9% false positives. While this
accurately detect split-view content. indicates there is substantial power in merely comparing the
similarity of content between multiple clients, a supervised
D. Minimum Profile Set classifierfaroutperformsclusteringwhenlabelingedgecases.
Finally, we quantify the trade-off between anti-cloaking
pipeline performance, and its efficiency and complexity. To VII. CLOAKINGINTHEWILD
do so, we start with the full system described here, and we
Having vetted our classifier, we apply it to an unlabeled
repeatedly identify the crawling profile that, when removed,
datasetof135,577searchresultsandadvertisementstargeting
least impacts the false positive rate. The result of this greedy
high-value, commonly abused keywords related to luxury
search of the anti-cloaking pipeline with the minimum capa-
products, weight loss, and mobile gaming. We measure the
bilities is shown in Figure 6.
prevalenceofcloakinginthewildandcategorizetheblackhat
As with all classification scores shown here, the scores are
techniques involved.
the mean values in a ten-fold stratified cross validation. The
results indicate that an anti-cloaking pipeline would still have
anacceptableperformancewithoutamobileuseronamobile A. Frequency
network, and without the content similarity feature class. If
In Table X, we show the incidence of cloaked content
any more capabilities are subtracted, the false negative rate
for Google Search results and Google Ads. We estimate
doubles, whereas the false positive rate remains fairly low
4.9% of mobile-targeted advertisements predicated on high-
even for a pipeline composed only by a mobile browser,
risk keywords direct to cloaked content. This demonstrates
desktop browser and Googlebot, all crawling from Google
that miscreants readily attempt to abuse the advertisement
IPs and cloud IPs. These browsers support clicking, taking
ecosystem as a distribution channel for nutraceuticals and
screenshots, and visit URLs with the same profile repeatedly.
knock-offmobilegamesandjustifiesaheightenedscrutinyfor
Since any further simplification of this basic anti-cloaking
specificadtargetingpractices.WemakenoclaimthatGoogle
pipeline doubles the false positive rate, we have established
fails to detect these cloaked URLs; only that miscreants
that this is the minimum anti-cloaking platform that is both
purposefullyprovideevasivecontenttoGooglebotwhileURLs
efficient, by avoiding unnecessary crawling and featurization,
remain operational.3 For search, we find 11.7% of URLs in
andeffectiveagainstcurrentcloaking.Wecautionreadersthat
thetop100resultsdirecttocloakedcontent.Thisisconsistent
this evaluation of the minimum viable anti-cloaking pipeline
with previous estimates of pharmaceutical-based cloaking in
should be performed routinely, so to react in a timely manner
Google search results where Wang et al. estimated 9.4% of
to a spread in popularity of more advanced cloaking tech-
search results linked to cloaked doorways [32]. Our results
niques.
illustrate that cloaking remains a common blackhat practice
E. Unsupervised Alternative requiringconstantmaintenanceonthepartofsecuritycrawlers
tokeeppacewiththearmsrace.Thatsaid,ourmeasurements
Supervisedlearningrequiresasteadystreamoftrainingdata
show that miscreants more commonly target search results
in the event miscreants adapt their techniques for displaying
over advertisements, likely due to the cost of advertising.
split-view content. As a potential alternative, we compare our
supervised classifier’s accuracy to that of an unsupervised
3We do not track whether URLs are eventually pulled, precluding any
clustering equivalent based on Gaussian mixture models. We
longitudinalevaluationforhowlongittakesbeforeadsaredisabled.
775533
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore. Restrictions apply.

Fig. 3: Top 20 features selected by our classifier ranked by their weight in our model.
1.0
False Positive Rate
5 x False Positive Rate
|     |     | 0.8 | False Negative Rate |     |     |     |     |     |     |     |
| --- | --- | --- | ------------------- | --- | --- | --- | --- | --- | --- | --- |
True Positive Rate
True Negative Rate
0.6
0.4
0.2
0.0
|     |         | d                          | y                        | ty ontent similarity |            | ty     |          | y t topic similarity |     |     |
| --- | ------- | -------------------------- | ------------------------ | -------------------- | ---------- | ------ | -------- | -------------------- | --- | --- |
|     |         | d d e                      | la r it st tree similari |                      |            | la r i |          | la r it              |     |     |
|     |         | E m b e r it y ructure sim | i                        |                      | Topic simi |        | t  s i m | i                    |     |     |
|     |         | m i l a                    |                          |                      |            |        | ensho    |                      |     |     |
|     | element | s  s i s t                 | u e                      | C                    |            | r e    |          | h o                  |     |     |
|     |         | a g e                      | R e q                    |                      |            | S c    | e        | e n s                |     |     |
|     |         | P                          |                          |                      |            |        | S c r    |                      |     |     |
(5x)
Fig. 4: Classifier performance when training only a single feature class. We include a magnified false positive rate to
emphasize an otherwise minimal variation. We order feature classes by ascending false positive rates.
B. Targeting Techniques cloaked content (and thus accurate detection). Note that we
|          |            |               |               |             | use    | the unlabeled | dataset  | as  | our test set to mitigate | any bias |
| -------- | ---------- | ------------- | ------------- | ----------- | ------ | ------------- | -------- | --- | ------------------------ | -------- |
| Cloaking | sites hide | their payload | from everyone | but the in- |        |               |          |     |                          |          |
|          |            |               |               |             | in our | labeled       | dataset. |     |                          |          |
tendedaudienceoforganicusers.Weanalyzehowmiscreants
arriveatthisdistinctionandstudyanydifferencesbetweenad We show the fingerprinting checks miscreants use for
andsearch-basedcloaking.Todoso,firstwemarkallcloaking GoogleSearchandGoogleAdsinTableXI.Wefindthemost
URLs in the unlabeled dataset with our full classifier. Then, prominenttargetingcriteriaisthepresenceofJavaScriptwhich
for each class of targeting techniques, such as checking that miscreantsusefor49.6%ofcloakedadsand22.4%ofcloaked
the visitor has a HTTP Referer set, we train a classifier on search results. This is followed in popularity by checking for
|             |         |                  |                 |          | Googlebot’s |     | IP address | and | User-Agent, and finally | evidence |
| ----------- | ------- | ---------------- | --------------- | -------- | ----------- | --- | ---------- | --- | ----------------------- | -------- |
| our labeled | dataset | but specifically | exclude browser | profiles |             |     |            |     |                         |          |
thatincludethetargetingtechniqueunderevaluation.Wethen that a client interacts with a page (e.g., clicking). Our results
measurethefractionofcloakingURLsintheunlabeleddataset highlight that any anti-cloaking pipeline must come outfitted
thatthisnewclassifieridentifiesascloaking,effectivelyacting with each of these capabilities to accurately contend with
cloaking.
asaproxyforwhichtargetingcriteriaiscriticaltoreceivede-
775544
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore.  Restrictions apply.

1.0
False Positive Rate
5 x False Positive Rate
|     |     |     | 0.8 |     | False Negative Rate |     |     |     |     |     |     |     |     |     |
| --- | --- | --- | --- | --- | ------------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
True Positive Rate
True Negative Rate
0.6
0.4
0.2
0.0
|     |             |     | e n t     | s        | la r it y         |     | la r i ty ontent similari | ty        |     | la r i ty | la r it | y t topic similarity |     |     |
| --- | ----------- | --- | --------- | -------- | ----------------- | --- | ------------------------- | --------- | --- | --------- | ------- | -------------------- | --- | --- |
|     |             |     | e l e m r | i t y  s | im i st tree simi |     |                           | o Topic s | im  | i         | s i m i |                      |     |     |
|     | No Embedded |     |   im il a | ucture   |                   |     |                           |           |     | sh        | o t     |                      |     |     |
|     |             |     | s s       | t r      | u e               |     |   C                       | N         |     | r e en    | h o     |                      |     |     |
|     |             |     | a g e     |          |  R e q            | N   | o                         |           | o   | S c       | e e n s |                      |     |     |
|     |             |     | N o   P   | N        | o                 |     |                           |           | N   | o         |  S c r  |                      |     |     |
N
Fig. 5: Classifier performance when training on all but one class of features. We include a magnified false positive rate (5x)
to emphasize an otherwise minimal variation. We order feature classes by ascending false positive rates.
TABLE XI: Fingerprinting techniques in the wild that are TABLE XII: Delivery techniques in the wild, broken down
| used to make | a   | cloaking | decision. | Broken | down | for | Google |     |        |        |          |           |               |         |
| ------------ | --- | -------- | --------- | ------ | ---- | --- | ------ | --- | ------ | ------ | -------- | --------- | ------------- | ------- |
|              |     |          |           |        |      |     |        | for | Google | Search | and Ads. | Same-page | modifications | include |
Search and Ads. server-side targeting as well as client-side rendering.
Fingerprintingcheck GoogleSearch GoogleAds CloakingType GoogleSearch GoogleAds
| Hasreferrerset? |     |     |     |     | 6.1%  |     | 5.4%  |                 |     |     |     |     |       |       |
| --------------- | --- | --- | --- | --- | ----- | --- | ----- | --------------- | --- | --- | --- | --- | ----- | ----- |
|                 |     |     |     |     |       |     |       | 30Xredirections |     |     |     |     | 33.6% | 19.9% |
| Userhasclicked? |     |     |     |     | 10.6% |     | 18.0% | 40Xclienterrors |     |     |     |     | 12.0% | 8.5%  |
IsGoogle(IP,UserAgent)? 14.3% 20.7% 50Xservererrors 2.5% 4.4%
HasJavaScriptsupport? 22.4% 49.6% JavaScriptredirections 29.9% 6.6%
| Ismobiledevice? |     |     |     |     | 4.9% |     | 8.5% | Same-pagemodifications |     |     |     |     | 22.0% | 60.6% |
| --------------- | --- | --- | --- | --- | ---- | --- | ---- | ---------------------- | --- | --- | --- | --- | ----- | ----- |
C. Delivery Techniques future iterations of the cloaking arms race.
| Cloaking | sites | deliver | their | uncloaked | content | to  | organic |     |     |     |     |     |     |     |
| -------- | ----- | ------- | ----- | --------- | ------- | --- | ------- | --- | --- | --- | --- | --- | --- | --- |
visitorsinavarietyofways.Somesitesopttoredirectvisitors VIII. CASESTUDIES
| to a monetized       |     | URL,   | either via | a server-side |                | decision      | (via    |              |      |               |            |            |                   |            |
| -------------------- | --- | ------ | ---------- | ------------- | -------------- | ------------- | ------- | ------------ | ---- | ------------- | ---------- | ---------- | ----------------- | ---------- |
|                      |     |        |            |               |                |               |         | In           | this | section       | we present | case       | studies exemplary | of the     |
| a 30X redirection),  |     | or     | on the     | client-side   | via            | JavaScript.   | To      |              |      |               |            |            |                   |            |
|                      |     |        |            |               |                |               |         | monetization |      | strategies    | among      | the Google | Search            | and Google |
| be less conspicuous, |     | other  | sites      | opt to        | display        | the uncloaked |         |              |      |               |            |            |                   |            |
|                      |     |        |            |               |                |               |         | Ads          | URLs | we identified | as         | cloaking.  |                   |            |
| content directly     |     | in the | landing    | page,         | either through | a             | reverse |              |      |               |            |            |                   |            |
proxy, or a modification of the DOM such as adding div, LeadGenerationforMobileApps:Weencounteredmultiple
img, or iframe elements. We analyze the most popular sites that entice mobile users to install both dubious and
delivery techniques in our dataset as determined by our legitimatethird-partyapps.Interestingly,aminorityofAlexa’s
network logs for sites labeled as cloaking, broken down by top domains also exhibit this behavior. For example, we
type in Table XII. We find delivery techniques in the wild show how mobile and desktop visitors see opensubtitles.org
differsubstantiallybetweensearchresultsandadvertisements. in Figure 7. When this site detects a visitor with an Android
Forinstance,JavaScriptredirectsaccountfor29.9%ofcloaked mobileUser-AgentandaHTTPreferrerset,itaddsanewdiv
search URLs compared to 6.6% of ads, with ads instead element via JavaScript. This element randomly loads an ad
| favoring | same-page | modifications. |     | Our | result | highlights | that |     |              |         |     |            |          |                 |
| -------- | --------- | -------------- | --- | --- | ------ | ---------- | ---- | --- | ------------ | ------- | --- | ---------- | -------- | --------------- |
|          |           |                |     |     |        |            |      | for | a legitimate | Android |     | app, or is | stylized | as fake Android |
whilemiscreantsmaycloakagainstproductsusingavarietyof notification.Whenclicked,thisnotificationleadstoadubious
techniques, our anti-cloaking system nevertheless succeeds at app that acts as a free app store. When installed, this app
generalizingandcaptureseachapproach.Anysecuritycrawler riddles the device with unwanted ads (through the AirPush
| must address | each | of these | techniques |     | as well | as prepare | for | library). |     |     |     |     |     |     |
| ------------ | ---- | -------- | ---------- | --- | ------- | ---------- | --- | --------- | --- | --- | --- | --- | --- | --- |
775555
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore.  Restrictions apply.

Fig. 6: Classifier performance degradation, when repeatedly removing the crawling profile that least affects the false positive
rate.
|     |     |     |     |     |     |     |     | Fig.     | 8: Cloaking | site    | that redirects | to   | advertisements. |     |
| --- | --- | --- | --- | --- | --- | --- | --- | -------- | ----------- | ------- | -------------- | ---- | --------------- | --- |
|     |     |     |     |     |     |     |     | platform | and Referer | header. | Also,          | this | site geolocates | the |
Fig.7:Observingopensubtitiles.orgfromdifferentdevicescan
|                  |                 |        |          |             |     |            |     | visitor and  | uses             | this information |          | to decide | which        | ads to run. |
| ---------------- | --------------- | ------ | -------- | ----------- | --- | ---------- | --- | ------------ | ---------------- | ---------------- | -------- | --------- | ------------ | ----------- |
| yield completely | different       |        | content. |             |     |            |     |              |                  |                  |          |           |              |             |
|                  |                 |        |          |             |     |            |     | Visiting     | the site         | from outside     | the      | US        | yields a     | blank page, |
|                  |                 |        |          |             |     |            |     | or a message | “We              | currently        | don’t    | have      | any sponsors | for this    |
| Malware:         | A few           | of the | cloaking | websites    | we  | identified | are | domain       | name”.           |                  |          |           |              |             |
| distributing     | malware.        | For    | example, | saomin.com, |     | delivers   | to  |              |                  |                  |          |           |              |             |
|                  |                 |        |          |             |     |            |     | Some         | traffic reseller |                  | employ a | wide      | set of rules | to decide   |
| mobile           | user an Android |        | app that | is flagged  | as  | malicious  | by  |              |                  |                  |          |           |              |             |
whatcontenttodisplay.Anexampleofthisismacauwinner.tk,
| 19 AntiVirus | engines | on  | VirusTotal. | In another |     | case, the | user |                |     |         |        |        |      |              |
| ------------ | ------- | --- | ----------- | ---------- | --- | --------- | ---- | -------------- | --- | ------- | ------ | ------ | ---- | ------------ |
|              |         |     |             |            |     |           |      | which pretends |     | to be a | parked | domain | when | visited from |
wasencouragedtoinstallamaliciousbrowserextensioncalled outside the US, whereas it delivers tailored content to users
FromDocToPDF.
|     |     |     |     |     |     |     |     | on residential | and | mobile | networks, | detecting | their | Internet |
| --- | --- | --- | --- | --- | --- | --- | --- | -------------- | --- | ------ | --------- | --------- | ----- | -------- |
TrafficResellers:Wehavealsoobservedcloakingsitesselling provider (e.g., it also displays “Dear AT&T Uverse user”).
Also,itdeliverscontentspecifictotheoperatingsystemofthe
| their organic | traffic | to a         | ring of | advertisers.        | For | example, | in   |                 |     |                |      |          |      |         |
| ------------- | ------- | ------------ | ------- | ------------------- | --- | -------- | ---- | --------------- | --- | -------------- | ---- | -------- | ---- | ------- |
|               |         |              |         |                     |     |          |      | user, mimicking |     | its appearance | when | creating | fake | windows |
| Figure 8      | we show | a screenshot |         | of pancakeshop.kim. |     | This     | site |                 |     |                |      |          |      |         |
redirects users to third-party advertisers based on the type of and alert boxes. The pages to which users get redirected
775566
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore.  Restrictions apply.

range from fake AntiViruses, to fake popular websites (e.g., Distributed Client Content Reporting: To overcome the
Facebook), to surveys. problem of staleness, we consider an alternative model where
a user’s browser opts to anonymously report a content digest
Affiliate fraud: We found cases where the cloaking site
after clicking on a search result or advertisement to the
performs affiliate fraud. For example, drseks.com, redirects
associated search engine or ad network. This server would
every other user to a major shopping retailer with an affiliate
then review the incoming digest against the copy fetched by
idset.Bydoingso,thisretailersharesafractionoftheprofits
its crawler. In the event of a mismatch, the server would
from a sale to the cloaked domain.
immediately re-crawl the URL to rule out the possibility of
IX. BREAKINGTHECLOAKINGARMSRACE an outdated digest. If there is still a client-server mismatch
after crawling, the search engine or ad network involved
As miscreants adopt increasingly sophisticated application-
could pull the reported URL from public listing to protect
specificcloakingtechniques,itbecomesdifficultfordefenders
all future clients. From a privacy perspective, the server
to keep pace with the cloaking arms race. Currently, our
receiving reports would already be aware the user clicked on
system is a viable solution, as it is designed to defeat current
theURL,suchashowsearchenginescurrentlyredirectvisitors
cloakingcapabilities.Wehavedeterminedtheminimumcapa-
through analytic interstitials. However, as users may click
bilities a current anti-cloaking pipeline would need precisely
through to a signed-in page containing sensitive content (e.g.,
to guide the design of such a pipeline, spending engineering
facebook.com),thedigestreportedmustnotleakpersonalized
time efficiently. On the long run, however, we envision that
content. Furthermore, this approach opens servers up to an
miscreants will add to their cloaking arsenal (e.g., carrier-
abuse problem where malicious clients may spoof digests to
specific mobile cloaking), increasing the cost of detection at
unduly trigger the removal of legitimate search results and
the expense of driving less organic traffic to their concealed
advertisements. However, assuming there are more legitimate
offers.Tocounterthistrend,weproposetwopossiblealterna-
clients than malicious and some form of rate limiting, servers
tives that would render it significantly harder for miscreants
can rely on majority voting to solve this problem, though the
to deliver split-view content, although they would require an
long tail of URLs may yet pose a challenge.
in-browser component.
Client-side Cloaking Detection:Ascloakinghingesonserv-
X. CONCLUSION
ing benign content to search engine and ad network crawlers, Inthiswork,weexploredthecloakingarmsraceplayingout
one option is for those same services to embed a succinct betweensecuritycrawlersandmiscreantsseekingtomonetize
digest of a webpage’s content in the parameters tied to search engines and ad networks via counterfeit storefronts
search and advertisement URLs. When users are redirected and malicious advertisements. While a wealth of prior work
after clicking on one of these URLs, the user’s browser exists in the area of understanding the prevalence of content
can compare the newly served content against the crawler’s hidden from prying eyes with specific cloaking techniques or
digest. If the two substantially differ, the browser can raise a the underlying monetization strategies, none marries both an
warning interstitial that alerts the user to a suspected scam, undergroundandempiricalperspectivethatarrivesatprecisely
phishing, or malware attack. Mechanistically, this comparison how cloaking operates in the wild today. We addressed this
naturallyfollowsthepairwisefeatureswelaidoutforouranti- gap, developing an anti-cloaking system that covers a spec-
cloaking system. The benefit over our current architecture is trum of browser, network, and contextual blackhat targeting
that crawlers no longer need to maintain multiple browsing techniques that we used to determine the minimum crawling
profilesornetworkvantages—clientsprovidethesecondview. capabilities required to contend with cloaking today.
Additionally, this approach respects the privacy of the users, Weinformedoursystem’sdesignbydirectlyengagingwith
as only the potentially-dangerous pages will be reported by blackmarket specialists selling cloaking software and services
the participating (i.e., opted-in) users. to obtain ten of the most sophisticated offerings. The built-
Therearehoweversomeopenchallengeswiththisapproach. in capabilities of these packages included blacklisting clients
First, dynamic content remains a concern. If miscreants can based on their IP addresses, reverse DNS, User-Agent, HTTP
limit the deviations introduced by cloaking to within typical headers,andtheorderofactionsaclienttakesuponvisitinga
norms (e.g., including only a small new button or URL), miscreant’s webpage. We overcame each of these techniques
the system may fail to detect the attack. That said, this also by fetching suspected cloaking URLs from multiple crawlers
constrainsanattackerinawaythatreducesclickthroughfrom that each emulated increasingly sophisticated legitimate user
users. Additionally, there is a risk with news sites and other behavior. We compared and classified the content returned
frequently updated pages that a crawler will serve incoming for 94,946 labeled URLs, arriving at a system that accurately
visitorsastaledigestduetoanoutdatedcrawl,thusburdening detected cloaking 95.5% of the time with a false positive rate
users with alerts that are in fact false positives. To avoid this, of 0.9%.
thecrawlerwouldeitherneedtoimmediatelyre-crawlthepage Whenwedeployedourcrawlerintothewildtoscan135,577
to confirm the change and suppress the alert, or the digest unknown URLs, we found 11.7% of the top 100 search
should account for the category of the site, allowing for a results related to luxury products and 4.9% of advertisements
higher threshold for news sites. targeting weight loss and mobile applications cloaked against
775577
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore. Restrictions apply.

Googlebot. In the process, we exposed a gap between cur- [19] WesMcKinney. Datastructuresforstatisticalcomputinginpython. In
Proceedingsofthe9th,volume445,pages51–56,2010.
| rent blackhat | practices | and        | the broader        | set of fingerprinting |     |                     |             |               |                  |                    |
| ------------- | --------- | ---------- | ------------------ | --------------------- | --- | ------------------- | ----------- | ------------- | ---------------- | ------------------ |
|               |           |            |                    |                       |     | [20] Keaton Mowery, | Dillon      | Bogenreif,    | Scott Yilek,     | and Hovav Shacham. |
| techniques    | known     | within the | research community | which                 | may |                     |             |               |                  |                    |
|               |           |            |                    |                       |     | Fingerprinting      | information | in javascript | implementations. | In Proceed-        |
yet be deployed. As such, we discussed future directions for ingsoftheWorkshoponWeb2.0SecurityandPrivacy,2011.
|     |     |     |     |     |     | [21] Keaton Mowery | and | Hovav Shacham. | Pixel | perfect: Fingerprinting |
| --- | --- | --- | --- | --- | --- | ------------------ | --- | -------------- | ----- | ----------------------- |
breakingthecloakingarmsracethatincludedclientsreporting
|                                                           |     |     |     |     |     | canvasinhtml5.   | InProceedingsoftheWorkshoponWeb2.0Security |     |     |     |
| --------------------------------------------------------- | --- | --- | --- | --- | --- | ---------------- | ------------------------------------------ | --- | --- | --- |
| browsingperspectivetocrawleroperators,hinderingtheability |     |     |     |     |     | andPrivacy,2012. |                                            |     |     |     |
of miscreants to show benign content exclusively to search [22] Martin Mulazzani, Philipp Reschl, Markus Huber, Manuel Leithner,
|             |              |     |     |     |     | SebastianSchrittwieser,EdgarWeippl,andFCWien. |     |     |     | Fastandreliable |
| ----------- | ------------ | --- | --- | --- | --- | --------------------------------------------- | --- | --- | --- | --------------- |
| engines and | ad networks. |     |     |     |     |                                               |     |     |     |                 |
browseridentificationwithjavascriptenginefingerprinting.InProceed-
|     |     | REFERENCES |     |     |     | ingsoftheWorkshoponWeb2.0SecurityandPrivacy,2013. |            |             |        |                     |
| --- | --- | ---------- | --- | --- | --- | ------------------------------------------------- | ---------- | ----------- | ------ | ------------------- |
|     |     |            |     |     |     | [23] Nick Nikiforakis,                            | Alexandros | Kapravelos, | Wouter | Joosen, Christopher |
[1] Alexa.Alexatop500globalsites.http://www.alexa.com/topsites,2012. Kruegel, Frank Piessens, and Giovanni Vigna. Cookieless monster:
[2] RossAnderson,ChrisBarton,RainerBo¨hme,RichardClayton,Michel Exploringtheecosystemofweb-baseddevicefingerprinting.InSecurity
J.G.vanEeten,MichaelLevi,TylerMoore,andStefanSavage. Mea- and Privacy (SP), 2013 IEEE Symposium on, pages 541–555. IEEE,
| suring | the cost of | cybercrime. | In Proceedings | of the Workshop | on  | 2013. |     |     |     |     |
| ------ | ----------- | ----------- | -------------- | --------------- | --- | ----- | --- | --- | --- | --- |
EconomicsofInformationSecurity(WEIS),2012. [24] Yuan Niu, Hao Chen, Francis Hsu, Yi-Min Wang, and Ming Ma. A
A´da´m
[3] Ka´roly Boda, Ma´te´ Fo¨ldes, Ga´bor Gyo¨rgy Gulya´s, and Sa´ndor quantitativestudyofforumspammingusingcontext-basedanalysis. In
| Imre. | User tracking | on  | the web via cross-browser | fingerprinting. |     | NDSS.Citeseer,2007. |     |     |     |     |
| ----- | ------------- | --- | ------------------------- | --------------- | --- | ------------------- | --- | --- | --- | --- |
In Information Security Technology for Applications, pages 31–46. [25] F. Pedregosa, G. Varoquaux, A. Gramfort, V. Michel, B. Thirion,
Springer,2012. O. Grisel, M. Blondel, P. Prettenhofer, and et al. Weiss. Scikit-learn:
[4] LeoBreiman,JeromeFriedman,CharlesJStone,andRichardAOlshen. Machine learning in Python. Journal of Machine Learning Research,
| Classificationandregressiontrees. |     |     | CRCpress,1984. |     |     | 12:2825–2830,2011. |     |     |     |     |
| --------------------------------- | --- | --- | -------------- | --- | --- | ------------------ | --- | --- | --- | --- |
[5] Moses S Charikar. Similarity estimation techniques from rounding [26] NielsProvos,PanayiotisMavrommatis,MoheebAbuRajab,andFabian
algorithms. InProceedingsofthethiry-fourthannualACMsymposium Monrose. AllyouriFRAMEspointtous. InProceedingsofthe17th
onTheoryofcomputing,pages380–388.ACM,2002. UsenixSecuritySymposium,pages1–15,July2008.
[6] M. Cova, C. Kruegel, and G. Vigna. Detection and analysis of drive- [27] GianlucaStringhini,ChristopherKruegel,andGiovanniVigna. Shady
by-downloadattacksandmaliciousJavaScriptcode. InProceedingsof paths: Leveraging surfing crowds to detect malicious web pages. In
the19thInternationalConferenceonWorldWideWeb,2010. Proceedings of the 2013 ACM SIGSAC conference on Computer &
[7] Peter Eckersley. How Unique Is Your Web Browser? In Privacy communicationssecurity,pages133–144.ACM,2013.
EnhancingTechnologies(PET),2010. [28] KurtThomas,DannyYuxingHuang,DavidWang,ElieBursztein,Chris
[8] DavidFifieldandSergeEgelman.Fingerprintingwebusersthroughfont Grier, Thomas J. Holt, Christopher Kruegel, Damon McCoy, Stefan
metrics. In Proceedings of the International Conference on Financial Savage, and Giovanni Vigna. Framing dependencies introduced by
CryptographyandDataSecurity,2015. undergroundcommoditization. InProceedingsoftheWorkshoponthe
[9] Sean Ford, Marco Cova, Christopher Kruegel, and Giovanni Vigna. EconomicsofInformationSecurity,2015.
Analyzing and detecting malicious flash advertisements. In Computer [29] Thomas Unger, Martin Mulazzani, Dominik Fruhwirt, Markus Huber,
SecurityApplicationsConference,2009.ACSAC’09.Annual,2009. Sebastian Schrittwieser, and Edgar Weippl. Shpf: enhancing http(s)
[10] gensim. models.ldamodel – Latent Dirichlet Allocation. https:// session security with browser fingerprinting. In Proceedings of the
radimrehurek.com/gensim/models/ldamodel.html,2015. InternationalConferenceonAvailability,ReliabilityandSecurity,2013.
[11] PierreGeurts,DamienErnst,andLouisWehenkel. Extremelyrandom- [30] W3C. Referrer Policy. http://w3c.github.io/webappsec/specs/
| izedtrees. | Machinelearning,63(1):3–42,2006. |     |     |     |     | referrer-policy/,2015. |     |     |     |     |
| ---------- | -------------------------------- | --- | --- | --- | --- | ---------------------- | --- | --- | --- | --- |
[12] ChrisGrier,LucasBallard,JuanCaballero,NehaChachra,ChristianJ. [31] DavidYWang,MatthewDer,MohammadKarami,LawrenceSaul,Da-
Dietrich, Kirill Levchenko, Panayiotis Mavrommatis, D. McCoy, An- monMcCoy,StefanSavage,andGeoffreyMVoelker. Search+seizure:
tonio Nappa, Andreas Pitsillidis, et al. Manufacturing compromise: Theeffectivenessofinterventionsonseocampaigns. InProceedingsof
The emergence of exploit-as-a-service. In Proceedings of the ACM the2014ConferenceonInternetMeasurementConference,2014.
ConferenceonComputerandCommunicationsSecurity(CCS),2012. [32] David Y Wang, Stefan Savage, and Geoffrey M Voelker. Cloak and
[13] MatthewHoffman,FrancisRBach,andDavidMBlei. Onlinelearning dagger:dynamicsofwebsearchcloaking. InProceedingsoftheACM
forlatentdirichletallocation.InNeuralInformationProcessingSystems, ConferenceonComputerandCommunicationsSecurity,2011.
2010. [33] Yi-MinWangandMingMa.Detectingstealthwebpagesthatuseclick-
[14] JohnPJohn,FangYu,YinglianXie,ArvindKrishnamurthy,andMart´ın through cloaking. In Microsoft Research Technical Report, MSR-TR,
| Abadi.deseo:Combatingsearch-resultpoisoning.InProceedingsofthe |     |     |     |     |     | 2006. |     |     |     |     |
| -------------------------------------------------------------- | --- | --- | --- | --- | --- | ----- | --- | --- | --- | --- |
USENIXSecuritySymposium,2011. [34] Y.M. Wang, M. Ma, Y. Niu, and H. Chen. Spam double-funnel:
[15] Alex Krizhevsky, Ilya Sutskever, and Geoffrey E Hinton. Imagenet Connecting web spammers with advertisers. In Proceedings of the
classification with deep convolutional neural networks. In Advances InternationalWorldWideWebConference,pages291–300,2007.
inneuralinformationprocessingsystems,pages1097–1105,2012. [35] BaoningWuandBrianDDavison. Detectingsemanticcloakingonthe
[16] Nektarios Leontiadis, Tyler Moore, and Nicolas Christin. Measuring web.InProceedingsofthe15thinternationalconferenceonWorldWide
| andanalyzingsearch-redirectionattacksintheillicitonlineprescription |     |     |     |     |     | Web,2006. |     |     |     |     |
| ------------------------------------------------------------------- | --- | --- | --- | --- | --- | --------- | --- | --- | --- | --- |
drugtrade. InUSENIXSecuritySymposium,2011. [36] ApostolisZarras,AlexandrosKapravelos,GianlucaStringhini,Thorsten
[17] NektariosLeontiadis,TylerMoore,andNicolasChristin.Anearlyfour- Holz, Christopher Kruegel, and Giovanni Vigna. The dark alleys of
yearlongitudinalstudyofsearch-enginepoisoning. InProceedingsof madisonavenue:Understandingmaliciousadvertisements. InProceed-
the2014ACMSIGSACConferenceonComputerandCommunications ingsofthe2014ConferenceonInternetMeasurementConference,2014.
Security,2014. [37] QingZhang,DavidYWang,andGeoffreyMVoelker.Dspin:Detecting
[18] Long Lu, Roberto Perdisci, and Wenke Lee. Surf: detecting and automaticallyspuncontentontheweb. InSymposiumonNetworkand
measuringsearchpoisoning.InProceedingsofthe18thACMconference DistributedSystemSecurity(NDSS),2014.
onComputerandcommunicationssecurity,2011.
775588
Authorized licensed use limited to: IEEE Xplore. Downloaded on January 27,2026 at 13:08:50 UTC from IEEE Xplore.  Restrictions apply.