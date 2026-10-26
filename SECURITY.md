# Biztonság és fenyegetésmodell

> **ALPHA.** Négy belső átnézés (jóváhagyási útvonal, bemenet-kezelés, majd mindkettő ellenőrző köre) leleteit javítottuk, de független, szakértői biztonsági átnézés még nem volt. Élesben ne használd addig.

**English summary:** Trove assumes agents and the content they write are untrusted, and the client does not trust the server or the network. The approver token is the security boundary; the agent instructions and the MCP client's own confirmation prompts are not. Main threats: prompt injection through proposal content (including invisible Unicode), approvals that apply more than was reviewed, token leakage, queue, disk and log flooding, and the limits of a hash-chained audit log that a process with write access could rewrite. The built-in web UI (`/ui/`) adds a browser attack surface: agent-written content rendered in a page with an authenticated owner session. The UI uses a password, Argon2id and opaque access/refresh cookies; authentication tokens are HttpOnly and never exposed to JavaScript. It never parses content as HTML, allows only knowledge base and http(s) links, loads no images or frames from content, and runs under a strict CSP with no inline code; it does not protect against anything that controls the browser itself (an agent with browser automation, a malicious extension). Report vulnerabilities privately to the maintainers (contact to be defined before the public release).

## Bizalmi határok

- A szerver és az adatmappája megbízható. Aki írni tudja az adatmappát, az mindent meg tud kerülni (repo, javaslatok, auditnapló).
- Az agent és minden, amit ír (téma, scope, útvonal, tartalom, a tükör `.trove/state.json`-ja), megbízhatatlan adat.
- A kliens nem bízik a szerverben és a hálózatban: a letöltött snapshotot teljes egészében ugyanazokkal a szabályokkal ellenőrzi, mint a szerver, mielőtt bármit írna; minden szervertől jövő mezőt (id, állapot, agent, digest, commit, hibaüzenet) escape-elve ír ki; redirectet nem követ.
- A jelszavas böngészős owner session, beállítás előtt pedig az approver token ad jóváhagyási jogosultságot. Az MCP kliens saját "megerősítés" ablaka nem biztonsági határ (lehet auto-approve), ezért az MCP-n nincs approve/reject/import, és a `trove mcp` approver tokennel nem indul.
- A webes felület (`/ui/`) csak statikus fájl; minden művelete a meglévő `/v1` API-n megy, a jogosultságot a szerver ellenőrzi. A böngésző, amelyben az owner sessiont használod, ugyanúgy a bizalmi határon belül van, mint az owner terminálja.

### Webes felület: jelszó, session, XSS és CSRF

- **Első beállítás:** meglévő approver token, új jelszó kétszer. A szerver egyetlen owner fiókot tárol. A beállított fiókot a token nem írhatja felül, nincs nyílt regisztráció vagy publikus jelszóreset. A jelszó 15-128 karakter, Argon2id hash (19 MiB, 2 iteráció, párhuzamosság 1), egyedi 16 bájtos salt.
- **Szállítás:** alapból a böngészős hitelesítés közvetlen TLS-t igényel, vagy csak a `web_trusted_proxies` pontos CIDR-jeiből fogad el `X-Forwarded-Proto: https` fejlécet. Tetszőleges kliens proxyfejléce nem elég. Opcionálisan a `web_allow_tailnet_http` engedélyez HTTP-t kizárólag közvetlen `100.64.0.0/10` peer IP-kről, mert a WireGuard a tailnet két végpontja között titkosít. HTTP módban a `web_origin` kötelező és tailnet IP-re kell mutasson; a session cookie nem `Secure`, ezért semmilyen nyilvános vagy sima LAN útvonalon nem használható.
- **Sessiontitkok:** független, véletlen, opaque access/refresh tokenek, csak hashként az atomikusan írt `browser-auth.json` fájlban. HTTPS-en a cookie-k `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` beállításúak, Domain nélkül. HTTP tailnet módban külön cookie-nevek és `HttpOnly; SameSite=Strict; Path=/` szerepel, Secure nélkül, mert a böngésző nem fogad Secure cookie-t HTTP-n. JavaScript nem olvashatja a hitelesítési cookie-kat; nincs localStorage/sessionStorage vagy URL-ben token.
- **Életciklus:** access 10 perc; refresh fix 7 nap. Refreshkor új tokenpár, a régi refresh felhasználtként megmarad; visszajátszáskor a sessioncsalád visszavonva. Legfeljebb 5 másodpercig kizárólag az azonos régi access+refresh pár és egyező CSRF érték kaphatja vissza ugyanazt a frissített választ párhuzamos kérés miatt. Ez a retry-cache csak memóriában van. Legfeljebb 16 eszközsession. Kijelentkezés és jelszócsere a szerveren is visszavon, utóbbi minden sessiont.
- **CSRF:** a cookie-s írásoknál pontosan konfigurált Origin-ellenőrzés és sessionhöz kötött CSRF cookie/egyedi fejléc ellenőrzése van. A CSRF cookie szándékosan olvasható JavaScriptből, de nem ad hitelesítési jogot. CORS nincs; a SameSite csak további védelmi réteg.
- **Próbálkozáskorlát:** jelszavas műveletek legfeljebb két párhuzamos Argon2 számítással, peer és globális próbálkozási ablakkal. A hibák általánosak; nyers jelszó, access/refresh token vagy setup token nem kerül logba. A korlát memóriában él, restartkor újraindul; az egyéb API-kra továbbra sincs általános HTTP rate limit.
- **Jogosultság:** agent/reader tokenből nem lesz owner session. A jelszó beállítása után a raw approver bearer token nem hívhat approve/reject végpontot; ezekhez owner böngészős session kell. A többi owner tokenes CLI-művelet megmarad, ezért az adminisztratív token továbbra sem kerülhet agenthez.
- **XSS:** a KB-tartalom adat. A markdown-megjelenítő DOM-csomópontokat épít `createElement`/`textContent` hívásokkal, nyers HTML nem fut, nincs távoli kép vagy iframe, a linkek KB-jegyzetre vagy normalizált http(s) címre mutathatnak. A CSP nem enged inline vagy külső scriptet. HttpOnly esetén egy XSS nem olvassa ki a hitelesítési cookie-t, de a böngészőből továbbra is végrehajthat hitelesített műveleteket.
- **Jóváhagyás:** a felület teljes diffet és digestet mutat, küldés előtt újra lekéri a review-t, változáskor megtagadja a küldést. Nincs automatikus vagy tömeges jóváhagyás. Ez nem emberi jelenlétet bizonyító hitelesítés: a belépett böngészőt vezérlő agent, rosszindulatú bővítmény vagy kompromittált OS a session nevében cselekedhet. Az owner saját, agent által nem vezérelt böngészője marad a bizalmi határ.
- **Helyreállítás:** csak megbízható helyi adminisztrátori konzolról, leállított szerver mellett a `browser-auth.json` kimozgatásával, majd offline owner tokenes új beállítással (pontos parancsok a README-ben). Hibás állapotfájlnál a szerver nem indul. Aki az adatmappát írja, továbbra is megkerülhet minden védelmet.

## Fenyegetések és védelmek

### Jóváhagyás többet alkalmaz, mint ami látszott
- A review sehol nem csonkít: sem a szerver API, sem a `trove review` CLI (sorhossz, fájlméret, útvonal, figyelmeztetés). Minden megváltozott sor teljes hosszában, escape-elve, közvetlenül a stdout-ra írva látszik (hosszú review-t pagerrel olvass). A méretet a beküldési korlát határolja, így amit az approver végiglát, pontosan az, amit a digest lefed és a commit alkalmaz.
- Az approve a fa-függő szabályokat a bázis és a jelenlegi HEAD fáján is futtatja (fájl/mappa és kis/nagybetűs ütközés, mappa-ikrek is); a commit után a `diff-tree` szerinti változott utaknak pontosan a javaslat útjainak kell lenniük.
- Az elavultság a szülő-utak, gyerek-utak, kis/nagybetűs fájl- és mappa-ikrek változását is figyeli; ha egy javaslat már nem fér bele a HEAD-be, `stale`-ként jelenik meg és rebase-elhető (nem ragad be).

### Prompt injection és láthatatlan Unicode
- A tartalomban blokkolva: vezérlőkarakterek, Unicode tag karakterek (U+E0000-E007F), bidi vezérlők, a variációs szelektor kiegészítő blokk (U+E0100-E01EF, "emoji smuggling"). Figyelmeztetés: egyéb láthatatlan karakterek (zero width, NBSP, U+FE00-FE0F).
- A review és minden kliens-kimenet escape-eli a nem grafikus (Cc, Cf, Co, Cn), sor/bekezdés-elválasztó, nem ASCII szóköz és variációs szelektor karaktereket.
- Útvonalban csak ASCII és a Latin-1 Supplement / Latin Extended-A blokk betűi (U+00C0-U+017F, néhány hasonmás nélkül: ı, ĸ, ŉ, ſ). Kizárva: más írásrendszerek, Latin Extended-B, IPA-kiterjesztések, kis kapitálisok, módosító betűk, teljes szélességű alakok, kombináló jelek (NFD), variációs szelektorok, láthatatlan és bidi karakterek. Ez a standard library-vel elérhető közelítése az "NFC és nincs megtéveszthető karakter" szabálynak, nem teljes Unicode-normalizálás.
- A téma egysoros, szűrt (titokszűréssel együtt); a commit üzenetbe csak ez és ellenőrzött nevek kerülnek, így tartalomból nem lehet trailert hamisítani. Helyreállításkor az id és a digest trailer együtt kell egyezzen.
- Maradék kockázat: a rutinszerű jóváhagyás és a hamis tény bekerülése. A végső szűrő az owner.

### Token-kiszivárgás
- A szerver csak SHA-256 hasht tárol, konstans idejű összehasonlítással. A kliens tokent környezeti változóból vagy fájlból olvas, parancssori kapcsolóként nem fogad el.
- Külön változó az agent/reader (`TROVE_TOKEN`) és az approver tokennek (`TROVE_APPROVER_TOKEN`). Az approver parancsok nem olvassák a `TROVE_TOKEN`-t, és az URL-jük csak explicit `--url`/`TROVE_URL` lehet.
- **Maradék (A-6):** a külön változó csak a véletlen keveredés ellen véd. Ha az owner a `TROVE_APPROVER_TOKEN`-t (vagy a token fájl útját) a shell profiljába vagy egy közös `.env`-be teszi, akkor minden onnan indított, shellt kapó agent örökli, és jóváhagyhat. Az approver tokent ezért csak a jóváhagyás idejére, egy külön, agent nélküli terminálban add meg (pl. kulcstárból egy parancsra), soha ne a profilban, és az agentet olyan környezetben futtasd, amely nem látja a token fájlt.
- A kliens nem küld tokent sima http-n nem loopback címre, csak `--insecure-http` / `TROVE_INSECURE_HTTP=1` mellett, és nem követ redirectet (a Go kliens azonos hosztra https->http redirectnél is továbbküldené az `Authorization` fejlécet).
- Kiszivárgott agent token: olvasni és a kvótáig írni tud, jóváhagyni nem. Kiszivárgott approver token: adminisztratív jog; jelszavas webes beállítás után approve/reject műveletre nem használható.
- **`trove init`:** a tokeneket (256 bit, `crypto/rand`) csak 0600-as token fájlokba írja, 0700-as mappákba, az approver tokent külön `owner/` mappába (a szerver `config/`-jától és az agent `agents/`-től elkülönítve); a `tokens.json`-ba csak a hash kerül. Tokent nem ír ki és nem naplóz (`--show-tokens` kivétel, egyszer). Írás atomikus (ideiglenes fájl, átnevezés); hiba vagy SIGINT/SIGTERM esetén visszagörget, egy korábbi összeomlásból maradt ideiglenes fájlt töröl. Meglévő beállítást `--force` nélkül nem ír felül. Nem loopback `listen` címre figyelmeztet és megerősítést kér. Figyelmeztet, ha a mappa egy git munkafán belül van.
- **Üdvözlő commit (`trove init`):** az egyetlen commit, ami nem javaslat jóváhagyásából születik. Az owner oldali `init` írja közvetlenül az adatmappába (aki azt írni tudja, úgyis mindent megkerülhet), az approve/import kódjával: approver actor, csak üres repóba, ugyanazok a validációs szabályok, fail-closed audit (`bootstrap-intent`, `bootstrap`), `Trove-Bootstrap: welcome` trailer. Futó szerver mellett (instance lock) nem fut le, meglévő tudásbázist nem módosít, az import nem írja felül.
- **Maradék:** egy géppel és felhasználóval futó agent az `owner/` mappát is olvashatja; a 0700 csak más felhasználók ellen véd. Az owner tokent tedd jelszókezelőbe vagy olyan helyre, amit az agent nem lát. Windowson a 0600/0700 jogokat az OS nem érvényesíti (az `init` jelzi).

### Sor-, lemez-, memória- és napló-telítés
- Agentenként 5, összesen 20 nyitott vázlat/javaslat, 7 napos lejárat; agentenként napi `agent_bytes_per_day` (20 MiB) írt tartalom és `agent_begins_per_day` (100) új vázlat.
- A bájt-kvóta az írás időpontja szerint számol (óránkénti jelölők a javaslat metaadatában), így a 24 óránál régebben nyitott vázlatba írt bájt is számít. A submit a kvótát a mutex alatt, a validáció előtt foglalja le, és elutasításkor vagy ütközéskor nem adja vissza (az ismételt próbálkozás is fogyaszt). Agentenként egyszerre egy submit fut, és legfeljebb 4 validáció párhuzamosan. A submitnál foglalt kvóta a következő mentésig csak a memóriában van; a szerver újraindítása (amit csak az owner tud kiváltani) ezt az egy foglalást elfelejtheti.
- A szerveroldali vázlat is `max_total_bytes`-hoz kötött, a tárolt fájl mérete is korlátozott, a JSON nem HTML-escape-el.
- A lezárt javaslatból a tartalom törlődik; az `archive/` csak metaadatot tart, és a memóriába csak az utolsó `archive_memory_days` napé töltődik. **Következmény (C-13):** egy elutasított vagy megszakított javaslat tartalma (pl. egy prompt-injection kísérlet) utólag nem vizsgálható, csak az útvonalai, mérete, digestje és figyelmeztetései. Aki vizsgálni akarja, a review idején mentse el a kimenetet.
- A hosszú műveletek (diff, validáció, titokszűrés) a globális mutexen kívül futnak (review, submit, az approve tartalom-ellenőrzése, digestenként egyszer); a mutex alatt az approve csak fa-szabályokat ellenőriz.
- **Elutasított kérések naplózása:** a szerepkör-sértések, limit- és kvóta-elutasítások és az elutasított beküldések nem a hash-láncolt auditba kerülnek, hanem a `security.jsonl`-be, kulcsonként (actor, esemény, ok) percenként legfeljebb 5, összesen percenként legfeljebb 120 sor, a többi összesítve; a fájl 8 MiB-nál forog (egy régi generáció). Így reader vagy agent token sem tudja az auditot és a lemezt telíteni, és a fail-closed approve nem áll le emiatt. Az ismeretlen tokenes kérések a stderr naplóba kerülnek, percenként legfeljebb 10 sor, `%q`-val idézve (nincs naplóinjekció).

### Útvonal-támadások
- Egy közös szabály (`validate.CheckPathSyntax` + `validate.PathIndex`) a szerveren, az importban és a kliensen: útvonal-szintaxis, fájl/mappa ütközés, kis/nagybetűs fájl- és mappa-ikrek egy javaslaton belül, a bázissal és a HEAD-del szemben is.
- A kliens a teljes snapshotot ellenőrzi írás előtt; ütközés esetén semmit nem ír.
- A git műveletek munkamásolat nélkül, ideiglenes indexszel futnak.

### Import
- A bundle import egy külön, ideiglenes repóban validál (fa-szabályok, fájlmód, tartalom-szabályok, titokszűrés a HEAD-en és a teljes előzményen, `fsckObjects`), és csak siker után fetch-el a `kb.git`-be. Elutasításkor, hibánál, lejárt időkorlátnál vagy panicnál az ideiglenes repó törlődik, a `kb.git`-ben nem marad sem ág, sem objektum (a titkos blob sem); egy összeomlás után maradt ideiglenes repót a következő indulás törli.
- A szkennelhetőnél (4 x `max_file_bytes`) nagyobb fájl vagy előzmény-verzió elutasítja az importot (nem csendes kihagyás).
- Minden importált fájlnak UTF-8 szövegnek kell lennie, vezérlő-, tag-, bidi karakter nélkül; bináris fájl nem importálható.
- A tar import fájlonként ellenőriz és tárol, a memóriában egyszerre egy fájl van.

### Titok a KB-ban
- A titokszűrés blokkol a tartalomban, a témában, a scope-ban, az útvonalban és az importban.
- Kulcsszavak szóhatárral (magyar `jelszó`, német `Passwort`/`Kennwort`, `pass`, `pw` is). Nem számít titoknak: helyőrző (`passwordhere`, `changeme`, `<...>`, `xxx`, `your-...`, `example`, csupa azonos karakter), kódrészlet (függvényhívás, pontozott azonosító, `$VAR`, út), és `kulcs: érték` alakban a kisbetűs gép-/azonosító-szerű érték. Blokkol: ismert token-formátumok, PEM, URL-be írt jelszó, `kulcs=érték` (legalább 6 karakter), idézett vagy jelszó-alakú `kulcs: érték`.
- A szűrő regex-alapú: a véletlen szivárgás tipikus alakjai ellen véd, szándékos kijátszás ellen nem. A gépi teszt (`TestKBNoBlockingFindings`, `TROVE_KB_DIR`) egy valódi KB-n 0 hamis blokkolást követel.

### TOCTOU és konzisztencia
- A fa-ellenőrzés és a commit egy mutex alatt fut; a tartalom-ellenőrzés a digesthez kötött. Az ág mozgatása `update-ref <új> <régi>` compare-and-swap.
- Az állapotváltás másolaton történik, és csak sikeres mentés után kerül a memóriába (submit, abort, reject, rebase, lejárat, applied): sikertelen írás után a memória és a lemez nem tér el.
- Egy példány fut egy adatmappán (OS-szintű zár a `trove.lock`-on; hálózati fájlrendszeren a flock megbízhatósága a telepítéstől függ).

## Az auditnapló korlátai

- Hash-láncolt, kanonikus JSONL: módosítás, törlés a közepéről, sorrendcsere, duplikált kulcs, hozzáfűzött adat felismerhető (`trove audit verify`).
- Az approve, a reject és az import fail-closed (approve-intent, reject-intent, import-intent sor előbb), az approve idempotens ága is. Egy `*-intent` sor önmagában nem jelent végrehajtást: az eredményt a követő `ok`/`failed` sor vagy a git előzmény mutatja.
- Induláskor csak a napló vége olvasódik (állandó memória és idő); a teljes láncellenőrzés a háttérben, streamelve fut, és csak figyelmeztet. Megszakadt írásból maradt csonka utolsó sort az indulás levágja és jelzi. Sikertelen írás vagy fsync után az `Append` visszavágja a fájlt, így a lánc nem törik el.
- Nem megváltoztathatatlan: aki írni tudja a fájlt, az újraszámolhatja a teljes láncot. A végéről törölt sorok csak egy máshol elmentett utolsó hash-sel (`--expect-last`) derülnek ki.
- Erősebb garancia (külön naplózó folyamat, append-only attribútum, távoli gyűjtő) későbbi feladat.

## Ismert korlátok

- Nincs HTTP szintű kapcsolatszám-korlát és általános rate limit (csak a kvóták, a validációs párhuzamosság és a naplózás korlátja), nincs TOTP-s második jóváhagyási csatorna.
- Nincs teljes Unicode-normalizálás (standard library), csak a fent leírt karakter-allowlist.
- Az IPv6 címekre nincs figyelmeztetés.
- Az alap Docker image-ek nincsenek digestre rögzítve.
- A kliens snapshot-alkalmazása nem atomi: a teljes előzetes ellenőrzés után írási hiba (pl. teli lemez) félig alkalmazott tükröt hagyhat.
